<h1><img src="assets/logo.png" width="36" align="absmiddle" alt="CTGuard Logo">&nbsp;CTGuard</h1>

<div align="center">
  <p><strong>Static analyzer that catches timing side-channel vulnerabilities in Go.</strong></p>

  [![CI](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml/badge.svg)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
  [![Go Report Card](https://goreportcard.com/badge/github.com/oasilturk/ctguard)](https://goreportcard.com/report/github.com/oasilturk/ctguard)
  [![Coverage](https://img.shields.io/endpoint?url=https://oasilturk.github.io/ctguard/.badges/coverage.json)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
  [![Go Reference](https://pkg.go.dev/badge/github.com/oasilturk/ctguard.svg)](https://pkg.go.dev/github.com/oasilturk/ctguard)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

<br>

CTGuard uses SSA-based taint tracking to find code paths where secret data leaks through execution timing. It catches comparisons with `==`, branches on private keys, secret-dependent indexing, and more.

<p align="center">
  <img src="assets/demo.gif" width="700" alt="CTGuard Demo">
</p>

## Getting Started

### Install

**macOS / Linux**

```bash
brew install oasilturk/tap/ctguard
```

or

```bash
go install github.com/oasilturk/ctguard/cmd/ctguard@latest
```

**Windows**

```bash
go install github.com/oasilturk/ctguard/cmd/ctguard@latest
```

Pre-built binaries for all platforms are available on the [Releases](https://github.com/oasilturk/ctguard/releases) page.

> ctguard runs as a `go vet` analyzer, so the Go toolchain must be installed and on `PATH` at runtime, even when using a pre-built binary.

### Run

Mark secret parameters, then scan:

```go
//ctguard:secret key
func Verify(key []byte, message []byte) bool {
    return bytes.Equal(key, expected) // CTGuard flags this
}
```

```bash
ctguard ./...
```

## Rules

| Rule | Description | Example |
|------|-------------|---------|
| **CT001** | Secret-dependent branching | `if secret == "admin"` |
| **CT002** | Non-constant-time comparison | `bytes.Equal(secret, input)` |
| **CT003** | Secret-dependent indexing | `table[secret[i]]` (cache timing) |
| **CT004** | Secret exposure in logs/errors | `log.Printf("%s", secret)` |
| **CT005** | Variable-time arithmetic | `secret / n`, `secret % n` |
| **CT006** | Secret on channels | `ch <- secret` |
| **CT007** | Secret in I/O sinks | `conn.Write(secret)` in isolated regions |

CT004, CT006 and CT007 report disclosure, so they only fire on confidential content. See [Two kinds of secret](#two-kinds-of-secret).

## Example

```go
//ctguard:secret key
func Check(key string) {
    if key == "admin" {      // secret-dependent comparison
        grantAccess()
    }
}
```

```
auth.go:3:8 CT001: branch depends on secret 'key' (confidence: high)
auth.go:3:8 CT002: string comparison uses secret 'key' (confidence: high)
```

Fix with constant-time operations:

```go
//ctguard:secret key
func Check(key string) {
    if subtle.ConstantTimeCompare([]byte(key), []byte("admin")) == 1 {
        grantAccess()
    }
}
```

```
No issues found
```

## Output Formats

```bash
ctguard ./...                    # Plain text (default)
ctguard -format=json ./...       # JSON
ctguard -format=sarif ./...      # SARIF (GitHub Code Scanning)
```

## CI Integration

### GitHub Actions

```yaml
- uses: oasilturk/ctguard@main
```

### With Code Scanning

```yaml
- uses: oasilturk/ctguard@main
  with:
    format: sarif
    args: "-fail=false ./..."
    sarif-file: ctguard.sarif

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ctguard.sarif
```

## Configuration

Create `.ctguard.yaml` in your project root:

```yaml
rules:
  enable: [all]
  disable: [CT003]

exclude:
  - "vendor/**"
  - "**/*_test.go"
```

<details>
<summary>All options</summary>

```yaml
annotations:
  secrets:
    - package: "github.com/vendor/pkg"
      function: "Compare"
      params: ["secret"]
  ignores:
    - package: "github.com/vendor/pkg"
      function: "SafeFunc"
      rules: all

format: json
fail: true
summary: true
min-confidence: low
```

See [.ctguard.yaml.example](.ctguard.yaml.example) for a full reference.

</details>

## Suppressing Findings

```go
//ctguard:ignore CT002 -- constant prefix check, not a timing risk
return strings.HasPrefix(token, "Bearer ")
```

```go
//ctguard:ignore              // all rules
//ctguard:ignore CT001        // specific rule
//ctguard:ignore CT001 CT002  // multiple rules
```

## How It Works

CTGuard integrates with `go vet` as a custom analyzer. It builds an SSA representation of your code, then:

1. Identifies secrets from two sources: `//ctguard:secret` annotations (and their `.ctguard.yaml` equivalent), plus crypto values it recognizes on its own, currently HMAC state from `hmac.New` and from a `sync.Pool` that produces one
2. Tracks taint across functions within a package (fixed-point iteration)
3. Runs 7 specialized rule checkers against the taint graph
4. Reports findings with confidence levels (high/low) based on taint precision

### Two kinds of secret

Not every secret-tainted value is confidential. CTGuard tracks a kind alongside the taint:

- **Content**: keys, passwords, tokens, anything you annotate. Every rule applies.
- **Authenticator**: an HMAC and whatever is derived from it. A MAC is meant to be published, so it is exempt from the disclosure rules (CT004, CT006, CT007). The timing rules still apply, because comparing or indexing by a MAC in variable time helps an attacker forge one.

Mixing the two never weakens the result: a value derived from both a MAC and a key is treated as content.

The authenticator classification is an assumption about intent, not a proof. When an HMAC output is itself a secret, the assumption is wrong and the disclosure rules go quiet; see [Limitations](#limitations).

```go
func sign(key, msg []byte) {
    m := hmac.New(sha256.New, key)
    m.Write(msg)
    log.Printf("sig=%x", m.Sum(nil))        // not a finding: a MAC is public
    if bytes.Equal(m.Sum(nil), given) {}    // CT002: still a forgery oracle
}
```

## Limitations

- **Taint does not cross package boundaries.** A secret passed to a function in another package is not tracked into that package's body. Mark the entry points there with `//ctguard:secret`, or declare them in `.ctguard.yaml` under `annotations.secrets`.
- **An HMAC whose output is itself a secret is treated as an authenticator.** `hmac.New(...).Sum(nil)` is the same expression whether the result is a signature meant to be published, a subkey from a hand-rolled KDF, or a capability such as a password-reset token, a signed value used as a bearer credential, or an HMAC-derived API key. ctguard cannot tell them apart, so all of them are exempt from CT004, CT006 and CT007, and logging one is not reported even when it is a real leak. Where the output is key material or a credential rather than a signature, annotate the parameter that receives it with `//ctguard:secret` to restore content taint. The timing rules are unaffected either way.
- **Taint is not tracked into closures, goroutines, or deferred functions.** A secret captured by a `go func(){...}()`, a closure, or a `defer` is not followed into that body.
- **CT007 only fires inside `//ctguard:isolated` regions**, which are opt-in.
- **Confidence is `high` or `low`**, derived from taint precision, not a numeric score.

## Compatibility

ctguard follows semantic versioning. Within a `1.x` release these stay stable: rule IDs (CT001-CT007), the `.ctguard.yaml` schema, the JSON and SARIF output shapes, CLI flag names, and the exit codes below. Additive changes (new rules, new optional fields) may land in minor releases.

| Exit code | Meaning |
|-----------|---------|
| `0` | No findings (or findings with `-fail=false`) |
| `1` | Findings reported, or the scan was incomplete (a package failed to load) |
| `2` | Usage or configuration error (bad flag, unknown rule, missing `go` toolchain) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT &copy; [oasilturk](https://github.com/oasilturk)
