# CTGuard

[![Go](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml/badge.svg)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/oasilturk/ctguard)](https://goreportcard.com/report/github.com/oasilturk/ctguard)
[![Coverage](https://img.shields.io/endpoint?url=https://oasilturk.github.io/ctguard/.badges/coverage.json)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/oasilturk/ctguard.svg)](https://pkg.go.dev/github.com/oasilturk/ctguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Catch timing side-channel vulnerabilities in your Go code.**

CTGuard finds vulnerabilities in code where secret data can be leaked through execution time, like when you compare passwords with `==` or branch on private keys. Each finding includes a confidence level to help you focus on the most certain issues.

![CTGuard Demo](demo/demo.gif)

## What It Catches

| Rule | What it detects |
|------|-----------------|
| CT001 | Branches and loops that depend on secret data (`if secretKey == ...`) |
| CT002 | Non-constant-time comparisons (`bytes.Equal` on secrets) |
| CT003 | Array/map indexing with secret indices (cache timing) |
| CT004 | Secrets leaked to logs or error messages |
| CT005 | Variable-time arithmetic operations (`/`, `%`, `<<`, `>>` on secrets) |
| CT006 | Secret related channel operations (send/receive) |
| CT007 | Secret data flowing into I/O sinks (network, file, syscall) within "isolated" regions |

## Quick Example

**Vulnerable Code:**
```go
//ctguard:secret key
func Check(key string) {
    normalized := strings.ToLower(key)  // taint propagates
    if normalized == "admin" {  // CT001: branch depends on secret!
        grantAccess()
    }
}
```
```
auth.go:4:5 CT001: branch depends on secret 'key' (confidence: high)
```

**Fixed:**
```go
//ctguard:secret key
func Check(key string) {
    normalized := strings.ToLower(key)
    if subtle.ConstantTimeCompare([]byte(normalized), []byte("admin")) == 1 {
        grantAccess()
    }
}
```
```
✓ No issues found
```

## Install

```bash
go install github.com/oasilturk/ctguard/cmd/ctguard@latest
```

## Usage

Mark your secret parameters:

```go
//ctguard:secret key
func Verify(key []byte, message []byte) bool {
    return bytes.Equal(key, expected) // CTGuard will flag this
}
```

Run it:

```bash
ctguard ./...
```

**Output formats:**

```bash
ctguard ./...                    # Plain text (default)
ctguard -format=json ./...       # JSON
ctguard -format=sarif ./...      # SARIF (for GitHub Code Scanning)
```

## Configuration

Create `.ctguard.yaml` in your project:

```yaml
rules:
  enable: [all]
  disable: [CT003]  # optionally disable rules

exclude:
  - "vendor/**"
  - "**/*_test.go"
```

<details>
<summary><b>Advanced Configuration</b></summary>

```yaml
# Without modifying the code. Wildcards are supported.
annotations:
  secrets:
    - package: "github.com/vendor/examples"
      function: "NonConstantTimeFunction"
      params: ["secret"]
  ignores:
    - package: "github.com/vendor/examples"
      function: "SafeFunction"
      rules: all    # or specific rules like ["CT001", "CT002"]

format: json        # plain, json, or sarif
fail: true          # exit code on findings
summary: true       # show stats
min-confidence: low # low or high
```

See [.ctguard.yaml.example](.ctguard.yaml.example) for all options.

> **Tip:** Use `-min-confidence=high` to filter out uncertain findings, or set `min-confidence: high` in config.
</details>

## CI Integration

**GitHub Actions:**
```yaml
- run: go install github.com/oasilturk/ctguard/cmd/ctguard@latest
- run: ctguard ./...
```

**With GitHub Code Scanning:**
```yaml
- run: ctguard -format=sarif ./... > ctguard.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ctguard.sarif
```

## Suppressing Findings

When you have a legitimate reason to ignore a finding:

```go
//ctguard:secret token
func ParseToken(token string) bool {
    //ctguard:ignore CT002 -- comparing constant prefix for parsing
    return strings.HasPrefix(token, "Bearer ")
}
```

## Learn More

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Example Config](.ctguard.yaml.example)

## License

MIT © [oasilturk](https://github.com/oasilturk)
