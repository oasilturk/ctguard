# CTGuard

[![Go](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml/badge.svg)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Catch timing side-channel vulnerabilities in your Go code.**

CTGuard finds vulnerabilities in code where secret data can be leaked through execution time, like when you compare passwords with `==` or branch on private keys.

![CTGuard Demo](demo/demo.gif)

## What It Catches

| Rule | What it detects |
|------|-----------------|
| CT001 | Branches and loops that depend on secret data (`if secretKey == ...`) |
| CT002 | Non-constant-time comparisons (`bytes.Equal` on secrets) |
| CT003 | Array/map indexing with secret indices (cache timing) |
| CT004 | Secrets leaked to logs or error messages |

## Quick Example

**❌ Vulnerable Code:**
```go
//ctguard:secret password
func Authenticate(password string) bool {
    hash := sha256.Sum256([]byte(password))  // taint propagates to hash
    expected := loadExpectedHash()
    return bytes.Equal(hash[:], expected)  // timing leak! exec time depends on a secret
}
```
```
auth.go:5:12 CT002: bytes.Equal uses secret 'password'
```

**✅ Fixed:**
```go
//ctguard:secret password
func Authenticate(password string) bool {
    hash := sha256.Sum256([]byte(password))  // taint propagates to hash
    expected := loadExpectedHash()
    return subtle.ConstantTimeCompare(hash[:], expected) == 1  // NO timing leak!
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
# For vendor code without modifying it
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "Verify"
      params: ["key"]

format: json      # plain, json, or sarif
fail: true        # exit code on findings
summary: true     # show stats
```

See [.ctguard.yaml.example](.ctguard.yaml.example) for all options.
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
