# CTGuard

[![Go](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml/badge.svg)](https://github.com/oasilturk/ctguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Static analysis tool that finds timing side-channel vulnerabilities in Go code.

## What It Catches

| Rule | What it detects |
|------|-----------------|
| CT001 | Branches that depend on secret data (`if secretKey == ...`) |
| CT002 | Non-constant-time comparisons (`bytes.Equal` on secrets) |
| CT003 | Array/map indexing with secret indices (cache timing) |
| CT004 | Secrets leaked to logs or error messages |

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

## Suppressing Findings

Sometimes you know better. Use `//ctguard:ignore`:

```go
//ctguard:ignore CT002 -- I know what I'm doing
return bytes.Equal(key, expected)
```

Or ignore everything in a function:

```go
//ctguard:ignore
//ctguard:secret key
func SafeCompare(key []byte) bool {
    // Nothing in here will be flagged
}
```

## Configuration

CTGuard supports configuration files for consistent settings across your project. Create a `.ctguard.yaml` in your project root:

```yaml
rules:
  enable:
    - all              # Or list specific rules: [CT001, CT002]
  disable:
    - CT003            # Optionally disable specific rules

# Config-based secret annotations (useful for vendor/3rd-party code)
annotations:
  secrets:
    - package: "github.com/vendor/crypto"
      function: "VerifyMAC"
      params: ["mac", "key"]

format: plain          # Output format: plain, json, or sarif
fail: true             # Exit with error code on findings
summary: true          # Show summary after scan
exclude:
  - "vendor/**"        # Exclude patterns
  - "**/*_test.go"
```

CTGuard will automatically search for `.ctguard.yaml` in:
- Current directory (and parent directories)
- Home directory (`~/.ctguard.yaml`)

Or specify a config file explicitly:

```bash
ctguard -config=path/to/config.yaml ./...
```

**Priority:** Code comments (`//ctguard:secret`) always override config file annotations.

**Note:** CLI flags always override config file settings.

See [.ctguard.yaml.example](.ctguard.yaml.example) for a complete configuration example.

## Output Formats

```bash
ctguard ./...                    # Plain text (default)
ctguard -format=json ./...       # JSON
ctguard -format=sarif ./...      # SARIF (for GitHub Code Scanning)
```

## CI Integration

```yaml
- name: Install CTGuard
  run: go install github.com/oasilturk/ctguard/cmd/ctguard@latest

- name: Run CTGuard
  run: ctguard ./...
```

For GitHub Code Scanning:

```yaml
- run: ctguard -format=sarif -fail=false ./... > ctguard.sarif

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ctguard.sarif
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome!

## License

MIT
