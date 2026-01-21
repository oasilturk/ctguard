# CTGuard

CTGuard is a static analysis tool for detecting potential timing side-channel risks in Go code.

## What it detects (MVP)
- **CT001**: Secret-dependent branches (e.g., secret-tainted data in `if` / `switch` conditions)
- **CT002**: Non-constant-time comparisons involving secret-tainted data

## Install (dev)
```bash
go install ./cmd/ctguard
```

## Usage
```bash
ctguard ./...
```

## Status
Pre-alpha. Expect false positives/negatives while the rules mature.

## Security
Please see [SECURITY.md](SECURITY.md) for responsible disclosure.
