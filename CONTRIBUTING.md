# Contributing

Thanks for wanting to contribute! Here's what you need to know.

## Setup

```bash
git clone https://github.com/oasilturk/ctguard.git
cd ctguard
go mod download
```

## Common Commands

```bash
make build    # Build binary to bin/ctguard
make test     # Run all tests
make lint     # Run linter
make fmt      # Format code
```

## Project Layout

```
cmd/ctguard/        # CLI
internal/
  analyzer/         # Main analysis driver
  annotations/      # Parsing annotations
  rules/            # CT001, CT002, etc.
  taint/            # Taint tracking
testdata/           # Test files
```

## Adding a New Rule

Want to add a new rule CTXXX? Here's the quick guideline:

1. Create `internal/rules/ctXXX_name.go`
2. Add `rules.RunCTXXX(...)` call in `internal/analyzer/analyzer.go`
3. Add help text in `cmd/ctguard/main.go`
4. Add test data in `testdata/src/`
5. Run `go test ./cmd/ctguard -run=TestGolden -update` to generate golden files
6. Update README

## Pull Requests

- Keep them small and focused
- Make sure tests pass (`make test`)
- Format your code (`make fmt`)

That's it! Open a PR and we'll figure out the rest together.
