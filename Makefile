.PHONY: build install fmt lint test test-golden golden-update ci clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

build:
	go build $(LDFLAGS) -o bin/ctguard ./cmd/ctguard

install:
	go install $(LDFLAGS) ./cmd/ctguard

fmt:
	gofmt -w .

lint:
	golangci-lint run $(shell go list ./... | grep -Ev '/(examples|testdata)/' | sed 's|github.com/oasilturk/ctguard|.|')

test:
	go test ./...

test-golden:
	go test ./cmd/ctguard -run TestGolden -v

golden-update:
	go test ./cmd/ctguard -update -run TestGolden -v

ci: fmt lint
	go clean -testcache
	go test ./...

clean:
	rm -rf bin/
