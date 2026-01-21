.PHONY: fmt lint test ci

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

test:
	go test ./...

ci: fmt lint test
