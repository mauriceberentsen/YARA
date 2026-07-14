.PHONY: build test vet fmt check

build:
	go build -o bin/yara ./cmd/yara

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

check: test vet
	@test -z "$$(gofmt -l cmd internal)" || (echo "Go files need formatting; run 'make fmt'" && exit 1)
