.PHONY: build test vet fmt ui-check check

build:
	go build -o bin/yara ./cmd/yara

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

ui-check:
	npm ci --prefix internal/cli/webui
	npm run check --prefix internal/cli/webui

check: ui-check test vet
	@test -z "$$(gofmt -l cmd internal)" || (echo "Go files need formatting; run 'make fmt'" && exit 1)
