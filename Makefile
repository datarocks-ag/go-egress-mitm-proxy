.PHONY: build test lint fmt clean run docker-build docker-run help

# Build variables
BINARY_NAME := mitm-proxy
GO := go
GOFLAGS := -ldflags="-s -w"

# Default target
all: lint test build

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'

## build: Build the binary
build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

## test: Run tests with coverage
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

## test-short: Run tests without race detector (faster)
test-short:
	$(GO) test -v -coverprofile=coverage.out ./...

## lint: Run golangci-lint
lint:
	golangci-lint run

## fmt: Format code
fmt:
	$(GO) fmt ./...
	goimports -w .

## vet: Run go vet
vet:
	$(GO) vet ./...

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME) coverage.out

## run: Run the proxy locally
run:
	$(GO) run .

## deps: Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

## certs: Generate development CA certificates
certs:
	bash scripts/gen-ca.sh

## docker-build: Build Docker image
docker-build:
	docker build -t go-egress-proxy:latest .

## docker-run: Run Docker container (requires config.yaml and certs/)
docker-run:
	docker run --rm -it \
		-p 8080:8080 \
		-p 9090:9090 \
		-v $(PWD)/config.yaml:/app/config.yaml:ro \
		-v $(PWD)/certs:/app/certs:ro \
		go-egress-proxy:latest

## install-tools: Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
