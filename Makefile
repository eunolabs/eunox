# Copyright 2026 Eunox Authors
# SPDX-License-Identifier: BUSL-1.1

VERSION ?= 0.1.0
GO ?= go
GOFLAGS ?= -race
GOLANGCI_LINT_VERSION ?= v2.12.2

.PHONY: all build test lint generate clean coverage check-license vet

all: lint test build

## Build all service binaries to ./bin/
build:
	mkdir -p bin
	$(GO) build -o bin/eunox-gateway           	./cmd/gateway
	$(GO) build -o bin/eunox-issuer            	./cmd/issuer
	$(GO) build -o bin/eunox-minter            	./cmd/minter
	$(GO) build -o bin/eunox-db-token-svc      	./cmd/db-token-svc
	$(GO) build -o bin/eunox-storage-grant-svc 	./cmd/storage-grant-svc
	$(GO) build -o bin/eunox-posture-emitter   	./cmd/posture-emitter
	$(GO) build -o bin/eunox-mcp         		./cmd/mcp

## Run tests with race detector
test:
	$(GO) test $(GOFLAGS) -count=1 ./...

## Run tests with coverage report
coverage:
	$(GO) test $(GOFLAGS) -count=1 -coverprofile=coverage.out -covermode=atomic ./pkg/...
	$(GO) tool cover -func=coverage.out
	@echo "---"
	@echo "Coverage report: coverage.out"

## Run linter
lint: vet
	@GOLANGCI_LINT=$$(command -v golangci-lint 2>/dev/null || true); \
	if [ -z "$$GOLANGCI_LINT" ]; then \
		echo "Installing golangci-lint..."; \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
		GOLANGCI_LINT="$$($(GO) env GOPATH)/bin/golangci-lint"; \
	fi; \
	"$$GOLANGCI_LINT" run ./...

## Run go vet
vet:
	$(GO) vet ./...

## Run code generation (oapi-codegen, etc.)
generate:
	$(GO) generate ./...

## Check license headers: BUSL-1.1 everywhere except cmd/mcp/ (Apache-2.0)
check-license:
	@echo "Checking license headers..."
	@fail=0; \
	for f in $$(find . -name '*.go' -not -path './vendor/*' -not -path './cmd/mcp/*'); do \
		if ! head -2 "$$f" | grep -q "SPDX-License-Identifier: BUSL-1.1"; then \
			echo "MISSING BUSL LICENSE HEADER: $$f"; \
			fail=1; \
		fi; \
	done; \
	for f in $$(find ./cmd/mcp -name '*.go'); do \
		if ! head -2 "$$f" | grep -q "SPDX-License-Identifier: Apache-2.0"; then \
			echo "MISSING APACHE LICENSE HEADER: $$f"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then exit 1; fi
	@echo "All files have correct license headers."

## Remove build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out
	$(GO) clean ./...
