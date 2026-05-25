# Copyright 2024-2025 Euno Platform Authors
# SPDX-License-Identifier: BUSL-1.1

VERSION ?= 0.1.0
GO ?= go
GOFLAGS ?= -race
GOLANGCI_LINT_VERSION ?= v2.1.6

.PHONY: all build test lint generate clean coverage check-license vet

all: lint test build

## Build all service binaries
build:
	$(GO) build ./...

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
	@which golangci-lint > /dev/null 2>&1 || { echo "Installing golangci-lint..."; go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); }
	golangci-lint run ./...

## Run go vet
vet:
	$(GO) vet ./...

## Run code generation (oapi-codegen, etc.)
generate:
	$(GO) generate ./...

## Check BSL license headers on all .go files
check-license:
	@echo "Checking BSL license headers..."
	@fail=0; \
	for f in $$(find . -name '*.go' -not -path './vendor/*'); do \
		if ! head -2 "$$f" | grep -q "SPDX-License-Identifier: BUSL-1.1"; then \
			echo "MISSING LICENSE HEADER: $$f"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then exit 1; fi
	@echo "All files have BSL license headers."

## Remove build artifacts
clean:
	rm -f coverage.out
	$(GO) clean ./...
