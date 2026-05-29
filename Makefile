# Copyright 2026 Eunox Authors
# SPDX-License-Identifier: BUSL-1.1

VERSION ?= 0.1.0
GO ?= go
GOFLAGS ?= -race
GOLANGCI_LINT_VERSION ?= v2.12.2

IMAGE_REPO    ?= eunolabs/eunox-mcp
DOCKERFILE_MCP     := deploy/docker/Dockerfile.mcp
DOCKERFILE_MCP_WIN := deploy/docker/Dockerfile.mcp.windows

.PHONY: all build test lint generate clean coverage check-license vet \
        docker-build-mcp docker-build-mcp-multi docker-push-mcp

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

## Build the eunox-mcp Docker image for the local platform (fast, no QEMU).
docker-build-mcp:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-f $(DOCKERFILE_MCP) \
		-t $(IMAGE_REPO):$(VERSION) \
		-t $(IMAGE_REPO):latest \
		.

## Build the eunox-mcp Docker image for linux/amd64 + linux/arm64 using buildx.
## Requires: docker buildx, QEMU (docker run --rm --privileged tonistiigi/binfmt --install all).
## Loads the result into the local image store (--load pushes only one platform at a time;
## omit --load and add --push to publish directly to Docker Hub instead).
docker-build-mcp-multi:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-f $(DOCKERFILE_MCP) \
		-t $(IMAGE_REPO):$(VERSION) \
		-t $(IMAGE_REPO):latest \
		.

## Push the locally built eunox-mcp image to Docker Hub.
## Run docker-build-mcp (or docker-build-mcp-multi --push) before this target.
docker-push-mcp:
	docker push $(IMAGE_REPO):$(VERSION)
	docker push $(IMAGE_REPO):latest

## Remove build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out
	$(GO) clean ./...
