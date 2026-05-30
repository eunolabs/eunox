# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Demo-only MCP server.  Built from the repository root so it shares the
# module cache with eunox-mcp:
#
#   docker build -f demo/mock-mcp-server/Dockerfile -t mock-mcp-server .

FROM golang:1.25-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/mock-mcp-server \
    ./demo/mock-mcp-server/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/mock-mcp-server /usr/local/bin/mock-mcp-server

USER 65534:65534

EXPOSE 8080

LABEL org.opencontainers.image.description="Eunox demo mock MCP server"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/usr/local/bin/mock-mcp-server"]
