# Copyright 2026 Eunox Authors
# SPDX-License-Identifier: BUSL-1.1
#
# Multi-stage Dockerfile for all Eunox services.
# Usage: docker build --build-arg SERVICE=gateway -t eunox/gateway .
#
# The final image is distroless (no shell, no package manager) and runs as
# non-root (UID 65534). The filesystem is read-only at runtime.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

ARG SERVICE
ARG VERSION=0.0.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN test -n "$SERVICE" || (echo "ERROR: --build-arg SERVICE is required" && exit 1)

# Install git for VCS info in go build, and ca-certificates for HTTPS.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependencies separately for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build the service binary statically (CGO disabled for distroless).
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -buildid=" \
    -o /out/service \
    ./cmd/${SERVICE}/

# ── Final stage (distroless) ─────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

# Import timezone data and CA certs from builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary.
COPY --from=builder /out/service /usr/local/bin/service

# Run as non-root (UID 65534 = nonroot in distroless).
USER 65534:65534

# Metadata labels.
LABEL org.opencontainers.image.source="https://github.com/edgeobs/eunox"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.vendor="Eunox"

ENTRYPOINT ["/usr/local/bin/service"]
