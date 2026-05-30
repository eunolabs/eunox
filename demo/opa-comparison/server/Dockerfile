# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage build — must be run from the repository root so that the Go
# module (github.com/eunolabs/eunox) is available in the build context.
#
#   docker build -f demo/opa-comparison/server/Dockerfile -t opa-cmp-server .

FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /opa-cmp-server \
    ./demo/opa-comparison/server/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /opa-cmp-server /opa-cmp-server
EXPOSE 9090
ENTRYPOINT ["/opa-cmp-server"]
