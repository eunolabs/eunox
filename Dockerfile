# syntax=docker/dockerfile:1
# eunox: one image with two binaries, `eunox` and the demo traffic generator
# `eunox-demo`, for linux/amd64 and linux/arm64.
#
#   docker build -t eunox .
#
# The build stage runs on the build machine's own platform and cross-compiles
# for the target, and the runtime stage runs nothing, so building for both
# platforms needs no emulation:
#
#   docker buildx build --platform linux/amd64,linux/arm64 .

FROM --platform=$BUILDPLATFORM rust:1.98-bookworm AS build
ARG TARGETARCH
# The Rust target for TARGETARCH, and a C cross-compiler when it isn't the
# build machine's own architecture (aws-lc-sys, under rustls, compiles C).
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) rust=x86_64-unknown-linux-gnu; pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) rust=aarch64-unknown-linux-gnu; pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$(dpkg --print-architecture)" != "$TARGETARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends $pkgs; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    rustup target add "$rust"; \
    echo "$rust" > /rust-target
# The same names work natively and cross: gcc installs triplet-prefixed links.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
WORKDIR /src
COPY . .
# Cache the registry and target directory across builds, one of each per
# architecture. A shared registry breaks parallel builds: cargo's lock for it
# is in CARGO_HOME, outside the mount, so two builds unpack the same crate at
# once ("failed to unpack package ... File exists"). Copy the binaries out,
# since the target directory lives only in the cache.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=eunox-registry-$TARGETARCH \
    --mount=type=cache,target=/src/target,id=eunox-target-$TARGETARCH \
    rust="$(cat /rust-target)" \
    && cargo build --release --locked --target "$rust" -p eunox --bins \
    && cp "target/$rust/release/eunox" "target/$rust/release/eunox-demo" /usr/local/bin/

FROM debian:bookworm-slim
# CA certificates for fetching operators' key directories and range files,
# taken from the build stage (also Debian bookworm) so this stage needs no RUN.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/local/bin/eunox /usr/local/bin/eunox-demo /usr/local/bin/
USER 65532:65532
# 5140/udp nginx syslog, 4317 OTLP logs (Envoy), 8041 Kong http-log, 8040 report and /metrics.
EXPOSE 5140/udp 4317 8041 8040
ENTRYPOINT ["eunox"]
CMD ["serve"]
