##############################################################################
# Tool Gateway — multi-stage Docker image
#
# Build context: repo root (the directory that contains package*.json and the
# "public" and "euno-platform" sub-trees).
#
# Configurable backends (all selected via environment variables at runtime):
#   • Call-counter / Revocation / Kill-switch / DPoP-replay stores:
#       REDIS_URL — if unset the gateway uses safe in-memory fallbacks
#                   (suitable for single-replica dev; not recommended for
#                   multi-replica or production deployments).
#   • Audit ledger:
#       AUDIT_LEDGER_BACKEND=none       — no append-only ledger (default)
#       AUDIT_LEDGER_BACKEND=in-memory  — ephemeral; dev/smoke-test only
#       AUDIT_LEDGER_BACKEND=postgres   — durable; requires AUDIT_LEDGER_PG_URL
#                                         + AUDIT_LEDGER_HMAC_SECRET
#   • Evidence signing:
#       ENABLE_CRYPTOGRAPHIC_AUDIT=false     — disabled (default)
#       ENABLE_CRYPTOGRAPHIC_AUDIT=true      — software HMAC signer;
#           requires EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE
#       AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault | aws-kms | gcp-cloudkms
#           — cloud-HSM signer; see .env.example for required variables
#
# See euno-platform/packages/tool-gateway/.env.example for the full
# environment-variable reference and infra/docker-compose.yml for a
# ready-made local stack with Redis + Postgres.
##############################################################################

FROM node:18-alpine AS builder

WORKDIR /app

# ── Layer 1: workspace manifests (high cache-hit; invalidated only on dep changes) ──
COPY package*.json ./
COPY tsconfig.json ./

# public packages (Apache-2.0 core types + interfaces)
COPY public/packages/common/package*.json      ./public/packages/common/

# euno-platform packages (BSL 1.1 infrastructure + services)
COPY euno-platform/packages/common-infra/package*.json     ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json           ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/tool-gateway/package*.json     ./euno-platform/packages/tool-gateway/

# Install ALL workspace dependencies (npm resolves workspace symlinks correctly).
# Including devDependencies so TypeScript and ts-jest are available for the build.
RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --workspace=@euno/tool-gateway \
      --include=dev

# ── Layer 2: source files ──────────────────────────────────────────────────────
COPY public/packages/common/      ./public/packages/common/
COPY euno-platform/packages/common-infra/     ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/           ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/ ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/tool-gateway/     ./euno-platform/packages/tool-gateway/

# ── Layer 3: build (dependency order) ─────────────────────────────────────────
RUN npm run build -w @euno/common-core
RUN npm run build -w @euno/common-infra
RUN npm run build -w @euno/common
RUN npm run build -w @euno/capability-issuer
RUN npm run build -w @euno/tool-gateway

##############################################################################
# Production image — lean runtime layer
##############################################################################
FROM node:18-alpine

LABEL org.opencontainers.image.title="Euno Tool Gateway" \
      org.opencontainers.image.description="Capability-based agent governance gateway (BSL 1.1)" \
      org.opencontainers.image.url="https://github.com/edgeobs/euno-platform" \
      org.opencontainers.image.source="https://github.com/edgeobs/euno-platform" \
      org.opencontainers.image.licenses="BUSL-1.1"

# Run as non-root user (uid/gid 1000 — compatible with most Kubernetes PSPs).
RUN addgroup -g 1000 gateway && \
    adduser -D -u 1000 -G gateway gateway

WORKDIR /app

# ── Layer 1: workspace manifests for production install ───────────────────────
COPY package*.json ./

COPY public/packages/common/package*.json      ./public/packages/common/
COPY euno-platform/packages/common-infra/package*.json     ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json           ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/tool-gateway/package*.json     ./euno-platform/packages/tool-gateway/

# Production dependencies only (no TypeScript compiler, no test frameworks).
RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --workspace=@euno/tool-gateway \
      --omit=dev

# ── Layer 2: compiled artifacts from builder ──────────────────────────────────
COPY --from=builder /app/public/packages/common/dist              ./public/packages/common/dist
COPY --from=builder /app/euno-platform/packages/common-infra/dist ./euno-platform/packages/common-infra/dist
COPY --from=builder /app/euno-platform/packages/common/dist       ./euno-platform/packages/common/dist
COPY --from=builder /app/euno-platform/packages/capability-issuer/dist ./euno-platform/packages/capability-issuer/dist
COPY --from=builder /app/euno-platform/packages/tool-gateway/dist ./euno-platform/packages/tool-gateway/dist

# Set the working directory to the gateway package so relative paths in
# dist/index.js resolve correctly.
WORKDIR /app/euno-platform/packages/tool-gateway

# Switch to non-root user after all filesystem writes are complete.
USER gateway

# Public gateway port (configure with PORT env var; default 3002).
EXPOSE 3002

# Admin port (configure with ADMIN_PORT env var; default 3003).
# Bind ADMIN_HOST to a non-public interface in production.
EXPOSE 3003

# Liveness probe: GET /health returns 200 when the server is running.
# Readiness probe: GET /health/ready returns 200 only after JWKS bootstrap.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 3002) + '/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1))"

# Cap heap at 512 MiB. Adjust NODE_OPTIONS for larger-scale deployments.
CMD ["node", "--max-old-space-size=512", "dist/index.js"]

