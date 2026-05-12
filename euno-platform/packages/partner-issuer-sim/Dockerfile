FROM node:18-alpine AS builder

WORKDIR /app

# ── Layer 1: workspace manifests ──────────────────────────────────────────────
COPY package*.json ./
COPY tsconfig.json ./

COPY public/packages/common/package*.json              ./public/packages/common/
COPY euno-platform/packages/common-infra/package*.json   ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json         ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/partner-issuer-sim/package*.json ./euno-platform/packages/partner-issuer-sim/

RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --workspace=@euno/partner-issuer-sim \
      --include=dev

# ── Layer 2: source files ──────────────────────────────────────────────────────
COPY public/packages/common/              ./public/packages/common/
COPY euno-platform/packages/common-infra/   ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/         ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/ ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/partner-issuer-sim/ ./euno-platform/packages/partner-issuer-sim/

# ── Layer 3: build ─────────────────────────────────────────────────────────────
RUN npm run build -w @euno/common-core \
    && npm run build -w @euno/common-infra \
    && npm run build -w @euno/common \
    && npm run build -w @euno/capability-issuer \
    && npm run build -w @euno/partner-issuer-sim

# --- Runtime image ---
FROM node:18-alpine

LABEL org.opencontainers.image.title="Euno Partner Issuer Simulator" \
      org.opencontainers.image.description="Cross-org trust harness — partner issuer simulator (BSL 1.1)" \
      org.opencontainers.image.url="https://github.com/edgeobs/euno-platform" \
      org.opencontainers.image.licenses="BUSL-1.1"

# Run as non-root
RUN addgroup -g 1000 partner && adduser -D -u 1000 -G partner partner

WORKDIR /app

COPY package*.json ./

COPY public/packages/common/package*.json              ./public/packages/common/
COPY euno-platform/packages/common-infra/package*.json   ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json         ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/partner-issuer-sim/package*.json ./euno-platform/packages/partner-issuer-sim/

RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --workspace=@euno/partner-issuer-sim \
      --omit=dev

COPY --from=builder /app/public/packages/common/dist              ./public/packages/common/dist
COPY --from=builder /app/euno-platform/packages/common-infra/dist ./euno-platform/packages/common-infra/dist
COPY --from=builder /app/euno-platform/packages/common/dist       ./euno-platform/packages/common/dist
COPY --from=builder /app/euno-platform/packages/capability-issuer/dist ./euno-platform/packages/capability-issuer/dist
COPY --from=builder /app/euno-platform/packages/partner-issuer-sim/dist ./euno-platform/packages/partner-issuer-sim/dist

WORKDIR /app/euno-platform/packages/partner-issuer-sim

USER partner

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT||4001) + '/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server.js"]

