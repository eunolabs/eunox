##############################################################################
# Capability Issuer — multi-stage Docker image
#
# Build context: repo root.
##############################################################################

FROM node:18-alpine AS builder

WORKDIR /app

# ── Layer 1: workspace manifests ──────────────────────────────────────────────
COPY package*.json ./
COPY tsconfig.json ./

COPY public/packages/common/package*.json             ./public/packages/common/
COPY euno-platform/packages/common-infra/package*.json  ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json        ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/

RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --include=dev

# ── Layer 2: source files ──────────────────────────────────────────────────────
COPY public/packages/common/           ./public/packages/common/
COPY euno-platform/packages/common-infra/  ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/        ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/ ./euno-platform/packages/capability-issuer/

# ── Layer 3: build ─────────────────────────────────────────────────────────────
RUN npm run build -w @euno/common-core
RUN npm run build -w @euno/common-infra
RUN npm run build -w @euno/common
RUN npm run build -w @euno/capability-issuer

##############################################################################
# Production image
##############################################################################
FROM node:18-alpine

LABEL org.opencontainers.image.title="Euno Capability Issuer" \
      org.opencontainers.image.description="Capability token issuer for Euno agent governance (BSL 1.1)" \
      org.opencontainers.image.url="https://github.com/edgeobs/euno-platform" \
      org.opencontainers.image.licenses="BUSL-1.1"

RUN addgroup -g 1000 issuer && \
    adduser -D -u 1000 -G issuer issuer

WORKDIR /app

COPY package*.json ./

COPY public/packages/common/package*.json             ./public/packages/common/
COPY euno-platform/packages/common-infra/package*.json  ./euno-platform/packages/common-infra/
COPY euno-platform/packages/common/package*.json        ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/

RUN npm ci \
      --workspace=@euno/common-core \
      --workspace=@euno/common-infra \
      --workspace=@euno/common \
      --workspace=@euno/capability-issuer \
      --omit=dev

COPY --from=builder /app/public/packages/common/dist              ./public/packages/common/dist
COPY --from=builder /app/euno-platform/packages/common-infra/dist ./euno-platform/packages/common-infra/dist
COPY --from=builder /app/euno-platform/packages/common/dist       ./euno-platform/packages/common/dist
COPY --from=builder /app/euno-platform/packages/capability-issuer/dist ./euno-platform/packages/capability-issuer/dist

WORKDIR /app/euno-platform/packages/capability-issuer

USER issuer

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 3001) + '/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1))"

CMD ["node", "--max-old-space-size=512", "dist/index.js"]

