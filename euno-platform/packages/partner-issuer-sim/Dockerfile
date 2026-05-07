FROM node:18-alpine AS builder

WORKDIR /app

# Copy workspace package manifests
COPY package*.json ./
COPY euno-platform/packages/common/package*.json ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/partner-issuer-sim/package*.json ./euno-platform/packages/partner-issuer-sim/

# Install dependencies (including dev deps for build)
RUN npm ci \
    --workspace=@euno/common \
    --workspace=@euno/capability-issuer \
    --workspace=@euno/partner-issuer-sim

# Copy source
COPY tsconfig.json ./
COPY euno-platform/packages/common ./euno-platform/packages/common
COPY euno-platform/packages/capability-issuer ./euno-platform/packages/capability-issuer
COPY euno-platform/packages/partner-issuer-sim ./euno-platform/packages/partner-issuer-sim

# Build the dependency chain
RUN npm run build --workspace=@euno/common \
    && npm run build --workspace=@euno/capability-issuer \
    && npm run build --workspace=@euno/partner-issuer-sim

# --- Runtime image ---
FROM node:18-alpine

# Run as non-root
RUN addgroup -g 1000 partner && adduser -D -u 1000 -G partner partner

WORKDIR /app

COPY package*.json ./
COPY euno-platform/packages/common/package*.json ./euno-platform/packages/common/
COPY euno-platform/packages/capability-issuer/package*.json ./euno-platform/packages/capability-issuer/
COPY euno-platform/packages/partner-issuer-sim/package*.json ./euno-platform/packages/partner-issuer-sim/

RUN npm ci --omit=dev \
    --workspace=@euno/common \
    --workspace=@euno/capability-issuer \
    --workspace=@euno/partner-issuer-sim

COPY --from=builder /app/euno-platform/packages/common/dist ./euno-platform/packages/common/dist
COPY --from=builder /app/euno-platform/packages/capability-issuer/dist ./euno-platform/packages/capability-issuer/dist
COPY --from=builder /app/euno-platform/packages/partner-issuer-sim/dist ./euno-platform/packages/partner-issuer-sim/dist

WORKDIR /app/euno-platform/packages/partner-issuer-sim

USER partner

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT||4001) + '/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server.js"]
