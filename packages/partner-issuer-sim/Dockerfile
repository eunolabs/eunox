FROM node:18-alpine AS builder

WORKDIR /app

# Copy workspace package manifests
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/
COPY packages/partner-issuer-sim/package*.json ./packages/partner-issuer-sim/

# Install dependencies (including dev deps for build)
RUN npm ci \
    --workspace=@euno/common \
    --workspace=@euno/capability-issuer \
    --workspace=@euno/partner-issuer-sim

# Copy source
COPY tsconfig.json ./
COPY packages/common ./packages/common
COPY packages/capability-issuer ./packages/capability-issuer
COPY packages/partner-issuer-sim ./packages/partner-issuer-sim

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
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/
COPY packages/partner-issuer-sim/package*.json ./packages/partner-issuer-sim/

RUN npm ci --omit=dev \
    --workspace=@euno/common \
    --workspace=@euno/capability-issuer \
    --workspace=@euno/partner-issuer-sim

COPY --from=builder /app/packages/common/dist ./packages/common/dist
COPY --from=builder /app/packages/capability-issuer/dist ./packages/capability-issuer/dist
COPY --from=builder /app/packages/partner-issuer-sim/dist ./packages/partner-issuer-sim/dist

WORKDIR /app/packages/partner-issuer-sim

USER partner

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT||4001) + '/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server.js"]
