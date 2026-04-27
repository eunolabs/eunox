# Multi-stage build for Tool Gateway with Sprint 3 sandbox hardening
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/tool-gateway/package*.json ./packages/tool-gateway/

# Install dependencies
RUN npm ci --workspace=@euno/common --workspace=@euno/tool-gateway

# Copy source code
COPY packages/common ./packages/common
COPY packages/tool-gateway ./packages/tool-gateway
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common && \
    npm run build --workspace=@euno/tool-gateway

# Production stage with hardened security
FROM node:18-alpine

# Sprint 3 Sandbox Hardening: Create non-privileged user
RUN addgroup -g 1002 -S euno && \
    adduser -u 1002 -S euno -G euno && \
    mkdir -p /app && \
    chown -R euno:euno /app

WORKDIR /app

# Copy production dependencies only
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/packages/common/package*.json ./packages/common/
COPY --from=builder /app/packages/tool-gateway/package*.json ./packages/tool-gateway/

# Install production dependencies only
RUN npm ci --workspace=@euno/common --workspace=@euno/tool-gateway --omit=dev

# Copy built artifacts
COPY --from=builder --chown=euno:euno /app/packages/common/dist ./packages/common/dist
COPY --from=builder --chown=euno:euno /app/packages/tool-gateway/dist ./packages/tool-gateway/dist

# Sprint 3 Sandbox Hardening: Set read-only filesystem (except writable temp)
RUN mkdir -p /tmp && chown euno:euno /tmp

# Switch to non-root user
USER euno

# Set working directory to tool-gateway
WORKDIR /app/packages/tool-gateway

# Expose port
EXPOSE 3002

# Sprint 3 Sandbox Hardening: Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3002/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start service with limited Node.js memory
CMD ["node", "--max-old-space-size=512", "dist/index.js"]
