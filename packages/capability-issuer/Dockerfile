# Multi-stage build for Capability Issuer with Sprint 3 sandbox hardening
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/

# Install dependencies
RUN npm ci --workspace=@euno/common --workspace=@euno/capability-issuer

# Copy source code
COPY packages/common ./packages/common
COPY packages/capability-issuer ./packages/capability-issuer
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common && \
    npm run build --workspace=@euno/capability-issuer

# Production stage with hardened security
FROM node:18-alpine

# Sprint 3 Sandbox Hardening: Create non-privileged user
RUN addgroup -g 1001 -S euno && \
    adduser -u 1001 -S euno -G euno && \
    mkdir -p /app && \
    chown -R euno:euno /app

WORKDIR /app

# Copy production dependencies only
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/packages/common/package*.json ./packages/common/
COPY --from=builder /app/packages/capability-issuer/package*.json ./packages/capability-issuer/

# Install production dependencies only
RUN npm ci --workspace=@euno/common --workspace=@euno/capability-issuer --omit=dev

# Copy built artifacts
COPY --from=builder --chown=euno:euno /app/packages/common/dist ./packages/common/dist
COPY --from=builder --chown=euno:euno /app/packages/capability-issuer/dist ./packages/capability-issuer/dist

# Sprint 3 Sandbox Hardening: Set read-only filesystem (except writable temp)
RUN mkdir -p /tmp && chown euno:euno /tmp

# Switch to non-root user
USER euno

# Set working directory to capability-issuer
WORKDIR /app/packages/capability-issuer

# Expose port
EXPOSE 3001

# Sprint 3 Sandbox Hardening: Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start service with limited Node.js memory
CMD ["node", "--max-old-space-size=512", "dist/index.js"]
