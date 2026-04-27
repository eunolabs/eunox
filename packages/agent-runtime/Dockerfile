# Sprint 1: Sandboxed Agent Runtime with Security Constraints
# - Read-only root filesystem
# - Least-privilege Linux capabilities
# - Network egress restricted to Tool Gateway only
# - No sensitive host paths mounted

FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/agent-runtime/package*.json ./packages/agent-runtime/

# Install dependencies (including devDependencies for build)
RUN npm ci --workspace=@euno/common --workspace=@euno/agent-runtime

# Copy source code
COPY packages/common ./packages/common
COPY packages/agent-runtime ./packages/agent-runtime
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common && \
    npm run build --workspace=@euno/agent-runtime

# --- Production image ---
FROM node:18-alpine

# Run as non-root user
RUN addgroup -g 1000 agent && \
    adduser -D -u 1000 -G agent agent

WORKDIR /app

# Copy only production package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/agent-runtime/package*.json ./packages/agent-runtime/

# Install production dependencies only
RUN npm ci --omit=dev --workspace=@euno/common --workspace=@euno/agent-runtime

# Copy built artifacts from builder stage
COPY --from=builder /app/packages/common/dist ./packages/common/dist
COPY --from=builder /app/packages/agent-runtime/dist ./packages/agent-runtime/dist

# Create writable directories for runtime
RUN mkdir -p /app/tmp /app/logs && \
    chown -R agent:agent /app/tmp /app/logs

# Set working directory to agent-runtime
WORKDIR /app/packages/agent-runtime

# Switch to non-root user
USER agent

# Expose port for health check endpoint
EXPOSE 3003

# Health check - exit 1 on error to correctly signal unhealthy container
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3003/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)}).on('error', () => process.exit(1))"

# Start the long-running agent runtime service
CMD ["node", "dist/main.js"]
