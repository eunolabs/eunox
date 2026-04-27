FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/tool-gateway/package*.json ./packages/tool-gateway/

# Install dependencies (including devDependencies for build)
RUN npm ci --workspace=@euno/common --workspace=@euno/tool-gateway

# Copy source code
COPY packages/common ./packages/common
COPY packages/tool-gateway ./packages/tool-gateway
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/tool-gateway

# --- Production image ---
FROM node:18-alpine

# Run as non-root user
RUN addgroup -g 1000 gateway && \
    adduser -D -u 1000 -G gateway gateway

WORKDIR /app

# Copy only production package files and built artifacts
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/tool-gateway/package*.json ./packages/tool-gateway/

# Install production dependencies only
RUN npm ci --omit=dev --workspace=@euno/common --workspace=@euno/tool-gateway

# Copy built artifacts from builder stage
COPY --from=builder /app/packages/common/dist ./packages/common/dist
COPY --from=builder /app/packages/tool-gateway/dist ./packages/tool-gateway/dist

# Set working directory to tool-gateway
WORKDIR /app/packages/tool-gateway

# Switch to non-root user
USER gateway

# Expose port
EXPOSE 3002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3002/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)}).on('error', () => process.exit(1))"

# Start service
CMD ["node", "dist/index.js"]
