FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/

# Install dependencies (including devDependencies for build)
RUN npm ci --workspace=@euno/common --workspace=@euno/capability-issuer

# Copy source code
COPY packages/common ./packages/common
COPY packages/capability-issuer ./packages/capability-issuer
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/capability-issuer

# --- Production image ---
FROM node:18-alpine

# Run as non-root user
RUN addgroup -g 1000 issuer && \
    adduser -D -u 1000 -G issuer issuer

WORKDIR /app

# Copy only production package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/

# Install production dependencies only
RUN npm ci --omit=dev --workspace=@euno/common --workspace=@euno/capability-issuer

# Copy built artifacts from builder stage
COPY --from=builder /app/packages/common/dist ./packages/common/dist
COPY --from=builder /app/packages/capability-issuer/dist ./packages/capability-issuer/dist

# Set working directory to capability-issuer
WORKDIR /app/packages/capability-issuer

# Switch to non-root user
USER issuer

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)}).on('error', () => process.exit(1))"

# Start service with limited Node.js memory (Sprint 3 sandbox hardening)
CMD ["node", "--max-old-space-size=512", "dist/index.js"]
