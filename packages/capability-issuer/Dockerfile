FROM node:18-alpine

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
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/capability-issuer

# Set working directory to capability-issuer
WORKDIR /app/packages/capability-issuer

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start service
CMD ["node", "dist/index.js"]
