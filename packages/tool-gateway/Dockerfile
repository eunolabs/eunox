FROM node:18-alpine

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
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/tool-gateway

# Set working directory to tool-gateway
WORKDIR /app/packages/tool-gateway

# Expose port
EXPOSE 3002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3002/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start service
CMD ["node", "dist/index.js"]
