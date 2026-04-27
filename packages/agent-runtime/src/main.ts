/**
 * Agent Runtime Service Entrypoint
 *
 * Long-running process that:
 * 1. Reads configuration from environment variables
 * 2. Initializes the AgentRuntime (acquires capability token, starts refresh loop)
 * 3. Serves a health-check HTTP endpoint on PORT (default 3003)
 * 4. Handles graceful shutdown on SIGTERM
 */

import * as http from 'http';
import { AgentRuntime } from './runtime';

const PORT = parseInt(process.env.PORT || '3003', 10);
const AGENT_ID = process.env.AGENT_ID;
const GATEWAY_URL = process.env.GATEWAY_URL;
const ISSUER_URL = process.env.ISSUER_URL;
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const TOKEN_REFRESH_INTERVAL = process.env.TOKEN_REFRESH_INTERVAL
  ? parseInt(process.env.TOKEN_REFRESH_INTERVAL, 10)
  : 600;

if (!AGENT_ID || !GATEWAY_URL || !ISSUER_URL || !AUTH_TOKEN) {
  console.error(
    'Missing required environment variables: AGENT_ID, GATEWAY_URL, ISSUER_URL, AUTH_TOKEN'
  );
  process.exit(1);
}

let runtime: AgentRuntime | null = null;
let healthy = false;

async function start(): Promise<void> {
  console.log(`[agent-runtime] Starting agent ${AGENT_ID}`);

  runtime = new AgentRuntime({
    agentId: AGENT_ID!,
    gatewayUrl: GATEWAY_URL!,
    issuerUrl: ISSUER_URL!,
    authToken: AUTH_TOKEN!,
    tokenRefreshInterval: TOKEN_REFRESH_INTERVAL,
  });

  await runtime.initialize();
  healthy = true;
  console.log(`[agent-runtime] Agent ${AGENT_ID} initialized successfully`);
}

// Health-check HTTP server - allows Kubernetes liveness/readiness probes
const server = http.createServer((req, res) => {
  if (req.url === '/health' && req.method === 'GET') {
    if (healthy) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', agentId: AGENT_ID }));
    } else {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'initializing', agentId: AGENT_ID }));
    }
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.listen(PORT, () => {
  console.log(`[agent-runtime] Health endpoint listening on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[agent-runtime] SIGTERM received, shutting down gracefully');
  healthy = false;
  if (runtime) {
    await runtime.shutdown();
  }
  server.close(() => {
    console.log('[agent-runtime] Server closed');
    process.exit(0);
  });
});

start().catch((err) => {
  console.error('[agent-runtime] Failed to start:', err);
  process.exit(1);
});
