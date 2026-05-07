/**
 * Agent Runtime Service Entrypoint
 *
 * All configuration is validated at boot via the typed `AgentRuntimeConfigSchema`
 * (see packages/common/src/config/schema.ts).  Run:
 *
 *   euno config dump-template --service agent-runtime
 *
 * to generate a `.env.example` listing every supported variable with its
 * description and default value.
 *
 * Long-running process that:
 * 1. Validates configuration against the typed schema
 * 2. Initializes the AgentRuntime (acquires capability token, starts refresh loop)
 * 3. Serves a health-check HTTP endpoint on PORT (default 3003)
 * 4. Handles graceful shutdown on SIGTERM
 */

import * as http from 'http';
import { loadConfigOrExit } from '@euno/common';
import { AgentRuntime } from './runtime';

// Validate the environment against the typed schema and exit with a
// structured error report on misconfig — no service code runs until
// every required variable is present and valid.
const cfg = loadConfigOrExit(process.env, 'agent-runtime');

let runtime: AgentRuntime | null = null;
let healthy = false;

async function start(): Promise<void> {
  console.log(`[agent-runtime] Starting agent ${cfg.AGENT_ID}`);

  runtime = new AgentRuntime({
    agentId: cfg.AGENT_ID,
    gatewayUrl: cfg.GATEWAY_URL,
    issuerUrl: cfg.ISSUER_URL,
    authToken: cfg.AUTH_TOKEN,
    tokenRefreshInterval: cfg.TOKEN_REFRESH_INTERVAL,
  });

  await runtime.initialize();
  healthy = true;
  console.log(`[agent-runtime] Agent ${cfg.AGENT_ID} initialized successfully`);
}

// Health-check HTTP server — allows Kubernetes liveness/readiness probes
const server = http.createServer((req, res) => {
  if (req.url === '/health' && req.method === 'GET') {
    if (healthy) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', agentId: cfg.AGENT_ID }));
    } else {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'initializing', agentId: cfg.AGENT_ID }));
    }
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.listen(cfg.PORT, () => {
  console.log(`[agent-runtime] Health endpoint listening on port ${cfg.PORT}`);
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
