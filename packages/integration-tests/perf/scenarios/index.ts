/**
 * Per-route scenario definitions.
 *
 * Each scenario is declarative: the runner (`lib/runner.ts`) reads the
 * shape, points autocannon at the harness URL, and asserts the SLO
 * declared in `slo.ts`. To add a new route's scenario:
 *
 *   1. Add an entry to `SLOS` in `slo.ts`.
 *   2. Add a builder here that emits the request shape (often
 *      parameterised by the harness so it can mint a fresh token /
 *      target a particular path).
 *   3. Done — the CLI picks it up automatically by name.
 *
 * The builders take the {@link PerfHarness} so a scenario can splice in
 * a freshly minted capability token, the issuer's user-auth token,
 * and the right backend host header for `/proxy/*`.
 */

import { PerfHarness } from '../lib/harness';
import { ScenarioDefinition } from '../lib/runner';
import { ISSUANCE_PROFILES } from '../profiles/definitions';

/**
 * Build the full set of scenarios. Returned in the order they should
 * run when no `--scenario` filter is provided.
 */
export function buildScenarios(h: PerfHarness): ScenarioDefinition[] {
  const adminAuth = { authorization: `Bearer ${h.capabilityTokenAdmin}` };
  const viewerAuth = { authorization: `Bearer ${h.capabilityTokenViewer}` };
  const renewableAuth = { authorization: `Bearer ${h.capabilityTokenRenewable}` };
  const adminApiAuth = { 'x-admin-api-key': h.adminApiKey };

  // Pre-serialise bodies once: autocannon reuses the buffer for every
  // request, so we want to pay the JSON-stringify cost zero times in
  // the steady state.
  const invokeBody = JSON.stringify({
    tool: 'read_file',
    args: { path: '/data/perf.json' },
  });
  const validateBody = JSON.stringify({
    action: 'read',
    resource: 'api://perf/customers',
  });
  const issueBody = JSON.stringify({ agentId: 'perf-agent-issuance' });
  // Attenuation must request a *subset* of the parent's
  // capabilities; the harness's perfPolicy grants `api://**` /
  // `tool://**` to Administrator, so a narrow `api://perf/**` /
  // `read` constraint always satisfies the subset check.
  const attenuateBody = JSON.stringify({
    requestedCapabilities: [{ resource: 'api://perf/**', actions: ['read'] }],
    ttl: 300,
  });
  const renewBody = JSON.stringify({ ttl: 600 });

  return [
    // ── Tool Gateway ─────────────────────────────────────────────────────
    {
      name: 'gateway-health-live',
      description: 'Liveness probe — must stay cheap so Kubernetes never times out.',
      target: 'gateway',
      request: { path: '/health/live', method: 'GET' },
    },
    {
      name: 'gateway-health-ready',
      description: 'Readiness probe (gates Service endpoints).',
      target: 'gateway',
      request: { path: '/health/ready', method: 'GET' },
    },
    {
      name: 'gateway-health',
      description:
        'Legacy `/health` route (kept for backwards compatibility). Aliased to the ' +
        'liveness handler in production; covered separately so a future change to ' +
        'the alias is caught here.',
      target: 'gateway',
      request: { path: '/health', method: 'GET' },
    },
    {
      name: 'gateway-metrics',
      description:
        'Prometheus scrape endpoint. The harness uses the same `createMetricsRegistry` ' +
        'configuration as production (default Node collectors enabled), so payload size ' +
        'and serialisation cost match what an operator would actually scrape.',
      target: 'gateway',
      request: { path: '/metrics', method: 'GET' },
    },
    {
      name: 'gateway-tools-invoke-allow',
      description:
        'Hot path: agent invokes a tool with an Administrator-scoped capability. ' +
        'Exercises JWT verify + action resolver + enforcement engine. Argument-schema ' +
        'and response-redaction lobes are not engaged because the perf policy mints ' +
        'plain capabilities (no `argumentSchema` / no redact-capable conditions); when ' +
        'a future scenario adds those, copy this builder and override the policy.',
      target: 'gateway',
      request: {
        path: '/api/v1/tools/invoke',
        method: 'POST',
        headers: {
          ...adminAuth,
          'content-type': 'application/json',
          'x-agent-id': 'perf-agent-admin',
        },
        body: invokeBody,
      },
    },
    {
      name: 'gateway-tools-invoke-deny',
      description:
        'Same hot path with a Viewer-scoped token that lacks write — measures the ' +
        'cost of a synchronous deny (the path SOC operators see most under attack).',
      target: 'gateway',
      request: {
        path: '/api/v1/tools/invoke',
        method: 'POST',
        headers: {
          ...viewerAuth,
          'content-type': 'application/json',
          'x-agent-id': 'perf-agent-viewer',
        },
        // `delete_file` resolves to `delete` — Viewer can't write.
        body: JSON.stringify({ tool: 'delete_file', args: {} }),
      },
      // 403 is the *expected* outcome here, not an error.
      expectedStatusCodes: [403],
    },
    {
      name: 'gateway-validate',
      description:
        '/api/v1/validate — "would this be allowed?" probe used by integrators ' +
        'and dashboards. Same enforcement cost as /tools/invoke without the proxy hop.',
      target: 'gateway',
      request: {
        path: '/api/v1/validate',
        method: 'POST',
        headers: { ...adminAuth, 'content-type': 'application/json' },
        body: validateBody,
      },
    },
    {
      name: 'gateway-proxy-get',
      description:
        'GET via /proxy/* with response-body interception enabled. Exercises ' +
        'the http-proxy-middleware path through to a local stub backend.',
      target: 'gateway',
      request: {
        path: '/proxy/api/perf/customers',
        method: 'GET',
        headers: adminAuth,
      },
    },
    {
      name: 'gateway-proxy-post',
      description:
        'POST via /proxy/* with no body — covers the POST decision path through ' +
        'the proxy middleware. JSON body parsing/forwarding is **not** exercised: ' +
        'sending a non-empty JSON body exposes an `express.json()` + ' +
        '`http-proxy-middleware` interaction that hangs the upstream waiting for ' +
        'content. That underlying gateway bug is out of scope for I-22 — perf ' +
        'testing simply surfaces it. When the bug is fixed, add a body to this ' +
        'scenario and tighten the SLO.',
      target: 'gateway',
      request: {
        path: '/proxy/api/perf/orders',
        method: 'POST',
        headers: adminAuth,
      },
    },
    {
      name: 'gateway-admin-status',
      description:
        'GET /admin/kill-switch/status — admin-API auth + KillSwitchManager lookup. ' +
        'Operators poll this dashboard during incidents, so it has its own SLO.',
      target: 'gateway-admin',
      request: {
        path: '/admin/kill-switch/status',
        method: 'GET',
        headers: adminApiAuth,
      },
    },
    // ── Capability Issuer ────────────────────────────────────────────────
    {
      name: 'issuer-health',
      description: 'Issuer liveness — Kubernetes probe.',
      target: 'issuer',
      request: { path: '/health', method: 'GET' },
    },
    {
      name: 'issuer-metrics',
      description:
        'Issuer Prometheus scrape — same default-collectors configuration as production.',
      target: 'issuer',
      request: { path: '/metrics', method: 'GET' },
    },
    {
      name: 'issuer-jwks',
      description:
        'GET /.well-known/jwks.json — the *live* key-distribution path. Gateway boot ' +
        'and refresh both use this (R-6); SLO floor defends the JWKS cache TTL.',
      target: 'issuer',
      request: { path: '/.well-known/jwks.json', method: 'GET' },
    },
    {
      name: 'issuer-public-key',
      description:
        'GET /api/v1/public-key — DEPRECATED legacy fetch (use /.well-known/jwks.json). ' +
        'Kept under a perf scenario so a regression in the deprecated path still ' +
        'surfaces during the deprecation window.',
      target: 'issuer',
      request: { path: '/api/v1/public-key', method: 'GET' },
    },
    {
      name: 'issuer-well-known-did',
      description:
        'GET /.well-known/did.json — DID document fetch used by external verifiers ' +
        'resolving the issuer DID.',
      target: 'issuer',
      request: { path: '/.well-known/did.json', method: 'GET' },
    },
    {
      name: 'issuer-well-known-meta',
      description:
        'GET /.well-known/capability-issuer — issuer metadata document (schema versions, ' +
        'signing algs, endpoint catalogue).',
      target: 'issuer',
      request: { path: '/.well-known/capability-issuer', method: 'GET' },
    },
    {
      name: 'issuer-issue',
      description:
        'Capability-issuance hot path: identity validate → role resolve → policy ' +
        'evaluate → RSA-2048 sign. The SLO floor on req/s defends the worst-case ' +
        'agent-startup burst when N agents come up simultaneously.',
      target: 'issuer',
      request: {
        path: '/api/v1/issue',
        method: 'POST',
        headers: {
          authorization: `Bearer ${h.userAuthToken}`,
          'content-type': 'application/json',
        },
        body: issueBody,
      },
    },
    {
      name: 'issuer-attenuate',
      description:
        'POST /api/v1/attenuate — verify parent → check subset → mint child. Adds ' +
        'a second RSA verify on top of the issuance hot path.',
      target: 'issuer',
      request: {
        path: '/api/v1/attenuate',
        method: 'POST',
        headers: { ...adminAuth, 'content-type': 'application/json' },
        body: attenuateBody,
      },
    },
    {
      name: 'issuer-renew',
      description:
        'POST /api/v1/renew — verify current → build renewed payload → sign. Uses a ' +
        'dedicated renewable token so the rate-limit + revocation surfaces are ' +
        'isolated from the gateway scenarios.',
      target: 'issuer',
      request: {
        path: '/api/v1/renew',
        method: 'POST',
        headers: { ...renewableAuth, 'content-type': 'application/json' },
        body: renewBody,
      },
    },

    // ── Profiled issuance (KMS + stacked optionals) ──────────────────────
    //
    // Each scenario targets a separate issuer instance wired with the
    // corresponding KMS simulator and optional components. The SLO
    // budgets in `slo.ts` are derived from typical same-region KMS p95
    // latencies plus the Node.js processing overhead baseline.
    //
    // The `+full` profiles are the key SLO defenders for the README claim
    // "Token issuance < 500 ms (p95)": if any of them fail, the stacked
    // overhead has grown beyond what the README documents.
    //
    // Each profiled issuer serves its own isolated in-memory state, so
    // scenarios can run sequentially without shared-state contamination.
    //
    // Load profile for profiled scenarios: fewer connections than the
    // baseline because each request holds a simulated KMS RTT open.
    // With 20 connections × 5 s × ~40ms/req (Azure) ≈ 2500 requests —
    // enough samples for stable p50/p99 percentiles.
    ...ISSUANCE_PROFILES.map(
      (profile): ScenarioDefinition => ({
        name: `issuer-issue:${profile.tag}`,
        description: profile.description,
        // Route to the profiled issuer URL via the 'issuer:<tag>' convention.
        target: `issuer:${profile.tag}`,
        request: {
          path: '/api/v1/issue',
          method: 'POST',
          headers: {
            authorization: `Bearer ${h.userAuthToken}`,
            'content-type': 'application/json',
          },
          body: issueBody,
        },
        // Profiled scenarios run with fewer connections to avoid saturating
        // the event loop with simulated async delays. The lower connection
        // count keeps the per-run sample count above ~1k while ensuring
        // that p99 reflects per-request latency, not queue time.
        load: { connections: 10, durationSeconds: 5 },
        // The p99 budget for each profiled scenario is declared in slo.ts
        // (the single source of truth). No sloOverride needed here — the
        // runner looks up `SLOS['issuer-issue:<tag>']` automatically.
      }),
    ),
  ];
}
