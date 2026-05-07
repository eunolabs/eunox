/**
 * Stand-alone entry point used by the Dockerfile / docker-compose harness.
 *
 * Reads configuration from environment variables and starts the partner
 * issuer sim Express app on `PORT` (default 4001).
 *
 * Environment:
 * - `PORT`                — listening port. Default 4001.
 * - `PARTNER_ISSUER_DID`  — partner DID; default `did:web:partner-sim.local%3A4001`.
 * - `PARTNER_AUDIENCE`    — JWT audience claim; default `tool-gateway`.
 * - `PARTNER_TOKEN_TTL`   — token TTL in seconds; default 900.
 * - `PARTNER_SEED`        — 32-byte hex / base64url seed for deterministic
 *                           key derivation. Recommended in CI so the DID
 *                           document is stable across container restarts.
 * - `PARTNER_KEY_DIR`     — optional directory for persisting the key pair.
 * - `PARTNER_TRUSTED_ISSUER_DIDS` — comma-separated list of issuer DIDs the
 *                                   partner accepts on `/validate`.
 */

import { createPartnerApp } from './app';
import { loadOrCreateKey } from './keys';

const port = parseInt(process.env.PORT || '4001', 10);
const issuerDid = process.env.PARTNER_ISSUER_DID || 'did:web:partner-sim.local%3A4001';
const audience = process.env.PARTNER_AUDIENCE || 'tool-gateway';
const ttl = parseInt(process.env.PARTNER_TOKEN_TTL || '900', 10);
const trustedIssuerDids = (process.env.PARTNER_TRUSTED_ISSUER_DIDS || '')
  .split(',')
  .map((s) => s.trim())
  .filter((s) => s.length > 0);

const key = loadOrCreateKey({
  seed: process.env.PARTNER_SEED,
  keyDir: process.env.PARTNER_KEY_DIR,
});

const app = createPartnerApp({
  issuerDid,
  audience,
  defaultTtlSeconds: ttl,
  key,
  trustedIssuerDids,
});

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[partner-issuer-sim] listening on :${port} as ${issuerDid}`);
});
