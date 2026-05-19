/**
 * Tests for the `PARTNER_ISSUER_DISCOVERY_URL` gateway auto-bootstrap
 * shortcut (Task 9 / § 4.7).
 *
 * `bootstrapPartnerFromDiscoveryUrl` is a pure async function exported from
 * `bootstrap.ts` that fetches a /.well-known/capability-issuer discovery
 * document and seeds the partner DID into an InMemoryPartnerDidRegistry.
 * All tests use a real http server on a random port as the fake discovery
 * endpoint to avoid mocking `fetch`.
 */

import * as http from 'http';
import type { AddressInfo } from 'net';
import { InMemoryPartnerDidRegistry } from '../src/partner-did-registry';
import { bootstrapPartnerFromDiscoveryUrl } from '../src/bootstrap';
import { createLogger } from '@euno/common';

const logger = createLogger('test', 'test');

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Start a minimal HTTP server that returns `body` as JSON for any request. */
function startFakeDiscoveryServer(
  body: unknown,
  statusCode = 200,
): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      const json = JSON.stringify(body);
      res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(json),
      });
      res.end(json);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      const url = `http://127.0.0.1:${port}/.well-known/capability-issuer`;
      resolve({
        url,
        close: () => new Promise((r, e) => server.close((err) => (err ? e(err) : r()))),
      });
    });
  });
}

/** Start a server that returns a non-JSON body (triggers parse error). */
function startBadBodyServer(): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('not json at all');
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      const url = `http://127.0.0.1:${port}/.well-known/capability-issuer`;
      resolve({
        url,
        close: () => new Promise((r, e) => server.close((err) => (err ? e(err) : r()))),
      });
    });
  });
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('bootstrapPartnerFromDiscoveryUrl (Task 9 gateway auto-bootstrap)', () => {
  const PARTNER_DID = 'did:web:partner.example.com';
  const JWKS_URI = 'https://partner.example.com/.well-known/jwks.json';

  const VALID_DISCOVERY = {
    schemaVersion: '1.0.0',
    issuer: PARTNER_DID,
    endpoints: {
      jwks: JWKS_URI,
      publicKey: '/api/v1/public-key (deprecated)',
      didDocument: '/.well-known/did.json',
    },
    capabilities: ['partner-federation'],
  };

  it('seeds the partner DID as active when given a valid discovery document', async () => {
    const { url, close } = await startFakeDiscoveryServer(VALID_DISCOVERY);
    const registry = new InMemoryPartnerDidRegistry();

    await bootstrapPartnerFromDiscoveryUrl(url, registry, logger);
    await close();

    expect(await registry.trusts(PARTNER_DID)).toBe(true);
    const entry = await registry.get(PARTNER_DID);
    expect(entry).toBeDefined();
    expect(entry!.status).toBe('active');
  });

  it('seeds the DID even when endpoints.jwks is absent (field is informational only)', async () => {
    const docWithoutJwks = { schemaVersion: '1.0.0', issuer: PARTNER_DID };
    const { url, close } = await startFakeDiscoveryServer(docWithoutJwks);
    const registry = new InMemoryPartnerDidRegistry();

    await bootstrapPartnerFromDiscoveryUrl(url, registry, logger);
    await close();

    // Should succeed — jwks is optional
    expect(await registry.trusts(PARTNER_DID)).toBe(true);
  });

  it('throws when registryRequired=true (production hardening)', async () => {
    const { url, close } = await startFakeDiscoveryServer(VALID_DISCOVERY);
    const registry = new InMemoryPartnerDidRegistry();

    await expect(
      bootstrapPartnerFromDiscoveryUrl(url, registry, logger, { registryRequired: true }),
    ).rejects.toThrow(/PARTNER_ISSUER_DISCOVERY_URL.*partner-DID registry is required/);
    await close();

    // Registry must remain empty — the seeding was blocked.
    expect(await registry.list()).toHaveLength(0);
  });

  it('proceeds normally when registryRequired=false (explicit opt-out)', async () => {
    const { url, close } = await startFakeDiscoveryServer(VALID_DISCOVERY);
    const registry = new InMemoryPartnerDidRegistry();

    await bootstrapPartnerFromDiscoveryUrl(url, registry, logger, { registryRequired: false });
    await close();

    expect(await registry.trusts(PARTNER_DID)).toBe(true);
  });

  it('does not throw when the discovery URL is unreachable (non-fatal)', async () => {
    const registry = new InMemoryPartnerDidRegistry();
    // Use a port that is unlikely to be listening — connect will fail.
    await expect(
      bootstrapPartnerFromDiscoveryUrl(
        'http://127.0.0.1:1/capability-issuer',
        registry,
        logger,
      ),
    ).resolves.toBeUndefined();
    // Registry must remain empty — no entry seeded.
    expect(await registry.list()).toHaveLength(0);
  });

  it('does not throw and skips registration when server returns non-2xx', async () => {
    const { url, close } = await startFakeDiscoveryServer({ error: 'not found' }, 404);
    const registry = new InMemoryPartnerDidRegistry();

    await expect(
      bootstrapPartnerFromDiscoveryUrl(url, registry, logger),
    ).resolves.toBeUndefined();
    await close();

    expect(await registry.list()).toHaveLength(0);
  });

  it('skips registration when discovery document is missing the `issuer` field', async () => {
    const { url, close } = await startFakeDiscoveryServer({
      // issuer intentionally absent
      endpoints: { jwks: JWKS_URI },
    });
    const registry = new InMemoryPartnerDidRegistry();

    await bootstrapPartnerFromDiscoveryUrl(url, registry, logger);
    await close();

    expect(await registry.list()).toHaveLength(0);
  });

  it('handles a bad (non-JSON) response body gracefully', async () => {
    const { url, close } = await startBadBodyServer();
    const registry = new InMemoryPartnerDidRegistry();

    await expect(
      bootstrapPartnerFromDiscoveryUrl(url, registry, logger),
    ).resolves.toBeUndefined();
    await close();

    expect(await registry.list()).toHaveLength(0);
  });

  it('does not overwrite an already-seeded entry for the same DID', async () => {
    const { url, close } = await startFakeDiscoveryServer(VALID_DISCOVERY);
    const registry = new InMemoryPartnerDidRegistry();
    registry.seed([PARTNER_DID]);

    // Should not throw even though the DID is already active.
    await bootstrapPartnerFromDiscoveryUrl(url, registry, logger);
    await close();

    // Still exactly one entry.
    const entries = await registry.list();
    expect(entries.filter((e) => e.did === PARTNER_DID)).toHaveLength(1);
    expect(await registry.trusts(PARTNER_DID)).toBe(true);
  });
});
