/**
 * Partner Federation — integration tests (Stage 5, Task 3)
 *
 * Covers the five scenarios called out in the execution plan §4.2:
 *
 *   1. Happy path — partner-issuer-sim mints a token; gateway verifier accepts it.
 *   2. Circuit-breaker trip — DID-document endpoint returns 503 N times;
 *      gateway denies subsequent requests with a "circuit open" message.
 *   3. Circuit-breaker half-open probe — after the cooldown, the next request
 *      probes and succeeds; circuit closes and normal resolution resumes.
 *   4. Untrusted DID — token whose `iss` is not in the registry → 401.
 *   5. Pin mismatch — DID document is reachable but its hash differs from the
 *      pinned value → request denied, circuit stays closed (data error ≠
 *      network error).
 *
 * All tests run in-process: partner-sim and mock DID-document servers are
 * mounted on ephemeral loopback ports to avoid container dependencies.
 */

import * as http from 'http';
import { AddressInfo } from 'net';
import * as crypto from 'crypto';
import * as jose from 'jose';
import express from 'express';
import {
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  CapabilityTokenPayload,
  ErrorCode,
} from '@euno/common';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import {
  PartnerIssuerResolver,
} from '../../tool-gateway/src/partner-issuer-resolver';
import {
  InMemoryPartnerDidRegistry,
  jcsSha256,
} from '../../tool-gateway/src/partner-did-registry';
import { createPartnerApp, loadOrCreateKey } from '@euno/partner-issuer-sim';
import { parseDidWebHttpAllowList } from '@euno/capability-issuer/adapters';

// ─── helpers ─────────────────────────────────────────────────────────────────

const PARTNER_SEED_HEX = 'c'.repeat(64);

function listenOnEphemeralPort(app: express.Express): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      resolve({ server, port: addr.port });
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/** Build an EdDSA key pair and a did:web DID document. */
async function makePartnerKeys(did: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';
  const privateJose = await jose.importPKCS8(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    'EdDSA',
  ) as jose.KeyLike;
  const vmId = `${did}#key-1`;
  const didDoc = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [
      { id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
  return { privateKey: privateJose, publicJwk, didDoc };
}

/** Mint a capability JWT signed by the given key. */
async function mintJWT(privateKey: jose.KeyLike, did: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: did,
    sub: 'partner-agent',
    aud: 'tool-gateway',
    iat: now,
    exp: now + 600,
    jti: `jti-${crypto.randomUUID()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
  } as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${did}#key-1` })
    .sign(privateKey);
}

/** Build a throw-away local SPKI so a JWTTokenVerifier can be constructed. */
async function localSpki(): Promise<string> {
  const { publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  return jose.exportSPKI(publicKey);
}

// ─── 1. Happy path ────────────────────────────────────────────────────────────

describe('partner-federation: happy path', () => {
  let partnerServer: http.Server;
  let partnerPort: number;
  let verifier: JWTTokenVerifier;

  beforeAll(async () => {
    // Reserve port, attach partner-sim app.
    const server = http.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    partnerPort = (server.address() as AddressInfo).port;

    const partnerDid = `did:web:127.0.0.1%3A${partnerPort}`;
    const key = loadOrCreateKey({ seed: PARTNER_SEED_HEX });
    const app = createPartnerApp({
      issuerDid: partnerDid,
      audience: 'tool-gateway',
      defaultTtlSeconds: 600,
      key,
    });
    server.on('request', app);
    partnerServer = server;

    const httpAllowList = parseDidWebHttpAllowList(`127.0.0.1:${partnerPort}`);
    const spki = await localSpki();
    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [partnerDid],
      httpAllowList,
    });
    verifier = new JWTTokenVerifier(spki, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver });
  });

  afterAll(async () => {
    if (partnerServer) await closeServer(partnerServer);
  });

  it('accepts a token minted by partner-issuer-sim', async () => {
    const issueRes = await fetch(`http://127.0.0.1:${partnerPort}/issue`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        partnerAgentId: 'partner-agent-fed',
        capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
      }),
    });
    expect(issueRes.status).toBe(200);
    const { token } = (await issueRes.json()) as { token: string };
    const payload: CapabilityTokenPayload = await verifier.verify(token);
    expect(payload.sub).toBe('partner-agent-fed');
    expect(payload.capabilities[0]?.resource).toBe('storage://shared/**');
  });
});

// ─── 2. Circuit-breaker trip ─────────────────────────────────────────────────

describe('partner-federation: circuit-breaker trip', () => {
  let didServer: http.Server;
  let partnerDid: string;
  let partnerPrivateKey: jose.KeyLike;
  let verifier: JWTTokenVerifier;
  let resolver: PartnerIssuerResolver;
  let httpResponseCode = 200;
  let didDocToReturn: Record<string, unknown>;

  beforeAll(async () => {
    const app = express();
    app.get('/.well-known/did.json', (_req, res) => {
      if (httpResponseCode !== 200) {
        res.status(httpResponseCode).end();
        return;
      }
      res.type('application/did+json').json(didDocToReturn);
    });
    const { server, port } = await listenOnEphemeralPort(app);
    didServer = server;
    partnerDid = `did:web:127.0.0.1%3A${port}`;

    const keys = await makePartnerKeys(partnerDid);
    partnerPrivateKey = keys.privateKey;
    didDocToReturn = keys.didDoc;

    const httpAllowList = parseDidWebHttpAllowList(`127.0.0.1:${port}`);
    const spki = await localSpki();
    resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [partnerDid],
      httpAllowList,
      negativeCacheTtlMs: 0,
      circuitBreaker: { failureThreshold: 3, windowMs: 10_000, cooldownMs: 60_000 },
    });
    verifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: resolver,
    });
  });

  afterAll(async () => {
    if (didServer) await closeServer(didServer);
  });

  afterEach(() => {
    // Reset server to healthy after each test.
    httpResponseCode = 200;
  });

  it('denies tokens when the DID endpoint returns 503 (failure 1–3)', async () => {
    httpResponseCode = 503;
    // Three failures should all fail with INVALID_TOKEN (not circuit-open yet after each one).
    for (let i = 0; i < 3; i++) {
      const token = await mintJWT(partnerPrivateKey, partnerDid);
      await expect(verifier.verify(token)).rejects.toMatchObject({
        code: ErrorCode.INVALID_TOKEN,
      });
    }
  });

  it('fast-fails with circuit-open message on subsequent calls after threshold is reached', async () => {
    // Circuit should be open now (3 failures recorded above).
    httpResponseCode = 200; // DID endpoint is healthy now but circuit is open
    const token = await mintJWT(partnerPrivateKey, partnerDid);
    const err = await verifier.verify(token).catch((e) => e);
    expect(err).toMatchObject({ code: ErrorCode.INVALID_TOKEN });
    expect(err.message).toMatch(/circuit open/i);
  });
});

// ─── 3. Circuit-breaker half-open probe ──────────────────────────────────────

describe('partner-federation: circuit-breaker half-open probe', () => {
  let didServer: http.Server;
  let partnerDid: string;
  let partnerPrivateKey: jose.KeyLike;
  let verifier: JWTTokenVerifier;
  let resolver: PartnerIssuerResolver;
  let httpResponseCode = 200;
  let didDocToReturn: Record<string, unknown>;

  beforeAll(async () => {
    const app = express();
    app.get('/.well-known/did.json', (_req, res) => {
      if (httpResponseCode !== 200) {
        res.status(httpResponseCode).end();
        return;
      }
      res.type('application/did+json').json(didDocToReturn);
    });
    const { server, port } = await listenOnEphemeralPort(app);
    didServer = server;
    partnerDid = `did:web:127.0.0.1%3A${port}`;

    const keys = await makePartnerKeys(partnerDid);
    partnerPrivateKey = keys.privateKey;
    didDocToReturn = keys.didDoc;

    const httpAllowList = parseDidWebHttpAllowList(`127.0.0.1:${port}`);
    const spki = await localSpki();

    jest.useFakeTimers({ advanceTimers: false });

    resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [partnerDid],
      httpAllowList,
      negativeCacheTtlMs: 0,
      circuitBreaker: { failureThreshold: 2, windowMs: 10_000, cooldownMs: 500 },
    });
    verifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: resolver,
    });
  });

  afterAll(async () => {
    jest.useRealTimers();
    if (didServer) await closeServer(didServer);
  });

  it('half-open probe succeeds after cooldown → circuit closes and tokens are accepted', async () => {
    // Step 1 — Trip the circuit with two failures.
    httpResponseCode = 503;
    for (let i = 0; i < 2; i++) {
      const token = await mintJWT(partnerPrivateKey, partnerDid);
      await expect(verifier.verify(token)).rejects.toMatchObject({ code: ErrorCode.INVALID_TOKEN });
    }

    // Step 2 — Verify circuit is open.
    {
      const token = await mintJWT(partnerPrivateKey, partnerDid);
      const err = await verifier.verify(token).catch((e) => e);
      expect(err.message).toMatch(/circuit open/i);
    }

    // Step 3 — Advance past the cooldown; DID endpoint becomes healthy.
    httpResponseCode = 200;
    jest.advanceTimersByTime(600); // > 500 ms cooldown

    // Step 4 — Next request probes and succeeds → circuit closes.
    const token = await mintJWT(partnerPrivateKey, partnerDid);
    const payload: CapabilityTokenPayload = await verifier.verify(token);
    expect(payload.iss).toBe(partnerDid);

    // Step 5 — Confirm the circuit is now closed (getCircuitBreakerStates).
    const states = resolver.getCircuitBreakerStates();
    expect(states.get(partnerDid)).toBe('closed');
  });
});

// ─── 4. Untrusted DID ────────────────────────────────────────────────────────

describe('partner-federation: untrusted DID rejection', () => {
  it('rejects a token whose iss is not in the trust registry with INVALID_TOKEN', async () => {
    const spki = await localSpki();
    // Resolver trusts only a different DID.
    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: ['did:web:trusted.example.com'],
    });
    const verifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: resolver,
    });

    const untrustedDid = 'did:web:untrusted.example.com';
    const { privateKey: untrustedKey } = await makePartnerKeys(untrustedDid);
    const token = await mintJWT(untrustedKey, untrustedDid);

    // The issuer is not trusted → INVALID_TOKEN (the local-key path also
    // fails because the token is EdDSA-signed, not RS256).
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('rejects a token from a DID that is absent from the InMemoryPartnerDidRegistry', async () => {
    const spki = await localSpki();
    const registry = new InMemoryPartnerDidRegistry();
    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [],
      registry,
    });
    const verifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: resolver,
    });

    const unknownDid = 'did:web:unknown.example.com';
    const { privateKey: unknownKey } = await makePartnerKeys(unknownDid);
    const token = await mintJWT(unknownKey, unknownDid);

    // DID is absent from registry → AUTHENTICATION_FAILED (trust check fails
    // before any network resolution is attempted).
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
    });
  });
});

// ─── 5. Pin mismatch ─────────────────────────────────────────────────────────

describe('partner-federation: pin mismatch', () => {
  let didServer: http.Server;
  let partnerDid: string;
  let partnerPrivateKey: jose.KeyLike;
  let partnerDidDoc: Record<string, unknown>;
  let resolver: PartnerIssuerResolver;
  let verifier: JWTTokenVerifier;
  let serverPort: number;

  beforeAll(async () => {
    const app = express();
    app.get('/.well-known/did.json', (_req, res) => {
      res.type('application/did+json').json(partnerDidDoc);
    });
    const { server, port } = await listenOnEphemeralPort(app);
    didServer = server;
    serverPort = port;
    partnerDid = `did:web:127.0.0.1%3A${port}`;

    const keys = await makePartnerKeys(partnerDid);
    partnerPrivateKey = keys.privateKey;
    partnerDidDoc = keys.didDoc;

    // Pin a hash that does NOT match the actual document.
    const wrongHash = 'a'.repeat(64);
    const registry = new InMemoryPartnerDidRegistry();
    await registry.propose({ did: partnerDid, proposer: 'alice', pinnedDocSha256: wrongHash });
    await registry.approve(partnerDid, 'bob', { pinnedDocSha256: wrongHash });

    const httpAllowList = parseDidWebHttpAllowList(`127.0.0.1:${port}`);
    const spki = await localSpki();
    resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [partnerDid],
      registry,
      httpAllowList,
      negativeCacheTtlMs: 0,
      circuitBreaker: { failureThreshold: 5, windowMs: 10_000, cooldownMs: 60_000 },
    });
    verifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: resolver,
    });
  });

  afterAll(async () => {
    if (didServer) await closeServer(didServer);
  });

  it('denies a token when the DID document hash does not match the pinned value', async () => {
    const token = await mintJWT(partnerPrivateKey, partnerDid);
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('circuit stays closed after repeated pin-mismatch failures (data error ≠ network failure)', async () => {
    // Five pin-mismatch failures should NOT trip the circuit.
    for (let i = 0; i < 5; i++) {
      const token = await mintJWT(partnerPrivateKey, partnerDid);
      const err = await verifier.verify(token).catch((e) => e);
      // Each denial must NOT be "circuit open".
      expect(err.message).not.toMatch(/circuit open/i);
    }

    // Circuit breaker must remain closed.
    const states = resolver.getCircuitBreakerStates();
    expect(states.get(partnerDid)).toBe('closed');
  });

  it('accepts the token once the registry entry is updated with the correct pin', async () => {
    // Use the correct hash of the DID document the server actually serves.
    const correctHash = jcsSha256(partnerDidDoc);

    // New registry seeded with the correct hash.
    const newRegistry = new InMemoryPartnerDidRegistry();
    await newRegistry.propose({ did: partnerDid, proposer: 'alice', pinnedDocSha256: correctHash });
    await newRegistry.approve(partnerDid, 'bob', { pinnedDocSha256: correctHash });

    const httpAllowList = parseDidWebHttpAllowList(`127.0.0.1:${serverPort}`);
    const spki = await localSpki();
    const newResolver = new PartnerIssuerResolver({
      trustedIssuerDids: [partnerDid],
      registry: newRegistry,
      httpAllowList,
    });
    const newVerifier = new JWTTokenVerifier(spki, {
      requireKid: false,
      algorithms: ['RS256'],
      partnerResolver: newResolver,
    });

    // Use the same key that corresponds to the document the server serves.
    const token = await mintJWT(partnerPrivateKey, partnerDid);
    const payload: CapabilityTokenPayload = await newVerifier.verify(token);
    expect(payload.iss).toBe(partnerDid);
  });
});
