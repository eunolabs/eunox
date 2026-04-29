/**
 * Cross-organization trust harness — end-to-end integration tests
 * (Sprint 3-4 gap #5: `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`).
 *
 * Exercises the full inbound and outbound paths between our gateway and a
 * simulated partner organization:
 *
 *   1. Inbound  — the partner mints a VC, sends it to our gateway, and
 *                 the gateway accepts it after resolving the partner's DID
 *                 over (test-mode) HTTP.
 *   2. Outbound — we mint a VC for the partner, the partner resolves our
 *                 DID, verifies the signature, and accepts the action.
 *   3. Untrusted — a third issuer DID (not in our trust list) is rejected
 *                  even when its DID document is reachable.
 *
 * Everything runs in-process — there is no docker dependency in the test
 * itself.  The partner sim is mounted on an ephemeral HTTP loopback port,
 * a tiny "our DID document host" is mounted on another, and the gateway's
 * verifier is configured with `DID_WEB_ALLOW_HTTP_FOR_HOSTS` pointing at
 * both so that did:web resolution targets `http://127.0.0.1:<port>` rather
 * than HTTPS.  See `infra/docker-compose.cross-org.yml` for the
 * containerised version of the same harness.
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
import { PartnerIssuerResolver } from '../../tool-gateway/src/partner-issuer-resolver';
import { createPartnerApp, loadOrCreateKey } from '@euno/partner-issuer-sim';

const PARTNER_SEED_HEX = 'b'.repeat(64);

interface ListeningServer {
  server: http.Server;
  host: string; // 127.0.0.1
  port: number;
}

function listenOnEphemeralPort(app: express.Express): Promise<ListeningServer> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      resolve({ server, host: '127.0.0.1', port: addr.port });
    });
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Mount a tiny did:web document host so the gateway's
 * resolveDID('did:web:127.0.0.1%3A<port>') call returns the supplied
 * document.  Returns the constructed DID and a teardown function.
 */
async function mountDidWebHost(didDocFactory: (did: string) => Record<string, unknown>) {
  const app = express();
  let did = '';
  app.get('/.well-known/did.json', (_req, res) => {
    res.type('application/did+json').json(didDocFactory(did));
  });
  const { server, port } = await listenOnEphemeralPort(app);
  did = `did:web:127.0.0.1%3A${port}`;
  return { did, port, teardown: () => close(server) };
}

describe('cross-org trust harness', () => {
  let originalAllow: string | undefined;

  beforeAll(() => {
    originalAllow = process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
  });

  afterAll(() => {
    if (originalAllow === undefined) {
      delete process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS;
    } else {
      process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = originalAllow;
    }
  });

  // -----------------------------------------------------------------
  // Inbound: partner → us
  // -----------------------------------------------------------------

  describe('inbound — partner-issued VC accepted by our gateway', () => {
    let partnerServer: http.Server;
    let partnerDid: string;
    let verifier: JWTTokenVerifier;

    beforeAll(async () => {
      // Reserve an ephemeral port WITHOUT releasing it: create the bare
      // http.Server, listen on port 0, then attach the partner Express app
      // as the request handler once we know which port the OS assigned.
      // This avoids the close/re-bind race the reviewer flagged
      // (https://github.com/edgeobs/euno/pull/36) where another process
      // could grab the freed port between calls.
      const server = http.createServer();
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const port = (server.address() as AddressInfo).port;

      partnerDid = `did:web:127.0.0.1%3A${port}`;
      const key = loadOrCreateKey({ seed: PARTNER_SEED_HEX });
      const app = createPartnerApp({
        issuerDid: partnerDid,
        audience: 'tool-gateway',
        defaultTtlSeconds: 600,
        key,
      });
      server.on('request', app);
      partnerServer = server;

      // Allow HTTP did:web resolution for the partner's loopback host.
      process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = `127.0.0.1:${port}`;

      // Gateway verifier with a throw-away local key + the partner DID
      // in the trusted set.
      const { publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
      const localSpki = await jose.exportSPKI(publicKey);
      const resolver = new PartnerIssuerResolver({ trustedIssuerDids: [partnerDid] });
      verifier = new JWTTokenVerifier(localSpki, ['RS256'], undefined, resolver);
    });

    afterAll(async () => {
      if (partnerServer) {
        await close(partnerServer);
      }
    });

    it('accepts a partner-minted VC', async () => {
      // Issue a VC by calling the partner sim's HTTP API.
      const issueRes = await fetch(`http://127.0.0.1:${(partnerServer.address() as AddressInfo).port}/issue`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          partnerAgentId: 'partner-agent-42',
          capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
        }),
      });
      expect(issueRes.status).toBe(200);
      const body = (await issueRes.json()) as { token: string };
      expect(body.token).toEqual(expect.any(String));

      // Gateway verifier resolves the partner DID over HTTP (allow-list
      // grants this exception) and verifies the signature.
      const payload: CapabilityTokenPayload = await verifier.verify(body.token);
      expect(payload.iss).toBe(partnerDid);
      expect(payload.sub).toBe('partner-agent-42');
      expect(payload.capabilities[0]!.resource).toBe('storage://shared/**');
      expect(payload.capabilities[0]!.actions).toContain('read');
    });

    it('rejects a partner-minted VC after the partner DID is removed from trust', async () => {
      // Re-issue a fresh VC.
      const issueRes = await fetch(`http://127.0.0.1:${(partnerServer.address() as AddressInfo).port}/issue`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          partnerAgentId: 'partner-agent-42',
          capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
        }),
      });
      const { token } = (await issueRes.json()) as { token: string };

      // Build a new verifier whose trust list does NOT include the partner.
      const { publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
      const localSpki = await jose.exportSPKI(publicKey);
      const emptyResolver = new PartnerIssuerResolver({ trustedIssuerDids: ['did:web:never-trusted.example'] });
      const strictVerifier = new JWTTokenVerifier(localSpki, ['RS256'], undefined, emptyResolver);

      await expect(strictVerifier.verify(token)).rejects.toMatchObject({
        code: ErrorCode.INVALID_TOKEN,
      });
    });
  });

  // -----------------------------------------------------------------
  // Outbound: us → partner
  // -----------------------------------------------------------------

  describe('outbound — partner accepts our VC', () => {
    let partnerServer: http.Server;
    let partnerPort: number;
    let ourDidTeardown: () => Promise<void>;
    let ourDid: string;
    let ourPrivateKey: jose.KeyLike;

    beforeAll(async () => {
      // 1. Generate our (Ed25519) signing key + did:web hosting our DID document.
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      ourPrivateKey = (await jose.importPKCS8(
        privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        'EdDSA'
      )) as jose.KeyLike;
      const publicJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
      publicJwk.alg = 'EdDSA';

      const ourHost = await mountDidWebHost((did) => ({
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        id: did,
        verificationMethod: [
          {
            id: `${did}#key-1`,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: publicJwk,
          },
        ],
        authentication: [`${did}#key-1`],
        assertionMethod: [`${did}#key-1`],
      }));
      ourDid = ourHost.did;
      ourDidTeardown = ourHost.teardown;

      // 2. Stand up the partner sim, configured to TRUST our DID on /validate.
      const partnerKey = loadOrCreateKey({ seed: PARTNER_SEED_HEX });
      const partnerApp = createPartnerApp({
        issuerDid: 'did:web:partner-sim.local',
        audience: 'partner-aud',
        defaultTtlSeconds: 600,
        key: partnerKey,
        trustedIssuerDids: [ourDid],
      });
      const partnerListener = await listenOnEphemeralPort(partnerApp);
      partnerServer = partnerListener.server;
      partnerPort = partnerListener.port;

      // Allow HTTP did:web for our host (the partner needs to resolve us).
      process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = `127.0.0.1:${ourHost.port}`;
    });

    afterAll(async () => {
      if (partnerServer) await close(partnerServer);
      if (ourDidTeardown) await ourDidTeardown();
    });

    it('partner /validate accepts a VC signed by our DID', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await new jose.SignJWT({
        iss: ourDid,
        sub: 'our-agent-1',
        aud: 'partner-aud',
        iat: now,
        exp: now + 600,
        jti: `our-jti-${crypto.randomUUID()}`,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: [{ resource: 'partner://api/orders', actions: ['read'] }],
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${ourDid}#key-1` })
        .sign(ourPrivateKey);

      const res = await fetch(`http://127.0.0.1:${partnerPort}/validate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token, action: 'read', resource: 'partner://api/orders' }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { allowed: boolean; issuer: string };
      expect(body.allowed).toBe(true);
      expect(body.issuer).toBe(ourDid);
    });
  });

  // -----------------------------------------------------------------
  // Untrusted issuer
  // -----------------------------------------------------------------

  describe('untrusted issuer', () => {
    it('our gateway rejects a VC from an unknown DID even if its document is reachable', async () => {
      // Stand up a perfectly valid did:web host for an unknown issuer.
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const privKeyJose = (await jose.importPKCS8(
        privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        'EdDSA'
      )) as jose.KeyLike;
      const publicJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
      publicJwk.alg = 'EdDSA';

      const host = await mountDidWebHost((did) => ({
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [
          { id: `${did}#key-1`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk },
        ],
      }));
      try {
        process.env.DID_WEB_ALLOW_HTTP_FOR_HOSTS = `127.0.0.1:${host.port}`;

        // Mint a token signed by this unknown DID.
        const now = Math.floor(Date.now() / 1000);
        const token = await new jose.SignJWT({
          iss: host.did,
          sub: 'rogue-agent',
          aud: 'tool-gateway',
          iat: now,
          exp: now + 600,
          jti: 'rogue-jti',
          schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
          capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
        })
          .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${host.did}#key-1` })
          .sign(privKeyJose);

        // Configure the gateway with a *different* trusted partner DID.
        const { publicKey: localPub } = await jose.generateKeyPair('RS256', { extractable: true });
        const localSpki = await jose.exportSPKI(localPub);
        const resolver = new PartnerIssuerResolver({
          trustedIssuerDids: ['did:web:trusted-partner.example'],
        });
        const verifier = new JWTTokenVerifier(localSpki, ['RS256'], undefined, resolver);

        await expect(verifier.verify(token)).rejects.toMatchObject({
          code: ErrorCode.INVALID_TOKEN,
        });
      } finally {
        await host.teardown();
      }
    });
  });
});
