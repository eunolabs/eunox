/**
 * Minimal OIDC mock server for smoke-testing the capability-issuer.
 *
 * Purpose: provide a Cognito-compatible ID-token issuer that the issuer
 * service can validate tokens against, without requiring a real IdP in the
 * smoke-test Docker Compose profile.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json           — JWKS with the ephemeral public key
 *   GET  /.well-known/openid-configuration — OIDC discovery document
 *   POST /token                            — mint a signed ID token
 *     Body (JSON): { nonce, groups?, sub? }
 *     Response:    { id_token, token_type }
 *
 * Security note: this server has NO authentication on the /token endpoint and
 * MUST NOT be deployed outside of isolated smoke-test environments.  It is
 * only active in the "smoke" Docker Compose profile.
 *
 * Runtime: Node.js 18+ (uses built-in Web Crypto API; no npm dependencies).
 */

import http from 'node:http';
import crypto from 'node:crypto';

const PORT = parseInt(process.env.PORT || '3003', 10);
const ISSUER = (process.env.MOCK_OIDC_ISSUER || `http://mock-oidc:${PORT}`).replace(/\/$/, '');
const CLIENT_ID = process.env.MOCK_OIDC_CLIENT_ID || 'euno-smoke-client';
const KID = 'mock-oidc-key-1';

// ── Key generation ───────────────────────────────────────────────────────────

let _privateKey;
let _jwks;

async function init() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  _privateKey = privateKey;

  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  jwk.use = 'sig';
  jwk.alg = 'ES256';
  jwk.kid = KID;
  _jwks = { keys: [jwk] };

  console.log(`[mock-oidc] issuer=${ISSUER}  clientId=${CLIENT_ID}`);
}

// ── JWT signing ──────────────────────────────────────────────────────────────

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJwt(header, payload) {
  const enc = (obj) => b64url(Buffer.from(JSON.stringify(obj)));
  const input = `${enc(header)}.${enc(payload)}`;
  const data = new TextEncoder().encode(input);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, _privateKey, data);
  return `${input}.${b64url(Buffer.from(sig))}`;
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function json(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ── Request handler ──────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];

    // JWKS endpoint
    if (url === '/.well-known/jwks.json' && req.method === 'GET') {
      return json(res, 200, _jwks);
    }

    // OIDC discovery document
    if (url === '/.well-known/openid-configuration' && req.method === 'GET') {
      return json(res, 200, {
        issuer: ISSUER,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        token_endpoint: `${ISSUER}/token`,
        authorization_endpoint: `${ISSUER}/authorize`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['ES256'],
        scopes_supported: ['openid', 'profile', 'email'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
      });
    }

    // Token minting endpoint
    if (url === '/token' && req.method === 'POST') {
      const raw = await readBody(req);
      let params = {};
      try { params = JSON.parse(raw); } catch (_) { /* ignore malformed body */ }

      const nonce = typeof params.nonce === 'string' ? params.nonce : '';
      const sub = typeof params.sub === 'string' ? params.sub : 'smoke-test-user';
      const groups = Array.isArray(params.groups) ? params.groups : ['developer'];
      const now = Math.floor(Date.now() / 1000);

      const idToken = await signJwt(
        { alg: 'ES256', typ: 'JWT', kid: KID },
        {
          iss: ISSUER,
          aud: CLIENT_ID,
          sub,
          iat: now,
          exp: now + 3600,
          nonce,
          token_use: 'id',
          groups,
          email: `${sub}@smoke-test.example`,
          'cognito:username': sub,
        },
      );

      return json(res, 200, { id_token: idToken, token_type: 'Bearer', expires_in: 3600 });
    }

    // Health probe (used by Docker healthcheck)
    if (url === '/health' && req.method === 'GET') {
      return json(res, 200, { status: 'ok' });
    }

    json(res, 404, { error: 'not found' });
  } catch (err) {
    console.error('[mock-oidc] handler error', err);
    json(res, 500, { error: String(err) });
  }
});

init()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[mock-oidc] listening on :{PORT}`);
    });
  })
  .catch((err) => {
    console.error('[mock-oidc] init failed', err);
    process.exit(1);
  });
