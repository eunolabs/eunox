/**
 * Partner Issuer Simulator — key management.
 *
 * Generates / loads a single Ed25519 signing key for the partner issuer.
 *
 * Two modes:
 * - `seed`: derive the key deterministically from a 32-byte seed (hex or
 *   base64url). Used in CI so the partner DID document is stable across
 *   container restarts. Pass via `PARTNER_SEED`.
 * - `random`: generate a fresh random key on first use. Used in dev.
 *
 * Optionally persists the public/private key pair to disk under
 * `PARTNER_KEY_DIR` so a restart in a non-CI environment keeps the same DID.
 *
 * The Ed25519 algorithm matches the cross-org harness design doc
 * (`docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`).
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as jose from 'jose';

export interface PartnerKeyMaterial {
  /** PEM-encoded PKCS#8 private key. */
  privateKeyPem: string;
  /** PEM-encoded SubjectPublicKeyInfo public key. */
  publicKeyPem: string;
  /** JWK representation of the public key (kty=OKP, crv=Ed25519, alg=EdDSA). */
  publicKeyJwk: jose.JWK;
}

const KEY_FILE_NAME = 'partner-ed25519.json';

/**
 * Decode a 32-byte seed from a hex or base64url string.
 * Accepts both common formats so operators can use whichever their secret
 * manager produces. Throws on invalid length.
 */
function decodeSeed(raw: string): Buffer {
  const trimmed = raw.trim();
  // Try hex first
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }
  // Then base64url (43 chars, no padding) or base64 (44 with =)
  try {
    const buf = Buffer.from(trimmed.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (buf.length === 32) {
      return buf;
    }
  } catch {
    // fall through
  }
  throw new Error(
    `PARTNER_SEED must be a 32-byte value encoded as hex (64 chars) or base64url (43 chars); got length=${trimmed.length}`
  );
}

/**
 * Build an Ed25519 key pair from a 32-byte seed using Node's crypto API.
 * Produces a deterministic PKCS#8 private key suitable for `jose`.
 */
function keyMaterialFromSeed(seed: Buffer): PartnerKeyMaterial {
  // Ed25519 PKCS#8 ASN.1 structure with the seed embedded as the OCTET STRING.
  // Header bytes from RFC 8410 §7 (the only thing that varies is the seed).
  const pkcs8Header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const der = Buffer.concat([pkcs8Header, seed]);
  const privateKey = crypto.createPrivateKey({
    key: der,
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const publicKeyJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
  publicKeyJwk.alg = 'EdDSA';
  publicKeyJwk.use = 'sig';
  return { privateKeyPem, publicKeyPem, publicKeyJwk };
}

/**
 * Generate a fresh random Ed25519 key pair.
 */
function randomKeyMaterial(): PartnerKeyMaterial {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const publicKeyJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
  publicKeyJwk.alg = 'EdDSA';
  publicKeyJwk.use = 'sig';
  return { privateKeyPem, publicKeyPem, publicKeyJwk };
}

/**
 * Load key material from disk if present, otherwise generate it (according
 * to `seed` / `random` mode), persist it (when a directory is provided),
 * and return it.
 *
 * @param opts.seed Optional seed string (hex or base64url, 32 bytes decoded).
 * @param opts.keyDir Optional directory to persist the key pair in. If the
 *                    directory contains a previously-written key, it is
 *                    reused (so `random` mode is also stable across
 *                    restarts when a key dir is configured).
 */
export function loadOrCreateKey(opts: { seed?: string; keyDir?: string }): PartnerKeyMaterial {
  const { seed, keyDir } = opts;

  if (keyDir) {
    const keyPath = path.join(keyDir, KEY_FILE_NAME);
    if (fs.existsSync(keyPath)) {
      const raw = fs.readFileSync(keyPath, 'utf8');
      const parsed = JSON.parse(raw) as PartnerKeyMaterial;
      if (parsed.privateKeyPem && parsed.publicKeyPem && parsed.publicKeyJwk) {
        return parsed;
      }
    }
  }

  const material = seed
    ? keyMaterialFromSeed(decodeSeed(seed))
    : randomKeyMaterial();

  if (keyDir) {
    fs.mkdirSync(keyDir, { recursive: true });
    const keyPath = path.join(keyDir, KEY_FILE_NAME);
    fs.writeFileSync(keyPath, JSON.stringify(material, null, 2), { mode: 0o600 });
  }

  return material;
}
