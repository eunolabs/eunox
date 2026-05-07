/**
 * Issuance Proofs — multi-issuer trust hardening.
 * ---------------------------------------------------------------------------
 * Addresses the critical "single-issuer trust root" risk: a single
 * compromised KMS `signDigest` permission on the issuer's workload identity
 * is currently sufficient to mint arbitrary capabilities for any subject
 * in `LOCAL_ISSUER_IDS`. This module introduces two independent layers
 * of cryptographic redundancy that a verifier (the gateway) can require
 * before accepting a token:
 *
 *   1. **Cosignature** ({@link Cosigner}). One or more independent
 *      authorities — held by a *different* principal than the primary
 *      issuer signing key (offline policy authority, second KMS in a
 *      different account, partner-issuer pod) — countersign a canonical
 *      {@link IssuanceReceipt} derived from the token. The gateway
 *      verifies each signature with the cosigner's public key from the
 *      cosigner JWKS. An attacker who steals only the primary KMS key
 *      cannot mint usable tokens because they do not control any
 *      cosigner's key.
 *
 *   2. **Transparency log** ({@link TransparencyLog}). An append-only,
 *      external (or at least separately keyed) log records every issuance
 *      and returns a Signed Certificate Timestamp ({@link Sct}) over the
 *      receipt hash. The gateway verifies the SCT against trusted log
 *      keys; auditors can reconcile the log against the issuer's audit
 *      trail to detect silent fraud. Even if the issuer is fully
 *      compromised, malicious issuances are visible to anyone who reads
 *      the log.
 *
 * This file owns:
 *   - canonical JSON serialization (sorted keys, deterministic) of the
 *     receipt + capability-set, hashed with SHA-256;
 *   - the signing-input bytes for cosignatures and SCTs;
 *   - {@link buildIssuanceReceipt} and {@link receiptHashFromPayload}
 *     pure helpers used by both the issuer (to build the receipt to sign)
 *     and the gateway (to reconstruct the verification input);
 *   - signature-verification primitives that take a JWK + alg + sig and
 *     verify against the canonical bytes.
 *
 * The signer-side abstractions ({@link Cosigner}, {@link TransparencyLog})
 * and the in-process software implementations live in
 * `./cosigner.ts` and `./transparency-log.ts` so this file remains a pure,
 * dependency-free description of the on-the-wire format.
 */

import * as jose from 'jose';
import * as nodeCrypto from 'crypto';
import {
  CapabilityConstraint,
  CapabilityTokenPayload,
  Cosignature,
  IssuanceProofs,
  IssuanceReceipt,
  Sct,
} from './wire';
import { JwkKey, JwkSet, pickJwkByKid } from './jwks';
import { CapabilityError, ErrorCode } from './utils';

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON canonicalisation: object keys are sorted
 * lexicographically at every depth, arrays preserve order, and primitives
 * round-trip via `JSON.stringify`. This is a small, dependency-free
 * implementation of the "JCS" (RFC 8785) shape for the subset of values
 * we serialize (objects, arrays, strings, finite numbers, booleans, null).
 *
 * Throws on `NaN` / `Infinity` / `undefined` / `Symbol` / `bigint` / `function`
 * so an accidentally non-serialisable receipt fails loudly at signing time
 * rather than silently producing incompatible bytes between the signer and
 * the verifier.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(
        `canonicalJsonStringify: non-finite number cannot be canonicalised: ${value}`,
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJsonStringify(v)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue; // JSON drops undefined; mirror that explicitly
      parts.push(`${JSON.stringify(k)}:${canonicalJsonStringify(v)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(
    `canonicalJsonStringify: unsupported value type: ${typeof value}`,
  );
}

/**
 * Hash an arbitrary canonicalisable value with SHA-256, returning the
 * raw 32-byte digest as base64url (no padding).
 */
export function sha256Base64Url(input: Uint8Array | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  const digest = nodeCrypto.createHash('sha256').update(buf).digest();
  return base64UrlEncode(digest);
}

function base64UrlEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(value: string): Buffer {
  const pad = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

// ---------------------------------------------------------------------------
// Receipt construction
// ---------------------------------------------------------------------------

/**
 * Compute the canonical hash of a capability set. Capabilities are
 * canonicalised via {@link canonicalJsonStringify} so an attacker
 * cannot reorder fields / actions to keep the same `capabilitiesHash`
 * with a different effective capability set.
 *
 * Note: the *order* of the array elements is preserved (we treat the
 * array as an ordered sequence). This matches the wire format: the
 * issuer chooses the order; reordering would change the hash.
 */
export function capabilitiesHash(capabilities: CapabilityConstraint[]): string {
  return sha256Base64Url(canonicalJsonStringify(capabilities));
}

/**
 * Build the canonical {@link IssuanceReceipt} from a fully-formed token
 * payload. Pure function; no I/O. Used by the issuer to produce the
 * bytes the cosigners and transparency log will sign, and by the gateway
 * to reconstruct the same bytes for verification.
 */
export function buildIssuanceReceipt(
  payload: Pick<
    CapabilityTokenPayload,
    'iss' | 'sub' | 'aud' | 'iat' | 'exp' | 'jti' | 'capabilities' | 'cnf'
  >,
): IssuanceReceipt {
  const receipt: IssuanceReceipt = {
    iss: payload.iss,
    sub: payload.sub,
    aud: payload.aud,
    iat: payload.iat,
    exp: payload.exp,
    jti: payload.jti,
    capabilitiesHash: capabilitiesHash(payload.capabilities),
  };
  // Bind DPoP holder-key thumbprint into the receipt when present so a
  // cosignature / SCT also commits to `cnf.jkt`. Omitted (not set to
  // undefined) when payload has no `cnf` so legacy receipt bytes are
  // unchanged. See IssuanceReceipt.cnfJkt for threat-model rationale.
  if (payload.cnf?.jkt) {
    receipt.cnfJkt = payload.cnf.jkt;
  }
  return receipt;
}

/**
 * Canonical signing-input bytes for a cosignature over an issuance
 * receipt. Signers and verifiers MUST use this exact serialization so
 * a cosignature produced by any conforming signer verifies under any
 * conforming verifier.
 *
 * The format is `"euno-issuance-receipt-v1\n" + canonical JSON of the
 * receipt`. The version prefix domain-separates this signature from
 * any future signature input and prevents cross-protocol confusion
 * (an attacker cannot reuse a cosignature minted for a different
 * Euno object as a cosignature on a receipt).
 */
export const COSIG_INPUT_DOMAIN_TAG = 'euno-issuance-receipt-v1';

export function canonicalReceiptSigningInput(receipt: IssuanceReceipt): Uint8Array {
  const json = canonicalJsonStringify(receipt);
  return Buffer.from(`${COSIG_INPUT_DOMAIN_TAG}\n${json}`, 'utf8');
}

/**
 * SHA-256 hash of the canonical receipt signing input — used as the
 * "receipt fingerprint" inside SCTs so an SCT binds to the exact
 * receipt without re-embedding all the fields.
 */
export function receiptHashFromPayload(
  payload: Pick<
    CapabilityTokenPayload,
    'iss' | 'sub' | 'aud' | 'iat' | 'exp' | 'jti' | 'capabilities' | 'cnf'
  >,
): string {
  return sha256Base64Url(canonicalReceiptSigningInput(buildIssuanceReceipt(payload)));
}

/**
 * Canonical signing-input bytes for an SCT. Domain-separated from the
 * cosignature input so the same signer key cannot accidentally produce
 * a value that decodes as both an SCT and a cosignature.
 *
 * Layout: `"euno-sct-v1\n" + logId + "\n" + timestamp(decimal) + "\n" + receiptHash`.
 * `logId` and `receiptHash` are bounded-charset strings (the latter is
 * base64url SHA-256), so the newline delimiter is unambiguous.
 */
export const SCT_INPUT_DOMAIN_TAG = 'euno-sct-v1';

export function canonicalSctSigningInput(
  logId: string,
  timestamp: number,
  receiptHash: string,
): Uint8Array {
  if (!Number.isInteger(timestamp) || timestamp < 0) {
    throw new Error(
      `canonicalSctSigningInput: timestamp must be a non-negative integer, got ${timestamp}`,
    );
  }
  if (logId.includes('\n')) {
    throw new Error(
      'canonicalSctSigningInput: logId must not contain newlines (would break delimiter)',
    );
  }
  return Buffer.from(
    `${SCT_INPUT_DOMAIN_TAG}\n${logId}\n${timestamp}\n${receiptHash}`,
    'utf8',
  );
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a single {@link Cosignature} against the canonical receipt
 * signing input. Returns `true` on a valid signature; throws
 * {@link CapabilityError} for verifier-misconfig errors (unknown alg,
 * malformed JWK), and returns `false` for legitimate "wrong signature".
 *
 * Caller is responsible for finding the JWK by `cosig.kid` from the
 * cosigner JWKS.
 */
export async function verifyCosignature(
  jwk: JwkKey,
  cosig: Cosignature,
  receipt: IssuanceReceipt,
): Promise<boolean> {
  if (cosig.alg !== jwk.alg && jwk.alg !== undefined) {
    // The cosignature explicitly declares an algorithm; the JWK may also
    // pin one (RFC 7517 § 4.4). When both are set, they MUST agree —
    // otherwise an attacker could pick whichever alg the verifier supports
    // and present a key minted for a different alg. (Algorithm-confusion
    // hardening, mirrors the issuer-side `algorithms` allow-list.)
    return false;
  }
  let key: jose.KeyLike | Uint8Array;
  try {
    key = await jose.importJWK(jwk as jose.JWK, cosig.alg);
  } catch (err) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `Cosignature verification: failed to import JWK for kid="${cosig.kid}": ${err instanceof Error ? err.message : 'unknown error'}`,
      401,
    );
  }
  let sig: Buffer;
  try {
    sig = base64UrlDecode(cosig.sig);
  } catch {
    return false;
  }
  const input = canonicalReceiptSigningInput(receipt);
  try {
    return await verifyRawSignature(cosig.alg, key, sig, input);
  } catch {
    return false;
  }
}

/**
 * Verify an {@link Sct} against trusted log keys. Returns `true` on a
 * valid signature, `false` on a mismatch. Caller has already located
 * the JWK by `sct.logId` + `sct.kid` from the trusted log JWKS.
 *
 * The verifier recomputes the SCT signing input from `(logId, timestamp,
 * receiptHash)` so an attacker cannot trick the verifier into accepting
 * a signature minted for a different `(logId, timestamp)`.
 */
export async function verifySct(
  jwk: JwkKey,
  sct: Sct,
  receiptHash: string,
): Promise<boolean> {
  if (sct.alg !== jwk.alg && jwk.alg !== undefined) {
    return false;
  }
  let key: jose.KeyLike | Uint8Array;
  try {
    key = await jose.importJWK(jwk as jose.JWK, sct.alg);
  } catch (err) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      `SCT verification: failed to import JWK for log="${sct.logId}" kid="${sct.kid}": ${err instanceof Error ? err.message : 'unknown error'}`,
      401,
    );
  }
  let sig: Buffer;
  try {
    sig = base64UrlDecode(sct.sig);
  } catch {
    return false;
  }
  let input: Uint8Array;
  try {
    input = canonicalSctSigningInput(sct.logId, sct.timestamp, receiptHash);
  } catch {
    return false;
  }
  try {
    return await verifyRawSignature(sct.alg, key, sig, input);
  } catch {
    return false;
  }
}

/**
 * Low-level "verify these raw bytes with this key under this alg" helper.
 * Uses Node's native `crypto.verify` / `crypto.sign` APIs, which work
 * directly on Node `KeyObject`s (the type returned by `jose.importJWK`
 * and `jose.importPKCS8` for asymmetric keys). This sidesteps the
 * WebCrypto `CryptoKey` interop tax and supports every algorithm the
 * rest of the codebase exposes.
 */
async function verifyRawSignature(
  alg: string,
  key: jose.KeyLike | Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  // Symmetric (HMAC) cosignatures are intentionally unsupported: the
  // shared-secret model does not give the independent-trust property
  // that motivates this whole module.
  if (key instanceof Uint8Array) return false;

  const params = jwaToNodeSignParams(alg);
  if (!params) return false;

  try {
    return nodeCrypto.verify(
      params.hash ?? null,
      Buffer.from(data),
      params.keyOpts(key as nodeCrypto.KeyObject),
      Buffer.from(signature),
    );
  } catch {
    return false;
  }
}

interface NodeSignParams {
  /**
   * Digest algorithm name passed as the first arg of `crypto.sign` /
   * `crypto.verify`. `null` for EdDSA (Ed25519/Ed448), which is its own
   * "pre-hash" scheme — Node ignores any digest parameter.
   */
  hash: string | null;
  /**
   * Build the key-options object passed as the third arg of
   * `crypto.sign` / `crypto.verify`. Encapsulates per-alg options like
   * RSA-PSS padding + salt length, and the IEEE P1363 (raw r||s) DSA
   * encoding for ECDSA — which is what JWA / WebCrypto produce, and what
   * RFC 7515 specifies for ES256/ES384/ES512.
   */
  keyOpts(key: nodeCrypto.KeyObject): nodeCrypto.SignKeyObjectInput | nodeCrypto.VerifyKeyObjectInput;
}

function jwaToNodeSignParams(alg: string): NodeSignParams | undefined {
  switch (alg) {
    case 'EdDSA':
      return { hash: null, keyOpts: (key) => ({ key }) };
    case 'ES256':
      return {
        hash: 'sha256',
        keyOpts: (key) => ({ key, dsaEncoding: 'ieee-p1363' }),
      };
    case 'ES384':
      return {
        hash: 'sha384',
        keyOpts: (key) => ({ key, dsaEncoding: 'ieee-p1363' }),
      };
    case 'ES512':
      return {
        hash: 'sha512',
        keyOpts: (key) => ({ key, dsaEncoding: 'ieee-p1363' }),
      };
    case 'RS256':
      return { hash: 'sha256', keyOpts: (key) => ({ key }) };
    case 'RS384':
      return { hash: 'sha384', keyOpts: (key) => ({ key }) };
    case 'RS512':
      return { hash: 'sha512', keyOpts: (key) => ({ key }) };
    case 'PS256':
      return {
        hash: 'sha256',
        keyOpts: (key) => ({
          key,
          padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32,
        }),
      };
    case 'PS384':
      return {
        hash: 'sha384',
        keyOpts: (key) => ({
          key,
          padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 48,
        }),
      };
    case 'PS512':
      return {
        hash: 'sha512',
        keyOpts: (key) => ({
          key,
          padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 64,
        }),
      };
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// Sign primitive (mirror of verify) — used by software cosigner / log
// ---------------------------------------------------------------------------

/**
 * Sign raw bytes with a private key under the given JWA algorithm.
 * Returns the raw signature bytes base64url-encoded for embedding in
 * {@link Cosignature.sig} or {@link Sct.sig}.
 *
 * Mirrors {@link verifyRawSignature} so a key that successfully signs
 * data here will verify under {@link verifyRawSignature} for the same
 * `alg`.
 */
export async function signRawBytes(
  alg: string,
  key: jose.KeyLike,
  data: Uint8Array,
): Promise<string> {
  const params = jwaToNodeSignParams(alg);
  if (!params) {
    throw new Error(`signRawBytes: unsupported alg "${alg}"`);
  }
  const sig = nodeCrypto.sign(
    params.hash ?? null,
    Buffer.from(data),
    params.keyOpts(key as nodeCrypto.KeyObject) as nodeCrypto.SignKeyObjectInput,
  );
  return base64UrlEncode(sig);
}

/**
 * Infer a JWA algorithm name from a Node {@link nodeCrypto.KeyObject}.
 * Used by {@link SoftwareCosigner} and {@link InMemoryTransparencyLog}
 * when the caller did not specify `alg` explicitly. Returns `undefined`
 * for RSA keys (no unambiguous default — caller must specify) and for
 * unsupported key types.
 */
export function inferAlgFromKeyObject(keyObject: nodeCrypto.KeyObject): string | undefined {
  const asymmetricType = keyObject.asymmetricKeyType;
  if (asymmetricType === 'ed25519' || asymmetricType === 'ed448') return 'EdDSA';
  if (asymmetricType === 'ec') {
    const details = (keyObject as unknown as { asymmetricKeyDetails?: { namedCurve?: string } })
      .asymmetricKeyDetails;
    switch (details?.namedCurve) {
      case 'prime256v1':
      case 'P-256':
        return 'ES256';
      case 'secp384r1':
      case 'P-384':
        return 'ES384';
      case 'secp521r1':
      case 'P-521':
        return 'ES512';
      default:
        return undefined;
    }
  }
  // RSA: no unambiguous default — caller must specify.
  return undefined;
}

// ---------------------------------------------------------------------------
// Aggregate verification helpers used by the gateway
// ---------------------------------------------------------------------------

/**
 * Outcome of {@link verifyIssuanceProofs} — encapsulates which proofs
 * were checked and which (if any) failed, so the gateway can produce a
 * structured error message.
 */
export interface ProofsVerificationResult {
  /** Number of cosignatures that successfully verified. */
  validCosignatures: number;
  /** Number of SCTs that successfully verified. */
  validScts: number;
  /**
   * Per-failure reasons. Empty when every required proof verified.
   * Caller decides whether the failure count meets the gateway's
   * `REQUIRE_*` thresholds.
   */
  failures: string[];
}

/**
 * Verify every cosignature and SCT carried by a token's `proofs` claim
 * against the supplied trusted JWKS. Pure verification — does not enforce
 * any "at least N cosigs" or "must have an SCT" policy; that is the
 * caller's responsibility (see `tool-gateway/src/proofs-verifier.ts`).
 *
 * Each cosignature's `kid` is looked up in `cosignerJwks`; each SCT's
 * `(logId, kid)` pair is looked up in `logJwksByLogId[sct.logId]`.
 * Unknown kids count as failures (audit-log them; do not silently treat
 * an unknown kid as "no proof present").
 */
export async function verifyIssuanceProofs(
  proofs: IssuanceProofs | undefined,
  receipt: IssuanceReceipt,
  trust: {
    cosignerJwks?: JwkSet;
    logJwksByLogId?: Map<string, JwkSet>;
  },
): Promise<ProofsVerificationResult> {
  const result: ProofsVerificationResult = {
    validCosignatures: 0,
    validScts: 0,
    failures: [],
  };
  if (!proofs) return result;

  const receiptHash = sha256Base64Url(canonicalReceiptSigningInput(receipt));

  if (proofs.cosig && Array.isArray(proofs.cosig) && proofs.cosig.length > 0) {
    if (!trust.cosignerJwks) {
      result.failures.push(
        'Cosignatures present on token but no cosigner JWKS is configured on the gateway',
      );
    } else {
      // Track which kids have already been counted toward the threshold
      // so a single cosigner approval cannot be replayed as multiple
      // "independent" cosignatures (e.g. attacker repeats the same
      // {kid,sig} entry twice to satisfy REQUIRE_COSIGNATURE_COUNT=2).
      const countedKids = new Set<string>();
      for (let i = 0; i < proofs.cosig.length; i += 1) {
        const cosig = proofs.cosig[i];
        // Defensive shape check — a malformed proofs.cosig[i] (null,
        // missing kid, wrong type) MUST become a clean verification
        // failure, not a 500 from a property-access throw upstack.
        if (!cosig || typeof cosig !== 'object'
          || typeof (cosig as { kid?: unknown }).kid !== 'string'
          || typeof (cosig as { sig?: unknown }).sig !== 'string'
          || typeof (cosig as { alg?: unknown }).alg !== 'string') {
          result.failures.push(`Cosignature at index ${i} is malformed (expected {kid,alg,sig})`);
          continue;
        }
        const jwk = pickJwkByKid(trust.cosignerJwks, cosig.kid);
        if (!jwk) {
          result.failures.push(`Cosignature kid="${cosig.kid}" is not in the trusted cosigner JWKS`);
          continue;
        }
        try {
          const ok = await verifyCosignature(jwk, cosig, receipt);
          if (ok) {
            if (countedKids.has(cosig.kid)) {
              // Valid signature, but this kid already counted — do not
              // double-count toward the N-of-M threshold.
              result.failures.push(
                `Cosignature kid="${cosig.kid}" appears more than once; only the first valid signature counts toward the threshold`,
              );
            } else {
              countedKids.add(cosig.kid);
              result.validCosignatures += 1;
            }
          } else {
            result.failures.push(`Cosignature kid="${cosig.kid}" did not verify`);
          }
        } catch (err) {
          result.failures.push(
            `Cosignature kid="${cosig.kid}" verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
          );
        }
      }
    }
  }

  if (proofs.sct && Array.isArray(proofs.sct) && proofs.sct.length > 0) {
    if (!trust.logJwksByLogId || trust.logJwksByLogId.size === 0) {
      result.failures.push(
        'SCTs present on token but no transparency-log JWKS is configured on the gateway',
      );
    } else {
      // Same independence rule as cosignatures: do not let a token
      // satisfy "valid SCT count >= 1" by repeating the same logId.
      // (Today the gateway only requires >= 1 SCT, but tracking by
      // logId keeps the invariant correct if a multi-log threshold
      // is ever introduced.)
      const countedLogIds = new Set<string>();
      for (let i = 0; i < proofs.sct.length; i += 1) {
        const sct = proofs.sct[i];
        if (!sct || typeof sct !== 'object'
          || typeof (sct as { logId?: unknown }).logId !== 'string'
          || typeof (sct as { kid?: unknown }).kid !== 'string'
          || typeof (sct as { alg?: unknown }).alg !== 'string'
          || typeof (sct as { sig?: unknown }).sig !== 'string'
          || typeof (sct as { timestamp?: unknown }).timestamp !== 'number') {
          result.failures.push(`SCT at index ${i} is malformed (expected {logId,kid,alg,timestamp,sig})`);
          continue;
        }
        const logJwks = trust.logJwksByLogId.get(sct.logId);
        if (!logJwks) {
          result.failures.push(`SCT logId="${sct.logId}" is not in the trusted log set`);
          continue;
        }
        const jwk = pickJwkByKid(logJwks, sct.kid);
        if (!jwk) {
          result.failures.push(
            `SCT logId="${sct.logId}" kid="${sct.kid}" is not in the log's trusted JWKS`,
          );
          continue;
        }
        try {
          const ok = await verifySct(jwk, sct, receiptHash);
          if (ok) {
            if (countedLogIds.has(sct.logId)) {
              result.failures.push(
                `SCT logId="${sct.logId}" appears more than once; only the first valid SCT counts toward the threshold`,
              );
            } else {
              countedLogIds.add(sct.logId);
              result.validScts += 1;
            }
          } else {
            result.failures.push(
              `SCT logId="${sct.logId}" kid="${sct.kid}" did not verify`,
            );
          }
        } catch (err) {
          result.failures.push(
            `SCT logId="${sct.logId}" kid="${sct.kid}" verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
          );
        }
      }
    }
  }

  return result;
}
