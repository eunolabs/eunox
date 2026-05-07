/**
 * Transparency Log — append-only witness of issuance receipts.
 * ---------------------------------------------------------------------------
 * The {@link TransparencyLog} interface is the issuer-side abstraction
 * over an external (or at least separately-keyed) append-only log that
 * records every capability issuance and returns a Signed Certificate
 * Timestamp ({@link Sct}) — analogous to RFC 6962 (Certificate
 * Transparency) for X.509 certificates.
 *
 * The point is **independent witness**: even if the entire issuer is
 * compromised, malicious issuances are visible to anyone who reads the
 * log. The gateway verifies SCTs against trusted log keys; auditors can
 * reconcile the log's append-only entry list against the issuer's audit
 * trail to detect silent fraud (issuances that bypass the log entirely
 * are obvious because they have no SCT, and issuances that the log
 * recorded but the issuer's audit trail did not are also obvious).
 *
 * In production, this should be backed by a real, externally-operated
 * transparency log service. For tests, local dev, and self-contained
 * deployments, the {@link InMemoryTransparencyLog} implementation here
 * provides a faithful, software-keyed log that signs SCTs with its own
 * private key. Operators who run this in-process MUST treat the log's
 * key as a separate secret from the primary issuer signing key — the
 * security gain comes from key independence, not from the implementation
 * being out-of-process.
 */

import * as nodeCrypto from 'crypto';
import * as jose from 'jose';
import {
  buildIssuanceReceipt,
  canonicalReceiptSigningInput,
  canonicalSctSigningInput,
  inferAlgFromKeyObject,
  sha256Base64Url,
  signRawBytes,
} from './issuance-proofs';
import { JwkKey, JwkSet } from './jwks';
import {
  CapabilityTokenPayload,
  IssuanceReceipt,
  Sct,
} from './wire';

/**
 * A transparency-log entry. Each `submit` call produces exactly one entry
 * that records the receipt + the SCT the log signed for it.
 */
export interface TransparencyLogEntry {
  /** Monotonic 0-based index of the entry within the log. */
  index: number;
  /** The receipt that was submitted. */
  receipt: IssuanceReceipt;
  /** The SCT the log signed (and returned to the submitter). */
  sct: Sct;
}

/**
 * Transparency-log integration interface. Implementations MUST be safe
 * to call concurrently and MUST be append-only (entries cannot be
 * reordered or deleted once accepted).
 */
export interface TransparencyLog {
  /** Stable identifier of this log; matches every {@link Sct.logId} produced. */
  getLogId(): string;

  /**
   * Submit a receipt to the log. The implementation appends an entry
   * and returns the SCT, which the issuer embeds in the token's
   * `proofs.sct[]` claim.
   *
   * Implementations SHOULD fail loudly: if the log cannot accept the
   * submission, the issuer MUST abort the issuance — minting a token
   * without an SCT when SCTs are required would reduce to the previous
   * single-signer trust model.
   */
  submit(receipt: IssuanceReceipt): Promise<Sct>;

  /**
   * Return the public JWKS the gateway should use to verify SCTs from
   * this log. Convenience for self-contained dev setups; production
   * deployments typically publish the JWKS at a stable URL controlled by
   * the log operator (separate principal from the issuer).
   */
  getPublicJwks(): Promise<JwkSet>;
}

/**
 * In-process software transparency log. Stores entries in memory and
 * signs SCTs with a software-held private key. For tests, local dev, and
 * deployments that intentionally co-locate the log with the issuer.
 *
 * **Production guidance**: the security guarantee depends on the log's
 * private key being held by a *different* principal than the primary
 * issuer signing key. If both keys live on the same workload identity,
 * the cosignature path is the more meaningful defence; the transparency
 * log here adds value only as an auditable, append-only audit trail.
 *
 * For the strongest defence, run the log as a separate service with its
 * own KMS-backed key, and load only its public JWKS into the gateway.
 */
export class InMemoryTransparencyLog implements TransparencyLog {
  private readonly logId: string;
  private readonly kid: string;
  private readonly alg: string;
  private readonly privateKey: jose.KeyLike;
  private readonly publicJwk: JwkKey;
  private readonly entries: TransparencyLogEntry[] = [];
  /**
   * Monotonic counter used to atomically reserve the next entry index
   * before the async signing step. Reading `entries.length` and then
   * awaiting `signRawBytes` is a TOCTOU race under concurrent submits:
   * two parallel calls would observe the same length, sign, and append
   * entries at the same index — breaking the append-order contract.
   * The counter is incremented synchronously up-front so each submit
   * owns a unique index for its lifetime.
   */
  private nextIndex = 0;
  /**
   * Optional clock injection — defaults to `Date.now`. Used in tests to
   * produce deterministic SCT timestamps.
   */
  private readonly clock: () => number;

  constructor(opts: {
    logId: string;
    kid: string;
    alg: string;
    privateKey: jose.KeyLike;
    publicJwk: JwkKey;
    clock?: () => number;
  }) {
    if (!opts.logId || opts.logId.includes('\n')) {
      throw new Error(
        'InMemoryTransparencyLog: logId is required and MUST NOT contain newlines',
      );
    }
    if (!opts.kid) throw new Error('InMemoryTransparencyLog: kid is required');
    if (!opts.alg) throw new Error('InMemoryTransparencyLog: alg is required');
    this.logId = opts.logId;
    this.kid = opts.kid;
    this.alg = opts.alg;
    this.privateKey = opts.privateKey;
    this.publicJwk = { ...opts.publicJwk, kid: opts.kid, alg: opts.alg, use: 'sig' };
    this.clock = opts.clock ?? (() => Date.now());
  }

  getLogId(): string {
    return this.logId;
  }

  async submit(receipt: IssuanceReceipt): Promise<Sct> {
    // Reserve a monotonic index synchronously BEFORE any await so two
    // concurrent submits cannot collide on the same index. If signing
    // throws below the index is simply not appended (logs may show a
    // gap, which is the correct semantic — a failed mint reserved a
    // slot it never used).
    const entryIndex = this.nextIndex;
    this.nextIndex += 1;
    const timestamp = this.clock();
    const receiptHash = sha256Base64Url(canonicalReceiptSigningInput(receipt));
    const input = canonicalSctSigningInput(this.logId, timestamp, receiptHash);
    const sig = await signRawBytes(this.alg, this.privateKey, input);
    const sct: Sct = {
      logId: this.logId,
      kid: this.kid,
      alg: this.alg,
      timestamp,
      entryIndex,
      sig,
    };
    // Append-only insertion. Concurrent submits may complete out of
    // order (signing latency varies); place each entry at its reserved
    // index so the final array is sorted by index regardless of
    // completion order.
    this.entries[entryIndex] = { index: entryIndex, receipt, sct };
    return sct;
  }

  async getPublicJwks(): Promise<JwkSet> {
    return { keys: [{ ...this.publicJwk }] };
  }

  /**
   * Read accessor for tests + auditors. Returns a defensive copy so
   * callers cannot mutate the underlying entry list. Filters out
   * reserved-but-not-yet-completed slots (concurrent submits whose
   * signing has not finished) so callers always see a contiguous
   * view of *appended* entries, in index order.
   */
  getEntries(): TransparencyLogEntry[] {
    const out: TransparencyLogEntry[] = [];
    for (const e of this.entries) {
      if (!e) continue; // sparse hole — slot reserved, signing in flight
      out.push({
        index: e.index,
        receipt: { ...e.receipt },
        sct: { ...e.sct },
      });
    }
    return out;
  }

  /**
   * Convenience factory: generate a fresh Ed25519 key for the log and
   * return a ready-to-use in-memory log. Used by tests and dev-mode
   * `.env.example` config — the same caveat as
   * {@link SoftwareCosigner.generateEd25519} applies (key is lost on
   * restart).
   */
  static async generateEd25519(opts: {
    logId: string;
    kid: string;
    clock?: () => number;
  }): Promise<InMemoryTransparencyLog> {
    const { privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    const joseKey = await jose.importPKCS8(pem, 'EdDSA');
    const publicKeyObj = nodeCrypto.createPublicKey(privateKey);
    const publicJwk = publicKeyObj.export({ format: 'jwk' }) as JwkKey;
    return new InMemoryTransparencyLog({
      logId: opts.logId,
      kid: opts.kid,
      alg: 'EdDSA',
      privateKey: joseKey,
      publicJwk,
      ...(opts.clock ? { clock: opts.clock } : {}),
    });
  }

  /**
   * Convenience factory: load a transparency log signing key from a PEM
   * (PKCS#8) private key on disk / in env. The matching public key is
   * exported from the private key.
   */
  static async fromPemPrivateKey(opts: {
    logId: string;
    kid: string;
    pem: string;
    alg?: string;
    clock?: () => number;
  }): Promise<InMemoryTransparencyLog> {
    const keyObject = nodeCrypto.createPrivateKey(opts.pem);
    const alg = opts.alg ?? inferAlgFromKeyObject(keyObject);
    if (!alg) {
      throw new Error(
        'InMemoryTransparencyLog.fromPemPrivateKey: could not infer alg from key; pass alg explicitly',
      );
    }
    const privateKey = await jose.importPKCS8(opts.pem, alg);
    const publicKeyObject = nodeCrypto.createPublicKey(keyObject);
    const publicJwk = publicKeyObject.export({ format: 'jwk' }) as JwkKey;
    return new InMemoryTransparencyLog({
      logId: opts.logId,
      kid: opts.kid,
      alg,
      privateKey,
      publicJwk,
      ...(opts.clock ? { clock: opts.clock } : {}),
    });
  }
}

/**
 * Helper used by the issuer's issuance pipeline: submit a receipt
 * derived from a freshly-built {@link CapabilityTokenPayload} to every
 * configured transparency log, in order. Returns the resulting array of
 * {@link Sct}s for embedding in `payload.proofs.sct`.
 *
 * If `logs` is empty the function returns `undefined` so the issuer can
 * omit the `sct` claim entirely (back-compat).
 *
 * Log failures abort the issuance: minting a token whose SCT submission
 * silently failed would let a partial outage become a "no transparency"
 * window an attacker could exploit.
 */
export async function witnessPayload(
  payload: CapabilityTokenPayload,
  logs: ReadonlyArray<TransparencyLog>,
): Promise<Sct[] | undefined> {
  if (logs.length === 0) return undefined;
  const receipt = buildIssuanceReceipt(payload);
  const scts: Sct[] = [];
  for (const log of logs) {
    scts.push(await log.submit(receipt));
  }
  return scts;
}
