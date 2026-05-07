/**
 * Latency-injecting stubs for the profiled issuance perf scenarios.
 *
 * Every optional component the capability issuer may call on the hot path
 * — KMS signer, cosigner, posture emitter, side-credential broker,
 * transparency-log witness — is represented here by a stub implementation
 * that:
 *
 *   1. Does the minimum real work needed to produce a valid return value
 *      (so the issuer's correctness checks pass), **and**
 *   2. Injects a configurable `await delay(latencyMs)` to simulate the
 *      network RTT / KMS processing time of the real component.
 *
 * The net effect: the autocannon runner measures the Node.js orchestration
 * overhead of each optional component independently of the variance of real
 * cloud networks. You choose the latency to model, e.g.:
 *
 *   - `kmsSignLatencyMs: 40`  → typical Azure Key Vault p50 same-region RTT
 *   - `cosignLatencyMs: 2`    → software Ed25519 sign (in-process)
 *   - `sideCredsLatencyMs: 8` → in-process broker stub
 *
 * The overall "does the budget hold?" story then becomes:
 *   simulated KMS latency + simulated optional latencies
 *   + measured Node.js overhead ≤ SLO budget
 *
 * Posture emission is intentionally **fire-and-forget** (the Promise is
 * not awaited on the critical path in the issuer service), so
 * `SimulatedPostureEmitter` simply schedules the delay and returns
 * immediately; the resolved value never feeds the token.
 */

import * as jose from 'jose';
import {
  CapabilityTokenPayload,
  Cosigner,
  IssuanceContext,
  IssuanceReceipt,
  Cosignature,
  JwkKey,
  JwkSet,
  Sct,
  PostureEmitterLike,
  AgentInventoryRecord,
  SigningAdapter,
  SigningAdapterConfig,
  CapabilityConstraint,
  DbCredential,
  StorageGrant,
  TransparencyLog,
  canonicalReceiptSigningInput,
  canonicalSctSigningInput,
  sha256Base64Url,
  signRawBytes,
} from '@euno/common';
import {
  SideCredentialBroker,
  SideCredentialMintContext,
} from '../../../capability-issuer/src/side-credential-broker';

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Resolves after `ms` milliseconds. Inlined to avoid importing a library. */
function delay(ms: number): Promise<void> {
  // Cast through `unknown` so the call compiles in the perf tsconfig
  // which does not include `@types/node` (the same pattern used in
  // `lib/harness.ts` and `lib/runner.ts` which also live under the
  // `tsconfig.perf.json` root that lacks `node` in `lib`).
  const setTimeoutFn = setTimeout as unknown as (fn: () => void, ms: number) => unknown;
  return new Promise<void>((resolve) => setTimeoutFn(resolve, ms));
}

// ---------------------------------------------------------------------------
// SimulatedKmsSigner
// ---------------------------------------------------------------------------

/**
 * A {@link SigningAdapter} that wraps a real in-process JOSE RSA signer
 * and injects a configurable delay before each `sign()` call to model
 * the network RTT of a cloud KMS (Azure Key Vault, AWS KMS, GCP Cloud KMS).
 *
 * The delay is applied on every `sign()` invocation so the autocannon
 * steady-state latency histogram reflects the KMS contribution faithfully.
 *
 * @example
 * const signer = await SimulatedKmsSigner.create({ signLatencyMs: 40 });
 * // 40 ms models Azure Key Vault p50 latency in the same Azure region.
 */
export class SimulatedKmsSigner extends SigningAdapter {
  private readonly inner: jose.KeyLike;
  private readonly spki: string;
  private readonly kid: string;
  private readonly signLatencyMs: number;
  private readonly alg: string;

  private constructor(opts: {
    inner: jose.KeyLike;
    spki: string;
    kid: string;
    signLatencyMs: number;
    alg: string;
  }) {
    super({
      type: 'simulated-kms',
      name: 'simulated-kms',
      algorithm: opts.alg,
    } as unknown as SigningAdapterConfig);
    this.inner = opts.inner;
    this.spki = opts.spki;
    this.kid = opts.kid;
    this.signLatencyMs = opts.signLatencyMs;
    this.alg = opts.alg;
  }

  /** Generate a fresh RSA-2048 key pair and wrap it in a `SimulatedKmsSigner`. */
  static async create(opts: {
    signLatencyMs: number;
    alg?: string;
    kid?: string;
  }): Promise<SimulatedKmsSigner> {
    const alg = opts.alg ?? 'RS256';
    const { privateKey, publicKey } = await jose.generateKeyPair(alg, {
      extractable: true,
    });
    const spki = await jose.exportSPKI(publicKey);
    return new SimulatedKmsSigner({
      inner: privateKey,
      spki,
      kid: opts.kid ?? `simulated-kms-${Date.now()}`,
      signLatencyMs: opts.signLatencyMs,
      alg,
    });
  }

  async sign(
    payload: CapabilityTokenPayload,
    _context?: IssuanceContext,
  ): Promise<string> {
    // Simulate the KMS network RTT *before* the cryptographic operation
    // so the extra latency is faithfully reflected in the p99 latency
    // histogram even when many requests are in flight concurrently.
    if (this.signLatencyMs > 0) await delay(this.signLatencyMs);
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: this.alg, kid: this.kid })
      .sign(this.inner);
  }

  async getPublicKey(): Promise<string> {
    return this.spki;
  }

  async getKeyId(): Promise<string> {
    return this.kid;
  }
}

// ---------------------------------------------------------------------------
// SimulatedCosigner
// ---------------------------------------------------------------------------

/**
 * A {@link Cosigner} that signs the canonical receipt bytes using an
 * in-process Ed25519 key and injects a configurable delay to model
 * an HSM-backed or remote co-signing service.
 *
 * The delay is applied on every `cosignReceipt()` call so the autocannon
 * histogram includes the cosigner's contribution. Set `cosignLatencyMs: 2`
 * for a software-only cosigner; set higher (e.g. 15–30 ms) to model an
 * HSM or remote co-signing micro-service.
 */
export class SimulatedCosigner implements Cosigner {
  private readonly _kid: string;
  private readonly privateKey: jose.KeyLike;
  private readonly publicKeyJwk: jose.JWK;
  private readonly cosignLatencyMs: number;

  private constructor(opts: {
    kid: string;
    privateKey: jose.KeyLike;
    publicKeyJwk: jose.JWK;
    cosignLatencyMs: number;
  }) {
    this._kid = opts.kid;
    this.privateKey = opts.privateKey;
    this.publicKeyJwk = opts.publicKeyJwk;
    this.cosignLatencyMs = opts.cosignLatencyMs;
  }

  /** Generate a fresh Ed25519 cosigner key. */
  static async create(opts: {
    kid?: string;
    cosignLatencyMs: number;
  }): Promise<SimulatedCosigner> {
    const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const publicKeyJwk = await jose.exportJWK(publicKey);
    return new SimulatedCosigner({
      kid: opts.kid ?? `simulated-cosigner-${Date.now()}`,
      privateKey,
      publicKeyJwk,
      cosignLatencyMs: opts.cosignLatencyMs,
    });
  }

  getKid(): string {
    return this._kid;
  }

  getAlgorithm(): string {
    return 'EdDSA';
  }

  async getPublicJwk(): Promise<JwkKey> {
    return { ...this.publicKeyJwk, kid: this._kid, use: 'sig', alg: 'EdDSA' } as JwkKey;
  }

  async cosignReceipt(receipt: IssuanceReceipt): Promise<Cosignature> {
    if (this.cosignLatencyMs > 0) await delay(this.cosignLatencyMs);

    // Match the SoftwareCosigner wire format exactly: sign the canonical
    // receipt bytes and return base64url-encoded raw signature bytes in
    // the `sig` field. A compact-JWS string would not verify under
    // verifyCosignature(), which calls verifyRawSignature() on the
    // base64url-decoded `sig` bytes directly.
    const input = canonicalReceiptSigningInput(receipt);
    const sig = await signRawBytes('EdDSA', this.privateKey, input);
    return { kid: this._kid, alg: 'EdDSA', sig };
  }
}

// ---------------------------------------------------------------------------
// SimulatedPostureEmitter
// ---------------------------------------------------------------------------

/**
 * A {@link PostureEmitterLike} that always reports `isEnabled() = true` and
 * schedules a fire-and-forget delay on each `emitObserved()` call to model
 * the async posture-inventory write (e.g. an HTTP PUT to a posture surface).
 *
 * Because the issuer never awaits `emitObserved()` on the critical path, the
 * latency injected here does **not** appear in the issuance p99. The stub
 * exists to verify that the fire-and-forget plumbing doesn't introduce
 * unexpected blocking or accumulate unhandled rejections under load.
 */
export class SimulatedPostureEmitter implements PostureEmitterLike {
  private readonly emitLatencyMs: number;

  constructor(opts: { emitLatencyMs: number }) {
    this.emitLatencyMs = opts.emitLatencyMs;
  }

  isEnabled(): boolean {
    return true;
  }

  async emitObserved(_record: AgentInventoryRecord): Promise<void> {
    // Fire-and-forget: the caller never awaits this, so the delay only
    // adds to background event-loop work, not to the critical path.
    if (this.emitLatencyMs > 0) await delay(this.emitLatencyMs);
  }

  async emitRevoked(_agentId: string, _revokedAt: string): Promise<void> {
    if (this.emitLatencyMs > 0) await delay(this.emitLatencyMs);
  }
}

// ---------------------------------------------------------------------------
// SimulatedSideCredentialBroker
// ---------------------------------------------------------------------------

/**
 * A {@link SideCredentialBroker} that returns a pair of dummy credential
 * stubs after a configurable delay to model the round-trip to a
 * side-credential micro-service (storage-grant-service, db-token-service).
 *
 * Storage and DB credential minting are both enabled so the scenario
 * exercises the full broker code path in the issuer service.
 */
export class SimulatedSideCredentialBroker implements SideCredentialBroker {
  private readonly mintLatencyMs: number;

  constructor(opts: { mintLatencyMs: number }) {
    this.mintLatencyMs = opts.mintLatencyMs;
  }

  isStorageEnabled(): boolean {
    return true;
  }

  isDbEnabled(): boolean {
    return true;
  }

  async mint(
    _signedToken: string,
    _capabilities: CapabilityConstraint[],
    _context: SideCredentialMintContext,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }> {
    if (this.mintLatencyMs > 0) await delay(this.mintLatencyMs);
    // Return empty arrays: the perf scenario is exercising the broker
    // code path (latency + orchestration), not the credential shape.
    // Returning empty arrays is always type-valid and avoids any
    // attempt to construct the complex discriminated-union shapes of
    // StorageGrant and DbCredential.
    return { storageGrants: [], dbCredentials: [] };
  }
}

// ---------------------------------------------------------------------------
// SimulatedTransparencyLog
// ---------------------------------------------------------------------------

/**
 * A {@link TransparencyLog} that accepts receipt submissions after a
 * configurable delay to model the latency of appending to a remote
 * transparency log (e.g. a Trillian-backed append-only tree).
 *
 * The delay models a same-datacenter transparency log service; for
 * cross-datacenter replication, increase `witnessLatencyMs` accordingly.
 */
export class SimulatedTransparencyLog implements TransparencyLog {
  private readonly _logId: string;
  private readonly witnessLatencyMs: number;
  private readonly kid: string;
  private readonly privateKey: jose.KeyLike;
  private readonly publicKey: jose.KeyLike;
  private entryIndex = 0;

  private constructor(opts: {
    logId: string;
    witnessLatencyMs: number;
    kid: string;
    privateKey: jose.KeyLike;
    publicKey: jose.KeyLike;
  }) {
    this._logId = opts.logId;
    this.witnessLatencyMs = opts.witnessLatencyMs;
    this.kid = opts.kid;
    this.privateKey = opts.privateKey;
    this.publicKey = opts.publicKey;
  }

  /** Generate a fresh Ed25519 log key. */
  static async create(opts: {
    logId?: string;
    witnessLatencyMs: number;
  }): Promise<SimulatedTransparencyLog> {
    const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    return new SimulatedTransparencyLog({
      logId: opts.logId ?? `simulated-log-${Date.now()}`,
      witnessLatencyMs: opts.witnessLatencyMs,
      kid: `simulated-log-key-${Date.now()}`,
      privateKey,
      publicKey,
    });
  }

  getLogId(): string {
    return this._logId;
  }

  async submit(receipt: IssuanceReceipt): Promise<Sct> {
    if (this.witnessLatencyMs > 0) await delay(this.witnessLatencyMs);

    // Reserve the entry index synchronously before the async signing step,
    // mirroring InMemoryTransparencyLog's TOCTOU-safe pattern.
    const entryIndex = this.entryIndex;
    this.entryIndex += 1;
    const timestamp = Date.now();

    // Match the InMemoryTransparencyLog wire format exactly:
    //   1. Hash the canonical receipt bytes → receiptHash (base64url SHA-256).
    //   2. Sign canonicalSctSigningInput(logId, timestamp, receiptHash) with
    //      signRawBytes so the returned `sig` is base64url-encoded raw bytes.
    // This means verifySct() will succeed given this log's public JWKS.
    const receiptHash = sha256Base64Url(canonicalReceiptSigningInput(receipt));
    const input = canonicalSctSigningInput(this._logId, timestamp, receiptHash);
    const sig = await signRawBytes('EdDSA', this.privateKey, input);

    return {
      logId: this._logId,
      kid: this.kid,
      alg: 'EdDSA',
      timestamp,
      entryIndex,
      sig,
    } satisfies Sct;
  }

  async getPublicJwks(): Promise<JwkSet> {
    const jwk = await jose.exportJWK(this.publicKey);
    return {
      keys: [{ ...jwk, kid: this.kid, use: 'sig', alg: 'EdDSA' } as JwkKey],
    };
  }
}
