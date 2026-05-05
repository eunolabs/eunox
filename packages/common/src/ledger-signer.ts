/**
 * Pluggable ledger backend for EvidenceSigner
 * ---------------------------------------------------------------------------
 * Closes the "compromised replica rewrites local chain" gap in
 * {@link AuditEvidenceSigner} by moving chain state into an external,
 * append-only store.
 *
 * ## Threat model
 *
 * `AuditEvidenceSigner` keeps `previousHash` and `seq` in process memory.
 * A compromised replica can therefore:
 *   - Restart with a forged `chainSeed` (or no seed) to create a parallel
 *     chain starting from seq=1 — the chain looks internally valid but does
 *     not continue the real history.
 *   - Re-sign old records with modified content; the chain still verifies
 *     because the attacker controls both the key (via the KMS policy the
 *     compromised process is authorised to call) and the in-process state.
 *
 * ## Solution
 *
 * `LedgerAuditEvidenceSigner` delegates chain state to a `LedgerBackend`.
 * The backend's `appendEntry` method is the *single* serialization point:
 *   1. Acquires an exclusive write lock on the chain tip.
 *   2. Reads the current tip (`previousHash`, `nextSeq`).
 *   3. Calls the provided `sign` callback to produce a `SignedAuditEvidence`.
 *   4. Validates that the signed record's `previousHash` matches the tip.
 *   5. Persists the record with a per-row HMAC (detects DB-level tampering).
 *   6. Releases the lock.
 *
 * A compromised replica cannot forge a valid entry because:
 *   - The DB-level advisory lock serialises all writers, so forking the chain
 *     by inserting a record with an arbitrary `previousHash` is rejected.
 *   - The per-row HMAC requires the `hmacSecret` (a separate credential,
 *     distinct from the signing key), so DB-level tampering is detectable even
 *     without re-checking cryptographic signatures.
 *   - `PostgresLedgerBackend` can optionally PUT a Merkle root of every N rows
 *     to an S3 Object-Lock bucket, providing an independent external witness:
 *     even a full DB + HMAC-key compromise cannot erase rows without the S3
 *     anchors betraying the gap.
 *
 * ## Implementations
 *
 *   - {@link InMemoryLedgerBackend}    — for development and unit tests.
 *   - {@link PostgresLedgerBackend}    — production; uses pg + per-row HMAC
 *                                        + optional S3 Object-Lock anchoring.
 *
 * ## Multi-replica operation
 *
 * Multiple gateway replicas can share the same `PostgresLedgerBackend` table.
 * The PostgreSQL transaction-level advisory lock (`pg_advisory_xact_lock`)
 * ensures only one replica is in the critical section at a time, so the global
 * chain always advances monotonically regardless of how many replicas are
 * writing concurrently.
 */

import * as crypto from 'crypto';
import { AuditEvidence, SignedAuditEvidence, GENESIS_HASH } from './wire';
import { EvidenceSigner } from './runtime';
import { CryptoSigner, signEvidenceWithChain, canonicalizeEvidenceFields } from './evidence';
import { canonicalSha256, computeMerkleRoot } from './utils';

// ── LedgerEntry ───────────────────────────────────────────────────────────────

/**
 * A single row stored in the external ledger by {@link LedgerBackend.appendEntry}.
 */
export interface LedgerEntry {
  /** Monotonically increasing 1-based sequence number assigned by the ledger. */
  seq: number;
  /** SHA-256 hex of the preceding `SignedAuditEvidence` (or GENESIS_HASH for seq=1). */
  previousHash: string;
  /**
   * `canonicalSha256` of the `SignedAuditEvidence` stored in this row.
   * This is the value stored in the next row's `previousHash`.
   */
  recordHash: string;
  /** Replica / pod identifier that wrote this row. */
  replicaId: string;
  /** Full signed evidence payload. */
  signedEvidence: SignedAuditEvidence;
  /** ISO-8601 timestamp when this row was appended. */
  ts: string;
  /**
   * Raw HMAC bytes as stored in the backend row (PostgreSQL backend only).
   *
   * Populated by {@link PostgresLedgerBackend.getEntries} so callers can
   * pass this directly to {@link PostgresLedgerBackend.verifyRowHmac} for
   * offline integrity verification without an additional raw DB query.
   * Absent for backends that do not use per-row HMACs (e.g.
   * {@link AzureConfidentialLedgerBackend}, {@link InMemoryLedgerBackend}).
   */
  rowHmac?: Buffer;
}

// ── Error types ───────────────────────────────────────────────────────────────

/**
 * Thrown by {@link LedgerBackend.appendEntry} when the incoming
 * `previousHash` does not match the current ledger tip, which would create
 * a fork in the chain.
 *
 * Callers MUST NOT silently swallow this error — it means either:
 *   a) a concurrent write from another replica advanced the chain between
 *      the time the signing callback ran and the moment the record was
 *      inserted (should not happen if the backend holds the write lock
 *      across both steps, but defensive programming pays off here), or
 *   b) a compromised replica attempted to insert a record with a fabricated
 *      `previousHash`.
 */
export class LedgerChainError extends Error {
  constructor(
    message: string,
    public readonly expectedPreviousHash: string,
    public readonly actualPreviousHash: string,
  ) {
    super(message);
    this.name = 'LedgerChainError';
  }
}

/**
 * Thrown when HMAC verification of a stored row fails.
 * Indicates DB-level tampering or HMAC-secret mismatch.
 */
export class LedgerHmacError extends Error {
  constructor(message: string, public readonly seq: number) {
    super(message);
    this.name = 'LedgerHmacError';
  }
}

// ── LedgerBackend interface ───────────────────────────────────────────────────

/**
 * Pluggable backend that owns the authoritative chain state.
 *
 * The key invariant: `appendEntry` is the **only** path by which chain state
 * advances; it must be atomic (acquire lock → read tip → sign → insert →
 * release lock) so no two calls can interleave and produce a fork.
 */
export interface LedgerBackend {
  /** Human-readable name for logging / metrics labels. */
  readonly name: string;

  /**
   * Optional startup initialisation.
   *
   * Implementations that maintain in-process chain state should seed it from
   * the external store here (e.g. `PostgresLedgerBackend` seeds
   * `lastAnchoredSeq`; `AzureConfidentialLedgerBackend` seeds the chain tip).
   * Called once by {@link LedgerAuditEvidenceSigner.initialize} before the
   * first `appendEntry`.
   *
   * Implementations MAY throw; the caller treats any thrown error as a
   * startup failure.
   */
  initialize?(): Promise<void>;

  /**
   * Atomically append one signed evidence record to the ledger.
   *
   * The backend MUST:
   *   1. Acquire an exclusive write lock on the chain.
   *   2. Read the current chain tip (`previousHash`, `nextSeq`).
   *   3. Call `sign(previousHash, nextSeq)` to produce a `SignedAuditEvidence`.
   *   4. Verify that `signed.previousHash === previousHash` (sanity check;
   *      throws `LedgerChainError` on mismatch).
   *   5. Persist the record.
   *   6. Release the lock.
   *
   * The `sign` callback is invoked WHILE THE LOCK IS HELD so no other writer
   * can advance the chain between steps 2 and 5. Implementations that use a
   * PostgreSQL advisory lock will block other replicas in step 1 until this
   * call returns.
   *
   * @param evidence   Unsigned evidence record to persist.
   * @param replicaId  Replica identifier stamped on the row.
   * @param sign       Signing callback; MUST be fast (e.g. in-process RSA or
   *                   KMS call in the low-ms range). The advisory lock is held
   *                   while this runs.
   * @returns          The fully signed and persisted evidence record.
   * @throws           `LedgerChainError` if chain integrity would be broken.
   */
  appendEntry(
    evidence: AuditEvidence,
    replicaId: string,
    sign: (previousHash: string, nextSeq: number) => Promise<SignedAuditEvidence>,
  ): Promise<SignedAuditEvidence>;

  /**
   * Return the current chain tip, or `null` when the ledger is empty.
   *
   * Used at startup to re-seed the in-process chain state from the external
   * store (continuity across process restarts).
   */
  getChainTip(): Promise<{ seq: number; tipHash: string } | null>;

  /**
   * Retrieve ledger entries in the inclusive range [fromSeq, toSeq].
   *
   * Used by offline verification tools to replay and validate the chain.
   */
  getEntries(fromSeq: number, toSeq: number): Promise<LedgerEntry[]>;

  /**
   * Gracefully release any external resources (e.g. DB connection pool).
   * Called during gateway shutdown.
   */
  close?(): Promise<void>;
}

// ── LedgerAuditEvidenceSigner ─────────────────────────────────────────────────

/**
 * An {@link EvidenceSigner} that externalises its chain state to a
 * {@link LedgerBackend}.
 *
 * Each `signEvidence` call delegates to `LedgerBackend.appendEntry`, which
 * holds the write lock across the entire read-tip → sign → insert cycle.
 * The in-process serial queue (`chainTail`) is kept as an additional defence
 * against multiple concurrent calls from the same process: it ensures this
 * class never has two in-flight `appendEntry` calls at once, which would
 * contend on the backend's lock and waste one signing round-trip.
 *
 * ### Startup seeding
 *
 * Call `initialize()` immediately after construction to prime the in-process
 * `lastKnownTipHash` from the ledger. This is a best-effort optimisation: if
 * the ledger is temporarily unavailable at startup, signing is simply delayed
 * until `appendEntry` can reach the backend.
 */
export class LedgerAuditEvidenceSigner implements EvidenceSigner {
  /**
   * Serial queue — prevents concurrent in-process signing calls from both
   * competing on the backend lock at the same time.
   */
  private chainTail: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly cryptoSigner: CryptoSigner,
    private readonly backend: LedgerBackend,
    private readonly replicaId: string,
  ) {}

  /**
   * Prime the signer's state by delegating to {@link LedgerBackend.initialize}
   * (if implemented).
   *
   * Call once at startup before the first `signEvidence`.  This lets backends
   * seed their in-process chain state (e.g. reading the tip from Postgres or
   * ACL) so the first signing call does not need an extra round-trip.
   */
  async initialize(): Promise<void> {
    if (typeof this.backend.initialize === 'function') {
      await this.backend.initialize();
    }
  }

  async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    return new Promise<SignedAuditEvidence>((resolve, reject) => {
      this.chainTail = this.chainTail
        .then(() =>
          this.backend.appendEntry(evidence, this.replicaId, (previousHash, nextSeq) =>
            signEvidenceWithChain(evidence, this.cryptoSigner, previousHash, nextSeq),
          ),
        )
        .then(resolve, reject)
        .catch(() => {
          // Swallow so the queue keeps draining on error.
        });
    });
  }

  async verifyEvidence(signedEvidence: SignedAuditEvidence): Promise<boolean> {
    const { signature, keyId, algorithm, previousHash, seq } = signedEvidence;
    if (!signature || !keyId || !algorithm || !previousHash || typeof seq !== 'number') {
      return false;
    }
    if (typeof this.cryptoSigner.verifyDigest !== 'function') {
      return false;
    }
    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(signature, 'base64');
    } catch {
      return false;
    }
    if (signatureBuffer.length === 0) {
      return false;
    }
    // Re-canonicalize using the fields stored on the record.
    const { signature: _sig, keyId: _kid, algorithm: _alg, previousHash: _ph, seq: _seq, ...evidenceFields } = signedEvidence;
    const canonical = canonicalizeEvidenceFields(evidenceFields, keyId, algorithm, previousHash, seq);
    const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();
    try {
      return await this.cryptoSigner.verifyDigest!(digest, signatureBuffer, keyId, algorithm);
    } catch {
      return false;
    }
  }

  /** Expose the backend for use by callers that need direct access. */
  getBackend(): LedgerBackend {
    return this.backend;
  }
}

// ── InMemoryLedgerBackend ─────────────────────────────────────────────────────

/**
 * In-memory implementation of {@link LedgerBackend}.
 *
 * Suitable for development and unit tests. Uses an async serial queue for
 * locking so the same contract as `PostgresLedgerBackend` is honoured —
 * tests written against this backend faithfully represent multi-replica
 * behaviour.
 *
 * **NOT suitable for production**: data is lost on process exit and there is
 * no HMAC or S3 anchoring.
 */
export class InMemoryLedgerBackend implements LedgerBackend {
  readonly name = 'in-memory';

  private entries: LedgerEntry[] = [];
  /** Serial queue for atomic append. */
  private appendTail: Promise<unknown> = Promise.resolve();

  async appendEntry(
    _evidence: AuditEvidence,
    replicaId: string,
    sign: (previousHash: string, nextSeq: number) => Promise<SignedAuditEvidence>,
  ): Promise<SignedAuditEvidence> {
    return new Promise<SignedAuditEvidence>((resolve, reject) => {
      this.appendTail = this.appendTail
        .then(async () => {
          const tip = this.entries[this.entries.length - 1];
          const previousHash = tip ? tip.recordHash : GENESIS_HASH;
          const nextSeq = tip ? tip.seq + 1 : 1;

          const signed = await sign(previousHash, nextSeq);

          // Sanity check: the sign callback must have used the previousHash we provided.
          if (signed.previousHash !== previousHash) {
            throw new LedgerChainError(
              `LedgerChainError: sign callback used previousHash "${signed.previousHash}" ` +
                `but ledger tip is "${previousHash}"`,
              previousHash,
              signed.previousHash,
            );
          }
          if (signed.seq !== nextSeq) {
            throw new LedgerChainError(
              `LedgerChainError: sign callback used seq ${signed.seq} but expected ${nextSeq}`,
              String(nextSeq) as unknown as string,
              String(signed.seq) as unknown as string,
            );
          }

          const recordHash = canonicalSha256(signed);
          const entry: LedgerEntry = {
            seq: nextSeq,
            previousHash,
            recordHash,
            replicaId,
            signedEvidence: signed,
            ts: new Date().toISOString(),
          };
          this.entries.push(entry);
          return signed;
        })
        .then(resolve, reject)
        .catch(() => {
          // Keep the queue alive on errors.
        });
    });
  }

  async getChainTip(): Promise<{ seq: number; tipHash: string } | null> {
    const tip = this.entries[this.entries.length - 1];
    if (!tip) return null;
    return { seq: tip.seq, tipHash: tip.recordHash };
  }

  async getEntries(fromSeq: number, toSeq: number): Promise<LedgerEntry[]> {
    return this.entries.filter((e) => e.seq >= fromSeq && e.seq <= toSeq);
  }

  /** Total number of entries in the in-memory store (for test assertions). */
  get size(): number {
    return this.entries.length;
  }

  /** Return all entries (for test assertions). */
  allEntries(): LedgerEntry[] {
    return [...this.entries];
  }
}

// ── PgPool minimal interface ──────────────────────────────────────────────────

/**
 * Minimal subset of the `pg.Pool` / `pg.Client` surface that
 * {@link PostgresLedgerBackend} needs. Defined locally so `@euno/common` does
 * not take a hard runtime dependency on the `pg` package — callers wire in the
 * real pool via `new PostgresLedgerBackend(pool, options)`.
 */
export interface PgQueryResult<R extends Record<string, unknown> = Record<string, unknown>> {
  rows: R[];
  rowCount: number | null;
}

export interface PgClientConnection {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>>;
  /** Return the connection to the pool. */
  release(err?: Error | boolean): void;
}

export interface PgPool {
  connect(): Promise<PgClientConnection>;
  end(): Promise<void>;
}

// ── S3AnchorClient interface ──────────────────────────────────────────────────

/**
 * Minimal interface for an S3-compatible Object-Lock PUT operation.
 *
 * Callers provide their own implementation (e.g. AWS SDK v3 `S3Client` wrapped
 * in a small adapter) so `@euno/common` does not depend on the AWS SDK.
 *
 * The implementation MUST issue the `PutObject` request with
 * `ObjectLockMode: 'COMPLIANCE'` (or `'GOVERNANCE'`) so the object is
 * immutable for the retention period — this is what makes the anchor
 * tamper-evident.
 */
export interface S3AnchorClient {
  putObject(params: {
    bucket: string;
    key: string;
    body: string;
    contentType: string;
  }): Promise<void>;
}

// ── PostgresLedgerBackend ─────────────────────────────────────────────────────

/**
 * Validates a table name to prevent SQL injection.
 *
 * Accepts only safe identifiers: ASCII letters, digits, underscores, and
 * schema-qualified names (one dot allowed, e.g. `audit.euno_ledger`).
 * Rejects quotes, semicolons, spaces, or any other special characters.
 */
function validateTableName(name: string): string {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/.test(name)) {
    throw new Error(
      `PostgresLedgerBackend: invalid table name "${name}". ` +
        'Table name must be a safe SQL identifier (letters, digits, underscores; ' +
        'one dot allowed for schema-qualified names, e.g. "audit.euno_ledger").',
    );
  }
  return name;
}

/**
 * Decode the HMAC secret from the caller-supplied string.
 *
 * Accepts three formats:
 *   - 64-char hex string (output of `openssl rand -hex 32`) — decoded as hex bytes.
 *   - Base64-encoded string (output of `openssl rand -base64 32`) — decoded as base64 bytes.
 *   - Raw UTF-8 string of at least 32 characters (legacy / testing only).
 *
 * Enforces a minimum decoded length of 32 bytes (256 bits).
 */
function decodeHmacSecret(raw: string): Buffer {
  // Try hex first: if the string is even-length and all hex chars, decode it.
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    const buf = Buffer.from(raw, 'hex');
    if (buf.length < 32) {
      throw new Error(
        `PostgresLedgerBackend: hmacSecret (hex) decodes to ${buf.length} bytes; ` +
          'minimum 32 bytes (256 bits) required.',
      );
    }
    return buf;
  }
  // Try base64: check if the string looks like valid base64 (no non-base64 chars).
  if (/^[A-Za-z0-9+/]+=*$/.test(raw)) {
    const buf = Buffer.from(raw, 'base64');
    // base64 decode never throws, but may produce short output for garbage input.
    if (buf.length >= 32) {
      return buf;
    }
  }
  // Fall back to raw UTF-8 — require at least 32 chars.
  const buf = Buffer.from(raw, 'utf8');
  if (buf.length < 32) {
    throw new Error(
      `PostgresLedgerBackend: hmacSecret (utf8) is only ${buf.length} bytes; ` +
        'minimum 32 bytes (256 bits) required. Generate a strong secret with: ' +
        'openssl rand -hex 32',
    );
  }
  return buf;
}

export interface PostgresLedgerOptions {
  /**
   * Name of the audit ledger table.
   * Must be a valid SQL identifier (letters, digits, underscores; one dot for
   * schema-qualified names is allowed, e.g. `audit.euno_ledger`).
   * Default: `euno_audit_ledger`.
   */
  table?: string;
  /**
   * HMAC-SHA-256 secret for per-row integrity.
   *
   * Each row stores `HMAC-SHA256(hmacSecret, seq:previousHash:recordHash:replicaId)`.
   * A DB administrator who modifies a row without knowing this secret will
   * produce an HMAC mismatch detectable by `verifyRowHmac`.
   *
   * Accepted formats (automatically detected):
   *   - 64-char lowercase hex string: `openssl rand -hex 32`  ← recommended
   *   - Base64-encoded string: `openssl rand -base64 32`
   *   - Raw UTF-8 string (minimum 32 characters)
   *
   * MUST decode to at least 32 bytes (256 bits). When rotating this secret,
   * provision a new table (or use AUDIT_LEDGER_TABLE to point at a new table)
   * so that existing rows with the old HMAC remain verifiable with the old
   * secret. Never UPDATE existing rows — the append-only model is the
   * tamper-evidence guarantee.
   */
  hmacSecret: string;
  /**
   * PostgreSQL advisory lock ID used to serialise writes across replicas.
   * Must be a stable 64-bit integer shared by all writers for this ledger.
   * Default: `0x455534004C454447` (= "EU4LEDG" in ASCII hex).
   */
  advisoryLockId?: bigint;
  /**
   * Optional S3 Object-Lock anchor.
   * When configured, every `anchorIntervalRows` successful appends trigger a
   * Merkle root PUT to S3, creating an independent external witness.
   */
  s3?: {
    client: S3AnchorClient;
    bucket: string;
    /**
     * Key prefix for anchor objects.
     * Resulting key: `{prefix}{replicaId}/{fromSeq}-{toSeq}.json`
     * Default: `audit-anchor/`.
     */
    prefix?: string;
    /**
     * Number of rows between S3 anchors.
     * Default: 1000.
     */
    anchorIntervalRows?: number;
  };
  /**
   * Called when an S3 anchor write fails.  The append itself succeeds —
   * anchoring is best-effort (the ledger is the primary tamper-evidence;
   * S3 is a secondary independent witness).
   */
  onAnchorError?: (err: Error) => void;
}

/** Row shape returned by the INSERT (no RETURNING needed; seq is application-assigned). */
interface LedgerInsertRow extends Record<string, unknown> {
  // placeholder: kept for type-checking consistency; INSERT does not RETURNING
}

/** Row shape returned by the SELECT for chain tip. */
interface LedgerTipRow extends Record<string, unknown> {
  seq: string;
  record_hash: string;
}

/** Row shape returned by getEntries. */
interface LedgerSelectRow extends Record<string, unknown> {
  seq: string;
  previous_hash: string;
  record_hash: string;
  replica_id: string;
  payload: SignedAuditEvidence; // JSONB auto-parsed by pg
  row_hmac: Buffer;
  created_at: Date;
}

/**
 * PostgreSQL-backed implementation of {@link LedgerBackend}.
 *
 * ### Schema
 *
 * ```sql
 * CREATE TABLE euno_audit_ledger (
 *   seq           BIGINT PRIMARY KEY,   -- explicit, application-assigned; NOT IDENTITY
 *   record_id     TEXT NOT NULL UNIQUE,
 *   replica_id    TEXT NOT NULL,
 *   previous_hash TEXT NOT NULL,
 *   record_hash   TEXT NOT NULL,
 *   payload       JSONB NOT NULL,
 *   row_hmac      BYTEA NOT NULL,
 *   created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
 * );
 * CREATE INDEX idx_euno_audit_ledger_created_at ON euno_audit_ledger (created_at);
 * ```
 *
 * ### Why explicit seq (not IDENTITY)
 *
 * The application computes `seq = tip.seq + 1` under the advisory lock and
 * then signs the record with that exact seq value (seq is part of the
 * canonical signed content).  IDENTITY sequences can skip on rollback or
 * connection-abort, which would wedge the chain (the signed seq no longer
 * matches the stored seq).  Using an explicit INSERT of the application-
 * computed seq — guarded by the advisory lock — guarantees the signed value
 * is always the stored value.
 *
 * ### Write serialisation
 *
 * Every append acquires `pg_advisory_xact_lock(advisoryLockId)` inside a
 * transaction. This lock is exclusive and transaction-scoped: it is
 * automatically released when the transaction commits or rolls back. Multiple
 * replicas sharing the same PostgreSQL cluster will therefore queue up on this
 * lock — only one writer is in the critical section at any time.
 *
 * ### Per-row HMAC
 *
 * Each row stores `HMAC-SHA256(hmacSecret, seq||":"||previousHash||":"||recordHash||":"||replicaId)`.
 * Verifying row HMACs offline (via `getEntries` + a HMAC-recomputation script)
 * detects silent DB-level modifications without re-verifying cryptographic
 * signatures.
 *
 * ### S3 Object-Lock anchor
 *
 * When `s3` is configured, every `anchorIntervalRows` successful appends
 * trigger a Merkle root of those rows' `recordHash` values to be PUT to S3
 * with the `Content-Type: application/json` header. The S3 bucket MUST have
 * Object Lock enabled so the object is immutable for its retention period.
 *
 * The anchor payload is a JSON object:
 * ```json
 * {
 *   "schemaVersion": "1.0",
 *   "fromSeq": 1,
 *   "toSeq": 1000,
 *   "merkleRoot": "<hex>",
 *   "replicaId": "<id>",
 *   "ts": "<ISO-8601>"
 * }
 * ```
 */
export class PostgresLedgerBackend implements LedgerBackend {
  readonly name: string;

  private readonly table: string;
  private readonly hmacSecret: Buffer;
  private readonly advisoryLockId: bigint;
  private readonly anchorIntervalRows: number;
  private readonly s3?: Required<PostgresLedgerOptions>['s3'];
  private readonly onAnchorError: (err: Error) => void;

  /**
   * Tracks the seq of the last S3 anchor so we know when to emit the next one.
   * Seeded from the DB tip by `initialize()` so restarts resume at the correct
   * position rather than re-anchoring a potentially huge range.
   */
  private lastAnchoredSeq = 0;

  constructor(
    private readonly pool: PgPool,
    options: PostgresLedgerOptions,
  ) {
    this.name = 'postgres';
    this.table = validateTableName(options.table ?? 'euno_audit_ledger');
    if (!options.hmacSecret || options.hmacSecret.length === 0) {
      throw new Error('PostgresLedgerBackend: hmacSecret is required');
    }
    this.hmacSecret = decodeHmacSecret(options.hmacSecret);
    this.advisoryLockId = options.advisoryLockId ?? BigInt('0x455534004C454447');
    this.anchorIntervalRows = options.s3?.anchorIntervalRows ?? 1000;
    this.s3 = options.s3;
    this.onAnchorError = options.onAnchorError ?? ((err) => {
      // Swallow by default; callers should wire in a logger.
      void err;
    });
  }

  /**
   * Seed `lastAnchoredSeq` from the current ledger tip.
   *
   * Call once at startup before the first `appendEntry`.  This prevents a
   * restarted replica from re-anchoring the entire existing ledger on its
   * first write.  If the DB is unavailable at startup the method throws and
   * the caller (typically `createLedgerSignerFromConfig`) should surface the
   * error as a startup failure.
   *
   * Also note: multiple replicas each call this independently — anchor
   * progress is per-process, not persisted in the DB.  In a multi-replica
   * deployment, all replicas will emit anchors for overlapping ranges after a
   * rolling restart.  This is safe: S3 Object-Lock PUT operations are
   * idempotent and the anchor payload is deterministic for a given seq range.
   */
  async initialize(): Promise<void> {
    const tip = await this.getChainTip();
    if (tip !== null) {
      // Seed anchor progress to the current tip so the first append after
      // restart doesn't re-anchor the entire existing history.
      this.lastAnchoredSeq = tip.seq;
    }
  }

  /**
   * Ensure the ledger table exists.  Call once at startup before the first
   * `appendEntry`.  Idempotent (uses `CREATE TABLE IF NOT EXISTS`).
   */
  async migrate(client?: PgClientConnection): Promise<void> {
    const shouldRelease = !client;
    const conn = client ?? await this.pool.connect();
    // For schema-qualified names like 'audit.euno_ledger' extract just the
    // table-name part for the index identifier — dots are not allowed in
    // unquoted PostgreSQL index names so 'idx_audit.euno_ledger_created_at'
    // would be parsed as schema 'idx_audit', index 'euno_ledger_created_at'
    // and fail with "schema does not exist".
    const tableParts = this.table.split('.');
    const tableNameOnly = tableParts[tableParts.length - 1]!;
    try {
      await conn.query(`
        CREATE TABLE IF NOT EXISTS ${this.table} (
          seq           BIGINT PRIMARY KEY,
          record_id     TEXT NOT NULL UNIQUE,
          replica_id    TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          record_hash   TEXT NOT NULL,
          payload       JSONB NOT NULL,
          row_hmac      BYTEA NOT NULL,
          created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
      await conn.query(`
        CREATE INDEX IF NOT EXISTS idx_${tableNameOnly}_created_at
          ON ${this.table} (created_at)
      `);
    } finally {
      if (shouldRelease) conn.release();
    }
  }

  async appendEntry(
    _evidence: AuditEvidence,
    replicaId: string,
    sign: (previousHash: string, nextSeq: number) => Promise<SignedAuditEvidence>,
  ): Promise<SignedAuditEvidence> {
    const conn = await this.pool.connect();
    try {
      await conn.query('BEGIN');

      // Acquire an exclusive advisory lock scoped to this transaction.
      // Blocks until any other writer in any replica releases its transaction.
      await conn.query(
        'SELECT pg_advisory_xact_lock($1)',
        [this.advisoryLockId.toString()],
      );

      // Read the current chain tip while holding the lock.
      const tipResult = await conn.query<LedgerTipRow>(
        `SELECT seq, record_hash FROM ${this.table} ORDER BY seq DESC LIMIT 1`,
      );
      const tipRow = tipResult.rows[0];
      const previousHash = tipRow ? tipRow.record_hash : GENESIS_HASH;
      const nextSeq = tipRow ? Number(tipRow.seq) + 1 : 1;

      // Invoke the signing callback INSIDE the lock so no other writer can
      // advance the chain tip between reading it and inserting our row.
      const signed = await sign(previousHash, nextSeq);

      // Sanity-check: the signing callback must use the exact chain state we provided.
      if (signed.previousHash !== previousHash) {
        throw new LedgerChainError(
          `LedgerChainError at seq ${nextSeq}: expected previousHash="${previousHash}" ` +
            `but signed record carries "${signed.previousHash}"`,
          previousHash,
          signed.previousHash,
        );
      }
      // Also verify the seq to make the backend contract symmetric with
      // InMemoryLedgerBackend and prevent a row whose signed seq doesn't
      // match the ledger-assigned seq from ever being committed.
      if (signed.seq !== nextSeq) {
        throw new LedgerChainError(
          `LedgerChainError at seq ${nextSeq}: expected seq=${nextSeq} ` +
            `but signed record carries seq=${signed.seq}`,
          String(nextSeq),
          String(signed.seq),
        );
      }

      const recordHash = canonicalSha256(signed);
      const rowHmac = this.computeRowHmac(nextSeq, previousHash, recordHash, replicaId);

      // Insert with the application-assigned seq (not IDENTITY) so the
      // committed seq always matches the signed seq.
      await conn.query<LedgerInsertRow>(
        `INSERT INTO ${this.table}
           (seq, record_id, replica_id, previous_hash, record_hash, payload, row_hmac)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
        [
          nextSeq,
          signed.id,
          replicaId,
          previousHash,
          recordHash,
          JSON.stringify(signed),
          rowHmac,
        ],
      );

      await conn.query('COMMIT');

      // Trigger S3 anchor asynchronously (fire-and-forget with error callback).
      if (this.s3 && nextSeq - this.lastAnchoredSeq >= this.anchorIntervalRows) {
        const fromSeq = this.lastAnchoredSeq + 1;
        const toSeq = nextSeq;
        this.lastAnchoredSeq = toSeq;
        this.triggerS3Anchor(fromSeq, toSeq, replicaId).catch((err) => {
          this.onAnchorError(err instanceof Error ? err : new Error(String(err)));
        });
      }

      return signed;
    } catch (err) {
      try {
        await conn.query('ROLLBACK');
      } catch {
        // Swallow rollback error; the original error is more useful.
      }
      throw err;
    } finally {
      conn.release();
    }
  }

  async getChainTip(): Promise<{ seq: number; tipHash: string } | null> {
    const conn = await this.pool.connect();
    try {
      const result = await conn.query<LedgerTipRow>(
        `SELECT seq, record_hash FROM ${this.table} ORDER BY seq DESC LIMIT 1`,
      );
      const row = result.rows[0];
      if (!row) return null;
      return { seq: Number(row.seq), tipHash: row.record_hash };
    } finally {
      conn.release();
    }
  }

  async getEntries(fromSeq: number, toSeq: number): Promise<LedgerEntry[]> {
    const conn = await this.pool.connect();
    try {
      const result = await conn.query<LedgerSelectRow>(
        `SELECT seq, previous_hash, record_hash, replica_id, payload, row_hmac, created_at
           FROM ${this.table}
          WHERE seq >= $1 AND seq <= $2
          ORDER BY seq ASC`,
        [fromSeq, toSeq],
      );
      return result.rows.map((row) => ({
        seq: Number(row.seq),
        previousHash: row.previous_hash,
        recordHash: row.record_hash,
        replicaId: row.replica_id,
        signedEvidence: row.payload,
        ts: (row.created_at instanceof Date ? row.created_at : new Date(row.created_at as unknown as string)).toISOString(),
        rowHmac: Buffer.isBuffer(row.row_hmac) ? row.row_hmac : Buffer.from(row.row_hmac as unknown as string, 'hex'),
      }));
    } finally {
      conn.release();
    }
  }

  /**
   * Verify the HMAC of a single ledger row.
   *
   * Returns `true` when the stored HMAC matches the recomputed value, `false`
   * otherwise. A `false` return indicates DB-level tampering or an HMAC-secret
   * mismatch.
   *
   * @param entry  A ledger entry as returned by `getEntries`.
   * @param rawHmac The raw HMAC bytes as stored in the `row_hmac` column.
   */
  verifyRowHmac(entry: LedgerEntry, rawHmac: Buffer): boolean {
    const expected = this.computeRowHmac(
      entry.seq,
      entry.previousHash,
      entry.recordHash,
      entry.replicaId,
    );
    // Guard against tampered / truncated rawHmac before timingSafeEqual
    // (which throws on length mismatch rather than returning false).
    if (!Buffer.isBuffer(rawHmac) || rawHmac.length !== expected.length) {
      return false;
    }
    try {
      return crypto.timingSafeEqual(expected, rawHmac);
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // ── private helpers ───────────────────────────────────────────────────────

  private computeRowHmac(
    seq: number,
    previousHash: string,
    recordHash: string,
    replicaId: string,
  ): Buffer {
    return crypto
      .createHmac('sha256', this.hmacSecret)
      .update(`${seq}:${previousHash}:${recordHash}:${replicaId}`, 'utf8')
      .digest();
  }

  private async triggerS3Anchor(
    fromSeq: number,
    toSeq: number,
    replicaId: string,
  ): Promise<void> {
    if (!this.s3) return;

    const entries = await this.getEntries(fromSeq, toSeq);
    if (entries.length === 0) return;

    const leafHashes = entries.map((e) => e.recordHash);
    const merkleRoot = computeMerkleRoot(leafHashes);
    const anchorPayload = JSON.stringify({
      schemaVersion: '1.0',
      fromSeq,
      toSeq,
      merkleRoot,
      replicaId,
      ts: new Date().toISOString(),
    });

    const prefix = this.s3.prefix ?? 'audit-anchor/';
    const key = `${prefix}${replicaId}/${fromSeq}-${toSeq}.json`;

    await this.s3.client.putObject({
      bucket: this.s3.bucket,
      key,
      body: anchorPayload,
      contentType: 'application/json',
    });
  }
}

// ── AzureConfidentialLedgerBackend ────────────────────────────────────────────

/**
 * Minimal client interface for Azure Confidential Ledger (ACL).
 *
 * Implement this using the official `@azure-rest/confidential-ledger` SDK
 * with `@azure/identity` for AAD authentication and inject the result via
 * {@link GatewayDependencies.ledgerAclClient} or directly into
 * {@link createLedgerSignerFromConfig}.
 *
 * Keeping this interface thin ensures `@euno/common` does not take a hard
 * runtime dependency on the Azure SDK — callers choose their own version
 * and authentication strategy.
 *
 * ### Example wiring (using the Azure REST SDK)
 *
 * ```typescript
 * import ConfidentialLedger from '@azure-rest/confidential-ledger';
 * import { DefaultAzureCredential } from '@azure/identity';
 *
 * const sdkClient = ConfidentialLedger(
 *   'https://<name>.confidentialledger.azure.com',
 *   new DefaultAzureCredential(),
 * );
 *
 * const aclClient: AzureConfidentialLedgerClient = {
 *   async appendTransaction(contents) {
 *     const res = await sdkClient.path('/app/transactions').post({ body: { contents } });
 *     if (res.status !== '201') throw new Error(`ACL append failed: ${res.status}`);
 *     return { transactionId: res.body.transactionId };
 *   },
 *   async getLatestCommittedTransaction() {
 *     const res = await sdkClient.path('/app/transactions').get();
 *     if (res.status === '204') return null;
 *     if (res.status !== '200') throw new Error(`ACL get latest failed: ${res.status}`);
 *     return { transactionId: res.body.transactionId, contents: res.body.contents };
 *   },
 *   async getTransaction(transactionId) {
 *     const res = await sdkClient.path('/app/transactions/{transactionId}', transactionId).get();
 *     if (res.status === '404') return null;
 *     if (res.status !== '200') throw new Error(`ACL get tx failed: ${res.status}`);
 *     return { transactionId, contents: res.body.contents };
 *   },
 * };
 * ```
 */
export interface AzureConfidentialLedgerClient {
  /**
   * Append a new entry to the current ledger collection.
   *
   * @param contents  Base64-encoded payload string (the raw bytes of the
   *                  serialised {@link AclEntryPayload}).
   * @returns         The ACL-assigned transaction ID used for later retrieval.
   */
  appendTransaction(contents: string): Promise<{ transactionId: string }>;

  /**
   * Retrieve the latest committed transaction from the current collection.
   *
   * Returns `null` when the collection is empty (no entries yet).
   */
  getLatestCommittedTransaction(): Promise<{
    transactionId: string;
    contents: string;
  } | null>;

  /**
   * Retrieve a specific transaction by its ACL transaction ID.
   *
   * Returns `null` when no such transaction exists (e.g. after a ledger
   * rotation or when the ID is from another collection).
   */
  getTransaction(transactionId: string): Promise<{
    transactionId: string;
    contents: string;
  } | null>;
}

/**
 * Options for {@link AzureConfidentialLedgerBackend}.
 */
export interface AzureConfidentialLedgerOptions {
  /**
   * Called when a non-fatal ACL operation error occurs (e.g. a `getTransaction`
   * call fails during `getEntries`). The backend continues operating but the
   * affected entry is omitted from the result. Default: swallow silently.
   */
  onError?: (err: Error) => void;
}

/**
 * Payload stored inside each ACL transaction's `contents` field.
 * Encoded as base64(JSON) so the ledger stores printable data.
 *
 * @internal
 */
export interface AclEntryPayload {
  schemaVersion: '1.0';
  seq: number;
  previousHash: string;
  recordHash: string;
  replicaId: string;
  signedEvidence: SignedAuditEvidence;
  ts: string;
}

function encodeAclContents(payload: AclEntryPayload): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

function decodeAclContents(contents: string): AclEntryPayload | null {
  try {
    const raw = Buffer.from(contents, 'base64').toString('utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      (parsed as AclEntryPayload).schemaVersion !== '1.0' ||
      typeof (parsed as AclEntryPayload).seq !== 'number' ||
      typeof (parsed as AclEntryPayload).previousHash !== 'string' ||
      typeof (parsed as AclEntryPayload).recordHash !== 'string' ||
      typeof (parsed as AclEntryPayload).replicaId !== 'string' ||
      typeof (parsed as AclEntryPayload).ts !== 'string' ||
      typeof (parsed as AclEntryPayload).signedEvidence !== 'object' ||
      (parsed as AclEntryPayload).signedEvidence === null
    ) {
      return null;
    }
    return parsed as AclEntryPayload;
  } catch {
    return null;
  }
}

/**
 * Azure Confidential Ledger-backed implementation of {@link LedgerBackend}.
 *
 * ### TEE-backed tamper evidence
 *
 * Azure Confidential Ledger runs inside a Trusted Execution Environment (TEE).
 * Entries cannot be deleted, modified, or reordered — even by Microsoft.  This
 * provides a stronger immutability guarantee than `PostgresLedgerBackend` (which
 * relies on per-row HMAC + optional S3 Object-Lock) without requiring a
 * separate secret (HMAC key).  ACL issues verifiable receipts that can be
 * checked against the TEE's public key offline.
 *
 * ### Write serialisation
 *
 * ACL does not expose a distributed lock primitive equivalent to PostgreSQL's
 * advisory lock.  This backend therefore uses an in-process serial queue
 * (identical to {@link InMemoryLedgerBackend}) to prevent concurrent writes
 * from the same process.  For multi-replica deployments each replica writes
 * its own chain segment; ACL still records every entry immutably, and each
 * segment is internally consistent.
 *
 * When a single global chain across all replicas is required, route all writes
 * through a single replica (e.g. a dedicated signing sidecar) or use
 * `PostgresLedgerBackend` which provides cross-replica serialisation via
 * `pg_advisory_xact_lock`.
 *
 * ### Trade-offs vs PostgresLedgerBackend
 *
 * | Property                       | ACL                              | Postgres         |
 * |--------------------------------|----------------------------------|------------------|
 * | Tamper evidence                | TEE (hardware)                   | HMAC + S3 anchor |
 * | Cross-replica chain            | No (per-replica segments)        | Yes (global lock)|
 * | Additional secrets             | None (ACL + AAD identity)        | HMAC key         |
 * | Offline receipt verification   | Yes (TEE receipts)               | Yes (HMAC replay)|
 *
 * ### getEntries
 *
 * `getEntries` uses an in-process `seq → transactionId` index built during
 * normal operation.  Entries appended before the current process started (or
 * before `initialize()` was called) are not in the index and will be absent
 * from the result.  For full offline chain replay, iterate ACL transactions
 * directly using the SDK and call `decodeAclContents` on each entry's
 * `contents` field.
 */
export class AzureConfidentialLedgerBackend implements LedgerBackend {
  readonly name = 'azure-confidential-ledger';

  /** Serial queue — prevents concurrent in-process appends from contending. */
  private appendTail: Promise<unknown> = Promise.resolve();

  /** In-process chain state.  Seeded from ACL by `initialize()`. */
  private tipHash: string = GENESIS_HASH;
  private tipSeq: number = 0;

  /**
   * In-process index: seq → ACL transactionId.
   *
   * Built incrementally as entries are written.  The tip entry is re-seeded
   * from ACL on `initialize()` so reads immediately after a process restart
   * can at least retrieve the tip.  Entries further back in history are only
   * in the index when they were written during the current process lifetime.
   */
  private readonly seqToTxId = new Map<number, string>();

  private readonly onError: (err: Error) => void;

  constructor(
    private readonly client: AzureConfidentialLedgerClient,
    options: AzureConfidentialLedgerOptions = {},
  ) {
    this.onError = options.onError ?? ((err) => {
      // Default: emit to stderr so the error is visible in logs without
      // crashing the process.  Supply `options.onError` to route to your
      // logger of choice.
      console.warn('AzureConfidentialLedgerBackend error:', err.message);
    });
  }

  /**
   * Seed in-process chain state from the latest committed ACL transaction.
   *
   * Call once before the first `appendEntry`.  Throws on any of these
   * conditions so startup fails closed rather than silently producing
   * a corrupt chain:
   *   - The ACL client call fails (connectivity / auth error).
   *   - The latest transaction exists but its `contents` cannot be decoded
   *     or validated as an `AclEntryPayload` — this indicates data corruption
   *     or a write from an incompatible implementation.
   */
  async initialize(): Promise<void> {
    const latest = await this.client.getLatestCommittedTransaction();
    if (!latest) return; // Collection is empty — chain starts from genesis.

    const payload = decodeAclContents(latest.contents);
    if (!payload) {
      throw new Error(
        `AzureConfidentialLedgerBackend.initialize(): latest transaction ` +
          `(id=${latest.transactionId}) has unrecognised or invalid contents. ` +
          `Expected a base64-encoded AclEntryPayload (schemaVersion="1.0"). ` +
          `Refusing to start with tipSeq=0 to prevent overlapping seq values in the ledger.`,
      );
    }
    this.tipHash = payload.recordHash;
    this.tipSeq = payload.seq;
    this.seqToTxId.set(payload.seq, latest.transactionId);
  }

  async appendEntry(
    _evidence: AuditEvidence,
    replicaId: string,
    sign: (previousHash: string, nextSeq: number) => Promise<SignedAuditEvidence>,
  ): Promise<SignedAuditEvidence> {
    return new Promise<SignedAuditEvidence>((resolve, reject) => {
      this.appendTail = this.appendTail
        .then(async () => {
          const previousHash = this.tipHash;
          const nextSeq = this.tipSeq + 1;

          const signed = await sign(previousHash, nextSeq);

          if (signed.previousHash !== previousHash) {
            throw new LedgerChainError(
              `AzureConfidentialLedgerBackend: expected previousHash="${previousHash}" ` +
                `but signed record carries "${signed.previousHash}"`,
              previousHash,
              signed.previousHash,
            );
          }
          if (signed.seq !== nextSeq) {
            throw new LedgerChainError(
              `AzureConfidentialLedgerBackend: expected seq=${nextSeq} ` +
                `but signed record carries seq=${signed.seq}`,
              String(nextSeq),
              String(signed.seq),
            );
          }

          const recordHash = canonicalSha256(signed);
          const payload: AclEntryPayload = {
            schemaVersion: '1.0',
            seq: nextSeq,
            previousHash,
            recordHash,
            replicaId,
            signedEvidence: signed,
            ts: new Date().toISOString(),
          };

          const contents = encodeAclContents(payload);
          const { transactionId } = await this.client.appendTransaction(contents);

          // Advance in-process state only AFTER the ACL write succeeds.
          // A failed write leaves the chain at the previous tip so the next
          // retry will re-sign with the same previousHash.
          this.tipHash = recordHash;
          this.tipSeq = nextSeq;
          this.seqToTxId.set(nextSeq, transactionId);

          return signed;
        })
        .then(resolve, reject)
        .catch(() => {
          // Keep the appendTail promise resolved after any error so future
          // calls can continue to queue.  The error has already been forwarded
          // to the caller via reject() in .then(resolve, reject) above, so
          // it is not lost — this catch only prevents an unhandled rejection
          // on the internal tail promise.
        });
    });
  }

  async getChainTip(): Promise<{ seq: number; tipHash: string } | null> {
    if (this.tipSeq === 0) return null;
    return { seq: this.tipSeq, tipHash: this.tipHash };
  }

  /**
   * Retrieve entries in [fromSeq, toSeq] using the in-process seq→txId index.
   *
   * Only entries that were appended during the current process lifetime (or
   * the single tip entry seeded by `initialize()`) are in the index.  Entries
   * outside the index are silently omitted.  Non-fatal `getTransaction` errors
   * are reported via `options.onError` and the affected entry is skipped.
   */
  async getEntries(fromSeq: number, toSeq: number): Promise<LedgerEntry[]> {
    const entries: LedgerEntry[] = [];
    for (let seq = fromSeq; seq <= toSeq; seq++) {
      const txId = this.seqToTxId.get(seq);
      if (!txId) continue; // Not in index.

      let tx: { transactionId: string; contents: string } | null;
      try {
        tx = await this.client.getTransaction(txId);
      } catch (err) {
        this.onError(err instanceof Error ? err : new Error(String(err)));
        continue;
      }
      if (!tx) continue;

      const payload = decodeAclContents(tx.contents);
      if (!payload || payload.seq !== seq) continue;

      entries.push({
        seq: payload.seq,
        previousHash: payload.previousHash,
        recordHash: payload.recordHash,
        replicaId: payload.replicaId,
        signedEvidence: payload.signedEvidence,
        ts: payload.ts,
      });
    }
    return entries;
  }

  async close(): Promise<void> {
    // ACL HTTP clients have no explicit cleanup.
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Configuration for {@link createLedgerSignerFromConfig}.
 */
export interface LedgerSignerConfig {
  /**
   * Which backend to use.
   *   - `'none'`      — no ledger backend; falls back to a pure in-process chain.
   *                     **Does not close the tamper-rewrite gap** — use only in
   *                     development.
   *   - `'in-memory'` — `InMemoryLedgerBackend` for tests.
   *   - `'postgres'`  — `PostgresLedgerBackend` for production (cross-replica
   *                     chain serialisation via `pg_advisory_xact_lock` + HMAC).
   *   - `'acl'`       — `AzureConfidentialLedgerBackend` for production on
   *                     Azure (TEE-backed immutability; single-process chain
   *                     serialisation only — no cross-replica locking).
   */
  backend: 'none' | 'in-memory' | 'postgres' | 'acl';

  /** Crypto signing primitive (shared with `AuditEvidenceSigner`). */
  cryptoSigner: CryptoSigner;

  /** Replica / pod identifier stamped on every ledger row. */
  replicaId: string;

  /**
   * PostgreSQL pool. Required when `backend === 'postgres'`.
   * The pool should be shared with other components (kill switch, revocation
   * store) rather than creating a new pool per component.
   */
  pgPool?: PgPool;

  /** PostgreSQL ledger backend options. Required when `backend === 'postgres'`. */
  pgOptions?: PostgresLedgerOptions;

  /** Optional S3 anchor client for the PostgreSQL backend. */
  s3?: PostgresLedgerOptions['s3'];

  /**
   * When `true`, run `PostgresLedgerBackend.migrate()` at startup to ensure
   * the table exists. Default `false` (rely on external schema management).
   */
  runMigrations?: boolean;

  /**
   * Azure Confidential Ledger client. Required when `backend === 'acl'`.
   *
   * Build this from `@azure-rest/confidential-ledger` + `@azure/identity` in
   * your entrypoint and inject it here (or via
   * `GatewayDependencies.ledgerAclClient` for the standard bootstrap).
   */
  aclClient?: AzureConfidentialLedgerClient;

  /** Options for the ACL backend. Used when `backend === 'acl'`. */
  aclOptions?: AzureConfidentialLedgerOptions;
}

/**
 * Factory that creates a {@link LedgerAuditEvidenceSigner} from a
 * {@link LedgerSignerConfig}.
 *
 * Returns `null` when `config.backend === 'none'` — the caller falls back to
 * `AuditEvidenceSigner`.
 */
export async function createLedgerSignerFromConfig(
  config: LedgerSignerConfig,
): Promise<LedgerAuditEvidenceSigner | null> {
  if (config.backend === 'none') {
    return null;
  }

  let backend: LedgerBackend;

  if (config.backend === 'in-memory') {
    backend = new InMemoryLedgerBackend();
  } else if (config.backend === 'postgres') {
    if (!config.pgPool) {
      throw new Error('createLedgerSignerFromConfig: pgPool is required for postgres backend');
    }
    if (!config.pgOptions) {
      throw new Error('createLedgerSignerFromConfig: pgOptions is required for postgres backend');
    }
    const pgBackend = new PostgresLedgerBackend(config.pgPool, {
      ...config.pgOptions,
      s3: config.s3 ?? config.pgOptions.s3,
    });
    if (config.runMigrations) {
      await pgBackend.migrate();
    }
    backend = pgBackend;
  } else if (config.backend === 'acl') {
    if (!config.aclClient) {
      throw new Error('createLedgerSignerFromConfig: aclClient is required for acl backend');
    }
    backend = new AzureConfidentialLedgerBackend(config.aclClient, config.aclOptions);
  } else {
    throw new Error(`createLedgerSignerFromConfig: unknown backend "${config.backend}"`);
  }

  const signer = new LedgerAuditEvidenceSigner(config.cryptoSigner, backend, config.replicaId);
  // initialize() delegates to backend.initialize() if implemented, seeding
  // chain state (Postgres lastAnchoredSeq, ACL tip hash) before the first
  // signing call.
  await signer.initialize();
  return signer;
}
