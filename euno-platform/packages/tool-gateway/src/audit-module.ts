/**
 * Audit module — evidence signer + ledger backend + audit pipeline.
 *
 * Encapsulates construction of:
 *   • Evidence signer (software or ledger-wrapped: postgres, per-replica-postgres,
 *     in-memory, Azure Confidential Ledger)
 *   • Async audit pipeline (R-9) with its Prometheus counters
 *
 * `buildAclClientFromEndpoint` is kept private to this module —
 * it was previously a file-scoped function in bootstrap.ts.
 *
 * All metric callbacks and the `metricsRegistry` MUST be fully
 * constructed when calling this function — the late-binding pattern
 * from the pre-R-3 bootstrap has been eliminated.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  AuditAnchor,
  AuditBatchSigner,
  AuditPipeline,
  AuditQueryStore,
  AzureConfidentialLedgerBackend,
  AzureConfidentialLedgerClient,
  BackpressurePolicy,
  Counter,
  createAuditLogger,
  createAuditPipeline,
  createKmsEvidenceSignerFromEnv,
  createLogger,
  createOcsfWinstonTransport,
  createSoftwareEvidenceSignerFromEnv,
  CrossChainAnchor,
  CrossChainAnchorOptions,
  EvidenceSigner,
  GatewayConfig,
  Gauge,
  InMemoryLedgerBackend,
  LedgerAuditEvidenceSigner,
  LedgerBackend,
  LedgerChainError,
  OcsfAuditTransport,
  PerReplicaPostgresLedgerBackend,
  PostgresAuditQueryStore,
  PostgresLedgerBackend,
  Registry,
  ServiceConfig,
  signedEvidenceToOcsf,
  SignedAuditEvidence,
  SignedBatchCommitment,
  SignedCrossChainCommitment,
} from '@euno/common';
import { CrossChainCommitmentStore } from './routes/chain-proof';

type Logger = ReturnType<typeof createLogger>;

/**
 * Minimal type stub for the `@azure-rest/confidential-ledger` SDK client.
 * @internal
 */
type AclSdkPath = {
  post(opts: { body: { contents: string } }): Promise<{ status: string; body: { transactionId: string } }>;
  get(): Promise<{ status: string; body: { transactionId: string; contents: string } }>;
};
type AclSdkClient = { path(route: string, ...params: string[]): AclSdkPath };
type AclSdkFactory = (endpoint: string, credential: unknown) => AclSdkClient;

/**
 * Build an {@link AzureConfidentialLedgerClient} by dynamically requiring
 * `@azure-rest/confidential-ledger` and `@azure/identity`.
 *
 * Both packages must be available at runtime (add to the deployment image).
 * Authentication uses `DefaultAzureCredential` — workload identity, managed
 * identity, or `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`
 * environment variables are all supported automatically.
 */
function buildAclClientFromEndpoint(endpoint: string): AzureConfidentialLedgerClient {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const ConfidentialLedger = ((require('@azure-rest/confidential-ledger') as { default: unknown }).default as AclSdkFactory);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { DefaultAzureCredential } = require('@azure/identity') as { DefaultAzureCredential: new () => unknown };
  const sdk = ConfidentialLedger(endpoint, new DefaultAzureCredential());
  return {
    async appendTransaction(contents: string) {
      const res = await sdk.path('/app/transactions').post({ body: { contents } });
      if (res.status !== '201') {
        throw new Error(`Azure Confidential Ledger append failed (HTTP ${res.status})`);
      }
      return { transactionId: res.body.transactionId };
    },
    async getLatestCommittedTransaction() {
      const res = await sdk.path('/app/transactions').get();
      if (res.status === '204') return null;
      if (res.status !== '200') {
        throw new Error(`Azure Confidential Ledger get-latest failed (HTTP ${res.status})`);
      }
      return { transactionId: res.body.transactionId, contents: res.body.contents };
    },
    async getTransaction(transactionId: string) {
      const res = await sdk.path('/app/transactions/{transactionId}', transactionId).get();
      if (res.status === '404') return null;
      if (res.status !== '200') {
        throw new Error(`Azure Confidential Ledger get-transaction failed (HTTP ${res.status})`);
      }
      return { transactionId, contents: res.body.contents };
    },
  };
}

export interface AuditModuleInput {
  validated: GatewayConfig;
  env: NodeJS.ProcessEnv;
  logger: Logger;
  config: ServiceConfig;
  metricsRegistry: Registry;
  replicaId: string;
  /** Optional injected ACL client (custom credential or test mock). */
  ledgerAclClient?: AzureConfidentialLedgerClient;
  /** Optional injected CrossChainAnchor for per-replica-postgres mode. */
  crossChainAnchorOverride?: CrossChainAnchor;
  /** F-6 OCSF transport; used by the pipeline's `onSigned` sink and the audit logger. */
  ocsfTransport?: OcsfAuditTransport;
}

export interface AuditModuleResult {
  /** The active evidence signer; undefined when `ENABLE_CRYPTOGRAPHIC_AUDIT=false`. */
  evidenceSigner?: EvidenceSigner;
  /**
   * Batch signer (same as `evidenceSigner` in software mode; the raw
   * software signer when a ledger backend wraps it). `undefined` when
   * signing is disabled.
   */
  auditBatchSigner?: AuditBatchSigner;
  /** Async audit pipeline (R-9); undefined when disabled or signing is off. */
  auditPipeline?: AuditPipeline;
  /** Drain timeout in ms for graceful shutdown. Populated when `auditPipeline` is set. */
  auditPipelineDrainTimeoutMs: number;
  /**
   * PostgreSQL pool owned by the ledger backend. Present when
   * `AUDIT_LEDGER_BACKEND=postgres` or `AUDIT_LEDGER_BACKEND=per-replica-postgres`.
   * Caller MUST call `ledgerPgPool.end()` on graceful shutdown.
   */
  ledgerPgPool?: import('@euno/common').PgPool;
  /**
   * Cross-chain anchor. Present when injected via `crossChainAnchorOverride`
   * or auto-created when `ENABLE_CROSS_CHAIN_ANCHOR=true` with
   * `AUDIT_LEDGER_BACKEND=per-replica-postgres`.
   * Caller MUST call `crossChainAnchor.stop()` on graceful shutdown.
   */
  crossChainAnchor?: CrossChainAnchor;
  /**
   * In-memory ring buffer of `SignedCrossChainCommitment` records emitted by
   * the cross-chain anchor.  Present when `crossChainAnchor` is set.
   * Served by the `GET /api/v1/audit/chain-proof` endpoint.
   */
  crossChainCommitmentStore?: CrossChainCommitmentStore;
  /**
   * The ledger backend used by the evidence signer. Present when a ledger
   * backend is configured (`AUDIT_LEDGER_BACKEND` is set and not `'none'`).
   *
   * Exposed so the audit query route can call `queryEntries()` to serve
   * the Task-7 `GET /api/v1/audit/records` endpoint without an additional
   * DB connection pool.
   */
  auditLedgerBackend?: import('@euno/common').LedgerBackend;
  /**
   * Query-only projection of the audit ledger (Task 9).
   *
   * For the `postgres` and `per-replica-postgres` backends this is a
   * {@link PostgresAuditQueryStore} backed by the same pool as the write
   * backend — no additional DB connection pool is needed.  For the
   * `in-memory` backend this is the same {@link InMemoryLedgerBackend}
   * instance (it satisfies {@link AuditQueryStore} structurally).
   *
   * The audit query route SHOULD prefer this over {@link auditLedgerBackend}
   * because the query store carries no chain state, advisory locks, or HMAC
   * material — it is a lighter-weight read path.
   */
  auditQueryStore?: AuditQueryStore;
}

/**
 * Build the evidence signer and (optionally) the async audit pipeline.
 *
 * Registers pipeline-specific Prometheus counters and gauges on the
 * supplied `metricsRegistry`.
 */
export async function buildAuditModule(input: AuditModuleInput): Promise<AuditModuleResult> {
  const {
    validated,
    env,
    logger,
    config,
    metricsRegistry,
    replicaId,
    ledgerAclClient: injectedAclClient,
    crossChainAnchorOverride,
    ocsfTransport,
  } = input;

  const signedDecisions = validated.EVIDENCE_SIGNED_DECISIONS as
    | Array<'allow' | 'deny'>
    | undefined;
  const willSignSomething =
    signedDecisions !== undefined
      ? signedDecisions.length > 0
      : !!config.enableCryptographicAudit;

  if (!willSignSomething) {
    return { auditPipelineDrainTimeoutMs: validated.AUDIT_PIPELINE_DRAIN_TIMEOUT_MS };
  }

  // Type-narrow the dynamic config fields once so we avoid repeated `as { ... }` casts below.
  type DynamicConfig = {
    AUDIT_SIGNING_KMS_PROVIDER?: string;
    AUDIT_LEDGER_BACKEND?: 'none' | 'postgres' | 'in-memory' | 'acl' | 'per-replica-postgres';
    AUDIT_LEDGER_PG_URL?: string;
    AUDIT_LEDGER_HMAC_SECRET?: string;
    AUDIT_LEDGER_TABLE?: string;
    AUDIT_LEDGER_RUN_MIGRATIONS?: boolean;
    AUDIT_LEDGER_S3_BUCKET?: string;
    AUDIT_LEDGER_ANCHOR_INTERVAL?: number;
    AUDIT_LEDGER_ACL_ENDPOINT?: string;
    AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS?: number;
    AUDIT_ANCHOR_URL?: string;
    ENABLE_CROSS_CHAIN_ANCHOR?: boolean;
  };
  const dynConfig = validated as typeof validated & DynamicConfig;
  let evidenceSigner: EvidenceSigner | undefined;
  let ledgerPgPool: import('@euno/common').PgPool | undefined;
  let crossChainAnchor: CrossChainAnchor | undefined;
  let crossChainCommitmentStore: CrossChainCommitmentStore | undefined;
  let auditBatchSigner: AuditBatchSigner | undefined;
  let auditLedgerBackend: LedgerBackend | undefined;
  let auditQueryStore: AuditQueryStore | undefined;

  try {
    // Select the evidence signer: KMS-backed (AUDIT_SIGNING_KMS_PROVIDER) takes
    // precedence over the software signer (EVIDENCE_SIGNING_KEY_PEM / _FILE).
    // Both produce byte-identical canonical evidence records and chain semantics
    // (same AuditEvidenceSigner wrapper); only the signature bytes, keyId, and
    // algorithm field differ — which is the explicit design of Task 5 (Stage 3).
    const kmsProvider = dynConfig.AUDIT_SIGNING_KMS_PROVIDER;
    const activeSigner = kmsProvider
      ? (() => {
          const kmsSigner = createKmsEvidenceSignerFromEnv(env);
          if (!kmsSigner) {
            throw new Error(
              `AUDIT_SIGNING_KMS_PROVIDER='${kmsProvider}' is set but the required ` +
                'KMS configuration variables are missing or invalid. ' +
                'Provide the appropriate AUDIT_SIGNING_<PROVIDER>_* variables.',
            );
          }
          logger.info('Cryptographic audit: using KMS-backed evidence signer', {
            provider: kmsProvider,
          });
          return kmsSigner;
        })()
      : (() => {
          const sw = createSoftwareEvidenceSignerFromEnv(env);
          if (!sw) {
            throw new Error(
              'No evidence signer is configured. Provide ' +
                'EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded ' +
                'private key) and optionally EVIDENCE_SIGNING_ALGORITHM / ' +
                'EVIDENCE_SIGNING_KEY_ID, or set AUDIT_SIGNING_KMS_PROVIDER to use ' +
                'a cloud KMS (azure-keyvault, aws-kms, gcp-cloudkms). ' +
                'Refusing to start with cryptographic audit enabled but no signer attached.',
            );
          }
          return sw;
        })();

    const ledgerBackendName = dynConfig.AUDIT_LEDGER_BACKEND;

    if (ledgerBackendName && ledgerBackendName !== 'none') {
      const pgUrl = dynConfig.AUDIT_LEDGER_PG_URL;
      const hmacSecret = dynConfig.AUDIT_LEDGER_HMAC_SECRET;
      const table = dynConfig.AUDIT_LEDGER_TABLE;
      const runMigrations = dynConfig.AUDIT_LEDGER_RUN_MIGRATIONS ?? false;
      const s3Bucket = dynConfig.AUDIT_LEDGER_S3_BUCKET;
      const anchorInterval = dynConfig.AUDIT_LEDGER_ANCHOR_INTERVAL ?? 1000;
      const aclEndpoint = dynConfig.AUDIT_LEDGER_ACL_ENDPOINT;

      if (ledgerBackendName === 'postgres') {
        if (!pgUrl) throw new Error('AUDIT_LEDGER_BACKEND=postgres requires AUDIT_LEDGER_PG_URL to be set.');
        if (!hmacSecret) throw new Error('AUDIT_LEDGER_BACKEND=postgres requires AUDIT_LEDGER_HMAC_SECRET to be set.');
        if (s3Bucket) {
          throw new Error(
            'AUDIT_LEDGER_S3_BUCKET is set but no S3 client is wired in the standard ' +
              'bootstrap. Provide an S3AnchorClient by constructing PostgresLedgerBackend ' +
              'directly (with the s3.client option) in a custom entrypoint, or unset ' +
              'AUDIT_LEDGER_S3_BUCKET to rely on HMAC + in-DB chain integrity only.',
          );
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-var-requires
        const { Pool } = require('pg') as { Pool: new (cfg: { connectionString: string }) => import('@euno/common').PgPool };
        const pgPool = new Pool({ connectionString: pgUrl });
        ledgerPgPool = pgPool;

        const pgBackend = new PostgresLedgerBackend(pgPool, {
          table,
          hmacSecret,
          onAnchorError: (err: Error) => logger.error('Ledger S3 anchor failed', { error: err.message }),
        });

        if (runMigrations) {
          if (validated.NODE_ENV === 'production') {
            logger.warn(
              'AUDIT_LEDGER_RUN_MIGRATIONS=true in production: the gateway service account ' +
                'is performing DDL on the audit ledger table. Production deployments should ' +
                'instead run migrations from a sidecar / Job under a separate database role ' +
                'with DDL privileges and grant the gateway role only DML on the table. See ' +
                'docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md §1.6.',
            );
          }
          await pgBackend.migrate();
          logger.info('Audit ledger migrations completed', { table: table ?? 'euno_audit_ledger' });
        }

        const cryptoSigner = activeSigner.getCryptoSigner();
        const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, pgBackend, replicaId);
        await ledgerSigner.initialize();
        evidenceSigner = ledgerSigner;
        auditBatchSigner = activeSigner;
        auditLedgerBackend = pgBackend;
        // Task 9: Dedicated query-only store backed by the same pool.
        // The query route only needs SELECT; no chain state or HMAC material required.
        auditQueryStore = new PostgresAuditQueryStore(pgPool, { table });

        logger.info('Audit ledger backend: postgres', {
          table: table ?? 'euno_audit_ledger',
          anchorInterval,
        });
      } else if (ledgerBackendName === 'acl') {
        let aclClient: AzureConfidentialLedgerClient;
        if (injectedAclClient) {
          aclClient = injectedAclClient;
          logger.info('Audit ledger backend: acl (using injected client)');
        } else if (aclEndpoint) {
          aclClient = buildAclClientFromEndpoint(aclEndpoint);
          logger.info('Audit ledger backend: acl', { endpoint: aclEndpoint });
        } else {
          throw new Error(
            'AUDIT_LEDGER_BACKEND=acl requires either injectDeps.ledgerAclClient ' +
              '(injected AzureConfidentialLedgerClient) or AUDIT_LEDGER_ACL_ENDPOINT to be set. ' +
              'For managed identity / workload identity deployments set AUDIT_LEDGER_ACL_ENDPOINT; ' +
              'the bootstrap will use DefaultAzureCredential. For custom credential scenarios ' +
              'provide ledgerAclClient via the second argument to initializeServices().',
          );
        }

        const aclBackend = new AzureConfidentialLedgerBackend(aclClient, {
          onError: (err: Error) => logger.error('Audit ledger ACL error', { error: err.message }),
        });
        const cryptoSigner = activeSigner.getCryptoSigner();
        const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, aclBackend, replicaId);
        await ledgerSigner.initialize();
        evidenceSigner = ledgerSigner;
        auditBatchSigner = activeSigner;
        auditLedgerBackend = aclBackend;
      } else if (ledgerBackendName === 'in-memory') {
        const inMemBackend = new InMemoryLedgerBackend();
        const cryptoSigner = activeSigner.getCryptoSigner();
        const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, inMemBackend, replicaId);
        await ledgerSigner.initialize();
        evidenceSigner = ledgerSigner;
        auditBatchSigner = activeSigner;
        auditLedgerBackend = inMemBackend;
        // Task 9: InMemoryLedgerBackend satisfies AuditQueryStore structurally.
        auditQueryStore = inMemBackend;
        logger.info('Audit ledger backend: in-memory (development only — not tamper-resistant)');
      } else if (ledgerBackendName === 'per-replica-postgres') {
        if (!pgUrl) throw new Error('AUDIT_LEDGER_BACKEND=per-replica-postgres requires AUDIT_LEDGER_PG_URL to be set.');
        if (!hmacSecret) throw new Error('AUDIT_LEDGER_BACKEND=per-replica-postgres requires AUDIT_LEDGER_HMAC_SECRET to be set.');

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-var-requires
        const { Pool } = require('pg') as { Pool: new (cfg: { connectionString: string }) => import('@euno/common').PgPool };
        const pgPool = new Pool({ connectionString: pgUrl });
        ledgerPgPool = pgPool;

        const perReplicaBackend = new PerReplicaPostgresLedgerBackend(pgPool, replicaId, {
          table,
          hmacSecret,
          onAnchorError: (err: Error) => logger.error('Per-replica ledger S3 anchor failed', { error: err.message }),
        });

        if (runMigrations) {
          if (validated.NODE_ENV === 'production') {
            logger.warn(
              'AUDIT_LEDGER_RUN_MIGRATIONS=true in production: the gateway service account ' +
                'is performing DDL on the audit ledger table. Production deployments should ' +
                'run migrations from a separate database role. See ' +
                'docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md §1.6.',
            );
          }
          await perReplicaBackend.migrate();
          logger.info('Per-replica audit ledger migrations completed', {
            table: table ?? 'euno_audit_ledger_v2',
          });
        }

        const cryptoSigner = activeSigner.getCryptoSigner();
        const ledgerSigner = new LedgerAuditEvidenceSigner(cryptoSigner, perReplicaBackend, replicaId);
        await ledgerSigner.initialize();
        evidenceSigner = ledgerSigner;
        auditBatchSigner = activeSigner;
        auditLedgerBackend = perReplicaBackend;
        // Task 9: Dedicated query-only store backed by the same pool.
        // The per-replica table has the same column layout as the standard table.
        auditQueryStore = new PostgresAuditQueryStore(pgPool, {
          table: table ?? 'euno_audit_ledger_v2',
        });

        if (s3Bucket) {
          logger.warn(
            'AUDIT_LEDGER_S3_BUCKET is set with per-replica-postgres but no S3 client is ' +
              'wired in the standard bootstrap. Cross-chain commitments will not be anchored ' +
              'to S3. Construct PerReplicaPostgresLedgerBackend with an S3AnchorClient in a ' +
              'custom entrypoint to enable S3 anchoring.',
          );
        }

        const crossChainIntervalMs = dynConfig.AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS ?? 60000;
        const enableCrossChain = dynConfig.ENABLE_CROSS_CHAIN_ANCHOR ?? false;

        if (crossChainAnchorOverride) {
          // Externally-injected anchor takes precedence over auto-start.
          // The caller is responsible for calling start() before passing it in
          // and for wiring any onCommitment callbacks.
          crossChainAnchor = crossChainAnchorOverride;
        } else if (enableCrossChain) {
          // Task 5 (Stage 5): auto-start when ENABLE_CROSS_CHAIN_ANCHOR=true.
          // Re-use the same cryptoSigner as the per-record evidence signer so
          // operators only need one key pair for both individual records and
          // cross-chain commitments.

          // Create the in-memory commitment store before constructing the anchor
          // so we can pass onCommitment as a constructor option (clean, no
          // post-construction monkey-patching of private fields).
          crossChainCommitmentStore = new CrossChainCommitmentStore();
          const store = crossChainCommitmentStore;

          // Track the last-commitment timestamp for the anchor lag gauge.
          // Declared here so the gauge's collect() closure can read it.
          let lastCommitmentTs = 0;

          const anchorOpts: CrossChainAnchorOptions = {
            intervalMs: crossChainIntervalMs,
            coordinatorId: replicaId,
            cryptoSigner: activeSigner.getCryptoSigner(),
            onError: (err: Error) =>
              logger.error('CrossChainAnchor error', { error: err.message }),
            onCommitment: (c: SignedCrossChainCommitment) => {
              store.add(c);
              lastCommitmentTs = Date.now();
            },
          };
          crossChainAnchor = new CrossChainAnchor(perReplicaBackend, anchorOpts);
          crossChainAnchor.start();
          logger.info('CrossChainAnchor auto-started (ENABLE_CROSS_CHAIN_ANCHOR=true)', {
            intervalMs: crossChainIntervalMs,
            coordinatorId: replicaId,
          });

          // Anchor lag gauge — updated lazily via collect() so no timer is needed.
          new Gauge({
            name: 'euno_cross_chain_anchor_lag_seconds',
            help:
              'Seconds elapsed since the last successful CrossChainAnchor commitment. ' +
              'Alert when this value exceeds 2 × AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS / 1000. ' +
              'A sustained high value indicates the Postgres replica-tips query is failing. ' +
              'Zero until the first commitment is emitted.',
            registers: [metricsRegistry],
            collect() {
              this.set(lastCommitmentTs === 0 ? 0 : (Date.now() - lastCommitmentTs) / 1000);
            },
          });
        }

        logger.info('Audit ledger backend: per-replica-postgres', {
          table: table ?? 'euno_audit_ledger_v2',
          replicaId,
          crossChainEnabled: crossChainAnchor !== undefined,
          crossChainAutoStarted: enableCrossChain && !crossChainAnchorOverride,
          crossChainIntervalMs,
        });
      } else {
        throw new Error(`Unknown AUDIT_LEDGER_BACKEND value: "${ledgerBackendName}"`);
      }
    } else {
      // No ledger backend — use the software signer with in-process chain state.
      evidenceSigner = activeSigner;
      auditBatchSigner = activeSigner;
      if (ledgerBackendName === 'none' || !ledgerBackendName) {
        logger.warn(
          'Cryptographic audit is enabled but AUDIT_LEDGER_BACKEND is not set. ' +
            'The hash chain lives only in process memory and a compromised replica ' +
            'can rewrite history. Set AUDIT_LEDGER_BACKEND=postgres for production.',
        );
      }
    }
  } catch (err) {
    if (err instanceof LedgerChainError) throw err;
    throw new Error(
      'Evidence signing is enabled (ENABLE_CRYPTOGRAPHIC_AUDIT=true with ' +
        'EVIDENCE_SIGNED_DECISIONS unset, or EVIDENCE_SIGNED_DECISIONS ' +
        'non-empty) but the configured evidence signer could not be ' +
        'initialised: ' +
        (err instanceof Error ? err.message : String(err)),
    );
  }

  if (!evidenceSigner) {
    throw new Error(
      'Evidence signing is enabled but no evidence signer is configured. Provide ' +
        'EVIDENCE_SIGNING_KEY_PEM or EVIDENCE_SIGNING_KEY_FILE (PEM-encoded private key), ' +
        'or set AUDIT_SIGNING_KMS_PROVIDER to use a cloud KMS backend (azure-keyvault, aws-kms, gcp-cloudkms).',
    );
  }

  if (signedDecisions !== undefined) {
    logger.info('Cryptographic audit enabled with per-decision signing', { signedDecisions });
  } else {
    const signerType = dynConfig.AUDIT_SIGNING_KMS_PROVIDER
      ? `KMS (${dynConfig.AUDIT_SIGNING_KMS_PROVIDER})`
      : 'software';
    logger.info(`Cryptographic audit enabled with ${signerType} evidence signer`);
  }

  // ── Async audit pipeline (R-9) ────────────────────────────────────────────

  let auditPipeline: AuditPipeline | undefined;

  if (validated.AUDIT_PIPELINE_ENABLED) {
    const ocsfProduct = { name: 'euno-tool-gateway', vendor: 'Euno' };

    const droppedCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_dropped_total',
      help: 'Audit-evidence records dropped by the async pipeline before they could be signed. ' +
        'Labelled by reason: queue_full (buffer full, waiter cap reached, or pipeline stopped) ' +
        'or aged_out (record exceeded AUDIT_PIPELINE_MAX_AGE_MS while waiting). A non-zero rate ' +
        'is the operator\'s signal to raise AUDIT_PIPELINE_MAX_SIZE / AUDIT_PIPELINE_WORKERS or ' +
        'to investigate signer latency.',
      labelNames: ['reason'],
      registers: [metricsRegistry],
    });
    droppedCounter.inc({ reason: 'queue_full' }, 0);
    droppedCounter.inc({ reason: 'aged_out' }, 0);

    const signedCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_signed_total',
      help: 'Audit-evidence records successfully signed by the async pipeline.',
      registers: [metricsRegistry],
    });
    signedCounter.inc(0);

    const signErrorsCounter = new Counter({
      name: 'euno_gateway_audit_pipeline_sign_errors_total',
      help: 'Audit-evidence records the async pipeline failed to sign (signer rejection). ' +
        'A persistent non-zero rate indicates a broken signer key or KMS outage.',
      registers: [metricsRegistry],
    });
    signErrorsCounter.inc(0);

    const batchEmittedCounter = new Counter({
      name: 'euno_gateway_audit_batch_emitted_total',
      help: 'Merkle batch commitments emitted by the async pipeline (signed or unsigned).',
      registers: [metricsRegistry],
    });
    batchEmittedCounter.inc(0);

    const batchErrorsCounter = new Counter({
      name: 'euno_gateway_audit_batch_errors_total',
      help: 'Errors producing or anchoring Merkle batch commitments.',
      registers: [metricsRegistry],
    });
    batchErrorsCounter.inc(0);

    // Pipeline queue depth gauge — accesses `auditPipeline` lazily.
    let createdPipeline: AuditPipeline | undefined;
    new Gauge({
      name: 'euno_gateway_audit_pipeline_queue_depth',
      help: 'Current number of unsigned audit-evidence records buffered in the async pipeline ring.',
      registers: [metricsRegistry],
      collect() {
        this.set(createdPipeline ? createdPipeline.queueDepth() : 0);
      },
    });

    const pipelineAuditLogger = createAuditLogger('tool-gateway', {
      region: validated.GATEWAY_REGION,
    });
    if (ocsfTransport) {
      pipelineAuditLogger.add(createOcsfWinstonTransport(ocsfTransport, ocsfProduct));
    }

    const batchAuditLogger = createAuditLogger('tool-gateway', {
      region: validated.GATEWAY_REGION,
    });

    const backpressure: BackpressurePolicy =
      (validated.AUDIT_PIPELINE_BACKPRESSURE as BackpressurePolicy | undefined) ??
      'drop_oldest_with_metric';

    const anchors: AuditAnchor[] = [];
    const anchorUrl = dynConfig.AUDIT_ANCHOR_URL;
    const AUDIT_ANCHOR_TIMEOUT_MS = 30_000;
    if (anchorUrl) {
      anchors.push({
        name: 'http',
        async anchorBatch(commitment: SignedBatchCommitment): Promise<void> {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), AUDIT_ANCHOR_TIMEOUT_MS);
          let response: Response;
          try {
            response = await fetch(anchorUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(commitment),
              signal: controller.signal,
            });
          } catch (err) {
            logger.error('Audit batch HTTP anchor failed', {
              error: err instanceof Error ? err.message : String(err),
              anchorUrl,
              timedOut: controller.signal.aborted,
            });
            throw err;
          } finally {
            clearTimeout(timer);
          }
          if (!response.ok) {
            logger.warn('Audit batch HTTP anchor returned non-OK status', {
              status: response.status,
              anchorUrl,
              batchId: commitment.batchId,
            });
            throw new Error(`HTTP anchor returned ${response.status}`);
          }
        },
      });
      logger.info('Audit batch HTTP anchor configured', { anchorUrl });
    }

    createdPipeline = createAuditPipeline({
      signer: evidenceSigner,
      maxSize: validated.AUDIT_PIPELINE_MAX_SIZE,
      workers: validated.AUDIT_PIPELINE_WORKERS,
      maxBatchSize: validated.AUDIT_PIPELINE_MAX_BATCH,
      maxAgeMs: validated.AUDIT_PIPELINE_MAX_AGE_MS,
      backpressure,
      maxWaiters: validated.AUDIT_PIPELINE_MAX_WAITERS,
      replicaId,
      batchSigner: auditBatchSigner,
      anchors,
      onDropped: (count: number, reason: string) => droppedCounter.inc({ reason }, count),
      onSigned: (signed: SignedAuditEvidence) => {
        signedCounter.inc();
        try {
          pipelineAuditLogger.info('Cryptographic evidence generated', {
            evidenceId: signed.id,
            sessionId: signed.sessionId,
            decision: signed.decision,
            signature: signed.signature.substring(0, 20) + '...',
            seq: signed.seq,
            previousHash: signed.previousHash.substring(0, 16) + '...',
          });
        } catch {
          // Audit-log emission is best-effort.
        }
        if (ocsfTransport) {
          void ocsfTransport.send(signedEvidenceToOcsf(signed, ocsfProduct));
        }
      },
      onSignError: (err: unknown) => {
        signErrorsCounter.inc();
        logger.error('Audit pipeline failed to sign evidence', {
          error: err instanceof Error ? err.message : String(err),
        });
      },
      onBatch: (commitment: SignedBatchCommitment) => {
        batchEmittedCounter.inc();
        try {
          batchAuditLogger.info('Audit batch commitment', {
            batchId: commitment.batchId,
            replicaId: commitment.replicaId,
            batchSeq: commitment.batchSeq,
            merkleRoot: commitment.merkleRoot,
            recordCount: commitment.recordCount,
            firstSeq: commitment.firstSeq,
            lastSeq: commitment.lastSeq,
            previousBatchHash: commitment.previousBatchHash.substring(0, 16) + '...',
          });
        } catch {
          // Audit-log emission is best-effort.
        }
      },
      onBatchError: (err: unknown) => {
        batchErrorsCounter.inc();
        logger.error('Audit batch commitment failed', {
          error: err instanceof Error ? err.message : String(err),
        });
      },
    });
    auditPipeline = createdPipeline;

    logger.info('Async audit pipeline enabled (R-9)', {
      maxSize: validated.AUDIT_PIPELINE_MAX_SIZE,
      workers: validated.AUDIT_PIPELINE_WORKERS,
      maxBatchSize: validated.AUDIT_PIPELINE_MAX_BATCH,
      maxAgeMs: validated.AUDIT_PIPELINE_MAX_AGE_MS,
      backpressure,
      maxWaiters: validated.AUDIT_PIPELINE_MAX_WAITERS ?? validated.AUDIT_PIPELINE_MAX_SIZE,
      replicaId,
      batchSigningEnabled: !!auditBatchSigner,
      httpAnchorEnabled: !!anchorUrl,
    });
  } else {
    logger.warn(
      'Async audit pipeline disabled (AUDIT_PIPELINE_ENABLED=false); ' +
        'evidence signing runs on the request critical path.',
    );
  }

  return {
    evidenceSigner,
    auditBatchSigner,
    auditPipeline,
    auditPipelineDrainTimeoutMs: validated.AUDIT_PIPELINE_DRAIN_TIMEOUT_MS,
    ledgerPgPool,
    crossChainAnchor,
    crossChainCommitmentStore,
    auditLedgerBackend,
    auditQueryStore,
  };
}
