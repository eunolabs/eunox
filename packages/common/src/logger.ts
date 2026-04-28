/**
 * Logging utility with structured logging support.
 *
 * The base loggers always write to the Console (so that the cloud-native
 * log shipper of the runtime environment — Azure Container Insights,
 * AWS Fluent Bit, GKE Cloud Logging fluentbit, etc. — can scrape them).
 *
 * In addition, when AWS or GCP environment variables are set (see
 * `buildCloudTransportsFromEnv` in `./log-transports`), the logger also
 * ships entries directly to CloudWatch Logs / Cloud Logging using the
 * official SDKs.  This is the Sprint-1 OBS multi-cloud parity path for
 * environments where direct stdout scraping is not available (e.g.
 * AWS ECS-on-EC2 without a sidecar, GCP Cloud Run jobs).
 *
 * Audit loggers additionally apply a tamper-evident hash chain to every
 * record (see {@link createAuditLogger}) so downstream log aggregators
 * can detect missing or modified entries even when shipping over an
 * untrusted transport.
 */

import * as crypto from 'crypto';
import winston from 'winston';
import { buildCloudTransportsFromEnv } from './log-transports';

/**
 * Create a logger instance with consistent formatting
 */
export function createLogger(serviceName: string, environment: string = 'development') {
  const logLevel = environment === 'production' ? 'info' : 'debug';

  const logger = winston.createLogger({
    level: logLevel,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { service: serviceName, environment },
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
      }),
      ...buildCloudTransportsFromEnv(serviceName, logLevel),
    ],
  });

  return logger;
}

/**
 * Per-logger hash-chain state. Maintained as module-level state keyed by
 * service name so multiple `createAuditLogger` calls for the same service
 * within a process share a single chain (matching operator expectations
 * that the chain is per-process, per-service).
 */
const auditChainState: Record<string, { seq: number; prevHash: string }> = {};

/**
 * Compute the canonical SHA-256 digest of an audit log entry. The
 * canonical form is the sorted JSON serialisation of the record minus the
 * chain fields themselves (so the digest covers the entry payload and
 * the previous-record hash, but not the about-to-be-computed hash).
 */
function canonicalAuditDigest(record: Record<string, unknown>, prevHash: string): string {
  const filtered: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    if (key === 'auditChain') continue;
    filtered[key] = record[key];
  }
  filtered._prevHash = prevHash;
  const canonical = JSON.stringify(filtered);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Winston format that appends an `auditChain` field to every log entry
 * containing a monotonically-increasing sequence number, the SHA-256
 * digest of the previous record (`prevHash`), and the SHA-256 digest of
 * the current record (`hash`). Tampering with any record — or removing
 * one — breaks the chain and is detectable by replaying the digests.
 *
 * The chain is reset on process restart but its terminal hash is stable
 * across process boundaries when the previous final hash is supplied via
 * `EUNO_AUDIT_CHAIN_SEED_<SERVICE>` (uppercased, non-alphanumerics
 * replaced with `_`). This allows operators to seed a new replica with
 * the last hash shipped by the previous one for cross-restart continuity.
 */
function tamperEvidentChainFormat(serviceName: string) {
  return winston.format((info) => {
    const state = auditChainState[serviceName] ?? {
      seq: 0,
      prevHash: process.env[`EUNO_AUDIT_CHAIN_SEED_${serviceName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`]
        ?? 'GENESIS',
    };
    const seq = state.seq + 1;
    // Snapshot the record fields *before* we add chain metadata so the
    // digest is computed over the operator-supplied payload only.
    const snapshot: Record<string, unknown> = {};
    for (const key of Object.keys(info)) {
      if (key === 'auditChain') continue;
      snapshot[key] = (info as Record<string, unknown>)[key];
    }
    const hash = canonicalAuditDigest(snapshot, state.prevHash);
    auditChainState[serviceName] = { seq, prevHash: hash };
    (info as Record<string, unknown>).auditChain = {
      seq,
      prevHash: state.prevHash,
      hash,
    };
    return info;
  })();
}

/**
 * Audit logger for compliance and security events.
 *
 * Audit records are emitted as a tamper-evident hash chain: every entry
 * carries an `auditChain` field with `seq`, `prevHash`, and `hash` so any
 * downstream verifier can detect missing, reordered, or modified records
 * by replaying the digests. This applies regardless of transport, giving
 * a baseline append-only guarantee even when the configured log sink
 * itself is mutable.
 */
export function createAuditLogger(serviceName: string) {
  return winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      tamperEvidentChainFormat(serviceName),
      winston.format.json()
    ),
    defaultMeta: { service: serviceName, logType: 'audit' },
    transports: [
      new winston.transports.Console(),
      // In production, audit logs should also flow to the cloud-native
      // log store.  These transports activate automatically when the
      // matching env vars are present (Azure: scraped by the Console
      // transport; AWS: AWS_CLOUDWATCH_LOG_GROUP; GCP: GCP_LOG_NAME).
      ...buildCloudTransportsFromEnv(serviceName, 'info'),
    ],
  });
}

/**
 * Reset the in-memory audit chain state for a service. Intended for tests
 * that need a deterministic starting point; production code should never
 * call this because resetting the chain destroys tamper evidence for any
 * records emitted before the reset.
 */
export function _resetAuditChainStateForTesting(serviceName?: string): void {
  if (serviceName) {
    delete auditChainState[serviceName];
  } else {
    for (const key of Object.keys(auditChainState)) {
      delete auditChainState[key];
    }
  }
}

export type Logger = winston.Logger;
