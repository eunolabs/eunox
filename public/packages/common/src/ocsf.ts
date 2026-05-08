/**
 * OCSF (Open Cybersecurity Schema Framework) audit transport — F-6.
 *
 * Maps Euno's two audit data shapes — {@link AuditLogEntry} (the
 * unsigned operational log emitted by issuer + gateway) and
 * {@link SignedAuditEvidence} (the cryptographically-signed evidence
 * for privileged actions) — into OCSF v1.1 events so any SIEM that
 * speaks OCSF can ingest them without writing a Euno-specific parser.
 *
 * Event class choices
 * -------------------
 * - **Issuance / renewal / attenuation / revocation / denial** of a
 *   capability are mapped to the **Authorization (3003)** class
 *   (category 3 = IAM, class 3003 = Authorize Session). They describe
 *   whether a principal was permitted to act, which is exactly what
 *   the OCSF Authorization class is for.
 * - **Action validation** at the gateway (a tool / proxy call that
 *   was either allowed or denied) is mapped to the **API Activity
 *   (6003)** class (category 6 = Application Activity, class 6003 =
 *   API Activity). This carries the HTTP method/path-equivalent
 *   information and is the canonical "an API call happened" event.
 *
 * Transport layer
 * ---------------
 * Mapping is decoupled from delivery via {@link OcsfAuditTransport}:
 *
 *   * {@link createStdoutOcsfTransport} writes one JSON-line per
 *     event to stderr (so existing stdout pipes are untouched).
 *   * {@link createFileOcsfTransport} appends to a rotating log
 *     file path.
 *   * {@link createHttpOcsfTransport} POSTs each batch to a SIEM
 *     collector URL; configurable headers (e.g. for an API key).
 *
 * The {@link createOcsfTransportFromEnv} factory selects one of the
 * above from `OCSF_TRANSPORT` and returns `undefined` (i.e. opt-in)
 * when unset, so existing deployments are unaffected.
 *
 * Why a sink and not a winston transport?
 * ---------------------------------------
 * The signed-evidence pipeline already exposes an `onSigned`
 * callback; piping OCSF events through that hook gives us
 * per-event delivery semantics decoupled from the winston log
 * format. For unsigned `AuditLogEntry` records we additionally
 * provide {@link createOcsfWinstonTransport} so deployments that
 * only configure the operational logger (no signed evidence) still
 * get OCSF emission.
 */

import TransportStream from 'winston-transport';
import { AuditLogEntry, SignedAuditEvidence } from './wire';
import { Logger } from './logger';

// =============================================================================
// OCSF data model — minimal subset we actually populate.
// =============================================================================

/**
 * OCSF schema version emitted on every record's `metadata.version`.
 * Bumping this in one place keeps every emitted event consistent
 * with the OCSF release the mappers below were validated against.
 */
const OCSF_SCHEMA_VERSION = '1.1.0';

/**
 * OCSF v1.1 metadata header attached to every event, identifying the
 * producer schema version and product. Matches OCSF v1.1.0 §
 * "metadata" object.
 */
export interface OcsfMetadata {
  version: string;
  product: {
    name: string;
    vendor_name: string;
    version?: string;
    feature?: { name: string };
  };
  /** Stable identifier for this event instance (RFC 4122 UUID). */
  uid?: string;
  /** Free-form list for SIEM-specific labels. */
  labels?: string[];
  /** OCSF class profile names this record conforms to. */
  profiles?: string[];
}

/** Common base every OCSF event extends. */
export interface OcsfEventBase {
  metadata: OcsfMetadata;
  /** Unix epoch milliseconds. */
  time: number;
  /** Severity ordinal (OCSF: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical). */
  severity_id: number;
  /** Activity ordinal — class-specific (see derived event types). */
  activity_id: number;
  /** Outcome ordinal (OCSF: 1=Success, 2=Failure). */
  status_id?: number;
  /** Human-readable status string mirroring `status_id`. */
  status?: 'Success' | 'Failure' | 'Unknown';
  /** OCSF class id (3003 for Authorization, 6003 for API Activity). */
  class_uid: number;
  /** OCSF category id (3 for IAM, 6 for Application Activity). */
  category_uid: number;
  /** OCSF type_uid = class_uid * 100 + activity_id. */
  type_uid: number;
  /** Free-form message. */
  message?: string;
  /** Originator info (region, etc.). */
  cloud?: { region?: string };
  /** Free-form unmapped fields the SIEM may still find useful. */
  unmapped?: Record<string, unknown>;
}

/**
 * OCSF Authorization event (class_uid 3003). Used for capability
 * issuance / attenuation / renewal / revocation / denial — anything
 * that grants or refuses authority.
 */
export interface OcsfAuthorizationEvent extends OcsfEventBase {
  class_uid: 3003;
  category_uid: 3;
  /** Activity: 1=Assign Privileges, 2=Revoke Privileges, 99=Other. */
  activity_id: 1 | 2 | 99;
  user?: { uid?: string; name?: string };
  actor?: { user?: { uid?: string }; session?: { uid?: string } };
  privileges?: string[];
  /** Resource(s) granted access to. */
  resources?: { uid?: string; type?: string }[];
}

/**
 * OCSF API Activity event (class_uid 6003). Used for gateway
 * action-validation outcomes (`validation` / `denial` AuditLogEntry
 * records and signed evidence for validated tool calls).
 */
export interface OcsfApiActivityEvent extends OcsfEventBase {
  class_uid: 6003;
  category_uid: 6;
  /** Activity: 1=Create, 2=Read, 3=Update, 4=Delete, 99=Other. */
  activity_id: 1 | 2 | 3 | 4 | 99;
  api?: {
    operation?: string;
    request?: { uid?: string };
    service?: { name?: string };
  };
  resources?: { uid?: string; type?: string }[];
  actor?: { user?: { uid?: string }; session?: { uid?: string } };
  /** Cryptographic evidence summary, when the source was a SignedAuditEvidence. */
  enrichments?: Array<{
    name: string;
    value: string;
    type?: string;
    data?: Record<string, unknown>;
  }>;
}

/** Discriminated union of every OCSF event we may emit. */
export type OcsfEvent = OcsfAuthorizationEvent | OcsfApiActivityEvent;

// =============================================================================
// Transport interface + reference implementations.
// =============================================================================

/**
 * OCSF delivery contract. `send` MAY batch internally; callers MUST
 * call `flush` and `close` during graceful shutdown so in-flight
 * batches reach the destination.
 *
 * Implementations are forbidden from throwing out of `send`: an
 * audit-transport failure must NEVER fail a request. They SHOULD log
 * to the supplied {@link Logger} (when one was passed at construction)
 * and surface metrics out-of-band.
 */
export interface OcsfAuditTransport {
  /** Async deliver a single event. MUST NOT throw. */
  send(event: OcsfEvent): Promise<void>;
  /** Flush any internal batch. MUST NOT throw. */
  flush(): Promise<void>;
  /** Stop the transport; subsequent `send` is a no-op. MUST NOT throw. */
  close(): Promise<void>;
  /** Free-form name for logs. */
  readonly name: string;
}

/**
 * Stdout/stderr OCSF transport — one JSON object per line.
 *
 * Defaults to **stderr** so existing stdout-based logging pipelines
 * (winston Console transport already writes there in production)
 * are not corrupted by OCSF events interleaving with operational
 * log lines. Callers who explicitly want stdout can pass `stream`.
 */
export function createStdoutOcsfTransport(
  opts: {
    /** Override the destination stream (default: `process.stderr`). */
    stream?: NodeJS.WritableStream;
  } = {},
): OcsfAuditTransport {
  const stream = opts.stream ?? process.stderr;
  let closed = false;
  return {
    name: 'ocsf-stdout',
    async send(event): Promise<void> {
      if (closed) return;
      try {
        stream.write(`${JSON.stringify(event)}\n`);
      } catch {
        // Never throw out of an audit transport.
      }
    },
    async flush(): Promise<void> {
      // Synchronous writes only — nothing to flush.
    },
    async close(): Promise<void> {
      closed = true;
    },
  };
}

/**
 * File-based OCSF transport — appends one JSON object per line to a
 * given path. Uses an O_APPEND-style write per event so concurrent
 * writers (e.g. multiple processes pointed at the same file) do not
 * truncate each other; the OS guarantees atomicity for writes
 * smaller than `PIPE_BUF`, which the ~2-3 KB OCSF records typically
 * fit within.
 *
 * Rotation is intentionally NOT handled here — operators should
 * configure logrotate / journald rotation around the file path.
 *
 * In-flight writes are tracked so `flush()` and `close()` resolve
 * only after every started append has completed — important on
 * SIGTERM, since gateway/issuer fire `send()` with `void` and would
 * otherwise lose the tail of the audit stream as the process exits.
 */
export function createFileOcsfTransport(opts: {
  path: string;
  logger?: Logger;
}): OcsfAuditTransport {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('fs') as typeof import('fs');
  let closed = false;
  const inflight = new Set<Promise<void>>();
  return {
    name: 'ocsf-file',
    async send(event): Promise<void> {
      if (closed) return;
      const task = (async () => {
        try {
          await fs.promises.appendFile(opts.path, `${JSON.stringify(event)}\n`);
        } catch (err) {
          opts.logger?.error('OCSF file transport write failed', {
            path: opts.path,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      })();
      inflight.add(task);
      task.finally(() => inflight.delete(task));
      await task;
    },
    async flush(): Promise<void> {
      if (inflight.size === 0) return;
      await Promise.all([...inflight]);
    },
    async close(): Promise<void> {
      closed = true;
      if (inflight.size === 0) return;
      await Promise.all([...inflight]);
    },
  };
}

/**
 * HTTP OCSF transport — POSTs each event as JSON to `url`. Honours
 * caller-supplied `headers` (e.g. an `Authorization: Bearer ...` for
 * a SIEM API key). Uses Node's built-in `fetch` so no new dependency
 * is added.
 *
 * Designed for **fire-and-forget**: failures are logged and
 * swallowed. SIEMs typically run their own replay pipelines from
 * archived logs, so a transient HTTP failure does not need to block
 * the request. Operators who want guaranteed delivery should layer
 * a queueing collector (Vector, Fluent Bit, Cribl) in front of this
 * transport instead.
 */
export function createHttpOcsfTransport(opts: {
  url: string;
  headers?: Record<string, string>;
  logger?: Logger;
  /** Per-request timeout (ms). Default 5000. */
  timeoutMs?: number;
}): OcsfAuditTransport {
  let closed = false;
  const timeoutMs = opts.timeoutMs ?? 5000;
  // In-flight tracker — gateway/issuer fire `void send()` so without
  // this set, `close()` (called from SIGTERM/SIGINT) would resolve
  // before any pending POST completed and we'd lose the tail of the
  // audit stream as the process exits.
  const inflight = new Set<Promise<void>>();
  return {
    name: 'ocsf-http',
    async send(event): Promise<void> {
      if (closed) return;
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      const task = (async () => {
        try {
          const res = await fetch(opts.url, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
            body: JSON.stringify(event),
            signal: ac.signal,
          });
          if (!res.ok) {
            opts.logger?.warn('OCSF HTTP transport non-2xx response', {
              url: opts.url,
              status: res.status,
            });
          }
        } catch (err) {
          opts.logger?.error('OCSF HTTP transport request failed', {
            url: opts.url,
            error: err instanceof Error ? err.message : String(err),
          });
        } finally {
          clearTimeout(timer);
        }
      })();
      inflight.add(task);
      task.finally(() => inflight.delete(task));
      await task;
    },
    async flush(): Promise<void> {
      if (inflight.size === 0) return;
      await Promise.all([...inflight]);
    },
    async close(): Promise<void> {
      closed = true;
      if (inflight.size === 0) return;
      await Promise.all([...inflight]);
    },
  };
}

// =============================================================================
// Mappers — Euno → OCSF.
// =============================================================================

/**
 * OCSF metadata describing the Euno emitter. The `version`,
 * `feature.name`, and `product.version` fields let SIEMs filter on
 * "events from Euno tool-gateway 1.0.0" without parsing the URL/host.
 */
export interface OcsfProductInfo {
  /** Logical product name, e.g. `"euno-tool-gateway"`. */
  name: string;
  /** Vendor — defaults to `"Euno"` when omitted. */
  vendor?: string;
  /** Software version, optional. */
  version?: string;
  /** Profile names (OCSF) the events conform to. */
  profiles?: string[];
}

function buildMetadata(product: OcsfProductInfo, uid?: string): OcsfMetadata {
  return {
    version: OCSF_SCHEMA_VERSION,
    product: {
      name: product.name,
      vendor_name: product.vendor ?? 'Euno',
      ...(product.version ? { version: product.version } : {}),
      feature: { name: 'capability-audit' },
    },
    ...(uid ? { uid } : {}),
    ...(product.profiles ? { profiles: product.profiles } : {}),
  };
}

/**
 * Map an action verb (`'read'` / `'write'` / `'delete'` / `'admin'` / etc.)
 * to OCSF API Activity activity_id. Anything unrecognised maps to
 * 99 (Other) so forward-compatible action verbs still produce a
 * valid event.
 */
function actionToApiActivityId(action: string | undefined): 1 | 2 | 3 | 4 | 99 {
  switch ((action ?? '').toLowerCase()) {
    case 'read':
    case 'list':
    case 'get':
      return 2;
    case 'write':
    case 'create':
    case 'post':
      return 1;
    case 'update':
    case 'patch':
    case 'put':
      return 3;
    case 'delete':
    case 'remove':
      return 4;
    default:
      return 99;
  }
}

/**
 * Map a Euno {@link AuditLogEntry} into an OCSF event. The
 * `eventType` field is the routing key:
 *
 *   * `issuance` / `renewal` / `revocation` → Authorization 3003
 *     (activity_id=1 grant, activity_id=2 revoke).
 *   * `validation` / `denial` → API Activity 6003 with
 *     `status_id` reflecting the decision.
 */
export function auditLogEntryToOcsf(
  entry: AuditLogEntry,
  product: OcsfProductInfo,
): OcsfEvent {
  const time = Date.parse(entry.timestamp);
  const safeTime = Number.isFinite(time) ? time : Date.now();
  const cloud = entry.region ? { region: entry.region } : undefined;

  // Many issuer-side denial paths (PIM, Conditional Access, rate
  // limit, consent missing, …) put their human-readable reason in
  // `metadata.reason` rather than the top-level `reason` field — see
  // role-resolution.ts and ca-evaluation in capability-issuer. Fall
  // back to that here so SIEMs receive a populated OCSF `message`
  // for every denial without having to dig into the `unmapped` blob
  // for a Euno-specific key. Top-level `reason` still wins when both
  // are present; this is purely a fallback.
  const message =
    entry.reason ??
    (entry.metadata && typeof entry.metadata['reason'] === 'string'
      ? (entry.metadata['reason'] as string)
      : undefined);

  const baseCommon = {
    metadata: buildMetadata(product, entry.id),
    time: safeTime,
    severity_id: entry.decision === 'deny' ? 3 : 1, // deny = Medium, allow = Informational
    status_id: entry.decision === 'allow' ? 1 : 2,
    status: (entry.decision === 'allow' ? 'Success' : 'Failure') as 'Success' | 'Failure',
    ...(cloud ? { cloud } : {}),
    ...(message ? { message } : {}),
  } as const;

  const resources = entry.resource
    ? [{ uid: entry.resource, type: 'capability-resource' }]
    : undefined;

  const actor = {
    user: entry.userId ? { uid: entry.userId } : undefined,
    session: entry.agentId ? { uid: entry.agentId } : undefined,
  };
  const actorTrimmed = actor.user || actor.session ? actor : undefined;

  if (
    entry.eventType === 'issuance' ||
    entry.eventType === 'renewal' ||
    entry.eventType === 'revocation'
  ) {
    const activityId: 1 | 2 = entry.eventType === 'revocation' ? 2 : 1;
    return {
      ...baseCommon,
      class_uid: 3003,
      category_uid: 3,
      activity_id: activityId,
      type_uid: 3003 * 100 + activityId,
      ...(entry.userId ? { user: { uid: entry.userId } } : {}),
      ...(actorTrimmed ? { actor: actorTrimmed } : {}),
      ...(entry.capabilityId ? { privileges: [entry.capabilityId] } : {}),
      ...(resources ? { resources } : {}),
      ...(entry.metadata ? { unmapped: entry.metadata } : {}),
    };
  }

  // validation / denial → API Activity
  const activityId = actionToApiActivityId(entry.action);
  return {
    ...baseCommon,
    class_uid: 6003,
    category_uid: 6,
    activity_id: activityId,
    type_uid: 6003 * 100 + activityId,
    api: {
      operation: entry.action,
      ...(entry.capabilityId ? { request: { uid: entry.capabilityId } } : {}),
      service: { name: product.name },
    },
    ...(actorTrimmed ? { actor: actorTrimmed } : {}),
    ...(resources ? { resources } : {}),
    ...(entry.metadata ? { unmapped: entry.metadata } : {}),
  };
}

/**
 * Map a {@link SignedAuditEvidence} record into an OCSF API Activity
 * event, attaching the cryptographic signature as an `enrichment`
 * object so SIEMs can verify it independently if they want.
 */
export function signedEvidenceToOcsf(
  evidence: SignedAuditEvidence,
  product: OcsfProductInfo,
): OcsfApiActivityEvent {
  const time = Date.parse(evidence.ts);
  const safeTime = Number.isFinite(time) ? time : Date.now();
  const activityId = actionToApiActivityId(evidence.action);
  return {
    metadata: buildMetadata(product, evidence.id),
    time: safeTime,
    severity_id: evidence.decision === 'deny' ? 3 : 1,
    status_id: evidence.decision === 'allow' ? 1 : 2,
    status: evidence.decision === 'allow' ? 'Success' : 'Failure',
    class_uid: 6003,
    category_uid: 6,
    activity_id: activityId,
    type_uid: 6003 * 100 + activityId,
    api: {
      operation: evidence.action,
      request: { uid: evidence.capabilityId },
      service: { name: product.name },
    },
    actor: {
      user: { uid: evidence.userId },
      session: { uid: evidence.sessionId },
    },
    resources: [{ uid: evidence.resource, type: 'capability-resource' }],
    enrichments: [
      {
        name: 'signature',
        value: evidence.signature,
        type: 'cryptographic-signature',
        data: {
          algorithm: evidence.algorithm,
          keyId: evidence.keyId,
          policyVersion: evidence.policyVersion,
          tool: evidence.tool,
          promptHash: evidence.promptHash,
          argsHash: evidence.argsHash,
          ...(evidence.documentsHash ? { documentsHash: evidence.documentsHash } : {}),
          nonce: evidence.nonce,
        },
      },
    ],
  };
}

// =============================================================================
// Winston transport bridge — for the operational AuditLogEntry stream.
// =============================================================================

/**
 * Winston transport that converts audit-channel log records (which
 * carry an {@link AuditLogEntry} as their meta) into OCSF events and
 * forwards them to the supplied {@link OcsfAuditTransport}.
 *
 * Wired by `bootstrap.ts` on both the issuer's and the gateway's
 * audit logger so any deployment that opts into OCSF gets coverage
 * for both signed-evidence events (via the audit-pipeline `onSigned`
 * sink) and the lighter-weight operational audit log.
 *
 * The transport is intentionally lenient — winston records that do
 * not look like an `AuditLogEntry` are silently dropped, so adding it
 * to a logger that also receives non-audit messages is safe.
 */
export function createOcsfWinstonTransport(
  ocsf: OcsfAuditTransport,
  product: OcsfProductInfo,
): TransportStream {
  return new (class extends TransportStream {
    constructor() {
      super({});
    }
    log(info: Record<string, unknown>, callback: () => void): void {
      try {
        if (looksLikeAuditLogEntry(info)) {
          const event = auditLogEntryToOcsf(info as unknown as AuditLogEntry, product);
          // Fire-and-forget; never throw.
          void ocsf.send(event);
        }
      } catch {
        // never fail the logging pipeline
      }
      callback();
    }
  })();
}

function looksLikeAuditLogEntry(info: unknown): boolean {
  if (typeof info !== 'object' || info === null) return false;
  const r = info as Record<string, unknown>;
  return (
    typeof r.id === 'string' &&
    typeof r.timestamp === 'string' &&
    typeof r.eventType === 'string' &&
    typeof r.decision === 'string' &&
    typeof r.agentId === 'string'
  );
}

// =============================================================================
// Env-driven factory.
// =============================================================================

/**
 * Construct an {@link OcsfAuditTransport} from the operator's
 * environment, or return `undefined` when no transport is configured
 * (opt-in semantics — existing deployments keep working unchanged).
 *
 * Recognised env vars (also see `EunoConfig`):
 *
 *   * `OCSF_TRANSPORT` — `"stdout"` | `"file"` | `"http"`. Anything
 *     else (including unset) yields `undefined`.
 *   * `OCSF_FILE_PATH` — path for the `file` transport (required when
 *     `OCSF_TRANSPORT=file`).
 *   * `OCSF_HTTP_URL` — collector URL for the `http` transport
 *     (required when `OCSF_TRANSPORT=http`).
 *   * `OCSF_HTTP_HEADERS` — JSON object of additional HTTP headers
 *     for the `http` transport (e.g. `{"x-api-key":"..."}`). Optional.
 */
export function createOcsfTransportFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
): OcsfAuditTransport | undefined {
  const kind = env.OCSF_TRANSPORT;
  if (!kind) return undefined;
  switch (kind) {
    case 'stdout':
      return createStdoutOcsfTransport();
    case 'file': {
      const path = env.OCSF_FILE_PATH;
      if (!path) {
        logger?.warn('OCSF_TRANSPORT=file but OCSF_FILE_PATH is unset; OCSF disabled');
        return undefined;
      }
      return createFileOcsfTransport({ path, logger });
    }
    case 'http': {
      const url = env.OCSF_HTTP_URL;
      if (!url) {
        logger?.warn('OCSF_TRANSPORT=http but OCSF_HTTP_URL is unset; OCSF disabled');
        return undefined;
      }
      let headers: Record<string, string> | undefined;
      if (env.OCSF_HTTP_HEADERS) {
        try {
          const parsed = JSON.parse(env.OCSF_HTTP_HEADERS);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            headers = {};
            for (const [k, v] of Object.entries(parsed)) {
              if (typeof v === 'string') headers[k] = v;
            }
          }
        } catch {
          logger?.warn('OCSF_HTTP_HEADERS is not valid JSON; ignoring');
        }
      }
      return createHttpOcsfTransport({ url, headers, logger });
    }
    default:
      logger?.warn(`Unknown OCSF_TRANSPORT="${kind}"; OCSF disabled`);
      return undefined;
  }
}
