/**
 * Optional cloud log-shipping transports for the Euno logger pipeline.
 *
 * Sprint-1 OBS calls for the audit/runtime logs to be shipped to the
 * cloud-native log store of every supported provider.  Azure already
 * documents Azure Monitor / Log Analytics as the production transport via
 * the standard winston Console transport scraped by the Container Insights
 * add-on (see `k8s/agent-runtime.yaml`).
 *
 * This module fills the AWS and GCP gaps:
 *
 *   * `createCloudWatchLogsTransport` — AWS CloudWatch Logs (also captures
 *     CloudTrail-equivalent audit lines because every audit record is
 *     emitted with `logType: 'audit'`).
 *   * `createCloudLoggingTransport` — GCP Cloud Logging (Stackdriver).
 *
 * The underlying SDKs (`winston-cloudwatch`, `@google-cloud/logging-winston`)
 * are intentionally **optional** peer dependencies so that:
 *
 *   1. The base `@euno/common` package stays dependency-light.
 *   2. Existing Azure-only deployments are not forced to install AWS / GCP
 *      SDKs they will never use.
 *   3. Operators can opt in by simply `npm install`-ing the matching SDK
 *      and setting the appropriate env vars.
 *
 * If the SDK is missing or required configuration is absent, the factory
 * returns `null` and the caller falls back to the Console transport that
 * the base logger already provides.
 */

import type * as winston from 'winston';
import type TransportStream from 'winston-transport';

/**
 * Configuration for the AWS CloudWatch Logs winston transport.
 */
export interface CloudWatchLogsTransportConfig {
  /** CloudWatch Logs log group name. */
  logGroupName: string;
  /**
   * CloudWatch Logs log stream name.  When omitted, the transport uses
   * `${process.env.SERVICE_NAME ?? 'euno'}-${process.env.HOSTNAME ?? 'instance'}`
   * so multiple replicas of the same service write to distinct streams.
   */
  logStreamName?: string;
  /** AWS region. Falls back to `AWS_REGION` env var. */
  awsRegion?: string;
  /** Optional explicit AWS credentials. Defaults to the standard provider chain. */
  awsAccessKeyId?: string;
  /** @see awsAccessKeyId */
  awsSecretKey?: string;
  /**
   * Format log entries as JSON instead of the default plain string.
   * Defaults to `true` so structured fields (sessionId, agentId, etc.) are
   * preserved end-to-end through CloudWatch Logs Insights.
   */
  jsonMessage?: boolean;
  /** Minimum log level forwarded to CloudWatch. Defaults to 'info'. */
  level?: string;
}

/**
 * Configuration for the GCP Cloud Logging winston transport.
 */
export interface CloudLoggingTransportConfig {
  /** GCP project ID. Falls back to `GOOGLE_CLOUD_PROJECT` / `GCLOUD_PROJECT`. */
  projectId?: string;
  /** Cloud Logging log name. Defaults to the service name. */
  logName?: string;
  /** Optional service-account key file path. Defaults to ADC. */
  keyFilename?: string;
  /** Minimum log level forwarded. Defaults to 'info'. */
  level?: string;
  /** Optional resource labels merged into every entry. */
  resource?: Record<string, unknown>;
  /** Default labels applied to every entry. */
  labels?: Record<string, string>;
}

/**
 * Lazy `require` so we never hard-fail when the optional SDK is missing.
 *
 * Marked as a function so that bundlers / tree-shakers do not eagerly
 * resolve the import at build time.
 *
 * Only `MODULE_NOT_FOUND` for the requested module is treated as "SDK
 * absent → return null".  Any other error (e.g. the SDK is installed but
 * fails during initialisation, or one of *its* transitive deps is missing)
 * is rethrown so misconfiguration is surfaced loudly instead of silently
 * disabling cloud log shipping.
 */
function tryRequire<T = unknown>(moduleName: string): T | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    return require(moduleName) as T;
  } catch (error: unknown) {
    const isMissingRequestedModule =
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      (error as { code?: unknown }).code === 'MODULE_NOT_FOUND' &&
      'message' in error &&
      typeof (error as { message?: unknown }).message === 'string' &&
      // Node phrases this as `Cannot find module 'foo'` / `"foo"` / bare —
      // match the module name itself rather than a specific quoting style.
      (error as { message: string }).message.includes(moduleName);

    if (isMissingRequestedModule) {
      return null;
    }
    throw error;
  }
}

/**
 * Create a winston transport that ships log entries to AWS CloudWatch Logs.
 *
 * Returns `null` (and emits nothing to stderr) when the optional
 * `winston-cloudwatch` package is not installed or when `logGroupName` is
 * missing — callers should then fall back to the Console transport.
 *
 * @example
 *   const cw = createCloudWatchLogsTransport({
 *     logGroupName: '/euno/tool-gateway',
 *     awsRegion: 'us-east-1',
 *   });
 *   if (cw) logger.add(cw);
 */
export function createCloudWatchLogsTransport(
  config: CloudWatchLogsTransportConfig
): TransportStream | null {
  if (!config.logGroupName) {
    return null;
  }

  const mod = tryRequire<unknown>('winston-cloudwatch');
  if (!mod) {
    return null;
  }
  // The package exposes the constructor as default OR as the module export
  // depending on the version; support both.
  const CloudWatchTransport =
    (mod as { default?: new (opts: unknown) => TransportStream }).default ??
    (mod as new (opts: unknown) => TransportStream);

  const options: Record<string, unknown> = {
    logGroupName: config.logGroupName,
    logStreamName:
      config.logStreamName ??
      `${process.env.SERVICE_NAME ?? 'euno'}-${process.env.HOSTNAME ?? 'instance'}`,
    awsRegion: config.awsRegion ?? process.env.AWS_REGION,
    jsonMessage: config.jsonMessage ?? true,
    level: config.level ?? 'info',
    // CloudWatch best practice: batch and use exponential backoff which the
    // package does internally. We only override credentials when explicit.
  };
  if (config.awsAccessKeyId && config.awsSecretKey) {
    options.awsAccessKeyId = config.awsAccessKeyId;
    options.awsSecretKey = config.awsSecretKey;
  }

  return new CloudWatchTransport(options);
}

/**
 * Create a winston transport that ships log entries to GCP Cloud Logging.
 *
 * Returns `null` when `@google-cloud/logging-winston` is not installed —
 * callers should then fall back to the Console transport (which is still
 * captured by GKE's default fluentbit shipper, just without structured
 * Cloud Logging severity mapping).
 *
 * @example
 *   const gcp = createCloudLoggingTransport({
 *     projectId: 'euno-prod',
 *     logName: 'tool-gateway',
 *   });
 *   if (gcp) logger.add(gcp);
 */
export function createCloudLoggingTransport(
  config: CloudLoggingTransportConfig = {}
): TransportStream | null {
  const mod = tryRequire<{ LoggingWinston?: new (opts: unknown) => TransportStream }>(
    '@google-cloud/logging-winston'
  );
  if (!mod || !mod.LoggingWinston) {
    return null;
  }
  const projectId =
    config.projectId ??
    process.env.GOOGLE_CLOUD_PROJECT ??
    process.env.GCLOUD_PROJECT;

  const options: Record<string, unknown> = {
    level: config.level ?? 'info',
    logName: config.logName,
    projectId,
    keyFilename: config.keyFilename,
    resource: config.resource,
    labels: config.labels,
  };
  // Strip undefined keys so the underlying SDK falls back to its own
  // discovery (ADC, GKE workload identity, etc).
  for (const k of Object.keys(options)) {
    if (options[k] === undefined) delete options[k];
  }
  return new mod.LoggingWinston(options);
}

/**
 * Convenience: build the additional cloud transports configured via env
 * vars.  Used by `createLogger` / `createAuditLogger` to enable
 * production log-shipping without code changes per service.
 *
 * `serviceName` is used to derive sensible per-service defaults so multiple
 * services don't converge on the same CloudWatch log stream when only the
 * `AWS_CLOUDWATCH_LOG_GROUP` env var is set:
 *
 *   - CloudWatch `logStreamName` defaults to
 *     `${serviceName}-${process.env.HOSTNAME ?? 'instance'}`.
 *
 * Recognised env vars:
 *   - `AWS_CLOUDWATCH_LOG_GROUP`  → enables CloudWatch transport
 *   - `AWS_CLOUDWATCH_LOG_STREAM` (optional override of the per-service default)
 *   - `AWS_REGION` (standard AWS env var)
 *   - `GCP_LOG_NAME`              → enables Cloud Logging transport
 *   - `GOOGLE_CLOUD_PROJECT` / `GCLOUD_PROJECT` (standard GCP env vars)
 */
export function buildCloudTransportsFromEnv(
  serviceName: string,
  level: string = 'info'
): TransportStream[] {
  const transports: TransportStream[] = [];

  if (process.env.AWS_CLOUDWATCH_LOG_GROUP) {
    const cw = createCloudWatchLogsTransport({
      logGroupName: process.env.AWS_CLOUDWATCH_LOG_GROUP,
      logStreamName:
        process.env.AWS_CLOUDWATCH_LOG_STREAM ??
        `${serviceName}-${process.env.HOSTNAME ?? 'instance'}`,
      awsRegion: process.env.AWS_REGION,
      level,
    });
    if (cw) transports.push(cw);
  }

  if (process.env.GCP_LOG_NAME) {
    const gcp = createCloudLoggingTransport({
      // GCP_LOG_NAME is the gate; if set, honour it. The `serviceName`
      // fallback only kicks in if the operator deliberately set the env
      // var to an empty string (treat as "auto-name from service").
      logName: process.env.GCP_LOG_NAME || serviceName,
      projectId:
        process.env.GOOGLE_CLOUD_PROJECT ?? process.env.GCLOUD_PROJECT,
      level,
    });
    if (gcp) transports.push(gcp);
  }

  return transports;
}

// Re-export the winston namespace type for convenience so callers don't
// have to take their own dependency on it just to extend a logger.
export type { winston };
