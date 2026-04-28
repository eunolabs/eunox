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
 */

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
 * Audit logger for compliance and security events
 */
export function createAuditLogger(serviceName: string) {
  return winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
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

export type Logger = winston.Logger;
