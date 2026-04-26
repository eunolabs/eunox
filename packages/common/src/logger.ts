/**
 * Logging utility with structured logging support
 */

import winston from 'winston';

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
      // In production, this should write to Azure Monitor / Log Analytics
      // new winston.transports.File({ filename: 'audit.log' }),
    ],
  });
}

export type Logger = winston.Logger;
