/**
 * Common utility functions for capability-based agent governance
 */

import * as crypto from 'crypto';

/**
 * Generate SHA-256 hash of an object
 * This matches the pattern from the Azure security reference:
 * Hash locally before signing with Key Vault
 */
export function sha256(data: unknown): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(data))
    .digest('hex');
}

/**
 * Generate a unique identifier (UUID v4)
 */
export function generateId(): string {
  return crypto.randomUUID();
}

/**
 * Check if a timestamp has expired
 */
export function isExpired(expirationTimestamp: number): boolean {
  return Date.now() >= expirationTimestamp * 1000;
}

/**
 * Get current Unix timestamp in seconds
 */
export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Calculate expiration timestamp
 * @param ttlSeconds Time to live in seconds
 */
export function getExpirationTimestamp(ttlSeconds: number): number {
  return getCurrentTimestamp() + ttlSeconds;
}

/**
 * Validate DID format
 * Basic validation for DID format: did:method:identifier
 */
export function isValidDID(did: string): boolean {
  const didPattern = /^did:[a-z0-9]+:[a-zA-Z0-9._-]+$/;
  return didPattern.test(did);
}

/**
 * Validate resource identifier format
 */
export function isValidResourceId(resource: string): boolean {
  // Resource should follow a URI-like pattern
  return resource.length > 0 && resource.includes(':');
}

/**
 * Check if an action is allowed for a resource given capability constraints
 */
export function isActionAllowed(
  action: string,
  resource: string,
  capabilities: Array<{ resource: string; actions: string[] }>
): boolean {
  for (const cap of capabilities) {
    if (matchesResource(resource, cap.resource) && cap.actions.includes(action)) {
      return true;
    }
  }
  return false;
}

/**
 * Match resource patterns
 * Supports wildcards: api://service/* matches api://service/endpoint
 */
export function matchesResource(resource: string, pattern: string): boolean {
  if (pattern === resource) {
    return true;
  }

  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1);
    return resource.startsWith(prefix);
  }

  if (pattern.endsWith('/**')) {
    const prefix = pattern.slice(0, -2);
    return resource.startsWith(prefix);
  }

  return false;
}

/**
 * Sanitize log data to remove sensitive information
 */
export function sanitizeForLog(data: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = ['password', 'secret', 'token', 'authorization', 'apikey', 'api_key'];
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeForLog(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Parse Bearer token from Authorization header
 */
export function parseBearerToken(authHeader?: string): string | null {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1] ?? null;
}

/**
 * Error codes for capability system
 */
export enum ErrorCode {
  INVALID_TOKEN = 'INVALID_TOKEN',
  EXPIRED_TOKEN = 'EXPIRED_TOKEN',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  INVALID_REQUEST = 'INVALID_REQUEST',
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  AUTHORIZATION_FAILED = 'AUTHORIZATION_FAILED',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
}

/**
 * Custom error class for capability system
 */
export class CapabilityError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'CapabilityError';
    Error.captureStackTrace(this, this.constructor);
  }
}
