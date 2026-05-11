/**
 * Common utility functions for capability-based agent governance
 */

import * as crypto from 'crypto';

/**
 * Generate SHA-256 hash of an object by serialising with JSON.stringify first.
 *
 * NOTE: Standard `JSON.stringify` is **not** canonical — key order, number
 * formatting and Unicode escaping vary across runtimes/versions. Two callers
 * that pass deeply-equal objects can therefore produce different digests.
 *
 * Use this only when both producer and consumer are guaranteed to use the same
 * exact serialised string (e.g. you already hold the JSON text). For any
 * audit, evidence, signing or cross-version comparison purpose use
 * {@link canonicalSha256} instead, which sorts keys recursively.
 */
export function sha256(data: unknown): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(data))
    .digest('hex');
}

/**
 * Generate SHA-256 hash of a string, hashing the raw UTF-8 bytes.
 * Use this when you already have a canonical string representation and want
 * cross-language interoperability (no surrounding quotes / JSON escaping).
 */
export function sha256String(data: string): string {
  return crypto
    .createHash('sha256')
    .update(data, 'utf8')
    .digest('hex');
}

/**
 * Produce a canonical JSON string of an arbitrary value.
 *
 * Guarantees deterministic byte output for deeply-equal inputs:
 *   - Object keys are sorted lexicographically (recursively).
 *   - `undefined` values and function values inside objects are omitted (matching
 *     `JSON.stringify` semantics).
 *   - `undefined` values inside arrays are encoded as `null` (matching
 *     `JSON.stringify` semantics).
 *   - `BigInt` values are rendered as a string suffixed with `n`.
 *   - Non-finite numbers (`NaN`, `Infinity`) are encoded as `null` (matching
 *     `JSON.stringify` semantics) so output remains valid JSON.
 *   - Circular references throw a `TypeError` rather than producing a
 *     misleading partial digest.
 *
 * Suitable for use as the input to a hash for audit evidence, token-content
 * comparison, or cross-runtime equality checks.
 */
export function canonicalize(data: unknown): string {
  const seen = new WeakSet<object>();

  const encode = (value: unknown): string | undefined => {
    if (value === null) return 'null';
    if (value === undefined) return undefined;

    const t = typeof value;

    if (t === 'bigint') {
      return JSON.stringify((value as bigint).toString() + 'n');
    }
    if (t === 'string') {
      return JSON.stringify(value);
    }
    if (t === 'boolean') {
      return value ? 'true' : 'false';
    }
    if (t === 'number') {
      return Number.isFinite(value as number) ? JSON.stringify(value) : 'null';
    }
    if (t === 'function' || t === 'symbol') {
      return undefined;
    }

    // Object / Array
    if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
      return encode((value as { toJSON: () => unknown }).toJSON());
    }

    if (seen.has(value as object)) {
      throw new TypeError('canonicalize: circular reference detected');
    }
    seen.add(value as object);

    try {
      if (Array.isArray(value)) {
        const parts = value.map((item) => {
          const encoded = encode(item);
          return encoded === undefined ? 'null' : encoded;
        });
        return '[' + parts.join(',') + ']';
      }

      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const encoded = encode(obj[key]);
        if (encoded === undefined) continue;
        parts.push(JSON.stringify(key) + ':' + encoded);
      }
      return '{' + parts.join(',') + '}';
    } finally {
      seen.delete(value as object);
    }
  };

  const result = encode(data);
  return result === undefined ? 'null' : result;
}

/**
 * Generate a SHA-256 digest of a value using its canonical JSON representation.
 * The output is stable across runtimes and key-insertion orders.
 *
 * Prefer this over {@link sha256} for any use that may be compared across
 * processes, machines, or versions (audit evidence, capability digests, etc.).
 */
export function canonicalSha256(data: unknown): string {
  return sha256String(canonicalize(data));
}

/**
 * Serialise an arbitrary unknown value to a string suitable for logging or
 * non-cryptographic comparison. Tolerates BigInt, circular references, and
 * `undefined`. NOT canonical — use {@link canonicalize} when reproducibility
 * matters.
 *
 * Uses a traversal-path ancestor stack rather than a global "seen" set so that
 * repeated (non-circular) references such as `{ a: shared, b: shared }` are
 * serialised correctly and are NOT falsely flagged as `[Circular]`.
 */
export function safeSerialize(data: unknown): string {
  if (data === undefined || data === null) {
    return '';
  }
  try {
    const serialize = (value: unknown, ancestors: object[]): unknown => {
      if (typeof value === 'bigint') {
        return value.toString() + 'n';
      }
      if (typeof value === 'object' && value !== null) {
        if (ancestors.includes(value)) {
          return '[Circular]';
        }
        const nextAncestors = [...ancestors, value];
        if (Array.isArray(value)) {
          return value.map((item) => serialize(item, nextAncestors));
        }
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          out[k] = serialize(v, nextAncestors);
        }
        return out;
      }
      return value;
    };
    return JSON.stringify(serialize(data, [])) ?? '';
  } catch {
    return String(data);
  }
}

/**
 * Generate a unique identifier (UUID v4)
 */
export function generateId(): string {
  return crypto.randomUUID();
}

/**
 * Compute the Merkle root of a list of SHA-256 hex digest strings.
 *
 * Follows the standard binary Merkle tree convention:
 *   - **Empty input** → {@link MERKLE_EMPTY_ROOT} (SHA-256 of the empty string,
 *     hex-encoded). Callers can distinguish "no records" from any non-empty tree.
 *   - **Single leaf** → the leaf hash itself (the root is the leaf).
 *   - **Odd number of leaves at any level** → the last node is duplicated before
 *     computing its parent, matching Bitcoin's and RFC 6962's convention.
 *   - **Internal node** → `sha256String(leftHex + rightHex)`.
 *
 * All leaf hashes must be 64-character lowercase hex strings (SHA-256).
 * Non-conforming entries throw so callers cannot accidentally pass
 * pre-base64-encoded or truncated digests.
 *
 * @param leafHashes  Array of 64-hex-char SHA-256 digests (one per record).
 * @returns           64-hex-char Merkle root.
 */
export function computeMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    // Sentinel for an empty batch — different from any valid tree root so
    // verifiers can distinguish "no records committed" from a real commitment.
    return MERKLE_EMPTY_ROOT;
  }

  for (const h of leafHashes) {
    if (!/^[0-9a-f]{64}$/.test(h)) {
      throw new Error(
        `computeMerkleRoot: leaf hash must be a 64-character lowercase hex string, got '${h.substring(0, 16)}...'`,
      );
    }
  }

  let level = leafHashes.map((h) => h.toLowerCase());

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      // Duplicate the last node when the level has an odd count.
      const right = i + 1 < level.length ? level[i + 1]! : level[i]!;
      next.push(sha256String(left + right));
    }
    level = next;
  }

  return level[0]!;
}

/**
 * Sentinel Merkle root used when there are no leaf hashes.
 * This is the SHA-256 hex digest of the empty string.
 */
export const MERKLE_EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

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

// Pre-compiled DID validation regex per the W3C DID Core grammar.
// idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
// method-specific-id = *( *idchar ":" ) 1*idchar
const DID_PATTERN = (() => {
  const idchar = '(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})';
  const methodSpecificId = `(?:${idchar}*:)*${idchar}+`;
  return new RegExp(`^did:[a-z0-9]+:${methodSpecificId}$`);
})();

/**
 * Validate DID format per the W3C DID Core specification.
 *
 * Grammar (simplified):
 *   did                = "did:" method-name ":" method-specific-id
 *   method-name        = 1*method-char
 *   method-char        = %x61-7A / DIGIT          ; lowercase letters and digits
 *   method-specific-id = *( *idchar ":" ) 1*idchar
 *   idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
 *   pct-encoded        = "%" HEXDIG HEXDIG
 *
 * The previous implementation rejected DIDs that contain colons or
 * percent-encoded characters in the method-specific-id (e.g.
 * `did:web:example.com:user:alice`, `did:peer:2.Ez6...`), which are valid for
 * many production DID methods. This implementation matches the spec.
 */
export function isValidDID(did: string): boolean {
  return DID_PATTERN.test(did);
}

/**
 * Validate resource identifier format
 */
export function isValidResourceId(resource: string): boolean {
  // Resource should follow a URI-like pattern
  return resource.length > 0 && resource.includes(':');
}

/**
 * Find the first capability in `capabilities` that permits `action` on
 * `resource`, applying the same wildcard resource-matching logic as
 * {@link matchesResource}.
 *
 * Returns the matched element so the caller can inspect `argumentSchema`,
 * `conditions`, and any other fields without a second O(n) scan. Returns
 * `null` when no capability matches — letting callers treat `null` as a
 * definitive denial without an additional boolean check.
 *
 * The function is generic so it works with any capability supertype (e.g.
 * `CapabilityConstraint`) without losing type information. Both the outer
 * array and the `actions` tuple are accepted as `readonly` so callers that
 * use `as const` literals (e.g. `actions: ['read'] as const`) do not need
 * a cast.
 */
export function findMatchingCapability<C extends { resource: string; actions: readonly string[] }>(
  action: string,
  resource: string,
  capabilities: readonly C[]
): C | null {
  for (const cap of capabilities) {
    if (matchesResource(resource, cap.resource) && cap.actions.includes(action)) {
      return cap;
    }
  }
  return null;
}

/**
 * Check if an action is allowed for a resource given capability constraints.
 *
 * Delegates to {@link findMatchingCapability} so the two functions share a
 * single code path and cannot diverge in their matching semantics.
 */
export function isActionAllowed(
  action: string,
  resource: string,
  capabilities: ReadonlyArray<{ resource: string; actions: readonly string[] }>
): boolean {
  return findMatchingCapability(action, resource, capabilities) !== null;
}

/**
 * Match a concrete resource string against a capability resource
 * pattern.
 *
 * Patterns are URI-shaped strings (e.g. `file://reports/2024.pdf`,
 * `db://analytics/customers`) and may include a single trailing
 * wildcard segment:
 *
 *   - `pattern/*`   matches exactly one additional path segment under
 *                   `pattern/` (does not span `/`).
 *   - `pattern/**`  matches any number (including zero) of additional
 *                   path segments under `pattern/`.
 *
 * Matching is anchored: a non-wildcard pattern must equal the resource
 * exactly. Schemes (the substring before `://`) must match exactly so
 * that `file://data/*` does not authorize `db://data/x`. When either
 * value omits a `://` scheme, the strings are compared as opaque path
 * segments — preserving the legacy behavior for non-URI resources.
 *
 * The earlier implementation used `startsWith(prefix)` for both `/*`
 * and `/**`, which (a) failed to distinguish single-segment from
 * recursive wildcards and (b) silently allowed scheme confusion. The
 * new implementation closes both gaps.
 */
export function matchesResource(resource: string, pattern: string): boolean {
  if (pattern === resource) {
    return true;
  }

  const recursive = pattern.endsWith('/**');
  const single = !recursive && pattern.endsWith('/*');
  if (!recursive && !single) {
    return false;
  }

  // Strip only the trailing wildcard token (`*` or `**`), preserving
  // the separator slash so `api://**` keeps its full scheme prefix
  // (`api://`) rather than being truncated to `api:/`.
  const prefix = recursive ? pattern.slice(0, -2) : pattern.slice(0, -1);

  // Enforce scheme equality when either side declares one. A pattern
  // without a scheme must not match a resource that has one (and vice
  // versa) — the gateway treats `file://data/x` and `db://data/x` as
  // entirely separate authorization domains. `indexOf('://')` finds
  // the scheme separator inside `prefix` regardless of any trailing
  // slash, so no normalization step is required.
  const patternSchemeIdx = prefix.indexOf('://');
  const resourceSchemeIdx = resource.indexOf('://');
  if (patternSchemeIdx >= 0 || resourceSchemeIdx >= 0) {
    if (patternSchemeIdx < 0 || resourceSchemeIdx < 0) return false;
    if (
      prefix.slice(0, patternSchemeIdx) !==
      resource.slice(0, resourceSchemeIdx)
    ) {
      return false;
    }
  }

  // The resource must extend the prefix, and there must be at least
  // one extra character (segment) after the trailing slash.
  if (!resource.startsWith(prefix)) {
    return false;
  }
  const tail = resource.slice(prefix.length);
  if (tail.length === 0) {
    return false;
  }

  if (recursive) {
    return true;
  }

  // Single-segment wildcard: the tail must not span a `/`.
  return !tail.includes('/');
}

/**
 * Default set of object keys whose values are redacted by {@link sanitizeForLog}.
 * Matched case-insensitively, exact-match (NOT substring) so a key like
 * `customerToken` is no longer redacted by accident, but common security keys
 * such as `jwt`, `bearer`, `cookie` or `session` are.
 */
export const SENSITIVE_LOG_KEYS: readonly string[] = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'access_token',
  'accesstoken',
  'refresh_token',
  'refreshtoken',
  'id_token',
  'idtoken',
  'authorization',
  'auth',
  'apikey',
  'api_key',
  'x-api-key',
  'jwt',
  'bearer',
  'cookie',
  'set-cookie',
  'session',
  'sessionid',
  'session_id',
  'client_secret',
  'clientsecret',
  'private_key',
  'privatekey',
];

/** Maximum recursion depth for {@link sanitizeForLog} to prevent runaway
 *  traversal of large/deep payloads. */
const SANITIZE_MAX_DEPTH = 8;
/** Maximum number of array entries traversed by {@link sanitizeForLog}.
 *  Remaining entries are summarised. */
const SANITIZE_MAX_ARRAY_ENTRIES = 100;

/**
 * Sanitize log data to remove sensitive information.
 *
 * - Keys are matched case-insensitively against {@link SENSITIVE_LOG_KEYS}
 *   using exact equality (not substring) — this fixes the previous behaviour
 *   where any key containing the substring `token` (e.g. `customerToken`) was
 *   redacted while obvious-but-non-listed names like `jwt` or `bearer` were
 *   not.
 * - Arrays are traversed (previously they were silently treated as objects,
 *   which produced index-keyed records).
 * - Recursion is bounded by {@link SANITIZE_MAX_DEPTH} and arrays larger than
 *   {@link SANITIZE_MAX_ARRAY_ENTRIES} are truncated, so very large payloads
 *   cannot blow up logging.
 * - Callers may supply additional sensitive key names via `extraSensitiveKeys`.
 */
export function sanitizeForLog(
  data: Record<string, unknown>,
  extraSensitiveKeys: readonly string[] = []
): Record<string, unknown> {
  const sensitive = new Set<string>(
    [...SENSITIVE_LOG_KEYS, ...extraSensitiveKeys].map((k) => k.toLowerCase())
  );

  const sanitizeValue = (value: unknown, depth: number): unknown => {
    if (depth >= SANITIZE_MAX_DEPTH) {
      return '[TRUNCATED:max-depth]';
    }
    if (value === null || typeof value !== 'object') {
      return value;
    }
    if (Array.isArray(value)) {
      const limit = Math.min(value.length, SANITIZE_MAX_ARRAY_ENTRIES);
      const out: unknown[] = new Array(limit);
      for (let i = 0; i < limit; i++) {
        out[i] = sanitizeValue(value[i], depth + 1);
      }
      if (value.length > limit) {
        out.push(`[TRUNCATED:${value.length - limit} more entries]`);
      }
      return out;
    }
    return sanitizeRecord(value as Record<string, unknown>, depth + 1);
  };

  const sanitizeRecord = (
    record: Record<string, unknown>,
    depth: number
  ): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      if (sensitive.has(key.toLowerCase())) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = sanitizeValue(value, depth);
      }
    }
    return out;
  };

  return sanitizeRecord(data, 0);
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
  /**
   * The agent or session has been terminated by an out-of-band control-plane
   * action (kill switch). Distinct from {@link TOKEN_REVOKED} because *any*
   * future token issued for this agent/session will also be blocked until the
   * kill switch is released, so callers MUST NOT auto-refresh and retry.
   */
  AGENT_TERMINATED = 'AGENT_TERMINATED',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  NOT_IMPLEMENTED = 'NOT_IMPLEMENTED',
  /**
   * The presented authentication token did not satisfy a Conditional
   * Access policy required for the requested capability tier (for
   * example MFA, compliant device, or a fresh sign-in). The caller
   * should re-authenticate to satisfy the policy and retry. Surfaced as
   * HTTP 403; audit reason `"conditional_access_unsatisfied"`. See
   * `docs/sprint-3-4-gaps/03-conditional-access.md`.
   */
  CONDITIONAL_ACCESS_REQUIRED = 'CONDITIONAL_ACCESS_REQUIRED',
  /**
   * The revocation check could not be completed because the backing
   * store (typically Redis) is temporarily unreachable.  The gateway
   * returns HTTP 503 so the agent runtime knows to retry later rather
   * than treating the failure as a token problem.
   *
   * This code is only emitted when `REVOCATION_UNAVAILABLE_MODE=503` is
   * configured on the gateway.  The default (`fail-closed`) continues to
   * return HTTP 401 (`TOKEN_REVOKED`) to preserve backward-compatible
   * fail-closed semantics.
   */
  REVOCATION_UNAVAILABLE = 'REVOCATION_UNAVAILABLE',

  // ── Stage-3 remote-enforcer codes (Task 9) ────────────────────────────────

  /**
   * The `X-Euno-Protocol-Version` header carries a version integer the
   * gateway does not support. The error body includes a `supportedVersions`
   * array. Returned with HTTP 400.
   */
  UNSUPPORTED_PROTOCOL_VERSION = 'UNSUPPORTED_PROTOCOL_VERSION',

  /**
   * The gateway or a required backing store (Redis, Postgres) is
   * temporarily unavailable and cannot serve an enforcement decision.
   * Callers MUST treat this as a denial (fail-closed) and MUST NOT
   * retry automatically without a back-off. Returned with HTTP 503.
   */
  GATEWAY_UNAVAILABLE = 'GATEWAY_UNAVAILABLE',

  /**
   * The request body exceeds the 512 KiB size limit for `POST
   * /api/v1/enforce`. Returned with HTTP 413.
   */
  REQUEST_TOO_LARGE = 'REQUEST_TOO_LARGE',

  /**
   * The caller authenticated successfully but the API key does not carry
   * the scope required for the requested operation (e.g. an `audit`-scoped
   * key calling the enforcement endpoint which requires `enforce` scope).
   * Returned with HTTP 403 to distinguish it from an auth failure (401).
   */
  PERMISSION_DENIED = 'PERMISSION_DENIED',

  /**
   * A required context field is absent from the `EnforceRequestContext` and
   * a condition that needs it (e.g. `ipRange` without `sourceIp`) cannot be
   * evaluated. The gateway denies with this code rather than silently
   * allowing. Returned inside an `EnforceResponse` with `decision: 'deny'`
   * (HTTP 200) so the client can distinguish a policy denial from a
   * protocol error.
   */
  MISSING_CONTEXT = 'MISSING_CONTEXT',

  /**
   * The tool call arguments failed the capability's `argumentSchema`
   * validation. Returned inside an `EnforceResponse` with `decision: 'deny'`
   * (HTTP 200). The `DenialInfo.details.schemaErrors` array carries the
   * per-field validation messages.
   */
  ARGUMENT_SCHEMA_VIOLATION = 'ARGUMENT_SCHEMA_VIOLATION',
}

/**
 * Custom error class for capability system
 */
export class CapabilityError extends Error {
  /**
   * Optional HTTP response headers the issuer/gateway error handler
   * should set on the outgoing 4xx/5xx response. Used today to
   * propagate `Retry-After` on `RATE_LIMIT_EXCEEDED` (F-1) so callers
   * back off the right amount rather than hammering the issuer; the
   * mechanism is intentionally generic so future error codes can
   * piggy-back without touching the error-handler middleware.
   */
  public readonly responseHeaders?: Record<string, string>;

  constructor(
    public code: ErrorCode,
    message: string,
    public statusCode: number = 500,
    responseHeaders?: Record<string, string>,
  ) {
    super(message);
    this.name = 'CapabilityError';
    if (responseHeaders) this.responseHeaders = responseHeaders;
    Error.captureStackTrace(this, this.constructor);
  }
}
