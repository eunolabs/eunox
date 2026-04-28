/**
 * Specialized Capability Validation
 *
 * Provides security validation for specific capability types to prevent
 * common attacks like directory traversal, SQL injection, etc.
 */

import { CapabilityError, ErrorCode } from './utils';

/**
 * Validate a file path to prevent directory traversal attacks.
 *
 * This helper performs **structural** validation of a path string. The
 * checks here detect things that are unambiguous regardless of the
 * downstream filesystem (absolute paths, parent-directory traversal, null
 * bytes, percent-encoded traversal). They do *not* attempt to detect
 * "dangerous content" inside legitimate-looking paths — that is a job for
 * the storage layer, which should resolve and canonicalize the path
 * relative to a fixed root and refuse to serve anything outside it.
 *
 * Capabilities that need to constrain *which* paths an agent may touch
 * should declare an `argumentSchema` (with `pattern`/`enum`) on the
 * capability constraint; the tool gateway's enforcement engine will then
 * apply that allowlist on every call.
 *
 * Checks:
 *  - empty / whitespace-only path
 *  - null bytes (raw and percent-encoded)
 *  - absolute paths (Unix and Windows)
 *  - parent-directory references (raw and percent-encoded)
 *  - leading current-directory references
 *  - hidden files / dotfiles
 *  - home-directory shortcuts (`~/`)
 *  - optional file-extension allowlist
 *
 * @param filePath           The file path to validate.
 * @param allowedExtensions  Optional list of allowed file extensions
 *                           (e.g. `['.txt', '.json']`).
 * @throws CapabilityError if the path is invalid.
 */
export function validateFilePath(
  filePath: string,
  allowedExtensions?: string[]
): void {
  // Check for empty path first so subsequent checks have a non-empty string.
  if (!filePath || filePath.trim().length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'File path cannot be empty',
      400
    );
  }

  // Check for null bytes (raw and URL-encoded).
  if (filePath.includes('\0') || /%00/i.test(filePath)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'File path contains null byte',
      400
    );
  }

  // Check for absolute paths (Unix and Windows)
  if (filePath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(filePath)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Absolute file paths are not allowed',
      400
    );
  }

  // Check for parent directory references (raw and URL-encoded).
  if (
    filePath.includes('../') ||
    filePath.includes('..\\') ||
    /%2e%2e/i.test(filePath)
  ) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Parent directory references (..) are not allowed',
      400
    );
  }

  // Check for current directory references at start
  if (filePath.startsWith('./') || filePath.startsWith('.\\')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Current directory references at start (./) are not allowed',
      400
    );
  }

  // Reject home-directory shortcuts.
  if (/^~[/\\]/.test(filePath)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Home directory references (~) are not allowed',
      400
    );
  }

  // Check for hidden files (starting with .)
  const pathParts = filePath.split(/[\\/]/);
  for (const part of pathParts) {
    if (part.startsWith('.') && part !== '.' && part !== '..') {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Hidden files (${part}) are not allowed`,
        400
      );
    }
  }

  // Check file extension if allowedExtensions is provided
  if (allowedExtensions && allowedExtensions.length > 0) {
    const hasAllowedExtension = allowedExtensions.some(ext =>
      filePath.toLowerCase().endsWith(ext.toLowerCase())
    );

    if (!hasAllowedExtension) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `File extension not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`,
        400
      );
    }
  }
}

/**
 * Validate SQL query parameters.
 *
 * **WARNING — this is NOT an SQL-injection defense.**
 *
 * Earlier versions of this helper attempted to detect SQL injection by
 * pattern-matching "dangerous" keywords (UNION SELECT, xp_cmdshell, OR 1=1,
 * etc.). Blacklist-based input filtering for SQL is a known anti-pattern:
 *  - it misses real attacks (encoding tricks, stacked queries, dialect
 *    differences, time-based blind injection, second-order injection); and
 *  - it rejects legitimate input (names containing apostrophes, free-text
 *    fields with the word "select", numeric strings that look like hex).
 *
 * The only correct defense against SQL injection is **parameterized queries
 * / prepared statements** in the data-access layer downstream of the gateway.
 * This helper now performs only generic structural hygiene checks that are
 * always safe to apply to any string value crossing a trust boundary:
 *  - reject embedded null bytes (a known parser-confusion trick);
 *  - enforce a maximum length to bound resource use;
 *  - optionally enforce a caller-supplied allowlist regex (`allowedPattern`)
 *    for fields whose grammar is known and narrow (UUIDs, ISO dates, etc.).
 *
 * Capabilities that need to constrain the *shape* of arguments should
 * declare an `argumentSchema` on the capability constraint instead — the
 * tool gateway's enforcement engine will validate it on every call.
 *
 * @param value           The value to sanity-check.
 * @param allowedPattern  Optional regex source the value must fully match.
 *                        When provided, callers express what they DO allow
 *                        (allowlist) rather than what they reject.
 * @param maxLength       Maximum permitted length. Defaults to 4096.
 * @throws CapabilityError if the value fails the structural checks.
 */
export function validateSQLParameter(
  value: string,
  allowedPattern?: RegExp,
  maxLength: number = 4096
): void {
  if (typeof value !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'SQL parameter must be a string',
      400
    );
  }

  // Reject embedded null bytes — never legitimate, frequently used to
  // confuse downstream parsers (truncation, smuggling).
  if (value.includes('\0')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'SQL parameter contains null byte',
      400
    );
  }

  // Bound length to prevent oversized inputs from reaching the database.
  if (value.length > maxLength) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `SQL parameter exceeds maximum length of ${maxLength}`,
      400
    );
  }

  // Optional caller-supplied allowlist. Anchored to whole-string match so
  // callers cannot accidentally accept attacker-controlled prefixes. The
  // `g` flag would make `.test()` stateful via `lastIndex`, so we strip
  // it (along with `y`, which is also incompatible with anchored
  // single-call matching) when re-building the regex.
  if (allowedPattern) {
    const safeFlags = Array.from(allowedPattern.flags)
      .filter(f => f !== 'g' && f !== 'y')
      .join('');
    const anchored = new RegExp(`^(?:${allowedPattern.source})$`, safeFlags);
    if (!anchored.test(value)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'SQL parameter does not match the allowed pattern',
        400
      );
    }
  }
}

/**
 * Validate a database table name
 *
 * Ensures the table name follows safe naming conventions:
 * - Only alphanumeric characters and underscores
 * - Starts with a letter
 * - Not too long
 *
 * @param tableName The table name to validate
 * @throws CapabilityError if the table name is invalid
 */
export function validateTableName(tableName: string): void {
  // Check for empty name
  if (!tableName || tableName.trim().length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Table name cannot be empty',
      400
    );
  }

  // Check length
  if (tableName.length > 64) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Table name is too long (max 64 characters)',
      400
    );
  }

  // Check format: must start with letter, contain only alphanumeric and underscore
  if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(tableName)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Table name must start with a letter and contain only alphanumeric characters and underscores',
      400
    );
  }

  // Check for SQL reserved keywords (common ones)
  const reservedKeywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
    'TABLE', 'DATABASE', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION',
    'TRIGGER', 'USER', 'GRANT', 'REVOKE', 'UNION', 'WHERE', 'FROM',
  ];

  if (reservedKeywords.includes(tableName.toUpperCase())) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Table name cannot be a SQL reserved keyword: ${tableName}`,
      400
    );
  }
}

/**
 * Validate a database column name
 *
 * Similar to table name validation but more permissive
 *
 * @param columnName The column name to validate
 * @throws CapabilityError if the column name is invalid
 */
export function validateColumnName(columnName: string): void {
  // Check for empty name
  if (!columnName || columnName.trim().length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Column name cannot be empty',
      400
    );
  }

  // Check length
  if (columnName.length > 64) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Column name is too long (max 64 characters)',
      400
    );
  }

  // Check format: must start with letter, contain only alphanumeric and underscore
  if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(columnName)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Column name must start with a letter and contain only alphanumeric characters and underscores',
      400
    );
  }

  // Check for SQL reserved keywords
  const reservedKeywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
    'TABLE', 'DATABASE', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION',
    'TRIGGER', 'USER', 'GRANT', 'REVOKE', 'UNION', 'WHERE', 'FROM',
  ];

  if (reservedKeywords.includes(columnName.toUpperCase())) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `Column name cannot be a SQL reserved keyword: ${columnName}`,
      400
    );
  }
}

/**
 * Validate resource patterns with wildcards
 *
 * Ensures wildcard patterns are used safely and don't allow
 * overly permissive access
 *
 * @param resourcePattern The resource pattern to validate
 * @throws CapabilityError if the pattern is too permissive
 */
export function validateResourcePattern(resourcePattern: string): void {
  // Check for empty pattern
  if (!resourcePattern || resourcePattern.trim().length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Resource pattern cannot be empty',
      400
    );
  }

  // Check for overly permissive patterns
  if (resourcePattern === '*' || resourcePattern === '**') {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Wildcard-only resource patterns are not allowed',
      400
    );
  }

  // Pattern must have a scheme (e.g., "file://", "api://", "storage://")
  if (!resourcePattern.includes('://')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Resource pattern must include a scheme (e.g., file://, api://, storage://)',
      400
    );
  }

  // Check for dangerous patterns
  if (resourcePattern.includes('..')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'Resource pattern cannot contain parent directory references (..)',
      400
    );
  }

  // Wildcards are only supported as a trailing "/*" or "/**" suffix.
  // This keeps validation aligned with matchesResource().
  if (resourcePattern.includes('*')) {
    const hasSingleSegmentWildcard = resourcePattern.endsWith('/*');
    const hasRecursiveWildcard = resourcePattern.endsWith('/**');

    if (!hasSingleSegmentWildcard && !hasRecursiveWildcard) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Resource pattern wildcards are only allowed at the end as /* or /**',
        400
      );
    }

    const suffixLength = hasRecursiveWildcard ? 3 : 2;
    const patternPrefix = resourcePattern.slice(0, -suffixLength);

    if (patternPrefix.includes('*')) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Resource pattern wildcards are only allowed at the end as /* or /**',
        400
      );
    }
  }
}
