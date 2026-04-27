/**
 * Specialized Capability Validation
 *
 * Provides security validation for specific capability types to prevent
 * common attacks like directory traversal, SQL injection, etc.
 */

import { CapabilityError, ErrorCode } from './utils';

/**
 * Validate a file path to prevent directory traversal attacks
 *
 * Checks for:
 * - Absolute paths (e.g., /etc/passwd)
 * - Parent directory references (e.g., ../)
 * - Hidden files (e.g., .bashrc)
 * - Null bytes
 * - Other dangerous patterns
 *
 * @param filePath The file path to validate
 * @param allowedExtensions Optional list of allowed file extensions (e.g., ['.txt', '.json'])
 * @throws CapabilityError if the path is invalid
 */
export function validateFilePath(
  filePath: string,
  allowedExtensions?: string[]
): void {
  // Check for null bytes
  if (filePath.includes('\0')) {
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

  // Check for parent directory references
  if (filePath.includes('../') || filePath.includes('..\\')) {
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

  // Check for empty path
  if (!filePath || filePath.trim().length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'File path cannot be empty',
      400
    );
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

  // Check for dangerous patterns
  const dangerousPatterns = [
    /\.\.[/\\]/,         // parent directory
    /^~[/\\]/,           // home directory
    /\$\{/,              // variable interpolation
    /%00/,               // URL encoded null byte
    /%2e%2e/i,           // URL encoded ..
    /<script/i,          // script tags
    /javascript:/i,      // javascript: protocol
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(filePath)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'File path contains dangerous pattern',
        400
      );
    }
  }
}

/**
 * Validate SQL query parameters to prevent SQL injection
 *
 * This is a basic validation. For production use, always use parameterized
 * queries or prepared statements instead of string concatenation.
 *
 * Checks for:
 * - SQL keywords in suspicious positions
 * - Comment markers
 * - String terminators
 * - Union-based injection attempts
 *
 * @param value The value to validate
 * @throws CapabilityError if the value contains SQL injection patterns
 */
export function validateSQLParameter(value: string): void {
  // Check for null bytes
  if (value.includes('\0')) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'SQL parameter contains null byte',
      400
    );
  }

  // Check for SQL comment markers
  const commentPatterns = [
    '--',     // SQL line comment
    '/*',     // SQL block comment start
    '*/',     // SQL block comment end
    '#',      // MySQL comment
    ';--',    // Statement terminator with comment
  ];

  for (const pattern of commentPatterns) {
    if (value.includes(pattern)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'SQL parameter contains comment marker',
        400
      );
    }
  }

  // Check for common SQL injection patterns
  const injectionPatterns = [
    /'\s*OR\s*'?1'?\s*=\s*'?1/i,          // OR 1=1
    /'\s*OR\s*'?1'?\s*=\s*'?1\s*--/i,     // OR 1=1--
    /'\s*;\s*DROP\s+TABLE/i,              // ; DROP TABLE
    /'\s*;\s*DELETE\s+FROM/i,             // ; DELETE FROM
    /'\s*;\s*UPDATE\s+/i,                 // ; UPDATE
    /\sUNION\s+SELECT/i,                  // UNION SELECT
    /\sUNION\s+ALL\s+SELECT/i,            // UNION ALL SELECT
    /'\s*EXEC\s*\(/i,                     // EXEC(
    /'\s*EXECUTE\s*\(/i,                  // EXECUTE(
    /xp_cmdshell/i,                       // xp_cmdshell
    /sp_executesql/i,                     // sp_executesql
    /\sINTO\s+OUTFILE/i,                  // INTO OUTFILE
    /\sINTO\s+DUMPFILE/i,                 // INTO DUMPFILE
    /LOAD_FILE/i,                         // LOAD_FILE
    /\bCHAR\s*\(/i,                       // CHAR( - encoding
    /0x[0-9a-f]+/i,                       // Hex encoding
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(value)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'SQL parameter contains suspicious pattern',
        400
      );
    }
  }

  // Check for excessive quote usage (potential injection attempt)
  const singleQuotes = (value.match(/'/g) || []).length;
  const doubleQuotes = (value.match(/"/g) || []).length;

  if (singleQuotes > 2 || doubleQuotes > 2) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'SQL parameter contains excessive quotes',
      400
    );
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
