/**
 * Tests for specialized capability validators
 */

import {
  validateFilePath,
  validateSQLParameter,
  validateTableName,
  validateColumnName,
  validateResourcePattern,
  CapabilityError,
} from '../src';

describe('validateFilePath', () => {
  describe('valid file paths', () => {
    it('should accept simple filename', () => {
      expect(() => validateFilePath('file.txt')).not.toThrow();
    });

    it('should accept relative path with subdirectories', () => {
      expect(() => validateFilePath('docs/readme.md')).not.toThrow();
    });

    it('should accept path with multiple levels', () => {
      expect(() => validateFilePath('a/b/c/file.json')).not.toThrow();
    });

    it('should accept path with allowed extension', () => {
      expect(() => validateFilePath('data.json', ['.json', '.txt'])).not.toThrow();
    });
  });

  describe('invalid file paths', () => {
    it('should reject absolute Unix paths', () => {
      expect(() => validateFilePath('/etc/passwd')).toThrow(CapabilityError);
      expect(() => validateFilePath('/etc/passwd')).toThrow('Absolute file paths are not allowed');
    });

    it('should reject absolute Windows paths', () => {
      expect(() => validateFilePath('C:\\Windows\\System32')).toThrow(CapabilityError);
      expect(() => validateFilePath('D:/Users/test')).toThrow(CapabilityError);
    });

    it('should reject parent directory references', () => {
      expect(() => validateFilePath('../etc/passwd')).toThrow(CapabilityError);
      expect(() => validateFilePath('docs/../../../etc/passwd')).toThrow(CapabilityError);
      expect(() => validateFilePath('..\\Windows\\System32')).toThrow(CapabilityError);
    });

    it('should reject current directory references at start', () => {
      expect(() => validateFilePath('./file.txt')).toThrow(CapabilityError);
      expect(() => validateFilePath('.\\file.txt')).toThrow(CapabilityError);
    });

    it('should reject hidden files', () => {
      expect(() => validateFilePath('.bashrc')).toThrow(CapabilityError);
      expect(() => validateFilePath('docs/.hidden')).toThrow(CapabilityError);
    });

    it('should reject null bytes', () => {
      expect(() => validateFilePath('file\0.txt')).toThrow(CapabilityError);
      expect(() => validateFilePath('file.txt\0')).toThrow(CapabilityError);
    });

    it('should reject empty path', () => {
      expect(() => validateFilePath('')).toThrow(CapabilityError);
      expect(() => validateFilePath('   ')).toThrow(CapabilityError);
    });

    it('should reject disallowed file extensions', () => {
      expect(() => validateFilePath('script.exe', ['.txt', '.json'])).toThrow(CapabilityError);
      expect(() => validateFilePath('data.xml', ['.json'])).toThrow(CapabilityError);
    });

    it('should reject home-directory and encoded-traversal patterns', () => {
      expect(() => validateFilePath('~/secrets')).toThrow(CapabilityError);
      expect(() => validateFilePath('file%00.txt')).toThrow(CapabilityError);
      expect(() => validateFilePath('file%2e%2e/etc')).toThrow(CapabilityError);
    });

    it('does not pretend to detect "dangerous content" inside legitimate paths', () => {
      // Earlier versions rejected these via a kitchen-sink denylist that
      // both missed real attacks and rejected legitimate filenames. The
      // structural checks (absolute / traversal / null byte / hidden /
      // empty) remain — those are unambiguous. Content-style rejections
      // are deliberately removed; the storage layer is responsible for
      // resolving paths against a fixed root.
      expect(() => validateFilePath('docs/file${var}.txt')).not.toThrow();
      expect(() => validateFilePath('docs/javascript-tutorial.md')).not.toThrow();
      expect(() => validateFilePath('docs/script-tag-guide.md')).not.toThrow();
    });
  });
});

describe('validateSQLParameter', () => {
  describe('valid SQL parameters', () => {
    it('should accept simple string', () => {
      expect(() => validateSQLParameter('John Doe')).not.toThrow();
    });

    it('should accept string with single quote', () => {
      expect(() => validateSQLParameter("O'Brien")).not.toThrow();
    });

    it('should accept numeric string', () => {
      expect(() => validateSQLParameter('12345')).not.toThrow();
    });

    it('should accept email address', () => {
      expect(() => validateSQLParameter('user@example.com')).not.toThrow();
    });

    // The previous blacklist-based implementation rejected these
    // legitimate strings because they happened to contain SQL-looking
    // tokens. The new contract is structural-only: the validator does
    // not pretend to detect SQL injection. Real defense is parameterized
    // queries upstream.
    it('should accept legitimate strings that look SQL-ish', () => {
      expect(() => validateSQLParameter('admin--user')).not.toThrow();
      expect(() => validateSQLParameter("'''triple''' quoted name")).not.toThrow();
      expect(() => validateSQLParameter('UNION pacific railroad')).not.toThrow();
      expect(() => validateSQLParameter('Order #1234')).not.toThrow();
    });
  });

  describe('structural rejections', () => {
    it('should reject null bytes', () => {
      expect(() => validateSQLParameter('test\0value')).toThrow(CapabilityError);
      expect(() => validateSQLParameter('test\0value')).toThrow('null byte');
    });

    it('should reject non-string values', () => {
      // Type-erased call to mirror real callers handling untyped JSON input.
      expect(() => validateSQLParameter(123 as unknown as string)).toThrow(CapabilityError);
    });

    it('should reject values exceeding maxLength', () => {
      const huge = 'a'.repeat(5000);
      expect(() => validateSQLParameter(huge)).toThrow(CapabilityError);
      expect(() => validateSQLParameter(huge, undefined, 10000)).not.toThrow();
    });
  });

  describe('caller-supplied allowlist', () => {
    it('accepts values that match the allowlist pattern', () => {
      expect(() =>
        validateSQLParameter('123e4567-e89b-12d3-a456-426614174000', /[0-9a-f-]+/i)
      ).not.toThrow();
    });

    it('rejects values that do not match the allowlist pattern', () => {
      expect(() =>
        validateSQLParameter("' OR '1'='1", /[0-9a-f-]+/i)
      ).toThrow(CapabilityError);
    });

    it('anchors the allowlist pattern to the whole value', () => {
      // A bare alphanumeric pattern must not accept a value that happens
      // to *start* with alphanumeric characters.
      expect(() =>
        validateSQLParameter('abc; DROP TABLE users', /[a-z]+/)
      ).toThrow(CapabilityError);
    });
  });
});

describe('validateTableName', () => {
  describe('valid table names', () => {
    it('should accept simple table name', () => {
      expect(() => validateTableName('users')).not.toThrow();
    });

    it('should accept table name with underscores', () => {
      expect(() => validateTableName('user_profiles')).not.toThrow();
    });

    it('should accept table name with numbers', () => {
      expect(() => validateTableName('users_v2')).not.toThrow();
    });

    it('should accept long valid name', () => {
      expect(() => validateTableName('a' + '1'.repeat(62))).not.toThrow();
    });
  });

  describe('invalid table names', () => {
    it('should reject empty name', () => {
      expect(() => validateTableName('')).toThrow(CapabilityError);
      expect(() => validateTableName('   ')).toThrow(CapabilityError);
    });

    it('should reject names starting with number', () => {
      expect(() => validateTableName('123users')).toThrow(CapabilityError);
    });

    it('should reject names starting with underscore', () => {
      expect(() => validateTableName('_users')).toThrow(CapabilityError);
    });

    it('should reject names with special characters', () => {
      expect(() => validateTableName('user-profiles')).toThrow(CapabilityError);
      expect(() => validateTableName('user.profiles')).toThrow(CapabilityError);
      expect(() => validateTableName('user$profiles')).toThrow(CapabilityError);
    });

    it('should reject names that are too long', () => {
      expect(() => validateTableName('a' + '1'.repeat(64))).toThrow(CapabilityError);
    });

    it('should reject SQL reserved keywords', () => {
      expect(() => validateTableName('SELECT')).toThrow(CapabilityError);
      expect(() => validateTableName('DROP')).toThrow(CapabilityError);
      expect(() => validateTableName('TABLE')).toThrow(CapabilityError);
      expect(() => validateTableName('user')).toThrow(CapabilityError);
    });
  });
});

describe('validateColumnName', () => {
  describe('valid column names', () => {
    it('should accept simple column name', () => {
      expect(() => validateColumnName('username')).not.toThrow();
    });

    it('should accept column name with underscores', () => {
      expect(() => validateColumnName('created_at')).not.toThrow();
    });

    it('should accept column name with numbers', () => {
      expect(() => validateColumnName('field1')).not.toThrow();
    });
  });

  describe('invalid column names', () => {
    it('should reject empty name', () => {
      expect(() => validateColumnName('')).toThrow(CapabilityError);
    });

    it('should reject names starting with number', () => {
      expect(() => validateColumnName('123field')).toThrow(CapabilityError);
    });

    it('should reject names with special characters', () => {
      expect(() => validateColumnName('user-name')).toThrow(CapabilityError);
      expect(() => validateColumnName('user.name')).toThrow(CapabilityError);
    });

    it('should reject names that are too long', () => {
      expect(() => validateColumnName('a' + '1'.repeat(64))).toThrow(CapabilityError);
    });

    it('should reject SQL reserved keywords', () => {
      expect(() => validateColumnName('SELECT')).toThrow(CapabilityError);
      expect(() => validateColumnName('from')).toThrow(CapabilityError);
      expect(() => validateColumnName('WHERE')).toThrow(CapabilityError);
    });
  });
});

describe('validateResourcePattern', () => {
  describe('valid resource patterns', () => {
    it('should accept pattern with scheme and path', () => {
      expect(() => validateResourcePattern('file://documents/reports')).not.toThrow();
    });

    it('should accept pattern with trailing /* wildcard', () => {
      expect(() => validateResourcePattern('api://service/*')).not.toThrow();
    });

    it('should accept pattern with trailing /** wildcard', () => {
      expect(() => validateResourcePattern('storage://bucket/folder/**')).not.toThrow();
    });

    it('should accept exact resource without wildcard', () => {
      expect(() => validateResourcePattern('api://service/endpoint')).not.toThrow();
    });
  });

  describe('invalid resource patterns', () => {
    it('should reject wildcard-only patterns', () => {
      expect(() => validateResourcePattern('*')).toThrow(CapabilityError);
      expect(() => validateResourcePattern('**')).toThrow(CapabilityError);
    });

    it('should reject patterns without scheme', () => {
      expect(() => validateResourcePattern('documents/*.txt')).toThrow(CapabilityError);
    });

    it('should reject empty pattern', () => {
      expect(() => validateResourcePattern('')).toThrow(CapabilityError);
    });

    it('should reject patterns with parent directory references', () => {
      expect(() => validateResourcePattern('file://../secrets/*')).toThrow(CapabilityError);
    });

    it('should reject wildcards not at the end as /* or /**', () => {
      expect(() => validateResourcePattern('file://documents/*.txt')).toThrow(CapabilityError);
      expect(() => validateResourcePattern('api://*/endpoint')).toThrow(CapabilityError);
    });

    it('should reject multiple wildcards', () => {
      expect(() => validateResourcePattern('api://*/*')).toThrow(CapabilityError);
      expect(() => validateResourcePattern('api://**/**')).toThrow(CapabilityError);
    });
  });
});
