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

    it('should reject dangerous patterns', () => {
      expect(() => validateFilePath('~/secrets')).toThrow(CapabilityError);
      expect(() => validateFilePath('file${var}.txt')).toThrow(CapabilityError);
      expect(() => validateFilePath('file%00.txt')).toThrow(CapabilityError);
      expect(() => validateFilePath('file%2e%2e/etc')).toThrow(CapabilityError);
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
  });

  describe('invalid SQL parameters', () => {
    it('should reject SQL comments', () => {
      expect(() => validateSQLParameter('admin--')).toThrow(CapabilityError);
      expect(() => validateSQLParameter('test/*comment*/')).toThrow(CapabilityError);
      expect(() => validateSQLParameter('value#comment')).toThrow(CapabilityError);
    });

    it('should reject SQL injection patterns', () => {
      expect(() => validateSQLParameter("' OR '1'='1")).toThrow(CapabilityError);
      expect(() => validateSQLParameter("' OR 1=1--")).toThrow(CapabilityError);
      expect(() => validateSQLParameter("'; DROP TABLE users--")).toThrow(CapabilityError);
      expect(() => validateSQLParameter("'; DELETE FROM users--")).toThrow(CapabilityError);
    });

    it('should reject UNION-based injection', () => {
      expect(() => validateSQLParameter("' UNION SELECT password FROM users--")).toThrow(CapabilityError);
      expect(() => validateSQLParameter("' UNION ALL SELECT * FROM admin--")).toThrow(CapabilityError);
    });

    it('should reject command execution attempts', () => {
      expect(() => validateSQLParameter('EXEC(xp_cmdshell)')).toThrow(CapabilityError);
      expect(() => validateSQLParameter('EXECUTE(sp_executesql)')).toThrow(CapabilityError);
    });

    it('should reject file operations', () => {
      expect(() => validateSQLParameter("' INTO OUTFILE '/tmp/dump'")).toThrow(CapabilityError);
      expect(() => validateSQLParameter('LOAD_FILE(\'/etc/passwd\')')).toThrow(CapabilityError);
    });

    it('should reject excessive quotes', () => {
      expect(() => validateSQLParameter("'''test'''")).toThrow(CapabilityError);
      expect(() => validateSQLParameter('"""test"""')).toThrow(CapabilityError);
    });

    it('should reject null bytes', () => {
      expect(() => validateSQLParameter('test\0value')).toThrow(CapabilityError);
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
  });
});

describe('validateResourcePattern', () => {
  describe('valid resource patterns', () => {
    it('should accept pattern with scheme and path', () => {
      expect(() => validateResourcePattern('file://documents/*.txt')).not.toThrow();
    });

    it('should accept pattern with wildcard', () => {
      expect(() => validateResourcePattern('api://service/*')).not.toThrow();
    });

    it('should accept pattern with multiple segments', () => {
      expect(() => validateResourcePattern('storage://bucket/folder/*')).not.toThrow();
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
  });
});
