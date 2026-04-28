module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js'],
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/capability-issuer$': '<rootDir>/../capability-issuer/src',
    '^@euno/capability-issuer/adapters$': '<rootDir>/../capability-issuer/src/exports',
    '^@euno/tool-gateway$': '<rootDir>/../tool-gateway/src',
    '^@euno/agent-runtime$': '<rootDir>/../agent-runtime/src',
  },
  testTimeout: 30000,
  verbose: true,
};
