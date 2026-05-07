module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common': ['../common/src'],
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
          '@euno/capability-issuer': ['../capability-issuer/src'],
          '@euno/capability-issuer/adapters': ['../capability-issuer/src/exports'],
          '@euno/tool-gateway': ['../tool-gateway/src'],
          '@euno/agent-runtime': ['../agent-runtime/src'],
          '@euno/partner-issuer-sim': ['../partner-issuer-sim/src'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/common/wire$': '<rootDir>/../common/src/wire',
    '^@euno/common/runtime$': '<rootDir>/../common/src/runtime',
    '^@euno/capability-issuer$': '<rootDir>/../capability-issuer/src',
    '^@euno/capability-issuer/adapters$': '<rootDir>/../capability-issuer/src/exports',
    '^@euno/tool-gateway$': '<rootDir>/../tool-gateway/src',
    '^@euno/agent-runtime$': '<rootDir>/../agent-runtime/src',
    '^@euno/partner-issuer-sim$': '<rootDir>/../partner-issuer-sim/src',
  },
  testTimeout: 30000,
  verbose: true,
};
