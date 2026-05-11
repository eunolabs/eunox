module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        // Map sub-packages to their source so tests run without a pre-built
        // dist/.  Mirrors the pattern used in euno-platform/packages/common/jest.config.js.
        paths: {
          '@euno/common': ['../common/src'],
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
          '@euno/common-core': ['../../../public/packages/common/src'],
          '@euno/common-infra': ['../common-infra/src'],
          '@euno/capability-issuer/adapters': ['../capability-issuer/src/exports'],
        },
      },
    }],
  },
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/index.ts',
  ],
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/common/wire$': '<rootDir>/../common/src/wire',
    '^@euno/common/runtime$': '<rootDir>/../common/src/runtime',
    '^@euno/common-core$': '<rootDir>/../../../public/packages/common/src',
    '^@euno/common-infra$': '<rootDir>/../common-infra/src',
    '^@euno/capability-issuer/adapters$': '<rootDir>/../capability-issuer/src/exports',
  },
};
