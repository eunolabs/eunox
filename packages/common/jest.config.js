module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        // Let ts-jest resolve @euno/common* sub-path imports from source so
        // the wire-runtime-split tests can import @euno/common/wire etc. without
        // a pre-built dist/.  Mirrors the same pattern used in tool-gateway.
        baseUrl: '.',
        paths: {
          '@euno/common': ['src'],
          '@euno/common/wire': ['src/wire'],
          '@euno/common/runtime': ['src/runtime'],
          '@euno/common/types': ['src/types'],
          '@euno/common-core': ['../common-core/src'],
          '@euno/common-infra': ['../common-infra/src'],
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
    '^@euno/common/types$': '<rootDir>/../common/src/types',
    '^@euno/common-core$': '<rootDir>/../common-core/src',
    '^@euno/common-infra$': '<rootDir>/../common-infra/src',
  },
};
