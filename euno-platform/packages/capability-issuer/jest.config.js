module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  setupFiles: ['./tests/jest.setup.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common': ['../common/src'],
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
          '@euno/common-core': ['../../../public/packages/common/src'],
          '@euno/common-core/*': ['../../../public/packages/common/src/*'],
          '@euno/common-infra': ['../common-infra/src'],
          '@euno/posture-emitter': ['../posture-emitter/src'],
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
    '^@euno/common-core/(.*)$': '<rootDir>/../../../public/packages/common/src/$1',
    '^@euno/common-infra$': '<rootDir>/../common-infra/src',
    '^@euno/posture-emitter$': '<rootDir>/../posture-emitter/src',
    // The `@nodable/entities` package (a transitive dependency of the AWS SDK's
    // XML parser) ships as pure ESM and cannot be loaded by Jest's CommonJS
    // runtime. Tests mock all AWS KMS interactions, so we substitute a CJS stub.
    '^@nodable/entities$': '<rootDir>/tests/__mocks__/nodable-entities-stub.cjs',
  },
};
