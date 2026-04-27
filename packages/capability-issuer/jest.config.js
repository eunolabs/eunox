module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common': ['../common/src'],
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
    // The `@nodable/entities` package (a transitive dependency of the AWS SDK's
    // XML parser) ships as pure ESM and cannot be loaded by Jest's CommonJS
    // runtime. Tests mock all AWS KMS interactions, so we substitute a CJS stub.
    '^@nodable/entities$': '<rootDir>/tests/__mocks__/nodable-entities-stub.cjs',
  },
};
