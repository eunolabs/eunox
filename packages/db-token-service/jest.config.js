module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common': ['../common/src'],
          '@euno/capability-issuer': ['../capability-issuer/src/exports'],
        },
      },
    }],
  },
  coverageDirectory: 'coverage',
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/capability-issuer$': '<rootDir>/../capability-issuer/src/exports',
    '^@nodable/entities$': '<rootDir>/../capability-issuer/tests/__mocks__/nodable-entities-stub.cjs',
  },
};
