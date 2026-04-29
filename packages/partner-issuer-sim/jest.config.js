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
          '@euno/capability-issuer': ['../capability-issuer/src'],
          '@euno/capability-issuer/adapters': ['../capability-issuer/src/exports'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/capability-issuer$': '<rootDir>/../capability-issuer/src',
    '^@euno/capability-issuer/adapters$': '<rootDir>/../capability-issuer/src/exports',
  },
};
