module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common': ['../../../euno-platform/packages/common/src'],
          '@euno/common/wire': ['../../../euno-platform/packages/common/src/wire'],
          '@euno/common/runtime': ['../../../euno-platform/packages/common/src/runtime'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../../../euno-platform/packages/common/src',
    '^@euno/common/wire$': '<rootDir>/../../../euno-platform/packages/common/src/wire',
    '^@euno/common/runtime$': '<rootDir>/../../../euno-platform/packages/common/src/runtime',
  },
  // Spawning the CLI as a subprocess can take a few seconds on cold caches.
  testTimeout: 30000,
};
