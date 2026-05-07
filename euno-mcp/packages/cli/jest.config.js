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
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/common/wire$': '<rootDir>/../common/src/wire',
    '^@euno/common/runtime$': '<rootDir>/../common/src/runtime',
  },
  // Spawning the CLI as a subprocess can take a few seconds on cold caches.
  testTimeout: 30000,
};
