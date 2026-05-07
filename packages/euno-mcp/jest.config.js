module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common-core': ['../common-core/src'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common-core$': '<rootDir>/../common-core/src',
  },
};
