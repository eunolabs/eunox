module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        baseUrl: '.',
        paths: {
          '@euno/common-core': ['../../../public/packages/common/src'],
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
    '^@euno/common-core$': '<rootDir>/../../../public/packages/common/src',
  },
};
