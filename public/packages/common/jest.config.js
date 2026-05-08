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
          '@euno/common-core': ['src'],
          '@euno/common-core/wire': ['src/wire'],
          '@euno/common-core/runtime': ['src/runtime'],
          '@euno/common-core/types': ['src/types'],
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
    '^@euno/common-core$': '<rootDir>/src',
    '^@euno/common-core/wire$': '<rootDir>/src/wire',
    '^@euno/common-core/runtime$': '<rootDir>/src/runtime',
    '^@euno/common-core/types$': '<rootDir>/src/types',
  },
};
