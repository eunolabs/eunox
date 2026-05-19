module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js'],
  collectCoverage: false,
  coverageDirectory: 'coverage',
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
  verbose: true,
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        baseUrl: '.',
        paths: {
          '@euno/common': ['../common/src'],
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
          '@euno/common-core': ['../../../public/packages/common/src'],
          '@euno/common-core/*': ['../../../public/packages/common/src/*'],
          '@euno/common-infra': ['../common-infra/src'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common$': '<rootDir>/../common/src',
    '^@euno/common/wire$': '<rootDir>/../common/src/wire',
    '^@euno/common/runtime$': '<rootDir>/../common/src/runtime',
    '^@euno/common-core$': '<rootDir>/../../../public/packages/common/src',
    '^@euno/common-core/(.*)$': '<rootDir>/../../../public/packages/common/src/$1',
    '^@euno/common-infra$': '<rootDir>/../common-infra/src',
  },
};
