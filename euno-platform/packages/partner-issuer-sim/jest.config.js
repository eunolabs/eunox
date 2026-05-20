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
          '@euno/common/wire': ['../common/src/wire'],
          '@euno/common/runtime': ['../common/src/runtime'],
          '@euno/common-core': ['../../../public/packages/common/src'],
          '@euno/common-core/*': ['../../../public/packages/common/src/*'],
          '@euno/common-infra': ['../common-infra/src'],
          '@euno/capability-issuer': ['../capability-issuer/src'],
          '@euno/capability-issuer/adapters': ['../capability-issuer/src/exports'],
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
    '^@euno/capability-issuer$': '<rootDir>/../capability-issuer/src',
    '^@euno/capability-issuer/adapters$': '<rootDir>/../capability-issuer/src/exports',
  },
};
