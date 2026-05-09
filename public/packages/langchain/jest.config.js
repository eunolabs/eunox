module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  globalSetup: './jest.globalSetup.js',
  testMatch: ['**/?(*.)+(spec|test).ts'],
  forceExit: true,
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common-core': ['../common/src'],
          '@euno/mcp': ['../mcp/src'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common-core$': '<rootDir>/../common/src',
    '^@euno/mcp$': '<rootDir>/../mcp/src',
  },
};
