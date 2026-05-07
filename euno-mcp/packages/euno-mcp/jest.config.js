module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        paths: {
          '@euno/common-core': ['../common-core/src'],
          '@modelcontextprotocol/sdk/client/index.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/client/index.d.ts'],
          '@modelcontextprotocol/sdk/client/stdio.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/client/stdio.d.ts'],
          '@modelcontextprotocol/sdk/client/streamableHttp.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/client/streamableHttp.d.ts'],
          '@modelcontextprotocol/sdk/server/index.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/index.d.ts'],
          '@modelcontextprotocol/sdk/server/stdio.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/stdio.d.ts'],
          '@modelcontextprotocol/sdk/server/streamableHttp.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/streamableHttp.d.ts'],
          '@modelcontextprotocol/sdk/types.js': ['../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/types.d.ts'],
        },
      },
    }],
  },
  moduleNameMapper: {
    '^@euno/common-core$': '<rootDir>/../common-core/src',
    // Map SDK public-API subpath imports (with .js) to their actual CJS files.
    // Using the exports-map-compatible paths (without dist/cjs prefix) + .js
    // extension avoids Node.js v24's wildcard exports double-expansion bug.
    '^@modelcontextprotocol/sdk/(.+\\.js)$': '<rootDir>/../../../node_modules/@modelcontextprotocol/sdk/dist/cjs/$1',
  },
};
