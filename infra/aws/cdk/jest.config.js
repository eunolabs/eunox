/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
  // CDK synthesis creates large temp assets; run sequentially to avoid
  // filling the disk when multiple stacks are synthesised in parallel.
  maxWorkers: 1,
};
