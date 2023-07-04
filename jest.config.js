/* eslint-disable no-undef */
/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  testTimeout: 10 * 60 * 1000,
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns: ['attic'],
  coverageReporters: ['json-summary'],
};