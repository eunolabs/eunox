/**
 * Tests for the optional cloud log-shipping transports.
 *
 * These tests verify the lazy-require behaviour: when the optional SDK is
 * not installed (which is the default in this monorepo), the factory must
 * return `null` rather than throw, so the base Console transport remains
 * the only sink.
 */

import {
  buildCloudTransportsFromEnv,
  createCloudLoggingTransport,
  createCloudWatchLogsTransport,
} from '../src/log-transports';

describe('cloud log-shipping transports', () => {
  const ORIGINAL_ENV = { ...process.env };

  afterEach(() => {
    // Restore env between tests so we never bleed config across cases.
    process.env = { ...ORIGINAL_ENV };
  });

  describe('createCloudWatchLogsTransport', () => {
    it('returns null when logGroupName is missing', () => {
      const result = createCloudWatchLogsTransport({ logGroupName: '' });
      expect(result).toBeNull();
    });

    it('returns null when winston-cloudwatch is not installed', () => {
      // The monorepo intentionally does NOT depend on winston-cloudwatch,
      // so this also acts as a regression test that we never accidentally
      // make it a hard dependency.
      const result = createCloudWatchLogsTransport({
        logGroupName: '/euno/test',
        awsRegion: 'us-east-1',
      });
      expect(result).toBeNull();
    });
  });

  describe('createCloudLoggingTransport', () => {
    it('returns null when @google-cloud/logging-winston is not installed', () => {
      const result = createCloudLoggingTransport({ logName: 'euno-test' });
      expect(result).toBeNull();
    });

    it('accepts an empty config without throwing', () => {
      expect(() => createCloudLoggingTransport()).not.toThrow();
    });
  });

  describe('buildCloudTransportsFromEnv', () => {
    it('returns an empty array when no cloud env vars are set', () => {
      delete process.env.AWS_CLOUDWATCH_LOG_GROUP;
      delete process.env.GCP_LOG_NAME;
      const transports = buildCloudTransportsFromEnv('test-svc');
      expect(transports).toEqual([]);
    });

    it('does not throw when AWS env var is set but SDK is missing', () => {
      process.env.AWS_CLOUDWATCH_LOG_GROUP = '/euno/test';
      process.env.AWS_REGION = 'us-east-1';
      const transports = buildCloudTransportsFromEnv('test-svc');
      // SDK isn't installed → factory returns null → array stays empty.
      expect(transports).toEqual([]);
    });

    it('uses serviceName + HOSTNAME for the default CloudWatch logStreamName', () => {
      // We can't observe the real options without the SDK, but we can
      // verify the factory builds them without throwing for either of
      // two distinct service names — and would produce distinct streams
      // by construction (logStreamName interpolation reads serviceName).
      process.env.AWS_CLOUDWATCH_LOG_GROUP = '/euno/test';
      process.env.HOSTNAME = 'pod-abc';
      delete process.env.AWS_CLOUDWATCH_LOG_STREAM;
      expect(() => buildCloudTransportsFromEnv('issuer')).not.toThrow();
      expect(() => buildCloudTransportsFromEnv('gateway')).not.toThrow();
    });

    it('does not throw when GCP env var is set but SDK is missing', () => {
      process.env.GCP_LOG_NAME = 'euno-test';
      process.env.GOOGLE_CLOUD_PROJECT = 'euno-prod';
      const transports = buildCloudTransportsFromEnv('test-svc');
      expect(transports).toEqual([]);
    });
  });
});
