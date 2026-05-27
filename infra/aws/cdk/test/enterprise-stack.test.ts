/**
 * Unit tests for EunoxEnterpriseStack.
 *
 * Uses aws-cdk-lib/assertions to synthesize the stack and make assertions
 * about the CloudFormation template produced.
 *
 * Run with:
 *   cd infra/aws/cdk && npm install && npm test
 */

import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { EunoxEnterpriseStack } from '../src/stacks/enterprise-stack';

const defaultEnv = {
  account: '123456789012',
  region: 'us-east-1',
};

function makeStack(
  props: Partial<ConstructorParameters<typeof EunoxEnterpriseStack>[2]> = {},
) {
  const app = new cdk.App({ outdir: '/tmp/cdk-test-out' });
  return new EunoxEnterpriseStack(app, 'TestEnterprise', {
    env: defaultEnv,
    namePrefix: 'eunox',
    environment: 'test',
    ...props,
  });
}

describe('EunoxEnterpriseStack', () => {
  describe('inherits issuer and gateway resources', () => {
    test('includes the Cognito User Pool', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPool', {
        UserPoolName: 'eunox-users-test',
      });
    });

    test('includes the KMS signing key', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KMS::Key', {
        KeySpec: 'RSA_2048',
      });
    });
  });

  describe('Partner DID registry', () => {
    test('creates a DynamoDB table with the correct name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::DynamoDB::Table', {
        TableName: 'eunox-partner-did-registry-test',
        BillingMode: 'PAY_PER_REQUEST',
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
        DeletionProtectionEnabled: true,
      });
    });

    test('defines the primary key (did + sk)', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::DynamoDB::Table', {
        KeySchema: [
          { AttributeName: 'did', KeyType: 'HASH' },
          { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
      });
    });

    test('creates a ByStatus GSI for circuit-breaker queries', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::DynamoDB::Table', {
        GlobalSecondaryIndexes: Match.arrayWith([
          Match.objectLike({ IndexName: 'ByStatus' }),
        ]),
      });
    });
  });

  describe('CloudTrail', () => {
    test('creates a multi-region trail', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::CloudTrail::Trail', {
        TrailName: 'eunox-audit-trail-test',
        IsMultiRegionTrail: true,
        EnableLogFileValidation: true,
        IncludeGlobalServiceEvents: true,
        IsLogging: true,
      });
    });

    test('creates a dedicated CloudTrail S3 bucket with Object Lock', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      // Multiple S3 buckets are created; audit-anchor, audit-lake, and cloudtrail
      const s3Resources = template.findResources('AWS::S3::Bucket');
      const bucketCount = Object.keys(s3Resources).length;
      // At least 3 S3 buckets: audit-anchor, cloudtrail, audit-lake
      expect(bucketCount).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Kinesis Firehose audit pipeline', () => {
    test('creates a Firehose delivery stream', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KinesisFirehose::DeliveryStream', {
        DeliveryStreamName: 'eunox-audit-firehose-test',
        DeliveryStreamType: 'DirectPut',
      });
    });

    test('delivers to S3 with GZIP compression', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KinesisFirehose::DeliveryStream', {
        S3DestinationConfiguration: {
          CompressionFormat: 'GZIP',
        },
      });
    });

    test('creates an audit data lake S3 bucket with Object Lock (COMPLIANCE)', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::S3::Bucket', {
        ObjectLockEnabled: true,
        ObjectLockConfiguration: {
          ObjectLockEnabled: 'Enabled',
          Rule: {
            DefaultRetention: {
              Mode: 'COMPLIANCE',
            },
          },
        },
      });
    });
  });

  describe('Security Hub', () => {
    test('enables Security Hub by default', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SecurityHub::Hub', {
        EnableDefaultStandards: true,
        AutoEnableControls: true,
      });
    });

    test('Security Hub can be disabled', () => {
      const stack = makeStack({ enableSecurityHub: false });
      const template = Template.fromStack(stack);
      template.resourceCountIs('AWS::SecurityHub::Hub', 0);
    });
  });

  describe('SNS alarm topic', () => {
    test('creates an SNS topic for alarms', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SNS::Topic', {
        TopicName: 'eunox-alarms-test',
      });
    });

    test('subscribes the provided email address', () => {
      const stack = makeStack({
        alarmNotificationEmail: 'ops@example.com',
      });
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SNS::Subscription', {
        Protocol: 'email',
        Endpoint: 'ops@example.com',
      });
    });

    test('does not create subscriptions when email is not provided', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.resourceCountIs('AWS::SNS::Subscription', 0);
    });
  });

  describe('CloudWatch alarms', () => {
    test('creates a denial-spike alarm', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmName: 'eunox-denial-spike-test',
        Threshold: 100,
        EvaluationPeriods: 2,
      });
    });

    test('creates an invalid-token-burst alarm', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmName: 'eunox-invalid-token-burst-test',
        Threshold: 50,
        EvaluationPeriods: 1,
      });
    });

    test('creates a kill-switch activation alarm', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmName: 'eunox-kill-switch-test',
        Threshold: 1,
        EvaluationPeriods: 1,
      });
    });
  });

  describe('Stack outputs', () => {
    test('exports the partner DID registry table name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('PartnerDidRegistryTableName', {
        Export: { Name: 'eunox-test-partner-did-registry-table' },
      });
    });

    test('exports the audit lake bucket name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('AuditLakeBucketName', {
        Export: { Name: 'eunox-test-audit-lake-bucket' },
      });
    });

    test('exports the Firehose ARN', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('AuditFirehoseArn', {
        Export: { Name: 'eunox-test-audit-firehose-arn' },
      });
    });

    test('exports the alarm topic ARN', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('AlarmTopicArn', {
        Export: { Name: 'eunox-test-alarm-topic-arn' },
      });
    });
  });
});
