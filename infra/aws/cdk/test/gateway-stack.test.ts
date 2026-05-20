/**
 * Unit tests for EunoGatewayStack.
 *
 * Uses aws-cdk-lib/assertions to synthesize the stack and make assertions
 * about the CloudFormation template produced.
 *
 * Run with:
 *   cd infra/aws/cdk && npm install && npm test
 */

import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { EunoGatewayStack } from '../src/stacks/gateway-stack';

const defaultEnv = {
  account: '123456789012',
  region: 'us-east-1',
};

function makeStack(props: Partial<ConstructorParameters<typeof EunoGatewayStack>[2]> = {}) {
  const app = new cdk.App();
  return new EunoGatewayStack(app, 'TestGateway', {
    env: defaultEnv,
    namePrefix: 'euno',
    environment: 'test',
    ...props,
  });
}

describe('EunoGatewayStack', () => {
  describe('KMS signing key', () => {
    test('creates an RSA-2048 SIGN_VERIFY key', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KMS::Key', {
        KeySpec: 'RSA_2048',
        KeyUsage: 'SIGN_VERIFY',
        EnableKeyRotation: false,
      });
    });

    test('sets a human-readable alias', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KMS::Alias', {
        AliasName: 'alias/euno-capability-signing',
      });
    });
  });

  describe('S3 audit anchor bucket', () => {
    test('enables versioning (required for Object Lock)', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::S3::Bucket', {
        VersioningConfiguration: { Status: 'Enabled' },
        ObjectLockEnabled: true,
      });
    });

    test('blocks all public access', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::S3::Bucket', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      });
    });
  });

  describe('Secrets Manager', () => {
    test('creates an HMAC key secret', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Name: 'euno/test/audit-ledger-hmac-secret',
      });
    });

    test('creates an admin API key secret', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Name: 'euno/test/gateway-admin-api-key',
      });
    });

    test('creates a Redis auth token secret', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Name: 'euno/test/redis-auth-token',
      });
    });
  });

  describe('CloudWatch log groups', () => {
    test('creates a runtime log group', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Logs::LogGroup', {
        LogGroupName: '/euno/runtime',
      });
    });

    test('creates an audit log group', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Logs::LogGroup', {
        LogGroupName: '/euno/audit',
      });
    });
  });

  describe('ECR repositories', () => {
    test('creates repositories for all Euno service images', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      const expectedImages = [
        'euno/capability-issuer',
        'euno/tool-gateway',
        'euno/api-key-minter',
        'euno/db-token-service',
        'euno/storage-grant-service',
        'euno/posture-emitter',
      ];
      for (const repositoryName of expectedImages) {
        template.hasResourceProperties('AWS::ECR::Repository', { RepositoryName: repositoryName });
      }
    });

    test('enables image scanning on push', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::ECR::Repository', {
        ImageScanningConfiguration: { ScanOnPush: true },
      });
    });

    test('sets IMMUTABLE image tag mutability', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::ECR::Repository', {
        ImageTagMutability: 'IMMUTABLE',
      });
    });
  });

  describe('RDS PostgreSQL', () => {
    test('creates a PostgreSQL 15.4 database instance', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::RDS::DBInstance', {
        Engine: 'postgres',
        DBInstanceClass: 'db.t3.medium',
        StorageEncrypted: true,
        MultiAZ: true,
      });
    });

    test('enables deletion protection', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::RDS::DBInstance', {
        DeletionProtection: true,
      });
    });
  });

  describe('ElastiCache Redis', () => {
    test('creates a Redis replication group with encryption', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::ElastiCache::ReplicationGroup', {
        AtRestEncryptionEnabled: true,
        TransitEncryptionEnabled: true,
        AutomaticFailoverEnabled: true,
        Engine: 'redis',
        EngineVersion: '7.1',
      });
    });
  });

  describe('EKS cluster', () => {
    test('creates an EKS cluster with audit logging enabled', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::AWSCDK-EKS-Cluster', {
        Config: {
          name: 'euno-eks-test',
          logging: {
            clusterLogging: [
              {
                types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
                enabled: true,
              },
            ],
          },
        },
      });
    });

    test('creates a Fargate profile for euno-system namespace by default', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::AWSCDK-EKS-FargateProfile', {
        Config: {
          fargateProfileName: 'euno-system',
          selectors: [
            { namespace: 'euno-system' },
            { namespace: 'euno-monitoring' },
          ],
        },
      });
    });
  });

  describe('Gateway IRSA role', () => {
    test('creates an IAM role with the correct name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Role', {
        RoleName: 'euno-gateway-irsa-test',
      });
    });

    test('includes KMS Verify permissions', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: [
            {
              Sid: 'VerifyCapabilityTokens',
              Effect: 'Allow',
              Action: ['kms:Verify', 'kms:GetPublicKey', 'kms:DescribeKey'],
            },
          ],
        },
      });
    });
  });

  describe('VPC', () => {
    test('creates a VPC with public and private subnets', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.resourceCountIs('AWS::EC2::VPC', 1);
      // 3 AZs × 3 subnet types = 9 subnets
      template.resourceCountIs('AWS::EC2::Subnet', 9);
    });

    test('creates NAT gateways for egress from private subnets', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.resourceCountIs('AWS::EC2::NatGateway', 3);
    });
  });

  describe('Stack outputs', () => {
    test('exports the cluster name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('ClusterName', {
        Export: { Name: 'euno-test-cluster-name' },
      });
    });

    test('exports the signing key ARN', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('SigningKeyArn', {
        Export: { Name: 'euno-test-signing-key-arn' },
      });
    });

    test('exports the audit anchor bucket name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('AuditAnchorBucketName', {
        Export: { Name: 'euno-test-audit-anchor-bucket' },
      });
    });
  });
});
