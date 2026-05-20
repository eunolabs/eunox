/**
 * Unit tests for EunoIssuerStack.
 *
 * Uses aws-cdk-lib/assertions to synthesize the stack and make assertions
 * about the CloudFormation template produced.
 *
 * Run with:
 *   cd infra/aws/cdk && npm install && npm test
 */

import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { EunoIssuerStack } from '../src/stacks/issuer-stack';

const defaultEnv = {
  account: '123456789012',
  region: 'us-east-1',
};

function makeStack(
  props: Partial<ConstructorParameters<typeof EunoIssuerStack>[2]> = {},
) {
  const app = new cdk.App();
  return new EunoIssuerStack(app, 'TestIssuer', {
    env: defaultEnv,
    namePrefix: 'euno',
    environment: 'test',
    ...props,
  });
}

describe('EunoIssuerStack', () => {
  describe('inherits gateway resources', () => {
    test('includes the KMS signing key', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KMS::Key', {
        KeySpec: 'RSA_2048',
        KeyUsage: 'SIGN_VERIFY',
      });
    });

    test('includes the S3 audit anchor bucket', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::S3::Bucket', {
        ObjectLockEnabled: true,
      });
    });

    test('includes ECR repositories', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::ECR::Repository', {
        RepositoryName: 'euno/capability-issuer',
      });
    });
  });

  describe('Cognito User Pool', () => {
    test('creates a Cognito User Pool with the correct name', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPool', {
        UserPoolName: 'euno-users-test',
        MfaConfiguration: 'OPTIONAL',
      });
    });

    test('configures password policy', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPool', {
        Policies: {
          PasswordPolicy: {
            MinimumLength: 12,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireNumbers: true,
            RequireSymbols: true,
          },
        },
      });
    });

    test('creates the operators user group', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPoolGroup', {
        GroupName: 'operators',
      });
    });

    test('creates the agent-users user group', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPoolGroup', {
        GroupName: 'agent-users',
      });
    });

    test('creates an app client with SRP auth flow', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
        ClientName: 'euno-agent-runtime',
        ExplicitAuthFlows: Match.arrayWith(['ALLOW_USER_SRP_AUTH']),
        AccessTokenValidity: 15,
        IdTokenValidity: 15,
        RefreshTokenValidity: 30,
      });
    });

    test('creates a Cognito User Pool Domain for SCIM bridge', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::Cognito::UserPoolDomain', {
        Domain: 'euno-test',
      });
    });
  });

  describe('Secrets', () => {
    test('creates a PARTNER_DID_PIN_SECRET', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Name: 'euno/test/partner-did-pin-secret',
      });
    });
  });

  describe('SSM parameters', () => {
    test('stores Cognito User Pool ID in SSM', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: '/euno/test/cognito-user-pool-id',
        Type: 'String',
      });
    });

    test('stores Cognito App Client ID in SSM', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: '/euno/test/cognito-client-id',
        Type: 'String',
      });
    });
  });

  describe('Issuer IRSA role', () => {
    test('creates an IAM role for the issuer pod', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Role', {
        RoleName: 'euno-issuer-irsa-test',
      });
    });

    test('includes KMS Sign permissions (issuer signs tokens)', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: [
            {
              Sid: 'SignCapabilityTokens',
              Effect: 'Allow',
              Action: [
                'kms:Sign',
                'kms:Verify',
                'kms:GetPublicKey',
                'kms:DescribeKey',
              ],
            },
          ],
        },
      });
    });

    test('includes Cognito read permissions for SCIM sync', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: [
            {
              Sid: 'CognitoReadAccess',
              Effect: 'Allow',
              Action: Match.arrayWith(['cognito-idp:ListUsers']),
            },
          ],
        },
      });
    });
  });

  describe('Stack outputs', () => {
    test('exports the issuer role ARN', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('IssuerRoleArn', {
        Export: { Name: 'euno-test-issuer-role-arn' },
      });
    });

    test('exports the Cognito User Pool ID', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('CognitoUserPoolId', {
        Export: { Name: 'euno-test-cognito-user-pool-id' },
      });
    });

    test('exports the Cognito App Client ID', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('CognitoAppClientId', {
        Export: { Name: 'euno-test-cognito-app-client-id' },
      });
    });

    test('exports the Cognito SCIM endpoint', () => {
      const stack = makeStack();
      const template = Template.fromStack(stack);
      template.hasOutput('CognitoScimEndpoint', {
        Export: { Name: 'euno-test-cognito-scim-endpoint' },
      });
    });
  });
});
