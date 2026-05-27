/**
 * EunoxIssuerStack — extends EunoxGatewayStack with the capability-issuer and
 * Cognito User Pool.
 *
 * Additional resources provisioned:
 *   - Cognito User Pool (MFA optional, email-verified, password policy)
 *   - Cognito App Client for agent-runtime auth flows
 *   - Cognito User Groups: operators, agent-users
 *   - Cognito User Pool Domain (for hosted UI / SCIM bridge)
 *   - IAM IRSA role for the capability-issuer pod:
 *       KMS Sign + Verify + GetPublicKey
 *       Secrets Manager read
 *       Cognito describe / admin operations
 *   - Secrets Manager secret for PARTNER_DID_PIN_SECRET
 *   - SSM Parameter Store entry for the Cognito User Pool ID (non-sensitive)
 *
 * Usage:
 *
 *   const app = new cdk.App();
 *   new EunoxIssuerStack(app, 'EunoxIssuer', {
 *     env: { account: '123456789012', region: 'us-east-1' },
 *     namePrefix: 'eunox',
 *     environment: 'prod',
 *   });
 */

import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { EunoxGatewayStack, EunoxGatewayStackProps } from './gateway-stack';

export interface EunoxIssuerStackProps extends EunoxGatewayStackProps {
  /**
   * When true (default) the Cognito User Pool is created in this stack.
   * Set to false and provide cognitoUserPoolArn to reuse an existing pool.
   */
  createCognitoUserPool?: boolean;
  /**
   * ARN of an existing Cognito User Pool to use when createCognitoUserPool
   * is false.  Ignored when createCognitoUserPool is true.
   */
  cognitoUserPoolArn?: string;
  /**
   * Cognito User Pool domain prefix (for hosted UI and SCIM bridge endpoint).
   * Defaults to `${namePrefix}-${environment}`.
   */
  cognitoDomainPrefix?: string;
}

/**
 * Eunox Issuer stack — adds Cognito User Pool and SCIM wiring on top of the
 * core gateway infrastructure.
 */
export class EunoxIssuerStack extends EunoxGatewayStack {
  /** Cognito User Pool for agent-user and operator identity management. */
  public readonly userPool: cognito.IUserPool;
  /** Cognito App Client for agent-runtime auth flows (ALLOW_USER_SRP_AUTH). */
  public readonly userPoolClient: cognito.UserPoolClient;
  /** Cognito User Pool domain for hosted UI and SCIM endpoint. */
  public readonly userPoolDomain: cognito.UserPoolDomain;
  /** IAM role assumed by the capability-issuer pod via IRSA. */
  public readonly issuerIrsaRole: iam.Role;
  /** Secrets Manager secret for the partner DID PIN. */
  public readonly partnerDidPinSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: EunoxIssuerStackProps = {}) {
    super(scope, id, props);

    const createPool = props.createCognitoUserPool ?? true;

    // ── Cognito User Pool ─────────────────────────────────────────────────────
    if (createPool) {
      this.userPool = new cognito.UserPool(this, 'UserPool', {
        userPoolName: `${this.namePrefix}-users-${this.deployEnv}`,
        selfSignUpEnabled: false,
        signInAliases: { email: true },
        autoVerify: { email: true },
        mfa: cognito.Mfa.OPTIONAL,
        mfaSecondFactor: { sms: false, otp: true },
        passwordPolicy: {
          minLength: 12,
          requireUppercase: true,
          requireLowercase: true,
          requireDigits: true,
          requireSymbols: true,
        },
        accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        standardAttributes: {
          email: { required: true, mutable: true },
          givenName: { required: false, mutable: true },
          familyName: { required: false, mutable: true },
        },
      });
    } else {
      if (!props.cognitoUserPoolArn) {
        throw new Error('cognitoUserPoolArn is required when createCognitoUserPool is false.');
      }
      // Import an existing User Pool by ARN when managed externally.
      this.userPool = cognito.UserPool.fromUserPoolArn(
        this,
        'UserPool',
        props.cognitoUserPoolArn,
      );
    }

    // App Client — used by the agent-runtime to authenticate users.
    this.userPoolClient = new cognito.UserPoolClient(this, 'AgentRuntimeClient', {
      userPool: this.userPool,
      userPoolClientName: `${this.namePrefix}-agent-runtime`,
      generateSecret: false,
      preventUserExistenceErrors: true,
      authFlows: {
        userSrp: true,
        userPassword: false,
        adminUserPassword: false,
        custom: false,
      },
      accessTokenValidity: cdk.Duration.minutes(15), // matches capability-token TTL
      idTokenValidity: cdk.Duration.minutes(15),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // Cognito User Pool Domain for hosted UI / SCIM bridge endpoint.
    const domainPrefix = props.cognitoDomainPrefix ?? `${this.namePrefix}-${this.deployEnv}`;
    this.userPoolDomain = new cognito.UserPoolDomain(this, 'UserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: { domainPrefix },
    });

    // User Groups: operators (privileged) and agent-users (standard).
    new cognito.CfnUserPoolGroup(this, 'OperatorsGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'operators',
      description: 'Privileged Eunox operators (mapped to admin capability).',
    });

    new cognito.CfnUserPoolGroup(this, 'AgentUsersGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'agent-users',
      description: 'Standard Eunox users (mapped to read/write capabilities).',
    });

    // ── Secrets Manager — PARTNER_DID_PIN_SECRET ──────────────────────────────
    this.partnerDidPinSecret = new secretsmanager.Secret(this, 'PartnerDidPinSecret', {
      secretName: `${this.namePrefix}/${this.deployEnv}/partner-did-pin-secret`,
      description: 'PARTNER_DID_PIN_SECRET — PIN protecting the partner DID private key.',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── SSM Parameter Store — Cognito pool ID (non-sensitive) ─────────────────
    new ssm.StringParameter(this, 'CognitoUserPoolIdParam', {
      parameterName: `/${this.namePrefix}/${this.deployEnv}/cognito-user-pool-id`,
      stringValue: this.userPool.userPoolId,
      description: 'AWS_COGNITO_USER_POOL_ID — consumed by capability-issuer bootstrap.',
    });

    new ssm.StringParameter(this, 'CognitoClientIdParam', {
      parameterName: `/${this.namePrefix}/${this.deployEnv}/cognito-client-id`,
      stringValue: this.userPoolClient.userPoolClientId,
      description: 'AWS_COGNITO_CLIENT_ID — consumed by capability-issuer bootstrap.',
    });

    // ── IRSA role for capability-issuer ───────────────────────────────────────
    const oidcProvider = this.cluster.openIdConnectProvider;

    // Use CfnJson to defer OIDC issuer token resolution to deployment time.
    const issuerIrsaConditions = new cdk.CfnJson(this, 'IssuerIrsaConditions', {
      value: {
        [`${oidcProvider.openIdConnectProviderIssuer}:sub`]:
          'system:serviceaccount:eunox-system:capability-issuer',
        [`${oidcProvider.openIdConnectProviderIssuer}:aud`]:
          'sts.amazonaws.com',
      },
    });

    this.issuerIrsaRole = new iam.Role(this, 'IssuerIrsaRole', {
      roleName: `${this.namePrefix}-issuer-irsa-${this.deployEnv}`,
      assumedBy: new iam.WebIdentityPrincipal(
        oidcProvider.openIdConnectProviderArn,
        {
          StringEquals: issuerIrsaConditions,
        },
      ),
    });

    // KMS Sign + Verify + GetPublicKey (issuer signs capability tokens)
    this.issuerIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'SignCapabilityTokens',
        effect: iam.Effect.ALLOW,
        actions: ['kms:Sign', 'kms:Verify', 'kms:GetPublicKey', 'kms:DescribeKey'],
        resources: [this.signingKey.keyArn],
      }),
    );

    // Secrets Manager: read secrets at startup
    this.issuerIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadIssuerSecrets',
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          this.hmacKeySecret.secretArn,
          this.adminApiKeySecret.secretArn,
          this.partnerDidPinSecret.secretArn,
        ],
      }),
    );

    // CloudWatch Logs
    this.issuerIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'IssuerLogs',
        effect: iam.Effect.ALLOW,
        actions: [
          'logs:PutLogEvents',
          'logs:CreateLogStream',
          'logs:DescribeLogStreams',
        ],
        resources: [
          `${this.runtimeLogGroup.logGroupArn}:*`,
          `${this.auditLogGroup.logGroupArn}:*`,
        ],
      }),
    );

    // Cognito read access (describe pool, list users for SCIM sync)
    this.issuerIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'CognitoReadAccess',
        effect: iam.Effect.ALLOW,
        actions: [
          'cognito-idp:DescribeUserPool',
          'cognito-idp:ListUsers',
          'cognito-idp:ListUsersInGroup',
          'cognito-idp:ListGroups',
          'cognito-idp:GetUser',
        ],
        resources: [this.userPool.userPoolArn],
      }),
    );

    // ── Stack outputs ─────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'IssuerRoleArn', {
      value: this.issuerIrsaRole.roleArn,
      description: 'Annotate the capability-issuer ServiceAccount with this ARN.',
      exportName: `${this.namePrefix}-${this.deployEnv}-issuer-role-arn`,
    });

    new cdk.CfnOutput(this, 'CognitoUserPoolId', {
      value: this.userPool.userPoolId,
      description: 'Set as AWS_COGNITO_USER_POOL_ID for capability-issuer.',
      exportName: `${this.namePrefix}-${this.deployEnv}-cognito-user-pool-id`,
    });

    new cdk.CfnOutput(this, 'CognitoAppClientId', {
      value: this.userPoolClient.userPoolClientId,
      description: 'Set as AWS_COGNITO_CLIENT_ID for capability-issuer.',
      exportName: `${this.namePrefix}-${this.deployEnv}-cognito-app-client-id`,
    });

    new cdk.CfnOutput(this, 'CognitoScimEndpoint', {
      value: `https://${domainPrefix}.auth.${this.region}.amazoncognito.com`,
      description:
        'Cognito hosted UI / SCIM bridge base URL. ' +
        'See docs/issuer-idp-setup.md §10 for SCIM wiring with IAM Identity Center.',
      exportName: `${this.namePrefix}-${this.deployEnv}-cognito-scim-endpoint`,
    });

    new cdk.CfnOutput(this, 'PartnerDidPinSecretArn', {
      value: this.partnerDidPinSecret.secretArn,
      description: 'AWS_SECRETS_ARN_PARTNER_DID_PIN_SECRET.',
      exportName: `${this.namePrefix}-${this.deployEnv}-partner-did-pin-secret-arn`,
    });
  }
}
