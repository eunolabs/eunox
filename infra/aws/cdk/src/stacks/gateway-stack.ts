/**
 * EunoGatewayStack — core infrastructure for the Euno tool-gateway.
 *
 * Provisions:
 *   - VPC with 3 AZs, public / private subnets, NAT gateways
 *   - EKS Fargate cluster (IRSA-enabled) for the euno-system namespace
 *   - RDS PostgreSQL (Multi-AZ, encrypted, audit-ledger + API-key databases)
 *   - ElastiCache Redis (TLS + auth-token, replication group for HA)
 *   - KMS asymmetric RSA-2048 key for capability-token signing
 *   - S3 bucket with Object Lock (COMPLIANCE mode) for cross-chain audit anchor
 *   - Secrets Manager secrets: HMAC key, admin API key, Redis auth token
 *   - IAM IRSA role for the tool-gateway pod
 *   - CloudWatch log groups (runtime + audit)
 *   - ECR repositories for all Euno service images
 *
 * Usage:
 *
 *   const app = new cdk.App();
 *   new EunoGatewayStack(app, 'EunoGateway', {
 *     env: { account: '123456789012', region: 'us-east-1' },
 *     namePrefix: 'euno',
 *     environment: 'prod',
 *   });
 */

import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { KubectlV30Layer } from '@aws-cdk/lambda-layer-kubectl-v30';
import { Construct } from 'constructs';

export interface EunoGatewayStackProps extends cdk.StackProps {
  /** Short resource-name prefix (3-12 lowercase chars). Default: 'euno'. */
  namePrefix?: string;
  /** Deployment environment label (pilot | staging | prod). Default: 'pilot'. */
  environment?: string;
  /** CloudWatch log-retention period in days. Default: 90. */
  logRetentionDays?: number;
  /**
   * EC2 instance type for the EKS managed node group.
   * Ignored when fargate is true. Default: 't3.large'.
   */
  nodeInstanceType?: string;
  /**
   * When true (default) the cluster uses Fargate-only execution — no managed
   * node groups are created.  When false a single managed node group with
   * nodeInstanceType is provisioned instead (useful for dev/CI environments
   * that require DaemonSets or privileged containers).
   */
  fargate?: boolean;
  /** RDS PostgreSQL instance type. Default: 't3.medium'. */
  dbInstanceClass?: string;
  /** Multi-AZ RDS deployment. Default: true. */
  dbMultiAz?: boolean;
  /** ElastiCache node type. Default: 'cache.t3.medium'. */
  cacheNodeType?: string;
  /** Number of ElastiCache read replicas. Default: 1. */
  cacheNumReplicas?: number;
  /** VPC CIDR block. Default: '10.40.0.0/16'. */
  vpcCidr?: string;
}

/**
 * Core Euno Gateway stack — provisions VPC, EKS, databases, KMS key, S3
 * audit anchor, secrets, and ECR repositories on AWS.
 */
export class EunoGatewayStack extends cdk.Stack {
  /** VPC shared across all Euno services. */
  public readonly vpc: ec2.Vpc;
  /** EKS cluster hosting Euno workloads. */
  public readonly cluster: eks.Cluster;
  /** Fargate profile covering the euno-system namespace. */
  public readonly fargateProfile?: eks.FargateProfile;
  /** KMS key for asymmetric capability-token signing (RSA-2048). */
  public readonly signingKey: kms.Key;
  /** S3 bucket with Object Lock for cross-chain audit anchor (SOC 2 CC7.4). */
  public readonly auditAnchorBucket: s3.Bucket;
  /** Primary RDS PostgreSQL instance (audit-ledger + API-key databases). */
  public readonly database: rds.DatabaseInstance;
  /** ElastiCache Replication Group (HA Redis). */
  public readonly redisReplicationGroup: elasticache.CfnReplicationGroup;
  /** Secrets Manager secret for the audit-ledger HMAC key. */
  public readonly hmacKeySecret: secretsmanager.Secret;
  /** Secrets Manager secret for the gateway admin API key. */
  public readonly adminApiKeySecret: secretsmanager.Secret;
  /** Secrets Manager secret for the ElastiCache auth token. */
  public readonly redisAuthTokenSecret: secretsmanager.Secret;
  /** IAM role assumed by the tool-gateway pod via IRSA. */
  public readonly gatewayIrsaRole: iam.Role;
  /** CloudWatch log group for runtime (application) logs. */
  public readonly runtimeLogGroup: logs.LogGroup;
  /** CloudWatch log group for audit (logType=audit) entries. */
  public readonly auditLogGroup: logs.LogGroup;
  /** ECR repositories keyed by image name. */
  public readonly repositories: Record<string, ecr.Repository>;

  protected readonly namePrefix: string;
  protected readonly deployEnv: string;
  protected readonly commonTags: Record<string, string>;

  constructor(scope: Construct, id: string, props: EunoGatewayStackProps = {}) {
    super(scope, id, props);

    this.namePrefix = props.namePrefix ?? 'euno';
    this.deployEnv = props.environment ?? 'pilot';
    this.commonTags = {
      product: 'euno',
      component: 'capability-governance',
      environment: this.deployEnv,
    };
    cdk.Tags.of(this).add('product', 'euno');
    cdk.Tags.of(this).add('component', 'capability-governance');
    cdk.Tags.of(this).add('environment', this.deployEnv);

    const logRetentionMap: Record<number, logs.RetentionDays> = {
      1: logs.RetentionDays.ONE_DAY,
      3: logs.RetentionDays.THREE_DAYS,
      5: logs.RetentionDays.FIVE_DAYS,
      7: logs.RetentionDays.ONE_WEEK,
      14: logs.RetentionDays.TWO_WEEKS,
      30: logs.RetentionDays.ONE_MONTH,
      60: logs.RetentionDays.TWO_MONTHS,
      90: logs.RetentionDays.THREE_MONTHS,
      120: logs.RetentionDays.FOUR_MONTHS,
      150: logs.RetentionDays.FIVE_MONTHS,
      180: logs.RetentionDays.SIX_MONTHS,
      365: logs.RetentionDays.ONE_YEAR,
      400: logs.RetentionDays.THIRTEEN_MONTHS,
      545: logs.RetentionDays.EIGHTEEN_MONTHS,
      731: logs.RetentionDays.TWO_YEARS,
      1827: logs.RetentionDays.FIVE_YEARS,
      3653: logs.RetentionDays.TEN_YEARS,
      0: logs.RetentionDays.INFINITE,
    };
    const logRetentionDays = props.logRetentionDays ?? 90;
    if (!(logRetentionDays in logRetentionMap)) {
      throw new Error(
        `Unsupported logRetentionDays value: ${logRetentionDays}. ` +
        `Supported values: ${Object.keys(logRetentionMap).join(', ')}.`,
      );
    }
    const logRetention = logRetentionMap[logRetentionDays];
    const fargate = props.fargate ?? true;
    const vpcCidr = props.vpcCidr ?? '10.40.0.0/16';

    // ── CloudWatch log groups ─────────────────────────────────────────────────
    this.runtimeLogGroup = new logs.LogGroup(this, 'RuntimeLogGroup', {
      logGroupName: `/${this.namePrefix}/runtime`,
      retention: logRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.auditLogGroup = new logs.LogGroup(this, 'AuditLogGroup', {
      logGroupName: `/${this.namePrefix}/audit`,
      retention: logRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── ECR repositories ──────────────────────────────────────────────────────
    const imageNames = [
      'capability-issuer',
      'tool-gateway',
      'api-key-minter',
      'db-token-service',
      'storage-grant-service',
      'posture-emitter',
    ];
    this.repositories = {};
    for (const name of imageNames) {
      this.repositories[name] = new ecr.Repository(this, `Ecr-${name}`, {
        repositoryName: `${this.namePrefix}/${name}`,
        imageScanOnPush: true,
        imageTagMutability: ecr.TagMutability.IMMUTABLE,
        encryptionKey: undefined, // AES-256 managed key (default)
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        lifecycleRules: [
          {
            description: 'Keep at most 30 images per repository',
            maxImageCount: 30,
          },
        ],
      });
    }

    // ── KMS signing key ───────────────────────────────────────────────────────
    this.signingKey = new kms.Key(this, 'CapabilitySigningKey', {
      description: `Euno capability-token signing key (${this.namePrefix}-${this.deployEnv})`,
      keySpec: kms.KeySpec.RSA_2048,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      enableKeyRotation: false, // asymmetric keys do not support rotation
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      alias: `alias/${this.namePrefix}-capability-signing`,
    });

    // ── S3 audit anchor bucket with Object Lock ───────────────────────────────
    this.auditAnchorBucket = new s3.Bucket(this, 'AuditAnchorBucket', {
      bucketName: `${this.namePrefix}-audit-anchor-${this.deployEnv}-${this.account}`,
      versioned: true, // required for Object Lock
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(2557)), // ~7 years
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── Secrets Manager secrets ───────────────────────────────────────────────
    this.hmacKeySecret = new secretsmanager.Secret(this, 'HmacKeySecret', {
      secretName: `${this.namePrefix}/${this.deployEnv}/audit-ledger-hmac-secret`,
      description: 'AUDIT_LEDGER_HMAC_SECRET — 64-byte hex HMAC key for audit evidence signing.',
      generateSecretString: {
        passwordLength: 128,
        excludePunctuation: true,
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.adminApiKeySecret = new secretsmanager.Secret(this, 'AdminApiKeySecret', {
      secretName: `${this.namePrefix}/${this.deployEnv}/gateway-admin-api-key`,
      description: 'ADMIN_API_KEY — gateway operator API key (≥32 chars).',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.redisAuthTokenSecret = new secretsmanager.Secret(this, 'RedisAuthTokenSecret', {
      secretName: `${this.namePrefix}/${this.deployEnv}/redis-auth-token`,
      description: 'ElastiCache Redis auth token for TLS-encrypted cluster access.',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── VPC ───────────────────────────────────────────────────────────────────
    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs: 3,
      natGateways: 3,
      subnetConfiguration: [
        {
          name: 'public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 20,
        },
        {
          name: 'private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 20,
        },
        {
          name: 'isolated',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
    });

    // ── Security groups ───────────────────────────────────────────────────────
    const dbSecurityGroup = new ec2.SecurityGroup(this, 'DbSecurityGroup', {
      vpc: this.vpc,
      description: 'Euno RDS PostgreSQL — allow EKS pods only.',
      allowAllOutbound: false,
    });

    const redisSecurityGroup = new ec2.SecurityGroup(this, 'RedisSecurityGroup', {
      vpc: this.vpc,
      description: 'Euno ElastiCache Redis — allow EKS pods only.',
      allowAllOutbound: false,
    });

    // ── RDS PostgreSQL ────────────────────────────────────────────────────────
    const dbSubnetGroup = new rds.SubnetGroup(this, 'DbSubnetGroup', {
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      description: 'Euno RDS subnet group (isolated subnets).',
    });

    this.database = new rds.DatabaseInstance(this, 'Database', {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_15_4,
      }),
      instanceType: new ec2.InstanceType(props.dbInstanceClass ?? 't3.medium'),
      vpc: this.vpc,
      subnetGroup: dbSubnetGroup,
      securityGroups: [dbSecurityGroup],
      multiAz: props.dbMultiAz ?? true,
      storageType: rds.StorageType.GP3,
      allocatedStorage: 20,
      maxAllocatedStorage: 200,
      storageEncrypted: true,
      deletionProtection: true,
      backupRetention: cdk.Duration.days(7),
      cloudwatchLogsExports: ['postgresql', 'upgrade'],
      cloudwatchLogsRetention: logRetention,
      enablePerformanceInsights: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      databaseName: 'euno',
    });

    // ── ElastiCache Redis replication group ───────────────────────────────────
    const cacheSubnetGroup = new elasticache.CfnSubnetGroup(this, 'CacheSubnetGroup', {
      description: 'Euno ElastiCache Redis subnet group (isolated subnets).',
      subnetIds: this.vpc.isolatedSubnets.map((s) => s.subnetId),
      cacheSubnetGroupName: `${this.namePrefix}-cache-${this.deployEnv}`,
    });

    this.redisReplicationGroup = new elasticache.CfnReplicationGroup(this, 'Redis', {
      replicationGroupDescription: `Euno HA Redis — ${this.namePrefix}-${this.deployEnv}`,
      replicationGroupId: `${this.namePrefix}-${this.deployEnv}`,
      atRestEncryptionEnabled: true,
      transitEncryptionEnabled: true,
      authToken: this.redisAuthTokenSecret.secretValue.unsafeUnwrap(),
      automaticFailoverEnabled: true,
      numCacheClusters: (props.cacheNumReplicas ?? 1) + 1, // 1 primary + N replicas
      cacheNodeType: props.cacheNodeType ?? 'cache.t3.medium',
      engine: 'redis',
      engineVersion: '7.1',
      cacheSubnetGroupName: cacheSubnetGroup.ref,
      securityGroupIds: [redisSecurityGroup.securityGroupId],
      snapshotRetentionLimit: 7,
    });
    this.redisReplicationGroup.addDependency(cacheSubnetGroup);

    // ── EKS cluster ───────────────────────────────────────────────────────────
    const clusterVersion = eks.KubernetesVersion.V1_30;

    this.cluster = new eks.Cluster(this, 'Cluster', {
      clusterName: `${this.namePrefix}-eks-${this.deployEnv}`,
      version: clusterVersion,
      kubectlLayer: new KubectlV30Layer(this, 'KubectlLayer'),
      vpc: this.vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
      defaultCapacity: fargate ? 0 : 2,
      defaultCapacityInstance: fargate
        ? undefined
        : new ec2.InstanceType(props.nodeInstanceType ?? 't3.large'),
      clusterLogging: [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
        eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
        eks.ClusterLoggingTypes.SCHEDULER,
      ],
    });

    if (fargate) {
      this.fargateProfile = new eks.FargateProfile(this, 'EunoSystemFargateProfile', {
        cluster: this.cluster,
        fargateProfileName: 'euno-system',
        selectors: [
          { namespace: 'euno-system' },
          { namespace: 'euno-monitoring' },
        ],
      });
    }

    // ── IRSA role for tool-gateway ────────────────────────────────────────────
    const oidcProvider = this.cluster.openIdConnectProvider;

    // Use CfnJson to defer OIDC issuer token resolution to deployment time.
    // The issuer URL contains CloudFormation intrinsic functions that cannot
    // be used directly as map keys during synthesis.
    const irsaConditions = new cdk.CfnJson(this, 'GatewayIrsaConditions', {
      value: {
        [`${oidcProvider.openIdConnectProviderIssuer}:sub`]:
          'system:serviceaccount:euno-system:tool-gateway',
        [`${oidcProvider.openIdConnectProviderIssuer}:aud`]:
          'sts.amazonaws.com',
      },
    });

    this.gatewayIrsaRole = new iam.Role(this, 'GatewayIrsaRole', {
      roleName: `${this.namePrefix}-gateway-irsa-${this.deployEnv}`,
      assumedBy: new iam.WebIdentityPrincipal(
        oidcProvider.openIdConnectProviderArn,
        {
          StringEquals: irsaConditions,
        },
      ),
    });

    // KMS Verify + GetPublicKey (gateway only verifies tokens)
    this.gatewayIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'VerifyCapabilityTokens',
        effect: iam.Effect.ALLOW,
        actions: ['kms:Verify', 'kms:GetPublicKey', 'kms:DescribeKey'],
        resources: [this.signingKey.keyArn],
      }),
    );

    // Secrets Manager: read the secrets this pod needs at startup
    this.gatewayIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadGatewaySecrets',
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          this.hmacKeySecret.secretArn,
          this.adminApiKeySecret.secretArn,
          this.redisAuthTokenSecret.secretArn,
        ],
      }),
    );

    // S3 anchor bucket: PutObject + GetObject
    this.gatewayIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AuditAnchorBucketAccess',
        effect: iam.Effect.ALLOW,
        actions: ['s3:PutObject', 's3:GetObject', 's3:PutObjectRetention'],
        resources: [`${this.auditAnchorBucket.bucketArn}/*`],
      }),
    );

    // CloudWatch Logs
    this.gatewayIrsaRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'GatewayLogs',
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

    // ── Stack outputs ─────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'ClusterName', {
      value: this.cluster.clusterName,
      description: 'EKS cluster name.',
      exportName: `${this.namePrefix}-${this.deployEnv}-cluster-name`,
    });

    new cdk.CfnOutput(this, 'ClusterOidcProviderArn', {
      value: oidcProvider.openIdConnectProviderArn,
      description: 'OIDC provider ARN for IRSA bindings.',
      exportName: `${this.namePrefix}-${this.deployEnv}-oidc-provider-arn`,
    });

    new cdk.CfnOutput(this, 'GatewayRoleArn', {
      value: this.gatewayIrsaRole.roleArn,
      description: 'Annotate the tool-gateway ServiceAccount with this ARN.',
      exportName: `${this.namePrefix}-${this.deployEnv}-gateway-role-arn`,
    });

    new cdk.CfnOutput(this, 'SigningKeyArn', {
      value: this.signingKey.keyArn,
      description: 'ARN to set as AWS_KMS_KEY_ID for AWSKMSSigner.',
      exportName: `${this.namePrefix}-${this.deployEnv}-signing-key-arn`,
    });

    new cdk.CfnOutput(this, 'AuditAnchorBucketName', {
      value: this.auditAnchorBucket.bucketName,
      description: 'Set as AUDIT_LEDGER_S3_BUCKET for cross-chain anchoring.',
      exportName: `${this.namePrefix}-${this.deployEnv}-audit-anchor-bucket`,
    });

    new cdk.CfnOutput(this, 'DatabaseEndpoint', {
      value: this.database.dbInstanceEndpointAddress,
      description: 'RDS endpoint for AUDIT_LEDGER_PG_URL and ISSUER_DB_URL.',
      exportName: `${this.namePrefix}-${this.deployEnv}-db-endpoint`,
    });

    new cdk.CfnOutput(this, 'HmacKeySecretArn', {
      value: this.hmacKeySecret.secretArn,
      description: 'AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET.',
      exportName: `${this.namePrefix}-${this.deployEnv}-hmac-key-secret-arn`,
    });

    new cdk.CfnOutput(this, 'AdminApiKeySecretArn', {
      value: this.adminApiKeySecret.secretArn,
      description: 'AWS_SECRETS_ARN_ADMIN_API_KEY.',
      exportName: `${this.namePrefix}-${this.deployEnv}-admin-api-key-secret-arn`,
    });
  }
}
