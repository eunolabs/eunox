/**
 * EunoEnterpriseStack — extends EunoIssuerStack with enterprise-grade features:
 * partner DID registry, SOC 2 audit pipeline, Security Hub, and CloudTrail.
 *
 * Additional resources provisioned:
 *   - DynamoDB table for partner DID registry (on-demand, point-in-time recovery)
 *   - CloudTrail trail for management events + S3 data events on the audit-anchor
 *     bucket to satisfy SOC 2 CC6.1 / CC7.2 / CC7.3
 *   - S3 bucket for CloudTrail logs (server-side encryption, Object Lock GOVERNANCE)
 *   - Kinesis Firehose delivery stream → S3 data lake for OCSF audit events
 *   - Security Hub enablement with CIS AWS Foundations Benchmark standard
 *   - CloudWatch alarms for SOC 2 alerting:
 *       • denial spike (euno_tool_call_denied_total)
 *       • invalid-token burst
 *       • kill-switch activation
 *   - SNS topic for alarm notifications (plug in PagerDuty / Slack)
 *   - Uses gateway/issuer IRSA roles inherited from base stacks
 *
 * Usage:
 *
 *   const app = new cdk.App();
 *   new EunoEnterpriseStack(app, 'EunoEnterprise', {
 *     env: { account: '123456789012', region: 'us-east-1' },
 *     namePrefix: 'euno',
 *     environment: 'prod',
 *     alarmNotificationEmail: 'ops@example.com',
 *   });
 */

import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { EunoIssuerStack, EunoIssuerStackProps } from './issuer-stack';

export interface EunoEnterpriseStackProps extends EunoIssuerStackProps {
  /**
   * Email address to receive CloudWatch alarm notifications.
   * When omitted, the SNS topic is created but has no subscriptions.
   */
  alarmNotificationEmail?: string;
  /**
   * Enable Security Hub with CIS AWS Foundations Benchmark standard.
   * Default: true.
   */
  enableSecurityHub?: boolean;
  /**
   * S3 prefix for CloudTrail logs. Default: 'AWSLogs'.
   */
  cloudTrailS3Prefix?: string;
  /**
   * Number of days to retain Kinesis Firehose → audit-lake records.
   * Default: 2557 (~7 years, SOC 2 CC7.4 retention).
   */
  auditLakeRetentionDays?: number;
}

/**
 * Euno Enterprise stack — adds partner DID registry, SOC 2 audit pipeline,
 * Security Hub, and enterprise alerting on top of the issuer infrastructure.
 */
export class EunoEnterpriseStack extends EunoIssuerStack {
  /** DynamoDB table storing partner DIDs and circuit-breaker state. */
  public readonly partnerDidRegistry: dynamodb.Table;
  /** S3 bucket for CloudTrail management / data event logs. */
  public readonly cloudTrailBucket: s3.Bucket;
  /** CloudTrail trail (management events + S3 data events for audit-anchor). */
  public readonly trail: cloudtrail.Trail;
  /** Kinesis Firehose delivery stream for OCSF audit events → S3 data lake. */
  public readonly auditFirehose: firehose.CfnDeliveryStream;
  /** S3 data lake bucket for OCSF audit events. */
  public readonly auditLakeBucket: s3.Bucket;
  /** Security Hub CfnHub resource (when enableSecurityHub is true). */
  public readonly securityHub?: securityhub.CfnHub;
  /** SNS topic for CloudWatch alarm notifications. */
  public readonly alarmTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: EunoEnterpriseStackProps = {}) {
    super(scope, id, props);

    const auditLakeRetentionDays = props.auditLakeRetentionDays ?? 2557;

    // ── Partner DID registry (DynamoDB) ───────────────────────────────────────
    this.partnerDidRegistry = new dynamodb.Table(this, 'PartnerDidRegistry', {
      tableName: `${this.namePrefix}-partner-did-registry-${this.deployEnv}`,
      partitionKey: { name: 'did', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // GSI for circuit-breaker state queries by status
    this.partnerDidRegistry.addGlobalSecondaryIndex({
      indexName: 'ByStatus',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'updatedAt', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ── CloudTrail bucket ─────────────────────────────────────────────────────
    this.cloudTrailBucket = new s3.Bucket(this, 'CloudTrailBucket', {
      bucketName: `${this.namePrefix}-cloudtrail-${this.deployEnv}-${this.account}`,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.governance(
        cdk.Duration.days(365),
      ),
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // CloudTrail requires a specific bucket policy.
    this.cloudTrailBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AWSCloudTrailAclCheck',
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:GetBucketAcl'],
        resources: [this.cloudTrailBucket.bucketArn],
      }),
    );
    this.cloudTrailBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AWSCloudTrailWrite',
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:PutObject'],
        resources: [
          `${this.cloudTrailBucket.bucketArn}/${props.cloudTrailS3Prefix ?? 'AWSLogs'}/*`,
        ],
        conditions: {
          StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' },
        },
      }),
    );

    // ── CloudTrail trail ──────────────────────────────────────────────────────
    this.trail = new cloudtrail.Trail(this, 'Trail', {
      trailName: `${this.namePrefix}-audit-trail-${this.deployEnv}`,
      bucket: this.cloudTrailBucket,
      s3KeyPrefix: props.cloudTrailS3Prefix,
      includeGlobalServiceEvents: true,
      isMultiRegionTrail: true,
      enableFileValidation: true,
      cloudWatchLogsRetention: logs.RetentionDays.THREE_MONTHS,
    });

    // Data events: S3 (audit-anchor bucket), Secrets Manager, KMS
    this.trail.addS3EventSelector(
      [{ bucket: this.auditAnchorBucket }],
      { readWriteType: cloudtrail.ReadWriteType.ALL },
    );

    // ── Audit data lake (Kinesis Firehose → S3) ───────────────────────────────
    this.auditLakeBucket = new s3.Bucket(this, 'AuditLakeBucket', {
      bucketName: `${this.namePrefix}-audit-lake-${this.deployEnv}-${this.account}`,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(
        cdk.Duration.days(auditLakeRetentionDays),
      ),
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      intelligentTieringConfigurations: [
        {
          name: 'archive-old-audit-records',
          archiveAccessTierTime: cdk.Duration.days(90),
          deepArchiveAccessTierTime: cdk.Duration.days(180),
        },
      ],
    });

    const firehoseRole = new iam.Role(this, 'FirehoseRole', {
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
    });
    firehoseRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AuditLakeBucketWrite',
        effect: iam.Effect.ALLOW,
        actions: ['s3:PutObject', 's3:GetBucketLocation', 's3:ListBucket', 's3:GetObject'],
        resources: [this.auditLakeBucket.bucketArn, `${this.auditLakeBucket.bucketArn}/*`],
      }),
    );
    firehoseRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'CloudWatchLogsWrite',
        effect: iam.Effect.ALLOW,
        actions: ['logs:PutLogEvents'],
        resources: [`${this.auditLogGroup.logGroupArn}:*`],
      }),
    );

    this.auditFirehose = new firehose.CfnDeliveryStream(this, 'AuditFirehose', {
      deliveryStreamName: `${this.namePrefix}-audit-firehose-${this.deployEnv}`,
      deliveryStreamType: 'DirectPut',
      s3DestinationConfiguration: {
        bucketArn: this.auditLakeBucket.bucketArn,
        prefix: 'ocsf-audit-events/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/',
        errorOutputPrefix: 'ocsf-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/',
        bufferingHints: { intervalInSeconds: 300, sizeInMBs: 128 },
        compressionFormat: 'GZIP',
        cloudWatchLoggingOptions: {
          enabled: true,
          logGroupName: this.auditLogGroup.logGroupName,
          logStreamName: 'firehose',
        },
        roleArn: firehoseRole.roleArn,
      },
    });

    // ── Security Hub ──────────────────────────────────────────────────────────
    if (props.enableSecurityHub !== false) {
      this.securityHub = new securityhub.CfnHub(this, 'SecurityHub', {
        enableDefaultStandards: true,
        autoEnableControls: true,
        controlFindingGenerator: 'SECURITY_CONTROL',
        tags: {
          product: 'euno',
          environment: this.deployEnv,
        },
      });
    }

    // ── SNS alarm topic ───────────────────────────────────────────────────────
    this.alarmTopic = new sns.Topic(this, 'AlarmTopic', {
      topicName: `${this.namePrefix}-alarms-${this.deployEnv}`,
      displayName: `Euno capability-governance alarms (${this.deployEnv})`,
    });

    if (props.alarmNotificationEmail) {
      this.alarmTopic.addSubscription(
        new snsSubscriptions.EmailSubscription(props.alarmNotificationEmail),
      );
    }

    // ── CloudWatch alarms (SOC 2 CC7.3 — monitoring and alerting) ─────────────
    const denialSpikeMetric = new cloudwatch.Metric({
      namespace: 'Euno/Gateway',
      metricName: 'ToolCallDeniedTotal',
      dimensionsMap: { environment: this.deployEnv },
      statistic: 'Sum',
      period: cdk.Duration.minutes(5),
    });

    const denialSpikeAlarm = new cloudwatch.Alarm(this, 'DenialSpikeAlarm', {
      alarmName: `${this.namePrefix}-denial-spike-${this.deployEnv}`,
      alarmDescription:
        'Euno capability-governance: unusual denial spike detected (CC7.3). ' +
        'Check deny-reason histogram in CloudWatch Insights.',
      metric: denialSpikeMetric,
      threshold: 100,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    denialSpikeAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alarmTopic));

    const invalidTokenMetric = new cloudwatch.Metric({
      namespace: 'Euno/Gateway',
      metricName: 'InvalidTokenBurst',
      dimensionsMap: { environment: this.deployEnv },
      statistic: 'Sum',
      period: cdk.Duration.minutes(5),
    });

    const invalidTokenAlarm = new cloudwatch.Alarm(this, 'InvalidTokenBurstAlarm', {
      alarmName: `${this.namePrefix}-invalid-token-burst-${this.deployEnv}`,
      alarmDescription:
        'Euno capability-governance: invalid-token burst detected (CC6.8). ' +
        'May indicate a credential leak or misconfigured agent.',
      metric: invalidTokenMetric,
      threshold: 50,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    invalidTokenAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alarmTopic));

    const killSwitchMetric = new cloudwatch.Metric({
      namespace: 'Euno/Gateway',
      metricName: 'KillSwitchActivation',
      dimensionsMap: { environment: this.deployEnv },
      statistic: 'Sum',
      period: cdk.Duration.minutes(1),
    });

    const killSwitchAlarm = new cloudwatch.Alarm(this, 'KillSwitchActivationAlarm', {
      alarmName: `${this.namePrefix}-kill-switch-${this.deployEnv}`,
      alarmDescription:
        'Euno capability-governance: kill-switch was activated (CC7.5). ' +
        'All tool-call enforcement is paused — immediate operator attention required.',
      metric: killSwitchMetric,
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    killSwitchAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alarmTopic));

    // ── DynamoDB IRSA grants for gateway (partner-federation circuit-breaker) ─
    this.partnerDidRegistry.grantReadData(this.gatewayIrsaRole);

    // ── Stack outputs ─────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, 'PartnerDidRegistryTableName', {
      value: this.partnerDidRegistry.tableName,
      description: 'PARTNER_DID_REGISTRY_TABLE — partner DID registry for circuit-breaker state.',
      exportName: `${this.namePrefix}-${this.deployEnv}-partner-did-registry-table`,
    });

    new cdk.CfnOutput(this, 'AuditLakeBucketName', {
      value: this.auditLakeBucket.bucketName,
      description: 'S3 data lake bucket for OCSF audit events (SOC 2 CC7.4).',
      exportName: `${this.namePrefix}-${this.deployEnv}-audit-lake-bucket`,
    });

    new cdk.CfnOutput(this, 'AuditFirehoseArn', {
      value: this.auditFirehose.attrArn,
      description:
        'Kinesis Firehose ARN for streaming OCSF audit events from tool-gateway.',
      exportName: `${this.namePrefix}-${this.deployEnv}-audit-firehose-arn`,
    });

    new cdk.CfnOutput(this, 'AlarmTopicArn', {
      value: this.alarmTopic.topicArn,
      description: 'SNS topic ARN for CloudWatch alarm notifications.',
      exportName: `${this.namePrefix}-${this.deployEnv}-alarm-topic-arn`,
    });
  }
}
