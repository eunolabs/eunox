#!/usr/bin/env node
/**
 * CDK app entry point.
 *
 * Selects the stack tier to deploy based on the EUNO_CDK_STACK env var:
 *
 *   EUNO_CDK_STACK=gateway    →  EunoGatewayStack    (core infra only)
 *   EUNO_CDK_STACK=issuer     →  EunoIssuerStack     (+ Cognito)
 *   EUNO_CDK_STACK=enterprise →  EunoEnterpriseStack  (+ SOC 2 pipeline)
 *
 * If EUNO_CDK_STACK is unset, all three stacks are instantiated so `cdk diff`
 * shows the full diff across tiers.
 *
 * Required env vars (all stacks):
 *   CDK_DEFAULT_ACCOUNT / CDK_DEFAULT_REGION   (set automatically by `cdk deploy`)
 *   EUNO_NAME_PREFIX                            (default: 'euno')
 *   EUNO_ENVIRONMENT                            (default: 'pilot')
 */

import * as cdk from 'aws-cdk-lib';
import { EunoGatewayStack } from '../src/stacks/gateway-stack';
import { EunoIssuerStack } from '../src/stacks/issuer-stack';
import { EunoEnterpriseStack } from '../src/stacks/enterprise-stack';

const app = new cdk.App();

const namePrefix = process.env['EUNO_NAME_PREFIX'] ?? 'euno';
const environment = process.env['EUNO_ENVIRONMENT'] ?? 'pilot';
const alarmEmail = process.env['EUNO_ALARM_EMAIL'];

const env: cdk.Environment = {
  account: process.env['CDK_DEFAULT_ACCOUNT'],
  region: process.env['CDK_DEFAULT_REGION'],
};

const commonProps = { namePrefix, environment, env };

const tier = process.env['EUNO_CDK_STACK'];

switch (tier) {
  case 'gateway':
    new EunoGatewayStack(app, 'EunoGateway', commonProps);
    break;
  case 'issuer':
    new EunoIssuerStack(app, 'EunoIssuer', commonProps);
    break;
  case 'enterprise':
    new EunoEnterpriseStack(app, 'EunoEnterprise', {
      ...commonProps,
      alarmNotificationEmail: alarmEmail,
    });
    break;
  default:
    // Deploy all tiers (useful for `cdk diff --all`)
    new EunoGatewayStack(app, 'EunoGateway', commonProps);
    new EunoIssuerStack(app, 'EunoIssuer', commonProps);
    new EunoEnterpriseStack(app, 'EunoEnterprise', {
      ...commonProps,
      alarmNotificationEmail: alarmEmail,
    });
}
