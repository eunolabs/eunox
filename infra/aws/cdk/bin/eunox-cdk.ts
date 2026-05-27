#!/usr/bin/env node
/**
 * CDK app entry point.
 *
 * Selects the stack tier to deploy based on the EUNOX_CDK_STACK env var:
 *
 *   EUNOX_CDK_STACK=gateway    →  EunoxGatewayStack    (core infra only)
 *   EUNOX_CDK_STACK=issuer     →  EunoxIssuerStack     (+ Cognito)
 *   EUNOX_CDK_STACK=enterprise →  EunoxEnterpriseStack  (+ SOC 2 pipeline)
 *
 * If EUNOX_CDK_STACK is unset, all three stacks are instantiated so `cdk diff`
 * shows the full diff across tiers.
 *
 * Required env vars (all stacks):
 *   CDK_DEFAULT_ACCOUNT / CDK_DEFAULT_REGION   (set automatically by `cdk deploy`)
 *   EUNOX_NAME_PREFIX                            (default: 'eunox')
 *   EUNOX_ENVIRONMENT                            (default: 'pilot')
 */

import * as cdk from 'aws-cdk-lib';
import { EunoxGatewayStack } from '../src/stacks/gateway-stack';
import { EunoxIssuerStack } from '../src/stacks/issuer-stack';
import { EunoxEnterpriseStack } from '../src/stacks/enterprise-stack';

const app = new cdk.App();

const namePrefix = process.env['EUNOX_NAME_PREFIX'] ?? 'eunox';
const environment = process.env['EUNOX_ENVIRONMENT'] ?? 'pilot';
const alarmEmail = process.env['EUNOX_ALARM_EMAIL'];

const env: cdk.Environment = {
  account: process.env['CDK_DEFAULT_ACCOUNT'],
  region: process.env['CDK_DEFAULT_REGION'],
};

const commonProps = { namePrefix, environment, env };

const tier = process.env['EUNOX_CDK_STACK'];

switch (tier) {
  case 'gateway':
    new EunoxGatewayStack(app, 'EunoxGateway', commonProps);
    break;
  case 'issuer':
    new EunoxIssuerStack(app, 'EunoxIssuer', commonProps);
    break;
  case 'enterprise':
    new EunoxEnterpriseStack(app, 'EunoxEnterprise', {
      ...commonProps,
      alarmNotificationEmail: alarmEmail,
    });
    break;
  default:
    // Deploy all tiers (useful for `cdk diff --all`)
    new EunoxGatewayStack(app, 'EunoxGateway', commonProps);
    new EunoxIssuerStack(app, 'EunoxIssuer', commonProps);
    new EunoxEnterpriseStack(app, 'EunoxEnterprise', {
      ...commonProps,
      alarmNotificationEmail: alarmEmail,
    });
}
