#!/usr/bin/env node
/**
 * CI lint: verify that the AWS Phase 1 multi-cloud documentation is complete.
 *
 * Checks performed:
 *   1. docs/deploy-eks.md exists and contains required sections:
 *      - IRSA (IAM Roles for Service Accounts)
 *      - ECR image configuration
 *      - ALB Ingress Controller + ACM
 *      - Helm deployment section
 *      - CloudWatch / Security Hub observability section
 *      - Security Hub findings mapping
 *      - EKS security checklist
 *   2. docs/secrets-aws.md exists and contains required sections:
 *      - AUDIT_LEDGER_HMAC_SECRET reference
 *      - GATEWAY_ADMIN_API_KEY reference (as ADMIN_API_KEY)
 *      - PARTNER_DID_PIN_SECRET reference
 *      - External Secrets Operator (ESO) section
 *      - ASCP (AWS Secrets and Configuration Provider) section
 *      - ESO vs. ASCP comparison table
 *   3. docs/issuer-idp-setup.md contains the Cognito SCIM bridge section (§10):
 *      - Section heading for Cognito SCIM bridge
 *      - IAM Identity Center reference
 *      - ISSUER_SCIM_BEARER_TOKEN environment variable reference
 *      - Attribute mappings table
 *   4. k8s/helm/euno/values-aws.yaml exists and contains required entries:
 *      - ECR registry reference
 *      - IRSA annotation (eks.amazonaws.com/role-arn)
 *      - SIGNING_PROVIDER: aws-kms
 *      - IDENTITY_PROVIDER: aws-cognito
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-multi-cloud-docs.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Exit codes:
 *   0 -- all checks pass
 *   1 -- one or more checks failed or a required file is missing
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let workspaceRoot = repoRoot;

for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--root' && argv[i + 1]) {
    workspaceRoot = resolve(argv[i + 1]);
    i++;
  } else if (argv[i].startsWith('--root=')) {
    workspaceRoot = resolve(argv[i].slice('--root='.length));
  } else {
    console.error(`Unknown argument: ${argv[i]}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const failures = [];

function requireFile(relPath, description) {
  const abs = resolve(workspaceRoot, relPath);
  if (!existsSync(abs)) {
    failures.push(`Missing file: ${description} (expected at ${relPath})`);
    return null;
  }
  return readFileSync(abs, 'utf8');
}

function requireText(content, needle, description) {
  if (content === null) return;
  if (!content.includes(needle)) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
  }
}

// ---------------------------------------------------------------------------
// Check 1 — docs/deploy-eks.md
// ---------------------------------------------------------------------------

const eksGuide = requireFile('docs/deploy-eks.md', 'docs/deploy-eks.md');

requireText(eksGuide, 'IAM Roles for Service Accounts',
  'deploy-eks.md: IAM Roles for Service Accounts (IRSA) section');
requireText(eksGuide, 'eks.amazonaws.com/role-arn',
  'deploy-eks.md: IRSA annotation example');
requireText(eksGuide, 'ECR',
  'deploy-eks.md: ECR image configuration section');
requireText(eksGuide, 'ALB Ingress Controller',
  'deploy-eks.md: ALB Ingress Controller section');
requireText(eksGuide, 'ACM',
  'deploy-eks.md: ACM certificate section');
requireText(eksGuide, 'values-aws.yaml',
  'deploy-eks.md: reference to values-aws.yaml');
requireText(eksGuide, 'CloudWatch',
  'deploy-eks.md: CloudWatch observability section');
requireText(eksGuide, 'Security Hub',
  'deploy-eks.md: Security Hub section');
requireText(eksGuide, 'OCSF',
  'deploy-eks.md: OCSF → Security Hub finding mapping');
requireText(eksGuide, 'CloudWatch Insights',
  'deploy-eks.md: CloudWatch Insights query templates');
requireText(eksGuide, 'denial_reason',
  'deploy-eks.md: denial_reason histogram query');

// ---------------------------------------------------------------------------
// Check 2 — docs/secrets-aws.md
// ---------------------------------------------------------------------------

const secretsAwsGuide = requireFile('docs/secrets-aws.md', 'docs/secrets-aws.md');

requireText(secretsAwsGuide, 'AUDIT_LEDGER_HMAC_SECRET',
  'secrets-aws.md: AUDIT_LEDGER_HMAC_SECRET referenced');
requireText(secretsAwsGuide, 'ADMIN_API_KEY',
  'secrets-aws.md: ADMIN_API_KEY (GATEWAY_ADMIN_API_KEY) referenced');
requireText(secretsAwsGuide, 'PARTNER_DID_PIN_SECRET',
  'secrets-aws.md: PARTNER_DID_PIN_SECRET referenced');
requireText(secretsAwsGuide, 'EunoKmsSigningPolicy',
  'secrets-aws.md: EunoKmsSigningPolicy IAM policy defined');
requireText(secretsAwsGuide, 'External Secrets Operator',
  'secrets-aws.md: External Secrets Operator (ESO) section');
requireText(secretsAwsGuide, 'SecretStore',
  'secrets-aws.md: ESO SecretStore resource example');
requireText(secretsAwsGuide, 'ExternalSecret',
  'secrets-aws.md: ESO ExternalSecret resource example');
requireText(secretsAwsGuide, 'Secrets Store CSI',
  'secrets-aws.md: ASCP / Secrets Store CSI driver section');
requireText(secretsAwsGuide, 'SecretProviderClass',
  'secrets-aws.md: SecretProviderClass resource example');
requireText(secretsAwsGuide, 'ESO vs. ASCP',
  'secrets-aws.md: ESO vs. ASCP comparison table or section');

// ---------------------------------------------------------------------------
// Check 3 — docs/issuer-idp-setup.md Cognito SCIM bridge section
// ---------------------------------------------------------------------------

const idpSetup = requireFile('docs/issuer-idp-setup.md', 'docs/issuer-idp-setup.md');

requireText(idpSetup, 'Cognito SCIM bridge',
  'issuer-idp-setup.md: Cognito SCIM bridge section heading');
requireText(idpSetup, 'IAM Identity Center',
  'issuer-idp-setup.md: AWS IAM Identity Center reference in Cognito SCIM section');
requireText(idpSetup, 'ISSUER_SCIM_BEARER_TOKEN',
  'issuer-idp-setup.md: ISSUER_SCIM_BEARER_TOKEN in Cognito SCIM section');
requireText(idpSetup, 'externalId',
  'issuer-idp-setup.md: externalId attribute mapping in Cognito SCIM section');
requireText(idpSetup, 'ISSUER_SCIM_GROUP_ROLE_MAP',
  'issuer-idp-setup.md: ISSUER_SCIM_GROUP_ROLE_MAP in Cognito SCIM section');

// ---------------------------------------------------------------------------
// Check 4 — k8s/helm/euno/values-aws.yaml
// ---------------------------------------------------------------------------

const valuesAws = requireFile('k8s/helm/euno/values-aws.yaml',
  'k8s/helm/euno/values-aws.yaml');

requireText(valuesAws, 'dkr.ecr',
  'values-aws.yaml: ECR registry reference (dkr.ecr)');
requireText(valuesAws, 'eks.amazonaws.com/role-arn',
  'values-aws.yaml: IRSA role-arn annotation');
requireText(valuesAws, 'aws-kms',
  'values-aws.yaml: SIGNING_PROVIDER: aws-kms');
requireText(valuesAws, 'aws-cognito',
  'values-aws.yaml: IDENTITY_PROVIDER: aws-cognito');
requireText(valuesAws, 'AWS_COGNITO_USER_POOL_ID',
  'values-aws.yaml: AWS_COGNITO_USER_POOL_ID placeholder');
requireText(valuesAws, 'gp3',
  'values-aws.yaml: gp3 EBS storage class for posture-emitter');

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

if (failures.length === 0) {
  console.log('check-multi-cloud-docs: all checks passed.');
  process.exit(0);
} else {
  console.error('check-multi-cloud-docs: FAILED');
  for (const f of failures) {
    console.error(`  FAIL: ${f}`);
  }
  process.exit(1);
}
