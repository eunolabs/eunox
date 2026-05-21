/**
 * Unit tests for scripts/check-multi-cloud-docs.mjs
 *
 * Uses Node.js built-in test runner (node:test) — no extra dependencies.
 * Run with:
 *   node --test scripts/__tests__/check-multi-cloud-docs.test.mjs
 *
 * Each test builds a synthetic fixture directory under os.tmpdir() and
 * invokes the script via child_process.spawnSync, asserting exit code and
 * stderr content.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, unlinkSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const scriptPath = resolve(__dirname, '..', 'check-multi-cloud-docs.mjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpRoot() {
  const base = mkdtempSync(join(tmpdir(), 'euno-multi-cloud-test-'));
  mkdirSync(join(base, 'docs'), { recursive: true });
  mkdirSync(join(base, 'k8s', 'helm', 'euno'), { recursive: true });
  return base;
}

function makeValidDeployEks() {
  return [
    '# Deploying Euno on Amazon EKS',
    '',
    '## 3. IAM Roles for Service Accounts (IRSA)',
    '',
    'Configure IRSA for each pod: eks.amazonaws.com/role-arn annotation.',
    '',
    '## 4. ECR image configuration',
    '',
    'Push images to ECR private registry.',
    '',
    '## 5. ALB Ingress Controller and ACM certificate',
    '',
    'Install the ALB Ingress Controller. Request an ACM certificate.',
    '',
    '## 6. Helm deployment with values-aws.yaml',
    '',
    '## 7. CloudWatch and Security Hub observability',
    '',
    'Prometheus → CloudWatch via ADOT Collector.',
    'OCSF audit event → Security Hub finding mapping.',
    'CloudWatch Insights query templates for denial_reason histograms.',
    '',
    '## 10. S3 audit anchor — endpoint configuration (Phase 2)',
    '',
    'Set AUDIT_LEDGER_S3_ENDPOINT for VPC endpoint deployments.',
    'Set AUDIT_LEDGER_S3_FORCE_PATH_STYLE=true for path-style addressing.',
    'VPC endpoint / PrivateLink configuration for S3.',
    'GovCloud: set AWS_REGION=us-gov-west-1.',
  ].join('\n');
}

function makeValidSecretsAws() {
  return [
    '# AWS Secrets Manager Integration',
    '',
    'AUDIT_LEDGER_HMAC_SECRET — stored in Secrets Manager.',
    'ADMIN_API_KEY — stored in Secrets Manager.',
    'PARTNER_DID_PIN_SECRET — stored in Secrets Manager.',
    '',
    '## 3. IAM policies',
    '',
    'EunoKmsSigningPolicy for KMS signing access.',
    '',
    '## 4. External Secrets Operator (ESO)',
    '',
    'Create a SecretStore in the euno namespace.',
    'Create an ExternalSecret for the gateway.',
    '',
    '## 5. AWS Secrets and Configuration Provider (ASCP)',
    '',
    'Install the Secrets Store CSI driver.',
    'Create a SecretProviderClass for the gateway.',
    '',
    '## 6. ESO vs. ASCP — comparison',
    '',
    '| Concern | External Secrets Operator | ASCP |',
    '',
    '## 9. Native SDK integration — AwsSecretsManagerSecretStore (Phase 2)',
    '',
    'Use AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET to override individual secrets.',
    'arnsBySecretName map built automatically from AWS_SECRETS_ARN_* env vars.',
    '',
    '## 9.4 EdDSA shim — AwsEdDsaSigner',
    '',
    'Set AWS_EDDSA_KEY_ARN=arn:aws:secretsmanager:... to enable EdDSA signing.',
  ].join('\n');
}

function makeValidIdpSetup() {
  return [
    '# Capability Issuer — IdP Setup Guide',
    '',
    '## 10. Cognito SCIM bridge (AWS IAM Identity Center)',
    '',
    'IAM Identity Center reference.',
    'ISSUER_SCIM_BEARER_TOKEN=<token>',
    'externalId attribute mapping.',
    'ISSUER_SCIM_GROUP_ROLE_MAP={"EunoReaders":"reader"}',
    '',
    '## 11. Google Workspace SCIM bridge (Cloud Identity)',
    '',
    'OAuth service account for SCIM provisioning.',
    'ISSUER_SCIM_BEARER_TOKEN=<token>',
    'externalId: user.id,   // Google internal user ID',
    'ISSUER_SCIM_GROUP_ROLE_MAP={"EunoReaders":"reader"}',
  ].join('\n');
}

function makeValidValuesAws() {
  return [
    '# Euno umbrella chart — AWS / EKS overrides',
    '',
    'gateway:',
    '  image:',
    '    repository: 123456789012.dkr.ecr.us-east-1.amazonaws.com/euno/tool-gateway',
    '  serviceAccountAnnotations:',
    '    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/euno-gateway-role"',
    '  env:',
    '    SIGNING_PROVIDER: aws-kms',
    '',
    'issuer:',
    '  env:',
    '    IDENTITY_PROVIDER: aws-cognito',
    '    AWS_COGNITO_USER_POOL_ID: "us-east-1_XXXXX"',
    '',
    'postureEmitter:',
    '  persistence:',
    '    storageClass: gp3',
  ].join('\n');
}

function makeValidMultiCloudPlan() {
  return [
    '# Multi-Cloud Ecosystem Support Plan',
    '',
    '## AWS ecosystem plan',
    '',
    '### Phase 2 — Native SDK integration (medium-term)',
    '',
    '- [x] **AWS Secrets Manager secrets-store adapter**',
    '  - arnsBySecretName map for ARN-based overrides.',
    '',
    '- [x] **S3 cross-chain anchor — region and endpoint improvements**',
    '  - AUDIT_LEDGER_S3_ENDPOINT env var added.',
    '',
    '- [x] **AWS KMS signer — additional key specs**',
    '  - EdDSA signing shim (AwsEdDsaSigner) for partner DID.',
    '',
    '## GCP ecosystem plan',
    '',
    '### Phase 2 — Native SDK integration (medium-term)',
    '',
    '- [x] **GCP Secret Manager secrets-store adapter**',
    '  - GcpSecretManagerSecretStore implemented in @euno/common-core.',
  ].join('\n');
}

function makeValidDeployGke() {
  return [
    '# Deploying Euno on Google Kubernetes Engine (GKE)',
    '',
    '## 3. Workload Identity Federation',
    '',
    'Configure Workload Identity for each pod.',
    'iam.gke.io/gcp-service-account annotation.',
    '',
    '## 4. Artifact Registry image configuration',
    '',
    'Push images to Artifact Registry.',
    '',
    '## 5. GKE Ingress and Google-managed SSL certificate',
    '',
    'Create a GKE Ingress resource.',
    'Create a ManagedCertificate for SSL.',
    '',
    '## 6. Helm deployment with values-gcp.yaml',
    '',
    '## 7. Cloud Monitoring and Security Command Center observability',
    '',
    'Prometheus → Cloud Monitoring via OpenTelemetry Collector.',
    'OCSF audit event → Security Command Center finding mapping.',
    'Log-based metrics for denial_reason histograms in Cloud Logging.',
  ].join('\n');
}

function makeValidSecretsGcp() {
  return [
    '# GCP Secret Manager Integration',
    '',
    'AUDIT_LEDGER_HMAC_SECRET — stored in Secret Manager.',
    'ADMIN_API_KEY — stored in Secret Manager.',
    'PARTNER_DID_PIN_SECRET — stored in Secret Manager.',
    '',
    '## 3. IAM bindings',
    '',
    'roles/secretmanager.secretAccessor binding for each service account.',
    '',
    '## 4. External Secrets Operator (ESO)',
    '',
    'Create a SecretStore in the euno namespace.',
    'Create an ExternalSecret for the gateway.',
    '',
    '## 5. Secret Manager Add-on (Secrets Store CSI Driver)',
    '',
    'Enable the Secret Manager Add-on on the GKE cluster.',
    '',
    '## 6. ESO vs. Secret Manager Add-on — comparison',
    '',
    '| Concern | External Secrets Operator | Secret Manager Add-on (CSI) |',
  ].join('\n');
}

function makeValidValuesGcp() {
  return [
    '# Euno umbrella chart — GCP / GKE overrides',
    '',
    'gateway:',
    '  image:',
    '    repository: us-central1-docker.pkg.dev/my-gcp-project/euno/tool-gateway',
    '  serviceAccountAnnotations:',
    '    iam.gke.io/gcp-service-account: "euno-gateway@my-gcp-project.iam.gserviceaccount.com"',
    '  env:',
    '    SIGNING_PROVIDER: gcp-cloudkms',
    '    GCP_PROJECT_ID: "my-gcp-project"',
    '',
    'issuer:',
    '  env:',
    '    IDENTITY_PROVIDER: gcp-identity',
    '',
    'postureEmitter:',
    '  persistence:',
    '    storageClass: premium-rwo',
  ].join('\n');
}

function makeValidFixtures(base) {
  writeFileSync(join(base, 'docs', 'deploy-eks.md'), makeValidDeployEks());
  writeFileSync(join(base, 'docs', 'secrets-aws.md'), makeValidSecretsAws());
  writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'), makeValidIdpSetup());
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'), makeValidValuesAws());
  writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'), makeValidMultiCloudPlanPhase3());
  writeFileSync(join(base, 'docs', 'deploy-gke.md'), makeValidDeployGke());
  writeFileSync(join(base, 'docs', 'secrets-gcp.md'), makeValidSecretsGcp());
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'), makeValidValuesGcp());
  // Phase 3 — GCP Terraform modules
  mkdirSync(join(base, 'infra', 'gcp', 'terraform', 'network'), { recursive: true });
  mkdirSync(join(base, 'infra', 'gcp', 'terraform', 'compute'), { recursive: true });
  mkdirSync(join(base, 'infra', 'gcp', 'terraform', 'data'), { recursive: true });
  mkdirSync(join(base, 'infra', 'gcp', 'terraform', 'security'), { recursive: true });
  mkdirSync(join(base, 'infra', 'gcp', 'terraform', 'observability'), { recursive: true });
  mkdirSync(join(base, 'infra', 'gcp', 'config-connector'), { recursive: true });
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'README.md'),
    makeValidGcpTfReadme());
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'network', 'main.tf'),
    makeValidGcpTfNetwork());
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'compute', 'main.tf'),
    makeValidGcpTfCompute());
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'data', 'main.tf'),
    makeValidGcpTfData());
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'security', 'main.tf'),
    makeValidGcpTfSecurity());
  writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'observability', 'main.tf'),
    makeValidGcpTfObservability());
  writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-sql.yaml'),
    makeValidGcpCcSql());
  writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'memorystore.yaml'),
    makeValidGcpCcMemorystore());
  writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-kms.yaml'),
    makeValidGcpCcKms());
  writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'artifact-registry.yaml'),
    makeValidGcpCcAr());
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'),
    makeValidValuesAzure());
  writeFileSync(join(base, 'docs', 'multi-cloud.md'),
    makeValidMultiCloudRunbook());
}

function run(root) {
  return spawnSync(process.execPath, [scriptPath, '--root', root], {
    encoding: 'utf8',
    timeout: 15000,
  });
}

// ---------------------------------------------------------------------------
// Tests — AWS Phase 1
// ---------------------------------------------------------------------------

test('passes on fully valid AWS Phase 1+2 and GCP Phase 1 documentation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    const result = run(base);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.match(result.stdout, /all checks passed/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when docs/deploy-eks.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'docs', 'deploy-eks.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /deploy-eks\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the IRSA section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('IAM Roles for Service Accounts', 'Identity config'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /IRSA/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the IRSA annotation example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('eks.amazonaws.com/role-arn', 'annotation'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /IRSA annotation/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the ECR section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace(/ECR/g, 'Container Registry'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ECR/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the ALB Ingress Controller section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace(/ALB Ingress Controller/g, 'Ingress Controller'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ALB Ingress Controller/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md does not reference values-aws.yaml', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('values-aws.yaml', 'values.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /values-aws\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the CloudWatch section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace(/CloudWatch/g, 'Metrics'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /CloudWatch/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the Security Hub section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace(/Security Hub/g, 'SIEM'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Security Hub/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the OCSF mapping', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('OCSF', 'structured'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /OCSF/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-eks.md is missing the denial_reason histogram query', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('denial_reason', 'denial-reason'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /denial_reason histogram/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when docs/secrets-aws.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'docs', 'secrets-aws.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /secrets-aws\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing AUDIT_LEDGER_HMAC_SECRET reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace(/AUDIT_LEDGER_HMAC_SECRET/g, 'HMAC_SECRET'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUDIT_LEDGER_HMAC_SECRET/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing PARTNER_DID_PIN_SECRET reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('PARTNER_DID_PIN_SECRET', 'DID_PIN_SECRET'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /PARTNER_DID_PIN_SECRET/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing the EunoKmsSigningPolicy definition', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace(/EunoKmsSigningPolicy/g, 'KmsPolicy'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /EunoKmsSigningPolicy/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing the ESO section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace(/External Secrets Operator/g, 'ESO'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /External Secrets Operator/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing the SecretStore example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    // Replace all 'SecretStore' occurrences including in AwsSecretsManagerSecretStore
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace(/SecretStore/g, 'StoreResource'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SecretStore/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing the ASCP / CSI section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('Secrets Store CSI', 'CSI provider'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ASCP.*CSI/i);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-aws.md is missing the ESO vs ASCP comparison', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('ESO vs. ASCP', 'Comparison'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ESO vs\. ASCP/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the Cognito SCIM bridge section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace('Cognito SCIM bridge', 'SCIM section'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cognito SCIM bridge/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the IAM Identity Center reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace(/IAM Identity Center/g, 'Identity Center'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /IAM Identity Center/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing ISSUER_SCIM_BEARER_TOKEN', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace(/ISSUER_SCIM_BEARER_TOKEN/g, 'SCIM_TOKEN'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ISSUER_SCIM_BEARER_TOKEN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the externalId attribute mapping', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace(/externalId/g, 'external_id'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /externalId/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when k8s/helm/euno/values-aws.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /values-aws\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-aws.yaml is missing the ECR registry reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'),
      makeValidValuesAws().replace(/dkr\.ecr/g, 'private.registry'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ECR registry/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-aws.yaml is missing the IRSA role-arn annotation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'),
      makeValidValuesAws().replace(/eks\.amazonaws\.com\/role-arn/g, 'role-annotation'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /IRSA role-arn/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-aws.yaml is missing aws-kms signing provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'),
      makeValidValuesAws().replace('aws-kms', 'software'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /aws-kms/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-aws.yaml is missing aws-cognito identity provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-aws.yaml'),
      makeValidValuesAws().replace('aws-cognito', 'azure-ad'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /aws-cognito/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ── Phase 2 tests ────────────────────────────────────────────────────────────

test('[Phase 2] fails when deploy-eks.md is missing AUDIT_LEDGER_S3_ENDPOINT', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('AUDIT_LEDGER_S3_ENDPOINT', 'S3_ENDPOINT'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUDIT_LEDGER_S3_ENDPOINT/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when deploy-eks.md is missing AUDIT_LEDGER_S3_FORCE_PATH_STYLE', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('AUDIT_LEDGER_S3_FORCE_PATH_STYLE', 'FORCE_PATH_STYLE'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUDIT_LEDGER_S3_FORCE_PATH_STYLE/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when deploy-eks.md is missing VPC endpoint reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace(/VPC endpoint/g, 'private endpoint'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /VPC endpoint/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when deploy-eks.md is missing GovCloud region example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-eks.md'),
      makeValidDeployEks().replace('us-gov-west-1', 'us-east-1'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GovCloud/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when secrets-aws.md is missing AwsSecretsManagerSecretStore section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('AwsSecretsManagerSecretStore', 'NativeSecretStore'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AwsSecretsManagerSecretStore/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when secrets-aws.md is missing AWS_SECRETS_ARN_* pattern', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace(/AWS_SECRETS_ARN_/g, 'SECRETS_ARN_'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AWS_SECRETS_ARN_/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when secrets-aws.md is missing arnsBySecretName explanation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('arnsBySecretName', 'arnMap'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /arnsBySecretName/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when secrets-aws.md is missing AwsEdDsaSigner documentation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('AwsEdDsaSigner', 'EdDsaSigner'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AwsEdDsaSigner/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when secrets-aws.md is missing AWS_EDDSA_KEY_ARN env var', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('AWS_EDDSA_KEY_ARN', 'EDDSA_KEY_ARN'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AWS_EDDSA_KEY_ARN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when multi-cloud-plan.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'docs', 'multi-cloud-plan.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /multi-cloud-plan\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when multi-cloud-plan.md AWS Secrets Manager item is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlan().replace(
        '[x] **AWS Secrets Manager secrets-store adapter**',
        '[ ] **AWS Secrets Manager secrets-store adapter**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AWS Secrets Manager adapter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when multi-cloud-plan.md S3 endpoint item is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlan().replace(
        '[x] **S3 cross-chain anchor',
        '[ ] **S3 cross-chain anchor',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /S3 endpoint item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 2] fails when multi-cloud-plan.md KMS signer item is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlan().replace(
        '[x] **AWS KMS signer',
        '[ ] **AWS KMS signer',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /KMS.*signer item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails with a useful error message on an unknown argument', () => {
  const result = spawnSync(process.execPath, [scriptPath, '--unknown-flag'], {
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown argument/);
});

test('accepts --root=<path> (equals-sign form)', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    const result = spawnSync(process.execPath, [scriptPath, `--root=${base}`], {
      encoding: 'utf8',
      timeout: 15000,
    });
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tests — GCP Phase 1
// ---------------------------------------------------------------------------

test('fails when docs/deploy-gke.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'docs', 'deploy-gke.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /deploy-gke\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Workload Identity section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace(/Workload Identity/g, 'Pod Identity'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Workload Identity/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Workload Identity annotation example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace('iam.gke.io/gcp-service-account', 'service-account-annotation'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Workload Identity annotation/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Artifact Registry section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace(/Artifact Registry/g, 'Container Registry'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Artifact Registry/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the GKE Ingress section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace(/GKE Ingress/g, 'Ingress'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GKE Ingress/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Google-managed SSL certificate section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace('ManagedCertificate', 'Certificate'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ManagedCertificate/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md does not reference values-gcp.yaml', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace('values-gcp.yaml', 'values.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /values-gcp\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Cloud Monitoring section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace(/Cloud Monitoring/g, 'Metrics'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cloud Monitoring/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the Security Command Center section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace(/Security Command Center/g, 'SIEM'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Security Command Center/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the OCSF → SCC mapping', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace('OCSF', 'structured'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /OCSF/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when deploy-gke.md is missing the denial_reason histogram query', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'deploy-gke.md'),
      makeValidDeployGke().replace('denial_reason', 'denial-reason'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /denial_reason histogram/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when docs/secrets-gcp.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'docs', 'secrets-gcp.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /secrets-gcp\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing AUDIT_LEDGER_HMAC_SECRET reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace('AUDIT_LEDGER_HMAC_SECRET', 'HMAC_SECRET'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUDIT_LEDGER_HMAC_SECRET/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing PARTNER_DID_PIN_SECRET reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace('PARTNER_DID_PIN_SECRET', 'DID_PIN_SECRET'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /PARTNER_DID_PIN_SECRET/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing the Secret Accessor IAM role binding', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace('secretAccessor', 'secretAdmin'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Secret Accessor/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing the ESO section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace(/External Secrets Operator/g, 'ESO'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /External Secrets Operator/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing the SecretStore example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace('SecretStore', 'StoreResource'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SecretStore/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing the Secret Manager Add-on section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace(/Secret Manager Add-on/g, 'CSI Add-on'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Secret Manager Add-on/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when secrets-gcp.md is missing the ESO vs. comparison', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'secrets-gcp.md'),
      makeValidSecretsGcp().replace('ESO vs.', 'Comparison:'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ESO vs\./);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the Google Workspace SCIM bridge section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace('Google Workspace SCIM bridge', 'GWS SCIM section'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Google Workspace SCIM bridge/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the OAuth service account reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace('OAuth service account', 'service account'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /OAuth service account/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md is missing the externalId = user.id mapping', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'),
      makeValidIdpSetup().replace('externalId: user.id,', 'externalId: userId,'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /externalId.*user\.id/i);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md §11 is missing ISSUER_SCIM_BEARER_TOKEN', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    // Keep ISSUER_SCIM_BEARER_TOKEN in §10 but remove it from §11 only.
    const content = makeValidIdpSetup().replace(
      'OAuth service account for SCIM provisioning.\nISSUER_SCIM_BEARER_TOKEN=<token>',
      'OAuth service account for SCIM provisioning.');
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'), content);
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ISSUER_SCIM_BEARER_TOKEN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when issuer-idp-setup.md §11 is missing ISSUER_SCIM_GROUP_ROLE_MAP', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    // Keep ISSUER_SCIM_GROUP_ROLE_MAP in §10 but remove it from §11 only.
    const content = makeValidIdpSetup().replace(
      'externalId: user.id,   // Google internal user ID\nISSUER_SCIM_GROUP_ROLE_MAP={"EunoReaders":"reader"}',
      'externalId: user.id,   // Google internal user ID');
    writeFileSync(join(base, 'docs', 'issuer-idp-setup.md'), content);
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ISSUER_SCIM_GROUP_ROLE_MAP/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when k8s/helm/euno/values-gcp.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    unlinkSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /values-gcp\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-gcp.yaml is missing the Artifact Registry reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'),
      makeValidValuesGcp().replace(/pkg\.dev/g, 'gcr.io'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Artifact Registry.*pkg\.dev/i);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-gcp.yaml is missing the Workload Identity annotation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'),
      makeValidValuesGcp().replace(/iam\.gke\.io\/gcp-service-account/g, 'service-account'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /iam\.gke\.io\/gcp-service-account/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-gcp.yaml is missing gcp-cloudkms signing provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'),
      makeValidValuesGcp().replace('gcp-cloudkms', 'software'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /gcp-cloudkms/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-gcp.yaml is missing gcp-identity identity provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'),
      makeValidValuesGcp().replace('gcp-identity', 'azure-ad'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /gcp-identity/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('fails when values-gcp.yaml is missing GCP_PROJECT_ID placeholder', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'),
      makeValidValuesGcp().replace(/GCP_PROJECT_ID/g, 'PROJECT_ID'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GCP_PROJECT_ID/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Helpers — GCP Phase 3 fixtures
// ---------------------------------------------------------------------------

function makeValidGcpTfReadme() {
  return [
    '# Euno — GCP Terraform Modules',
    '',
    '## Quick start',
    '',
    '```bash',
    'terraform init',
    '```',
    '',
    '```bash',
    'terraform apply tfplan',
    '```',
    '',
    '## Module reference',
    '',
    '### network/ — VPC, subnets, Cloud NAT',
    '### compute/ — GKE, Workload Identity, autoscaling',
    '### data/ — Cloud SQL, Memorystore',
    '### security/ — Cloud KMS keyring, Secret Manager, IAM',
    '### observability/ — Cloud Monitoring dashboards, alerting policies',
  ].join('\n');
}

function makeValidGcpTfNetwork() {
  return [
    '# Module: network',
    'resource "google_compute_network" "main" {',
    '  name = "${var.name_prefix}-vpc"',
    '}',
    'resource "google_compute_router_nat" "nat" {',
    '  name = "${var.name_prefix}-nat"',
    '}',
  ].join('\n');
}

function makeValidGcpTfCompute() {
  return [
    '# Module: compute',
    'resource "google_container_cluster" "main" {',
    '  name = local.cluster_name',
    '  workload_identity_config {',
    '    workload_pool = "${var.project_id}.svc.id.goog"',
    '  }',
    '}',
    'resource "google_container_node_pool" "system" {',
    '  autoscaling {',
    '    min_node_count = var.gke_node_count',
    '    max_node_count = var.gke_node_max_count',
    '  }',
    '}',
  ].join('\n');
}

function makeValidGcpTfData() {
  return [
    '# Module: data',
    'resource "google_sql_database_instance" "main" {',
    '  database_version = "POSTGRES_15"',
    '}',
    'resource "google_redis_instance" "main" {',
    '  tier = var.redis_tier',
    '}',
  ].join('\n');
}

function makeValidGcpTfSecurity() {
  return [
    '# Module: security',
    'resource "google_kms_key_ring" "main" {',
    '  name = local.keyring_name',
    '}',
    'resource "google_kms_crypto_key" "capability_signing" {',
    '  purpose = "ASYMMETRIC_SIGN"',
    '}',
    'resource "google_secret_manager_secret" "secrets" {',
    '  for_each = local.secret_names',
    '}',
    'resource "google_project_iam_member" "issuer_secret_accessor" {',
    '  role = "roles/secretmanager.secretAccessor"',
    '}',
  ].join('\n');
}

function makeValidGcpTfObservability() {
  return [
    '# Module: observability',
    'resource "google_monitoring_dashboard" "euno_runtime" {',
    '  dashboard_json = jsonencode({',
    '    displayName = "Euno Runtime"',
    '  })',
    '}',
    'resource "google_monitoring_alert_policy" "denial_spike" {',
    '  display_name = "Euno — Denial Spike"',
    '  conditions {',
    '    condition_threshold {',
    '      filter = "metric.type=\\"euno_denial_rate\\""',
    '    }',
    '  }',
    '}',
  ].join('\n');
}

function makeValidGcpCcSql() {
  return [
    'apiVersion: sql.cnrm.cloud.google.com/v1beta1',
    'kind: SQLInstance',
    'metadata:',
    '  name: euno-postgres',
    'spec:',
    '  databaseVersion: POSTGRES_15',
    '---',
    'apiVersion: sql.cnrm.cloud.google.com/v1beta1',
    'kind: SQLDatabase',
    'metadata:',
    '  name: euno-db',
  ].join('\n');
}

function makeValidGcpCcMemorystore() {
  return [
    'apiVersion: redis.cnrm.cloud.google.com/v1beta1',
    'kind: RedisInstance',
    'metadata:',
    '  name: euno-redis',
    'spec:',
    '  tier: STANDARD_HA',
    '  redisVersion: REDIS_7_0',
  ].join('\n');
}

function makeValidGcpCcKms() {
  return [
    'apiVersion: cloudkms.cnrm.cloud.google.com/v1beta1',
    'kind: KMSKeyRing',
    'metadata:',
    '  name: euno-keyring',
    '---',
    'apiVersion: cloudkms.cnrm.cloud.google.com/v1beta1',
    'kind: KMSCryptoKey',
    'metadata:',
    '  name: euno-capability-signing-key',
    '---',
    'apiVersion: iam.cnrm.cloud.google.com/v1beta1',
    'kind: IAMPolicyMember',
    'metadata:',
    '  name: euno-issuer-workloadIdentityUser',
    'spec:',
    '  role: roles/iam.workloadIdentityUser',
  ].join('\n');
}

function makeValidGcpCcAr() {
  return [
    'apiVersion: artifactregistry.cnrm.cloud.google.com/v1beta1',
    'kind: ArtifactRegistryRepository',
    'metadata:',
    '  name: euno-images',
    'spec:',
    '  format: DOCKER',
  ].join('\n');
}

function makeValidValuesAzure() {
  return [
    '# Euno umbrella chart — Azure / AKS overrides',
    '',
    'gateway:',
    '  image:',
    '    repository: myacr.azurecr.io/euno/tool-gateway',
    '  serviceAccountAnnotations:',
    '    azure.workload.identity/client-id: "00000000-0000-0000-0000-000000000000"',
    '  env:',
    '    SIGNING_PROVIDER: azure-keyvault',
    '',
    'issuer:',
    '  env:',
    '    IDENTITY_PROVIDER: azure-ad',
    '    AZURE_AD_TENANT_ID: "00000000-0000-0000-0000-000000000000"',
    '',
    'postureEmitter:',
    '  persistence:',
    '    storageClass: managed-csi',
  ].join('\n');
}

function makeValidMultiCloudRunbook() {
  return [
    '# Multi-Cloud Deployment Runbook',
    '',
    'This document is the index for multi-cloud deployment and describes the',
    'migration path from single-cloud to multi-cloud.',
    '',
    '## Per-cloud deployment guides',
    '',
    'See [deploy-eks.md](deploy-eks.md) for AWS.',
    'See [deploy-gke.md](deploy-gke.md) for GCP.',
    '',
    'Helm overrides: values-azure.yaml, values-aws.yaml, values-gcp.yaml.',
    '',
    '## Migration paths',
    '',
    'Use a cross-chain anchor for disaster recovery across clouds.',
  ].join('\n');
}

function makeValidMultiCloudPlanPhase3() {
  return [
    makeValidMultiCloudPlan(),
    '',
    '## GCP ecosystem plan',
    '',
    '### Phase 3 — Infrastructure-as-code (longer-term)',
    '',
    '- [x] **Terraform module** (`infra/gcp/terraform/`)',
    '  - network/ data/ security/ observability/',
    '',
    '- [x] **Google Cloud Deployment Manager / Config Connector** (`infra/gcp/config-connector/`)',
    '  - KRM manifests for Cloud SQL, Memorystore, Cloud KMS, Artifact Registry.',
    '',
    '## Cross-cloud work',
    '',
    '- [x] **Helm chart — cloud-specific values files**',
    '  - values-azure.yaml, values-aws.yaml, values-gcp.yaml',
    '',
    '- [x] Integration test matrix across cloud adapters',
    '  - tests/cloud-adapters/ test suites.',
    '',
    '- [x] **Multi-cloud runbook index** (`docs/multi-cloud.md`)',
    '  - Quick comparison table.',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Tests — GCP Phase 3
// ---------------------------------------------------------------------------

test('[Phase 3] passes when all Phase 3 fixtures are present', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    const result = run(base);
    assert.equal(result.status, 0, `stderr: ${result.stderr}`);
    assert.match(result.stdout, /all checks passed/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/README.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'README.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /infra\/gcp\/terraform\/README\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when terraform README is missing terraform init', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'README.md'),
      makeValidGcpTfReadme().replace('terraform init', 'tf init'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /terraform init/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when terraform README is missing terraform apply', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'README.md'),
      makeValidGcpTfReadme().replace('terraform apply', 'tf apply'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /terraform apply/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when terraform README is missing network/ reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'README.md'),
      makeValidGcpTfReadme().replace('network/', 'vpc-module/'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /network\//);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/network/main.tf is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'network', 'main.tf'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /network\/main\.tf/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when network/main.tf is missing google_compute_network', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'network', 'main.tf'),
      makeValidGcpTfNetwork().replace('google_compute_network', 'google_compute_vpc'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /google_compute_network/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when network/main.tf is missing Cloud NAT resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'network', 'main.tf'),
      makeValidGcpTfNetwork().replace('google_compute_router_nat', 'google_compute_router'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cloud NAT/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/compute/main.tf is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'compute', 'main.tf'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /compute\/main\.tf/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when compute/main.tf is missing GKE cluster resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'compute', 'main.tf'),
      makeValidGcpTfCompute().replace('google_container_cluster', 'google_gke_cluster'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /google_container_cluster/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when compute/main.tf is missing Workload Identity config', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'compute', 'main.tf'),
      makeValidGcpTfCompute().replace('workload_identity_config', 'identity_config'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Workload Identity/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when compute/main.tf is missing autoscaling', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'compute', 'main.tf'),
      makeValidGcpTfCompute().replace('autoscaling', 'scaling'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /autoscaling/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/data/main.tf is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'data', 'main.tf'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /data\/main\.tf/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when data/main.tf is missing Cloud SQL resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'data', 'main.tf'),
      makeValidGcpTfData().replace('google_sql_database_instance', 'google_sql_instance'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cloud SQL instance/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when data/main.tf is missing Memorystore resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'data', 'main.tf'),
      makeValidGcpTfData().replace('google_redis_instance', 'google_memorystore_instance'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Memorystore Redis/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/security/main.tf is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'security', 'main.tf'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /security\/main\.tf/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when security/main.tf is missing Cloud KMS key ring', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'security', 'main.tf'),
      makeValidGcpTfSecurity().replace('google_kms_key_ring', 'google_kms_ring'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cloud KMS key ring/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when security/main.tf is missing Secret Manager resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'security', 'main.tf'),
      makeValidGcpTfSecurity().replace('google_secret_manager_secret', 'google_sm_secret'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Secret Manager secret/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when security/main.tf is missing secretAccessor IAM role', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'security', 'main.tf'),
      makeValidGcpTfSecurity().replace('secretmanager.secretAccessor', 'secretmanager.admin'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /secretAccessor/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/terraform/observability/main.tf is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'terraform', 'observability', 'main.tf'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /observability\/main\.tf/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when observability/main.tf is missing Cloud Monitoring dashboard', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'observability', 'main.tf'),
      makeValidGcpTfObservability().replace('google_monitoring_dashboard', 'google_dashboard'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Cloud Monitoring dashboard/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when observability/main.tf is missing alert policy', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'terraform', 'observability', 'main.tf'),
      makeValidGcpTfObservability().replace('google_monitoring_alert_policy', 'google_alert'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /alert policy/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/config-connector/cloud-sql.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-sql.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /cloud-sql\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when cloud-sql.yaml is missing SQLInstance resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-sql.yaml'),
      makeValidGcpCcSql().replace(/SQLInstance/g, 'DatabaseInstance'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SQLInstance/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/config-connector/memorystore.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'config-connector', 'memorystore.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /memorystore\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when memorystore.yaml is missing RedisInstance resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'memorystore.yaml'),
      makeValidGcpCcMemorystore().replace('RedisInstance', 'MemorystoreInstance'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /RedisInstance/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/config-connector/cloud-kms.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-kms.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /cloud-kms\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when cloud-kms.yaml is missing KMSKeyRing resource', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-kms.yaml'),
      makeValidGcpCcKms().replace(/KMSKeyRing/g, 'KeyRing'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /KMSKeyRing/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when cloud-kms.yaml is missing Workload Identity binding', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'cloud-kms.yaml'),
      makeValidGcpCcKms().replace(/workloadIdentityUser/g, 'workloadIdentityViewer'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Workload Identity IAM binding/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when infra/gcp/config-connector/artifact-registry.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'infra', 'gcp', 'config-connector', 'artifact-registry.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /artifact-registry\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when artifact-registry.yaml is missing ArtifactRegistryRepository', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'infra', 'gcp', 'config-connector', 'artifact-registry.yaml'),
      makeValidGcpCcAr().replace('ArtifactRegistryRepository', 'DockerRepository'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ArtifactRegistryRepository/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when k8s/helm/euno/values-azure.yaml is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /values-azure\.yaml/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when values-azure.yaml is missing ACR registry reference', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'),
      makeValidValuesAzure().replace(/azurecr\.io/g, 'myregistry.io'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /azurecr\.io/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when values-azure.yaml is missing Workload Identity annotation', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'),
      makeValidValuesAzure().replace(/azure\.workload\.identity\/client-id/g, 'client-id'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /azure\.workload\.identity\/client-id/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when values-azure.yaml is missing azure-keyvault signing provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'),
      makeValidValuesAzure().replace('azure-keyvault', 'software'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /azure-keyvault/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when values-azure.yaml is missing azure-ad identity provider', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-azure.yaml'),
      makeValidValuesAzure().replace('azure-ad', 'azure-b2c'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /azure-ad/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when docs/multi-cloud.md is missing', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    rmSync(join(base, 'docs', 'multi-cloud.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /multi-cloud\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud.md is missing deploy-eks.md link', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud.md'),
      makeValidMultiCloudRunbook().replace(/deploy-eks\.md/g, 'eks-guide.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /deploy-eks\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud.md is missing deploy-gke.md link', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud.md'),
      makeValidMultiCloudRunbook().replace(/deploy-gke\.md/g, 'gke-guide.md'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /deploy-gke\.md/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud.md is missing migration path section', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud.md'),
      makeValidMultiCloudRunbook().replace('migration', 'upgrade'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /migration/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud.md is missing cross-chain anchor example', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud.md'),
      makeValidMultiCloudRunbook().replace('cross-chain anchor', 'audit anchor'));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /cross-chain anchor/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud-plan.md is missing GCP Terraform module check', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] **Terraform module**',
        '[ ] **Terraform module**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GCP Terraform module item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud-plan.md is missing Config Connector check', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] **Google Cloud Deployment Manager / Config Connector**',
        '[ ] **Google Cloud Deployment Manager / Config Connector**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Config Connector item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud-plan.md Helm values files item is not fully checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] **Helm chart — cloud-specific values files**',
        '[ ] **Helm chart — cloud-specific values files**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Helm values files item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Phase 3] fails when multi-cloud-plan.md multi-cloud runbook index is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] **Multi-cloud runbook index**',
        '[ ] **Multi-cloud runbook index**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /multi-cloud runbook index item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[GCP Phase 2] fails when multi-cloud-plan.md GCP Secret Manager item is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] **GCP Secret Manager secrets-store adapter**',
        '[ ] **GCP Secret Manager secrets-store adapter**',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GCP Secret Manager secrets-store adapter/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('[Cross-cloud] fails when multi-cloud-plan.md integration test matrix item is not checked', () => {
  const base = makeTmpRoot();
  try {
    makeValidFixtures(base);
    writeFileSync(join(base, 'docs', 'multi-cloud-plan.md'),
      makeValidMultiCloudPlanPhase3().replace(
        '[x] Integration test matrix across cloud adapters',
        '[ ] Integration test matrix across cloud adapters',
      ));
    const result = run(base);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /integration test matrix item/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
