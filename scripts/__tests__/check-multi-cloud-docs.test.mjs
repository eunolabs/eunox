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
    '        externalId: user.id,   // Google internal user ID',
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
  writeFileSync(join(base, 'docs', 'deploy-gke.md'), makeValidDeployGke());
  writeFileSync(join(base, 'docs', 'secrets-gcp.md'), makeValidSecretsGcp());
  writeFileSync(join(base, 'k8s', 'helm', 'euno', 'values-gcp.yaml'), makeValidValuesGcp());
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

test('passes on fully valid multi-cloud Phase 1 documentation', () => {
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
      makeValidSecretsAws().replace('AUDIT_LEDGER_HMAC_SECRET', 'HMAC_SECRET'));
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
    writeFileSync(join(base, 'docs', 'secrets-aws.md'),
      makeValidSecretsAws().replace('SecretStore', 'StoreResource'));
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
