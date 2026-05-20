# ----------------------------------------------------------------------------
# Module: security
# Provisions Cloud KMS keyring + asymmetric signing key, Secret Manager
# secrets for every Euno credential, and the IAM bindings that allow the
# issuer and gateway service accounts to consume them.
# ----------------------------------------------------------------------------

variable "project_id"  { type = string }
variable "name_prefix" { type = string }
variable "gcp_region"  { type = string }
variable "environment" { type = string }
variable "labels"      { type = map(string) }

locals {
  keyring_name     = "${var.name_prefix}-keyring-${var.environment}"
  signing_key_name = "capability-signing-key"
  issuer_sa_email  = "${var.name_prefix}-issuer-sa@${var.project_id}.iam.gserviceaccount.com"
  gateway_sa_email = "${var.name_prefix}-gateway-sa@${var.project_id}.iam.gserviceaccount.com"

  # Secrets managed by this module — placeholder versions are created here;
  # operators must add the actual secret values via:
  #   gcloud secrets versions add <name> --data-file=<file>
  secret_names = {
    audit_ledger_hmac_secret = "${var.name_prefix}-audit-ledger-hmac-secret"
    gateway_admin_api_key    = "${var.name_prefix}-gateway-admin-api-key"
    partner_did_pin_secret   = "${var.name_prefix}-partner-did-pin-secret"
    issuer_db_password       = "${var.name_prefix}-issuer-db-password"
    pepper_hex               = "${var.name_prefix}-pepper-hex"
  }
}

# ---------------------------------------------------------------------------
# Cloud KMS — key ring + asymmetric RSA-2048 signing key
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "main" {
  name     = local.keyring_name
  project  = var.project_id
  location = var.gcp_region
}

resource "google_kms_crypto_key" "capability_signing" {
  name     = local.signing_key_name
  key_ring = google_kms_key_ring.main.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "SOFTWARE"
  }

  labels = var.labels

  # Signing keys must never be deleted accidentally.
  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Secret Manager — one secret per Euno credential
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "secrets" {
  for_each  = local.secret_names
  project   = var.project_id
  secret_id = each.value

  labels = var.labels

  replication {
    auto {}
  }
}

# Grant both SAs access to read secrets via roles/secretmanager.secretAccessor.
# This is the same role used by the ESO GCP provider and the Secret Manager
# Add-on — see docs/secrets-gcp.md for details.
resource "google_project_iam_member" "issuer_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${local.issuer_sa_email}"
}

resource "google_project_iam_member" "gateway_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${local.gateway_sa_email}"
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "signing_key_id" {
  value       = google_kms_crypto_key.capability_signing.id
  description = "Cloud KMS crypto key ID — set as GCP_KMS_KEY_NAME."
}

output "keyring_id" {
  value       = google_kms_key_ring.main.id
  description = "Cloud KMS key ring ID."
}

output "secret_ids" {
  value       = { for k, v in google_secret_manager_secret.secrets : k => v.id }
  description = "Map of logical name → Secret Manager secret resource IDs."
}
