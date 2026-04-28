# ----------------------------------------------------------------------------
# Euno Capability-Native Agent Governance — GCP Terraform deployment
# ----------------------------------------------------------------------------
#
# Sprint-1 multi-cloud parity for `infra/bicep/main.bicep`.  Provisions every
# GCP resource required by the capability-native runtime:
#
#   * Cloud Logging log bucket  (parity with Log Analytics Workspace)
#   * Cloud KMS asymmetric signing key  (parity with Key Vault RSA key)
#   * Identity Platform tenant inputs (parity with Azure AD app registration —
#     consumed by GCPIdentityProvider in @euno/capability-issuer)
#   * Workload Identity Federation binding for the Capability Issuer
#     ServiceAccount (parity with Azure user-assigned managed identity)
#   * Service account for Tool Gateway with Cloud Logging write permission
#   * Artifact Registry repository (parity with ACR)
#   * GKE cluster (parity with AKS) with Workload Identity enabled and
#     control-plane logs streamed to Cloud Logging
#   * Security Command Center notification config skeleton (consumed by
#     ../../gcp/security/scc-custom-modules.yaml)
#
# Deploy with:
#
#   cd infra/terraform/gcp
#   terraform init
#   terraform apply -var="project_id=<your-project>"
#
# All naming is parameterized so the same module can be re-applied for staging
# / pilot / prod by changing `name_prefix` and `environment`.
# ----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.20.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
variable "project_id" {
  description = "GCP project ID hosting the Euno deployment."
  type        = string
}

variable "name_prefix" {
  description = "Short prefix used to name all resources (3-12 lowercase chars)."
  type        = string
  default     = "euno"
  validation {
    condition     = length(var.name_prefix) >= 3 && length(var.name_prefix) <= 12
    error_message = "name_prefix must be 3-12 characters."
  }
}

variable "gcp_region" {
  description = "GCP region for regional resources."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
  default     = "pilot"
}

variable "labels" {
  description = "Labels applied to all resources."
  type        = map(string)
  default = {
    product   = "euno"
    component = "capability-governance"
  }
}

variable "log_retention_days" {
  description = "Cloud Logging bucket retention in days."
  type        = number
  default     = 90
}

variable "gke_node_machine_type" {
  description = "Machine type for the GKE node pool."
  type        = string
  default     = "e2-standard-4"
}

variable "gke_node_count" {
  description = "Number of nodes per zone for the GKE node pool."
  type        = number
  default     = 1
}

variable "gke_node_max_count" {
  description = "Maximum number of nodes per zone (cluster autoscaler upper bound)."
  type        = number
  default     = 3
}

variable "subnet_cidr" {
  description = "Primary CIDR for the GKE subnet."
  type        = string
  default     = "10.50.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range for GKE pods."
  type        = string
  default     = "10.52.0.0/14"
}

variable "services_cidr" {
  description = "Secondary range for GKE services."
  type        = string
  default     = "10.56.0.0/20"
}

variable "enable_scc_notification" {
  description = "Create a Security Command Center notification config (requires Org-level enablement)."
  type        = bool
  default     = false
}

variable "scc_organization_id" {
  description = "Organization ID for SCC notification config (only when enable_scc_notification = true)."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Locals
# ---------------------------------------------------------------------------
locals {
  common_labels = merge(var.labels, { environment = var.environment })

  cluster_name      = "${var.name_prefix}-gke-${var.environment}"
  network_name      = "${var.name_prefix}-vpc"
  subnet_name       = "${var.name_prefix}-subnet"
  signing_keyring   = "${var.name_prefix}-keyring-${var.environment}"
  signing_key_name  = "capability-signing-key"
  artifact_repo     = "${var.name_prefix}-images"
  issuer_sa_id      = "${var.name_prefix}-issuer-sa"
  gateway_sa_id     = "${var.name_prefix}-gateway-sa"
  log_bucket_name   = "${var.name_prefix}-runtime-logs-${var.environment}"
  audit_log_bucket  = "${var.name_prefix}-audit-logs-${var.environment}"
  pubsub_topic_scc  = "${var.name_prefix}-scc-findings"
}

# ---------------------------------------------------------------------------
# Required APIs
# ---------------------------------------------------------------------------
resource "google_project_service" "required" {
  for_each = toset([
    "container.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "compute.googleapis.com",
    "identitytoolkit.googleapis.com",
    "securitycenter.googleapis.com",
    "pubsub.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------
# Networking — VPC + subnet (with secondary ranges for VPC-native GKE)
# ---------------------------------------------------------------------------
resource "google_compute_network" "main" {
  name                    = local.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  depends_on              = [google_project_service.required]
}

resource "google_compute_subnetwork" "main" {
  name                     = local.subnet_name
  ip_cidr_range            = var.subnet_cidr
  region                   = var.gcp_region
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

resource "google_compute_router" "nat" {
  name    = "${var.name_prefix}-router"
  region  = var.gcp_region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.name_prefix}-nat"
  router                             = google_compute_router.nat.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# ---------------------------------------------------------------------------
# Cloud Logging — dedicated log buckets (parity with Log Analytics Workspace)
# ---------------------------------------------------------------------------
resource "google_logging_project_bucket_config" "runtime" {
  project        = var.project_id
  location       = var.gcp_region
  retention_days = var.log_retention_days
  bucket_id      = local.log_bucket_name
  description    = "Euno runtime logs (parity with Azure Log Analytics)."
}

resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.gcp_region
  retention_days = var.log_retention_days
  bucket_id      = local.audit_log_bucket
  description    = "Euno audit logs (logType=audit) — used by SCC custom modules."
}

# Sink the audit-tagged logs into the dedicated bucket.
resource "google_logging_project_sink" "audit" {
  name        = "${var.name_prefix}-audit-sink"
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.gcp_region}/buckets/${local.audit_log_bucket}"
  # jsonPayload.logType is set by createAuditLogger() in @euno/common.
  filter                 = "jsonPayload.logType=\"audit\""
  unique_writer_identity = true
  depends_on             = [google_logging_project_bucket_config.audit]
}

# ---------------------------------------------------------------------------
# Cloud KMS asymmetric signing key (parity with Key Vault RSA-2048 key)
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "main" {
  name       = local.signing_keyring
  location   = var.gcp_region
  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key" "capability_signing" {
  name     = local.signing_key_name
  key_ring = google_kms_key_ring.main.id
  purpose  = "ASYMMETRIC_SIGN"
  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "SOFTWARE"
  }
  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Artifact Registry (parity with ACR)
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "images" {
  location      = var.gcp_region
  repository_id = local.artifact_repo
  description   = "Euno service container images."
  format        = "DOCKER"
  labels        = local.common_labels
  depends_on    = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Service accounts + Workload Identity bindings
# (parity with Azure user-assigned managed identity)
# ---------------------------------------------------------------------------
resource "google_service_account" "issuer" {
  account_id   = local.issuer_sa_id
  display_name = "Euno Capability Issuer"
  description  = "Used by capability-issuer pods via GKE Workload Identity."
}

resource "google_service_account" "gateway" {
  account_id   = local.gateway_sa_id
  display_name = "Euno Tool Gateway"
  description  = "Used by tool-gateway pods via GKE Workload Identity."
}

# IAM: issuer can sign with the KMS key + verify + read public key.
resource "google_kms_crypto_key_iam_member" "issuer_signer" {
  crypto_key_id = google_kms_crypto_key.capability_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_kms_crypto_key_iam_member" "issuer_viewer" {
  crypto_key_id = google_kms_crypto_key.capability_signing.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.issuer.email}"
}

# IAM: gateway only needs Verify + read public key.
resource "google_kms_crypto_key_iam_member" "gateway_verifier" {
  crypto_key_id = google_kms_crypto_key.capability_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_kms_crypto_key_iam_member" "gateway_viewer" {
  crypto_key_id = google_kms_crypto_key.capability_signing.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}

# Logging permissions for both services so the GCP Cloud Logging transport
# (see packages/common/src/log-transports.ts) can write structured entries.
resource "google_project_iam_member" "issuer_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_project_iam_member" "gateway_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# Workload Identity bindings (Kubernetes SA → GCP SA).
resource "google_service_account_iam_member" "issuer_wi" {
  service_account_id = google_service_account.issuer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[euno-system/capability-issuer]"
}

resource "google_service_account_iam_member" "gateway_wi" {
  service_account_id = google_service_account.gateway.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[euno-system/tool-gateway]"
}

# Allow either workload to pull images from Artifact Registry.
resource "google_artifact_registry_repository_iam_member" "issuer_reader" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_artifact_registry_repository_iam_member" "gateway_reader" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.gateway.email}"
}

# ---------------------------------------------------------------------------
# GKE cluster (parity with AKS)
# ---------------------------------------------------------------------------
resource "google_container_cluster" "main" {
  name     = local.cluster_name
  location = var.gcp_region
  # Use a release channel for managed upgrades; the literal version below is
  # only honoured when release_channel is UNSPECIFIED.
  release_channel {
    channel = "REGULAR"
  }
  initial_node_count       = 1
  remove_default_node_pool = true
  network                  = google_compute_network.main.id
  subnetwork               = google_compute_subnetwork.main.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  addons_config {
    network_policy_config {
      disabled = false
    }
  }

  resource_labels = local.common_labels

  deletion_protection = false

  depends_on = [
    google_project_service.required,
    google_compute_subnetwork.main,
  ]
}

resource "google_container_node_pool" "system" {
  name       = "system"
  location   = var.gcp_region
  cluster    = google_container_cluster.main.name
  node_count = var.gke_node_count

  autoscaling {
    min_node_count = var.gke_node_count
    max_node_count = var.gke_node_max_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.gke_node_machine_type
    disk_size_gb = 64
    disk_type    = "pd-standard"
    image_type   = "COS_CONTAINERD"
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    labels = local.common_labels
  }
}

# ---------------------------------------------------------------------------
# Security Command Center — Pub/Sub topic + (optional) notification config
# Consumes ../../gcp/security/scc-custom-modules.yaml.
# ---------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_findings" {
  name       = local.pubsub_topic_scc
  labels     = local.common_labels
  depends_on = [google_project_service.required]
}

resource "google_scc_notification_config" "euno" {
  count        = var.enable_scc_notification ? 1 : 0
  config_id    = "${var.name_prefix}-findings"
  organization = var.scc_organization_id
  description  = "Euno capability-governance findings → Pub/Sub for alerting."
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "category=\"EUNO_DENIAL_SPIKE\" OR category=\"EUNO_INVALID_TOKEN_BURST\" OR category=\"EUNO_KILL_SWITCH\""
  }
}

# ---------------------------------------------------------------------------
# Outputs — feed these into the kubectl/helm manifests under ../../../k8s
# ---------------------------------------------------------------------------
output "cluster_name" {
  value       = google_container_cluster.main.name
  description = "GKE cluster name."
}

output "cluster_endpoint" {
  value       = google_container_cluster.main.endpoint
  description = "GKE control-plane endpoint."
  sensitive   = true
}

output "workload_pool" {
  value       = google_container_cluster.main.workload_identity_config[0].workload_pool
  description = "Workload Identity pool ID."
}

output "issuer_service_account_email" {
  value       = google_service_account.issuer.email
  description = "Annotate the capability-issuer KSA with this GCP SA email."
}

output "gateway_service_account_email" {
  value       = google_service_account.gateway.email
  description = "Annotate the tool-gateway KSA with this GCP SA email."
}

output "signing_key_id" {
  value       = google_kms_crypto_key.capability_signing.id
  description = "Set as GCP_KMS_KEY_NAME for GCPCloudKMSSigner."
}

output "artifact_registry_url" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
  description = "Push container images to this URL."
}

output "runtime_log_bucket" {
  value       = google_logging_project_bucket_config.runtime.bucket_id
  description = "Cloud Logging bucket for runtime logs."
}

output "audit_log_bucket" {
  value       = google_logging_project_bucket_config.audit.bucket_id
  description = "Cloud Logging bucket for audit (logType=audit) entries."
}

output "scc_findings_topic" {
  value       = google_pubsub_topic.scc_findings.id
  description = "Pub/Sub topic that SCC custom modules publish findings to."
}
