# ----------------------------------------------------------------------------
# Module: compute
# Provisions the GKE cluster with Workload Identity, autoscaling node pool,
# service accounts for the issuer and gateway pods, and Artifact Registry.
# ----------------------------------------------------------------------------

variable "project_id"            { type = string }
variable "name_prefix"           { type = string }
variable "gcp_region"            { type = string }
variable "environment"           { type = string }
variable "labels"                { type = map(string) }
variable "network_id"            { type = string }
variable "subnetwork_id"         { type = string }
variable "gke_node_machine_type" { type = string }
variable "gke_node_count"        { type = number }
variable "gke_node_max_count"    { type = number }
variable "signing_key_id"        { type = string }

locals {
  cluster_name    = "${var.name_prefix}-gke-${var.environment}"
  issuer_sa_id    = "${var.name_prefix}-issuer-sa"
  gateway_sa_id   = "${var.name_prefix}-gateway-sa"
  artifact_repo   = "${var.name_prefix}-images"
}

# ---------------------------------------------------------------------------
# Service accounts — one per Euno service
# ---------------------------------------------------------------------------
resource "google_service_account" "issuer" {
  project      = var.project_id
  account_id   = local.issuer_sa_id
  display_name = "Euno Capability Issuer"
  description  = "Used by capability-issuer pods via GKE Workload Identity."
}

resource "google_service_account" "gateway" {
  project      = var.project_id
  account_id   = local.gateway_sa_id
  display_name = "Euno Tool Gateway"
  description  = "Used by tool-gateway pods via GKE Workload Identity."
}

# Workload Identity bindings — Kubernetes SA → GCP SA.
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

# KMS signing permissions.
resource "google_kms_crypto_key_iam_member" "issuer_signer" {
  crypto_key_id = var.signing_key_id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_kms_crypto_key_iam_member" "issuer_viewer" {
  crypto_key_id = var.signing_key_id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_kms_crypto_key_iam_member" "gateway_signer" {
  crypto_key_id = var.signing_key_id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_kms_crypto_key_iam_member" "gateway_viewer" {
  crypto_key_id = var.signing_key_id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}

# Cloud Logging write access.
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

# Monitoring write access.
resource "google_project_iam_member" "issuer_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_project_iam_member" "gateway_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# ---------------------------------------------------------------------------
# Artifact Registry — container image registry
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "images" {
  project       = var.project_id
  location      = var.gcp_region
  repository_id = local.artifact_repo
  description   = "Euno service container images."
  format        = "DOCKER"
  labels        = var.labels
}

resource "google_artifact_registry_repository_iam_member" "issuer_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.issuer.email}"
}

resource "google_artifact_registry_repository_iam_member" "gateway_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.gateway.email}"
}

# ---------------------------------------------------------------------------
# GKE cluster — regional, Workload Identity enabled, autoscaling node pool
# ---------------------------------------------------------------------------
resource "google_container_cluster" "main" {
  name     = local.cluster_name
  project  = var.project_id
  location = var.gcp_region

  release_channel {
    channel = "REGULAR"
  }

  # We manage the node pool separately for autoscaling flexibility.
  initial_node_count       = 1
  remove_default_node_pool = true

  network    = var.network_id
  subnetwork = var.subnetwork_id

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
    # GKE Workload Identity is already enabled via workload_identity_config.
  }

  # Disable basic auth and client certificates (use Workload Identity + RBAC).
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  resource_labels = var.labels

  deletion_protection = false
}

resource "google_container_node_pool" "system" {
  name       = "system"
  project    = var.project_id
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
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"

    # Bind each node to its dedicated GCP SA so Workload Identity can derive
    # pod-level credentials without any JSON key file on disk.
    service_account = google_service_account.gateway.email

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = var.labels
  }
}

# ---------------------------------------------------------------------------
# Outputs
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

output "artifact_registry_url" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
  description = "Push container images to this URL."
}
