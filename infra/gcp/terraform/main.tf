# ----------------------------------------------------------------------------
# Euno — GCP Terraform root module
# ----------------------------------------------------------------------------
# Composes the network, compute, data, security, and observability sub-modules
# into a complete Euno deployment on GCP.
#
# Usage:
#   cd infra/gcp/terraform
#   terraform init
#   terraform plan  -out=tfplan
#   terraform apply tfplan
# ----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.20.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Shared inputs
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
  description = "GCP region for all regional resources."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment label (e.g. pilot, staging, prod)."
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

# Networking inputs forwarded to module.network
variable "subnet_cidr" {
  description = "Primary subnet CIDR for GKE nodes."
  type        = string
  default     = "10.50.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range CIDR for GKE pods."
  type        = string
  default     = "10.52.0.0/14"
}

variable "services_cidr" {
  description = "Secondary range CIDR for GKE services."
  type        = string
  default     = "10.56.0.0/20"
}

# Compute inputs forwarded to module.compute
variable "gke_node_machine_type" {
  description = "Machine type for GKE nodes."
  type        = string
  default     = "e2-standard-4"
}

variable "gke_node_count" {
  description = "Initial number of nodes per zone."
  type        = number
  default     = 1
}

variable "gke_node_max_count" {
  description = "Maximum nodes per zone for the cluster autoscaler."
  type        = number
  default     = 3
}

# Data inputs forwarded to module.data
variable "db_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-g1-small"
}

variable "db_ha_enabled" {
  description = "Enable Cloud SQL high-availability replica."
  type        = bool
  default     = true
}

variable "redis_tier" {
  description = "Memorystore Redis tier (BASIC or STANDARD_HA)."
  type        = string
  default     = "STANDARD_HA"
}

variable "redis_memory_size_gb" {
  description = "Memorystore Redis memory size in GiB."
  type        = number
  default     = 4
}

# Observability inputs forwarded to module.observability
variable "log_retention_days" {
  description = "Cloud Logging bucket retention in days."
  type        = number
  default     = 90
}

# ---------------------------------------------------------------------------
# Enable required APIs once — shared across modules
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
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "securitycenter.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

locals {
  common_labels = merge(var.labels, { environment = var.environment })
}

# ---------------------------------------------------------------------------
# Sub-modules
# ---------------------------------------------------------------------------
module "network" {
  source = "./network"

  project_id    = var.project_id
  name_prefix   = var.name_prefix
  gcp_region    = var.gcp_region
  labels        = local.common_labels
  subnet_cidr   = var.subnet_cidr
  pods_cidr     = var.pods_cidr
  services_cidr = var.services_cidr

  depends_on = [google_project_service.required]
}

module "security" {
  source = "./security"

  project_id  = var.project_id
  name_prefix = var.name_prefix
  gcp_region  = var.gcp_region
  environment = var.environment
  labels      = local.common_labels

  depends_on = [google_project_service.required]
}

module "compute" {
  source = "./compute"

  project_id            = var.project_id
  name_prefix           = var.name_prefix
  gcp_region            = var.gcp_region
  environment           = var.environment
  labels                = local.common_labels
  network_id            = module.network.network_id
  subnetwork_id         = module.network.subnetwork_id
  gke_node_machine_type = var.gke_node_machine_type
  gke_node_count        = var.gke_node_count
  gke_node_max_count    = var.gke_node_max_count
  signing_key_id        = module.security.signing_key_id

  depends_on = [module.network, module.security]
}

module "data" {
  source = "./data"

  project_id           = var.project_id
  name_prefix          = var.name_prefix
  gcp_region           = var.gcp_region
  environment          = var.environment
  labels               = local.common_labels
  network_id           = module.network.network_id
  db_tier              = var.db_tier
  db_ha_enabled        = var.db_ha_enabled
  redis_tier           = var.redis_tier
  redis_memory_size_gb = var.redis_memory_size_gb

  depends_on = [module.network]
}

module "observability" {
  source = "./observability"

  project_id         = var.project_id
  name_prefix        = var.name_prefix
  gcp_region         = var.gcp_region
  environment        = var.environment
  labels             = local.common_labels
  log_retention_days = var.log_retention_days

  depends_on = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Outputs — pass these to kubectl / helm
# ---------------------------------------------------------------------------
output "cluster_name" {
  value       = module.compute.cluster_name
  description = "GKE cluster name."
}

output "gcp_region" {
  value       = var.gcp_region
  description = "GCP region used for all resources."
}

output "issuer_service_account_email" {
  value       = module.compute.issuer_service_account_email
  description = "Annotate the capability-issuer KSA with this GCP SA email."
}

output "gateway_service_account_email" {
  value       = module.compute.gateway_service_account_email
  description = "Annotate the tool-gateway KSA with this GCP SA email."
}

output "signing_key_id" {
  value       = module.security.signing_key_id
  description = "Set as GCP_KMS_KEY_NAME for GCPCloudKMSSigner."
}

output "artifact_registry_url" {
  value       = module.compute.artifact_registry_url
  description = "Push container images to this URL."
}

output "gateway_db_url" {
  value       = module.data.gateway_db_url
  description = "PostgreSQL connection URL for AUDIT_LEDGER_PG_URL / ISSUER_DB_URL."
  sensitive   = true
}

output "gateway_redis_url" {
  value       = module.data.gateway_redis_url
  description = "Redis connection URL for REDIS_URL (TLS, AUTH enabled)."
  sensitive   = true
}
