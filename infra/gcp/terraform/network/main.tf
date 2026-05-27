# ----------------------------------------------------------------------------
# Module: network
# Provisions the VPC, subnet (with GKE secondary ranges), Cloud Router, and
# Cloud NAT required by the Eunox GKE deployment.
# ----------------------------------------------------------------------------

variable "project_id"    { type = string }
variable "name_prefix"   { type = string }
variable "gcp_region"    { type = string }
variable "labels"        { type = map(string) }
variable "subnet_cidr"   { type = string }
variable "pods_cidr"     { type = string }
variable "services_cidr" { type = string }

locals {
  network_name = "${var.name_prefix}-vpc"
  subnet_name  = "${var.name_prefix}-subnet"
}

resource "google_compute_network" "main" {
  name                    = local.network_name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  name                     = local.subnet_name
  project                  = var.project_id
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

# Private services access — required for Cloud SQL private IP.
resource "google_compute_global_address" "private_services" {
  name          = "${var.name_prefix}-private-services-range"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

# Cloud NAT — provides outbound internet access for private GKE nodes.
resource "google_compute_router" "nat" {
  name    = "${var.name_prefix}-router"
  project = var.project_id
  region  = var.gcp_region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.name_prefix}-nat"
  project                            = var.project_id
  router                             = google_compute_router.nat.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "network_id" {
  value       = google_compute_network.main.id
  description = "VPC network self-link — passed to compute and data modules."
}

output "network_name" {
  value       = google_compute_network.main.name
  description = "VPC network name."
}

output "subnetwork_id" {
  value       = google_compute_subnetwork.main.id
  description = "Primary subnet self-link — passed to the compute module."
}
