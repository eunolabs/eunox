# ----------------------------------------------------------------------------
# Module: data
# Provisions Cloud SQL for PostgreSQL (audit/issuer database) and Memorystore
# for Redis (session cache, rate-limit counters, kill-switch state).
# ----------------------------------------------------------------------------

variable "project_id"           { type = string }
variable "name_prefix"          { type = string }
variable "gcp_region"           { type = string }
variable "environment"          { type = string }
variable "labels"               { type = map(string) }
variable "network_id"           { type = string }
variable "db_tier"              { type = string }
variable "db_ha_enabled"        { type = bool }
variable "redis_tier"           { type = string }
variable "redis_memory_size_gb" { type = number }

terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

locals {
  db_instance_name = "${var.name_prefix}-pg-${var.environment}"
  redis_name       = "${var.name_prefix}-redis-${var.environment}"
}

# ---------------------------------------------------------------------------
# Cloud SQL — PostgreSQL 15, private IP, optional HA replica
# ---------------------------------------------------------------------------
resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "-_"
}

resource "google_sql_database_instance" "main" {
  name             = local.db_instance_name
  project          = var.project_id
  region           = var.gcp_region
  database_version = "POSTGRES_15"

  settings {
    tier              = var.db_tier
    availability_type = var.db_ha_enabled ? "REGIONAL" : "ZONAL"
    disk_autoresize   = true
    disk_size         = 20
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 14
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
      require_ssl     = true
    }

    maintenance_window {
      day          = 7  # Sunday
      hour         = 4
      update_track = "stable"
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    user_labels = var.labels
  }

  deletion_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_sql_database" "eunox" {
  name     = "eunox"
  project  = var.project_id
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "eunox" {
  name     = "eunox"
  project  = var.project_id
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
}

# ---------------------------------------------------------------------------
# Memorystore for Redis — STANDARD_HA tier by default (Redis 7.x)
# ---------------------------------------------------------------------------
resource "google_redis_instance" "main" {
  name           = local.redis_name
  project        = var.project_id
  region         = var.gcp_region
  memory_size_gb = var.redis_memory_size_gb
  tier           = var.redis_tier

  redis_version      = "REDIS_7_0"
  display_name       = "Eunox session/rate-limit cache"
  authorized_network = var.network_id

  # TLS and AUTH are mandatory in production.
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled            = true

  redis_configs = {
    "maxmemory-policy" = "allkeys-lru"
  }

  labels = var.labels
}

# ---------------------------------------------------------------------------
# Outputs — consumed by the root module and surfaced to Helm
# ---------------------------------------------------------------------------
output "db_instance_connection_name" {
  value       = google_sql_database_instance.main.connection_name
  description = "Cloud SQL instance connection name for the Auth Proxy sidecar."
}

output "db_private_ip" {
  value       = google_sql_database_instance.main.private_ip_address
  description = "Cloud SQL private IP address for direct VPC access."
}

output "gateway_db_url" {
  value       = "postgresql://eunox:${random_password.db_password.result}@${google_sql_database_instance.main.private_ip_address}:5432/eunox?sslmode=require"
  description = "PostgreSQL connection URL — use as AUDIT_LEDGER_PG_URL / ISSUER_DB_URL."
  sensitive   = true
}

output "redis_host" {
  value       = google_redis_instance.main.host
  description = "Memorystore Redis host IP."
}

output "redis_port" {
  value       = google_redis_instance.main.port
  description = "Memorystore Redis port."
}

output "gateway_redis_url" {
  value       = "rediss://:${google_redis_instance.main.auth_string}@${google_redis_instance.main.host}:${google_redis_instance.main.port}"
  description = "Redis connection URL (TLS + AUTH) — use as REDIS_URL."
  sensitive   = true
}
