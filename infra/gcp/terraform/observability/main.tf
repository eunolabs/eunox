# ----------------------------------------------------------------------------
# Module: observability
# Provisions Cloud Monitoring dashboards, alerting policies, and the Cloud
# Logging infrastructure needed to monitor the Eunox runtime.
# ----------------------------------------------------------------------------

variable "project_id"         { type = string }
variable "name_prefix"        { type = string }
variable "gcp_region"         { type = string }
variable "environment"        { type = string }
variable "labels"             { type = map(string) }
variable "log_retention_days" { type = number }
variable "notification_channel_ids" {
  type    = list(string)
  default = []
}

locals {
  log_bucket_name = "${var.name_prefix}-runtime-logs-${var.environment}"
  audit_bucket_id = "${var.name_prefix}-audit-logs-${var.environment}"
}

# ---------------------------------------------------------------------------
# Cloud Logging — dedicated log buckets
# ---------------------------------------------------------------------------
resource "google_logging_project_bucket_config" "runtime" {
  project        = var.project_id
  location       = var.gcp_region
  retention_days = var.log_retention_days
  bucket_id      = local.log_bucket_name
  description    = "Eunox runtime logs."
}

resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.gcp_region
  retention_days = var.log_retention_days
  bucket_id      = local.audit_bucket_id
  description    = "Eunox audit logs (logType=audit) — consumed by Security Command Center."
}

# Route audit-tagged entries to the dedicated audit bucket.
resource "google_logging_project_sink" "audit" {
  name        = "${var.name_prefix}-audit-sink"
  project     = var.project_id
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.gcp_region}/buckets/${local.audit_bucket_id}"
  filter                 = "jsonPayload.logType=\"audit\""
  unique_writer_identity = true

  depends_on = [google_logging_project_bucket_config.audit]
}

# Grant the sink writer identity write access to the audit bucket.
resource "google_project_iam_member" "audit_sink_writer" {
  project = var.project_id
  role    = "roles/logging.bucketWriter"
  member  = google_logging_project_sink.audit.writer_identity
}

# ---------------------------------------------------------------------------
# Cloud Monitoring — runtime dashboard
# ---------------------------------------------------------------------------
resource "google_monitoring_dashboard" "eunox_runtime" {
  project        = var.project_id
  dashboard_json = jsonencode({
    displayName = "Eunox Runtime — ${var.environment}"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Tool enforcement requests / min"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/eunox_enforce_requests\" resource.type=\"k8s_container\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },
        {
          width  = 6
          height = 4
          widget = {
            title = "Denial rate by reason"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/eunox_denial_rate\" resource.type=\"k8s_container\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_RATE"
                      groupByFields      = ["metric.labels.denial_reason"]
                      crossSeriesReducer = "REDUCE_SUM"
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        },
        {
          width  = 12
          height = 4
          widget = {
            title = "p99 enforcement latency (ms)"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/eunox_enforce_latency_ms\" resource.type=\"k8s_container\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_PERCENTILE_99"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        }
      ]
    }
  })
}

# ---------------------------------------------------------------------------
# Cloud Monitoring — alerting policies
# ---------------------------------------------------------------------------

# Denial spike alert — mirrors the CloudWatch alarm in the AWS module.
resource "google_monitoring_alert_policy" "denial_spike" {
  project      = var.project_id
  display_name = "Eunox — Denial Spike (${var.environment})"
  combiner     = "OR"
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = "Denial rate exceeds 50/min for 5 minutes"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/eunox_denial_rate\" resource.type=\"k8s_container\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "3600s"
  }

  user_labels = var.labels
}

# Invalid token burst alert.
resource "google_monitoring_alert_policy" "invalid_token_burst" {
  project      = var.project_id
  display_name = "Eunox — Invalid Token Burst (${var.environment})"
  combiner     = "OR"
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = "Invalid tokens exceed 20/min for 2 minutes"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/eunox_invalid_token_rate\" resource.type=\"k8s_container\""
      duration        = "120s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "3600s"
  }

  user_labels = var.labels
}

# Pod crash-loop alert.
resource "google_monitoring_alert_policy" "pod_crash_loop" {
  project      = var.project_id
  display_name = "Eunox — Pod Crash Loop (${var.environment})"
  combiner     = "OR"
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = "GKE pod restart count > 5 in 10 minutes"
    condition_threshold {
      filter          = "metric.type=\"kubernetes.io/container/restart_count\" resource.type=\"k8s_container\" resource.labels.namespace_name=\"eunox-system\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.pod_name"]
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = var.labels
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "runtime_log_bucket_id" {
  value       = google_logging_project_bucket_config.runtime.bucket_id
  description = "Cloud Logging bucket for runtime logs."
}

output "audit_log_bucket_id" {
  value       = google_logging_project_bucket_config.audit.bucket_id
  description = "Cloud Logging bucket for audit (logType=audit) entries."
}

output "dashboard_name" {
  value       = google_monitoring_dashboard.eunox_runtime.id
  description = "Cloud Monitoring dashboard resource name."
}
