# ----------------------------------------------------------------------------
# Euno Sprint-1 OBS multi-cloud parity for infra/sentinel/analytic-rules.json
# on GCP.  Materializes each Cloud Logging filter from
# `cloud-logging-queries.json` as a `google_logging_metric` + a
# `google_monitoring_alert_policy`.
#
# Apply this Terraform module *after* `infra/terraform/gcp/main.tf` has
# created the project resources.  Use the same project_id var.
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

variable "project_id" {
  description = "GCP project ID hosting the Euno deployment."
  type        = string
}

variable "alert_notification_channels" {
  description = "List of `projects/<id>/notificationChannels/<id>` IDs to attach to every alert policy."
  type        = list(string)
  default     = []
}

provider "google" {
  project = var.project_id
}

locals {
  rules = {
    "deny-spike" = {
      display = "Euno - Capability denial spike"
      filter  = <<-EOT
        resource.type="k8s_container"
        labels."k8s-pod/app"=~"tool-gateway|capability-issuer|agent-runtime"
        (jsonPayload.message:"Action denied" OR jsonPayload.message:"AUTHORIZATION_FAILED" OR jsonPayload.message:"INVALID_TOKEN")
      EOT
      threshold = 5
    }
    "write-in-readonly" = {
      display = "Euno - Write attempt from a read-only session"
      filter  = <<-EOT
        resource.type="k8s_container"
        jsonPayload.logType="audit"
        jsonPayload.decision="deny"
        jsonPayload.action=("write" OR "delete" OR "update" OR "create")
        (jsonPayload.reason:"Insufficient permissions" OR jsonPayload.reason:"Invalid audience")
      EOT
      threshold = 1
    }
    "invalid-token-burst" = {
      display = "Euno - Burst of invalid capability tokens"
      filter  = <<-EOT
        resource.type="k8s_container"
        (jsonPayload.message:"INVALID_TOKEN" OR jsonPayload.message:"EXPIRED_TOKEN" OR jsonPayload.message:"invalid signature")
      EOT
      threshold = 20
    }
    "kill-switch-activated" = {
      display = "Euno - Kill switch activated"
      filter  = <<-EOT
        resource.type="k8s_container"
        (jsonPayload.message:"Kill switch activated" OR jsonPayload.message:"KILL_ALL_AGENTS" OR jsonPayload.message:"kill switch enabled")
      EOT
      threshold = 1
    }
    "token-revocation-spike" = {
      display = "Euno - Token revocation spike"
      filter  = <<-EOT
        resource.type="k8s_container"
        jsonPayload.message:"Token revoked via admin API"
      EOT
      threshold = 10
    }
  }
}

resource "google_logging_metric" "rule" {
  for_each = local.rules
  name     = "euno_${replace(each.key, "-", "_")}"
  project  = var.project_id
  filter   = each.value.filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    display_name = each.value.display
  }
}

resource "google_monitoring_alert_policy" "rule" {
  for_each     = local.rules
  display_name = each.value.display
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "${each.value.display} - threshold breached"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.rule[each.key].name}\" resource.type=\"k8s_container\""
      duration        = "300s"
      comparison      = "COMPARISON_GE"
      threshold_value = each.value.threshold
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  notification_channels = var.alert_notification_channels

  documentation {
    mime_type = "text/markdown"
    content   = "Sprint-1 OBS rule. See `infra/sentinel/analytic-rules.json` for the Azure equivalent and `infra/gcp/security/cloud-logging-queries.json` for the source filter."
  }
}

output "metric_names" {
  value = { for k, v in google_logging_metric.rule : k => v.name }
}

output "alert_policy_names" {
  value = { for k, v in google_monitoring_alert_policy.rule : k => v.name }
}
