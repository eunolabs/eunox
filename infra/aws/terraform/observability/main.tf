# ---------------------------------------------------------------------------
# Euno observability module — CloudWatch, Security Hub, CloudTrail, alarms
# ---------------------------------------------------------------------------

locals {
  common_tags            = merge(var.tags, { environment = var.environment })
  cloudtrail_bucket_name = "${var.name_prefix}-cloudtrail-${var.environment}-${var.aws_account_id}"
}

# ── CloudWatch log groups ─────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "runtime" {
  name              = "/${var.name_prefix}/runtime"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/${var.name_prefix}/audit"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# ── SNS alarm topic ───────────────────────────────────────────────────────────

resource "aws_sns_topic" "alarms" {
  name         = "${var.name_prefix}-alarms-${var.environment}"
  display_name = "Euno capability-governance alarms (${var.environment})"
  tags         = local.common_tags
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count     = var.alarm_notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_notification_email
}

# ── CloudWatch alarms (SOC 2 CC7.3) ──────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "denial_spike" {
  alarm_name          = "${var.name_prefix}-denial-spike-${var.environment}"
  alarm_description   = "Euno capability-governance: unusual denial spike detected (SOC 2 CC7.3). Check denial_reason histogram in CloudWatch Insights."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "ToolCallDeniedTotal"
  namespace           = "Euno/Gateway"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = var.denial_spike_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions = {
    environment = var.environment
  }
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "invalid_token_burst" {
  alarm_name          = "${var.name_prefix}-invalid-token-burst-${var.environment}"
  alarm_description   = "Euno capability-governance: invalid-token burst detected (SOC 2 CC6.8). May indicate a credential leak or misconfigured agent."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "InvalidTokenBurst"
  namespace           = "Euno/Gateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions = {
    environment = var.environment
  }
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "kill_switch_activation" {
  alarm_name          = "${var.name_prefix}-kill-switch-${var.environment}"
  alarm_description   = "Euno capability-governance: kill-switch was activated (SOC 2 CC7.5). All tool-call enforcement is paused — immediate operator attention required."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "KillSwitchActivation"
  namespace           = "Euno/Gateway"
  period              = 60 # 1 minute
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions = {
    environment = var.environment
  }
  tags = local.common_tags
}

# ── Security Hub ──────────────────────────────────────────────────────────────

resource "aws_securityhub_account" "main" {
  count                      = var.enable_security_hub ? 1 : 0
  enable_default_standards   = true
  auto_enable_controls       = true
  control_finding_generator  = "SECURITY_CONTROL"
}

resource "aws_securityhub_standards_subscription" "cis_foundations" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

# ── CloudTrail ────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.cloudtrail_bucket_name
  force_destroy = false
  tags          = merge(local.common_tags, { logType = "cloudtrail" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.aws_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${var.name_prefix}/cloudtrail"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cw" {
  name               = "${var.name_prefix}-cloudtrail-cw-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.name_prefix}-audit-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${var.audit_anchor_bucket_arn}/"]
    }
  }

  tags = local.common_tags

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
