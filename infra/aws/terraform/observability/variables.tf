variable "name_prefix" {
  description = "Short prefix used to name all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID (used for log group and CloudTrail bucket naming)."
  type        = string
}

variable "aws_region" {
  description = "AWS region."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days."
  type        = number
  default     = 90
}

variable "alarm_notification_email" {
  description = "Email address to subscribe to the CloudWatch alarm SNS topic. Empty = no subscription."
  type        = string
  default     = ""
}

variable "denial_spike_threshold" {
  description = "CloudWatch alarm threshold for euno_tool_call_denied_total in a 5-minute window."
  type        = number
  default     = 100
}

variable "enable_security_hub" {
  description = "Enable Security Hub with CIS AWS Foundations Benchmark standard."
  type        = bool
  default     = true
}

variable "audit_anchor_bucket_arn" {
  description = "S3 audit anchor bucket ARN for CloudTrail data-event selector."
  type        = string
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
