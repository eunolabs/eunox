variable "name_prefix" {
  description = "Short prefix used to name all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
}

variable "cluster_oidc_provider_arn" {
  description = "OIDC provider ARN from the compute module (for IRSA)."
  type        = string
}

variable "cluster_oidc_provider_url" {
  description = "OIDC provider URL (includes https://) from the compute module."
  type        = string
}

variable "audit_anchor_bucket_arn" {
  description = "S3 audit anchor bucket ARN (provisioned in this security module)."
  type        = string
  default     = ""
}

variable "enable_cognito" {
  description = "When true, provision a Cognito User Pool and App Client."
  type        = bool
  default     = true
}

variable "cognito_domain_prefix" {
  description = "Cognito User Pool domain prefix (e.g. 'eunox-prod')."
  type        = string
  default     = ""
}

variable "aws_account_id" {
  description = "AWS account ID (used for bucket naming)."
  type        = string
}

variable "kms_deletion_window_days" {
  description = "KMS key deletion window in days."
  type        = number
  default     = 30
}

variable "s3_audit_retention_days" {
  description = "Object Lock compliance retention for the audit anchor bucket in days."
  type        = number
  default     = 2557
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
