variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID — used for uniquely named S3 buckets."
  type        = string
}

variable "name_prefix" {
  description = "Short prefix used to name all resources (3-12 lowercase alphanumeric chars)."
  type        = string
  default     = "euno"
  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.name_prefix))
    error_message = "name_prefix must be 3-12 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "Deployment environment label (pilot | staging | prod)."
  type        = string
  default     = "pilot"
  validation {
    condition     = contains(["pilot", "staging", "prod"], var.environment)
    error_message = "environment must be one of: pilot, staging, prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.30"
}

variable "use_fargate" {
  description = "When true, provision EKS Fargate for euno-system instead of a managed node group."
  type        = bool
  default     = true
}

variable "db_instance_class" {
  description = "RDS PostgreSQL instance class."
  type        = string
  default     = "db.t3.medium"
}

variable "db_username" {
  description = "Master username for the RDS PostgreSQL instance."
  type        = string
  default     = "euno_admin"
}

variable "db_multi_az" {
  description = "Enable Multi-AZ for the RDS instance (recommended for production)."
  type        = bool
  default     = true
}

variable "cache_node_type" {
  description = "ElastiCache Redis node type."
  type        = string
  default     = "cache.t3.medium"
}

variable "cache_num_replicas" {
  description = "Number of ElastiCache read replicas in addition to the primary."
  type        = number
  default     = 1
}

variable "redis_auth_token" {
  description = "Auth token for the Redis cluster (supply via TF_VAR_redis_auth_token or tfvars)."
  type        = string
  sensitive   = true
}

variable "enable_cognito" {
  description = "When true, provision a Cognito User Pool for agent-user identity."
  type        = bool
  default     = true
}

variable "cognito_domain_prefix" {
  description = "Cognito User Pool domain prefix (must be globally unique). Defaults to <name_prefix>-<environment>."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 90
}

variable "alarm_notification_email" {
  description = "Email address for CloudWatch alarm SNS notifications. Leave empty to skip subscription."
  type        = string
  default     = ""
}

variable "enable_security_hub" {
  description = "Enable Security Hub with CIS AWS Foundations Benchmark."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    product   = "euno"
    component = "capability-governance"
  }
}
