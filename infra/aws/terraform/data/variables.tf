variable "name_prefix" {
  description = "Short prefix used to name all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "isolated_subnet_ids" {
  description = "Isolated subnet IDs for RDS and ElastiCache (no NAT egress)."
  type        = list(string)
}

variable "eks_cluster_security_group_id" {
  description = "EKS cluster security group ID allowed to connect to RDS/Redis."
  type        = string
}

variable "db_instance_class" {
  description = "RDS PostgreSQL instance class."
  type        = string
  default     = "db.t3.medium"
}

variable "db_username" {
  description = "Master username for the RDS PostgreSQL instance."
  type        = string
  default     = "eunox_admin"
}

variable "db_multi_az" {
  description = "Enable Multi-AZ for the RDS instance."
  type        = bool
  default     = true
}

variable "db_allocated_storage_gib" {
  description = "Initial RDS storage in GiB."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage_gib" {
  description = "Maximum RDS storage in GiB (for autoscaling)."
  type        = number
  default     = 200
}

variable "db_backup_retention_days" {
  description = "RDS automated backup retention in days."
  type        = number
  default     = 7
}

variable "cache_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t3.medium"
}

variable "cache_num_replicas" {
  description = "Number of ElastiCache read replicas (in addition to 1 primary)."
  type        = number
  default     = 1
}

variable "redis_auth_token" {
  description = "Auth token for the Redis cluster (must be set in secrets or SSM)."
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
