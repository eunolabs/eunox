variable "name_prefix" {
  description = "Short prefix used to name all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs (one per AZ)."
  type        = list(string)
  default     = ["10.40.0.0/20", "10.40.16.0/20", "10.40.32.0/20"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (one per AZ)."
  type        = list(string)
  default     = ["10.40.64.0/20", "10.40.80.0/20", "10.40.96.0/20"]
}

variable "isolated_subnet_cidrs" {
  description = "Isolated (no-egress) subnet CIDRs for RDS and ElastiCache."
  type        = list(string)
  default     = ["10.40.128.0/24", "10.40.129.0/24", "10.40.130.0/24"]
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "cluster_name" {
  description = "EKS cluster name (used for kubernetes.io/cluster tag on subnets)."
  type        = string
}
