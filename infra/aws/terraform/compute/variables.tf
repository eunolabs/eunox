variable "name_prefix" {
  description = "Short prefix used to name all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment label."
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.30"
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for EKS worker nodes and Fargate."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the cluster (mixed required by EKS)."
  type        = list(string)
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "use_fargate" {
  description = "When true, provision a Fargate profile instead of a managed node group."
  type        = bool
  default     = true
}

variable "node_instance_type" {
  description = "EC2 instance type for the managed node group (ignored when use_fargate=true)."
  type        = string
  default     = "t3.large"
}

variable "node_desired_size" {
  description = "Desired node count for the managed node group."
  type        = number
  default     = 3
}

variable "node_max_size" {
  description = "Maximum node count for the managed node group."
  type        = number
  default     = 9
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
