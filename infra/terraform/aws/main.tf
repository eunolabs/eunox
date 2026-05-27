# ----------------------------------------------------------------------------
# Eunox Capability-Native Agent Governance — AWS Terraform deployment
# ----------------------------------------------------------------------------
#
# Sprint-1 multi-cloud parity for `infra/bicep/main.bicep`.  Provisions every
# AWS resource required by the capability-native runtime:
#
#   * CloudWatch Log Group  (parity with Log Analytics Workspace)
#   * KMS asymmetric signing key  (parity with Key Vault RSA key)
#   * Cognito User Pool + App Client  (parity with Azure AD app registration —
#     consumed by AWSCognitoIdentityProvider in @eunox/capability-issuer)
#   * IAM role for the Capability Issuer pod with KMS Sign/Verify permissions
#     (assumable via IRSA — parity with Azure user-assigned managed identity)
#   * IAM role for the Tool Gateway pod with CloudWatch Logs PutLogEvents
#   * ECR repositories for the three service images (parity with ACR)
#   * EKS cluster (parity with AKS) with OIDC provider for IRSA, control-plane
#     logs streamed to CloudWatch
#   * Security Hub enablement (consumes the custom insights in
#     ../../aws/security/security-hub-insights.json)
#
# Deploy with:
#
#   cd infra/terraform/aws
#   terraform init
#   terraform apply -var="name_prefix=eunox"
#
# All naming is parameterized so the same module can be re-applied for staging
# / pilot / prod by changing `name_prefix` and `environment`.
# ----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
variable "name_prefix" {
  description = "Short prefix used to name all resources (3-12 lowercase chars)."
  type        = string
  default     = "eunox"
  validation {
    condition     = length(var.name_prefix) >= 3 && length(var.name_prefix) <= 12
    error_message = "name_prefix must be 3-12 characters."
  }
}

variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment tag."
  type        = string
  default     = "pilot"
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    product   = "eunox"
    component = "capability-governance"
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 90
}

variable "eks_kubernetes_version" {
  description = "Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.30"
}

variable "eks_node_instance_type" {
  description = "EC2 instance type for EKS managed node group."
  type        = string
  default     = "t3.large"
}

variable "eks_node_desired_size" {
  description = "Desired number of nodes in the EKS managed node group."
  type        = number
  default     = 3
}

variable "eks_node_max_size" {
  description = "Maximum number of nodes in the EKS managed node group."
  type        = number
  default     = 9
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

variable "enable_security_hub" {
  description = "Enable AWS Security Hub in the deployment region."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Naming + locals
# ---------------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  common_tags = merge(var.tags, { environment = var.environment })

  log_group_name        = "/${var.name_prefix}/runtime"
  audit_log_group_name  = "/${var.name_prefix}/audit"
  signing_key_alias     = "alias/${var.name_prefix}-capability-signing"
  cluster_name          = "${var.name_prefix}-eks-${var.environment}"
  issuer_role_name      = "${var.name_prefix}-issuer-irsa-${var.environment}"
  gateway_role_name     = "${var.name_prefix}-gateway-irsa-${var.environment}"
  cognito_pool_name     = "${var.name_prefix}-users-${var.environment}"

  # Public and private subnet lists must always be the same length so they
  # can share an `azs` index and so each private subnet maps to a NAT
  # gateway in the matching public subnet.  Validated by the `check`
  # blocks below.
  public_subnet_count  = length(var.public_subnet_cidrs)
  private_subnet_count = length(var.private_subnet_cidrs)
  subnet_count         = local.public_subnet_count
  available_az_count   = length(data.aws_availability_zones.available.names)
  azs                  = slice(data.aws_availability_zones.available.names, 0, local.subnet_count)
}

check "matching_subnet_cidr_counts" {
  assert {
    condition     = local.public_subnet_count == local.private_subnet_count
    error_message = "public_subnet_cidrs and private_subnet_cidrs must contain the same number of CIDR blocks (each private subnet egresses through the NAT gateway in the public subnet at the same index)."
  }
}

check "sufficient_availability_zones" {
  assert {
    condition     = local.subnet_count <= local.available_az_count
    error_message = "The number of subnet CIDR blocks (${local.subnet_count}) must not exceed the number of availability zones available in the selected AWS region (${local.available_az_count})."
  }
}

# ---------------------------------------------------------------------------
# Networking — VPC / subnets / IGW / NAT for EKS workers
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.common_tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.common_tags, { Name = "${var.name_prefix}-igw" })
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags = merge(local.common_tags, {
    Name                                          = "${var.name_prefix}-public-${count.index}"
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  })
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags = merge(local.common_tags, {
    Name                                          = "${var.name_prefix}-private-${count.index}"
    "kubernetes.io/role/internal-elb"             = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  })
}

resource "aws_eip" "nat" {
  count      = length(var.public_subnet_cidrs)
  domain     = "vpc"
  tags       = merge(local.common_tags, { Name = "${var.name_prefix}-nat-${count.index}" })
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count         = length(var.public_subnet_cidrs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(local.common_tags, { Name = "${var.name_prefix}-nat-${count.index}" })
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rt-public" })
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = length(var.private_subnet_cidrs)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rt-private-${count.index}" })
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ---------------------------------------------------------------------------
# CloudWatch Log Groups (parity with Log Analytics Workspace)
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "runtime" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = local.audit_log_group_name
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, { logType = "audit" })
}

# ---------------------------------------------------------------------------
# KMS asymmetric signing key (parity with Key Vault RSA-2048 key)
# ---------------------------------------------------------------------------
resource "aws_kms_key" "capability_signing" {
  description              = "Eunox capability-token signing key (Sprint 1 parity with Azure Key Vault)"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false # asymmetric KMS keys do not support automatic rotation
  deletion_window_in_days  = 30
  tags                     = local.common_tags
}

resource "aws_kms_alias" "capability_signing" {
  name          = local.signing_key_alias
  target_key_id = aws_kms_key.capability_signing.key_id
}

# ---------------------------------------------------------------------------
# ECR repositories (parity with ACR)
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "service" {
  for_each             = toset(["capability-issuer", "tool-gateway", "agent-runtime"])
  name                 = "${var.name_prefix}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "AES256"
  }
  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# Cognito User Pool — consumed by AWSCognitoIdentityProvider
# (parity with Azure AD app registration)
# ---------------------------------------------------------------------------
resource "aws_cognito_user_pool" "main" {
  name                     = local.cognito_pool_name
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OPTIONAL"
  software_token_mfa_configuration {
    enabled = true
  }
  password_policy {
    minimum_length    = 12
    require_uppercase = true
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
  }
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
  tags = local.common_tags
}

resource "aws_cognito_user_pool_client" "agent_runtime" {
  name                          = "${var.name_prefix}-agent-runtime"
  user_pool_id                  = aws_cognito_user_pool.main.id
  generate_secret               = false
  prevent_user_existence_errors = "ENABLED"
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
  ]
  access_token_validity  = 15 # minutes — matches capability-token TTL
  id_token_validity      = 15
  refresh_token_validity = 30 # days
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

resource "aws_cognito_user_group" "operators" {
  name         = "operators"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Privileged Eunox operators (mapped to admin capability)"
}

resource "aws_cognito_user_group" "agent_users" {
  name         = "agent-users"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Standard Eunox users (mapped to read/write capabilities)"
}

# ---------------------------------------------------------------------------
# EKS cluster (parity with AKS)
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "eks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${var.name_prefix}-eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
  ])
  role       = aws_iam_role.eks_cluster.name
  policy_arn = each.value
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_node" {
  name               = "${var.name_prefix}-eks-node-role"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ])
  role       = aws_iam_role.eks_node.name
  policy_arn = each.value
}

resource "aws_eks_cluster" "main" {
  name     = local.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_kubernetes_version

  vpc_config {
    subnet_ids              = concat(aws_subnet.public[*].id, aws_subnet.private[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id
  instance_types  = [var.eks_node_instance_type]

  scaling_config {
    desired_size = var.eks_node_desired_size
    max_size     = var.eks_node_max_size
    min_size     = var.eks_node_desired_size
  }

  update_config {
    max_unavailable = 1
  }

  tags       = local.common_tags
  depends_on = [aws_iam_role_policy_attachment.eks_node]
}

# ---------------------------------------------------------------------------
# OIDC provider for EKS  →  enables IRSA (IAM Roles for Service Accounts).
# IRSA is the AWS parity of Azure user-assigned managed identity.
# ---------------------------------------------------------------------------
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  tags            = local.common_tags
}

# ---------------------------------------------------------------------------
# IRSA role for the Capability Issuer  →  KMS Sign/Verify on the signing key
# (parity with the Azure user-assigned managed identity granted Key Vault
#  Crypto User in main.bicep).
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "issuer_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:eunox-system:capability-issuer"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "issuer_irsa" {
  name               = local.issuer_role_name
  assume_role_policy = data.aws_iam_policy_document.issuer_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "issuer_kms" {
  statement {
    sid    = "SignWithCapabilityKey"
    effect = "Allow"
    actions = [
      "kms:Sign",
      "kms:Verify",
      "kms:GetPublicKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.capability_signing.arn]
  }
  statement {
    sid    = "AuditAndRuntimeLogs"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${aws_cloudwatch_log_group.runtime.arn}:*",
      "${aws_cloudwatch_log_group.audit.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "issuer" {
  name   = "${var.name_prefix}-issuer-kms"
  role   = aws_iam_role.issuer_irsa.id
  policy = data.aws_iam_policy_document.issuer_kms.json
}

# ---------------------------------------------------------------------------
# IRSA role for the Tool Gateway  →  CloudWatch Logs writer + KMS Verify
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "gateway_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:eunox-system:tool-gateway"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway_irsa" {
  name               = local.gateway_role_name
  assume_role_policy = data.aws_iam_policy_document.gateway_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid    = "VerifyCapabilityTokens"
    effect = "Allow"
    actions = [
      "kms:Verify",
      "kms:GetPublicKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.capability_signing.arn]
  }
  statement {
    sid    = "AuditAndRuntimeLogs"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${aws_cloudwatch_log_group.runtime.arn}:*",
      "${aws_cloudwatch_log_group.audit.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "${var.name_prefix}-gateway"
  role   = aws_iam_role.gateway_irsa.id
  policy = data.aws_iam_policy_document.gateway.json
}

# ---------------------------------------------------------------------------
# Security Hub — consumes the custom insights JSON in
# ../../aws/security/security-hub-insights.json
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "main" {
  count                     = var.enable_security_hub ? 1 : 0
  enable_default_standards  = true
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# ---------------------------------------------------------------------------
# Outputs — feed these into the kubectl/helm manifests under ../../../k8s
# ---------------------------------------------------------------------------
output "cluster_name" {
  value       = aws_eks_cluster.main.name
  description = "EKS cluster name."
}

output "cluster_oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.eks.arn
  description = "OIDC provider ARN for IRSA bindings."
}

output "issuer_role_arn" {
  value       = aws_iam_role.issuer_irsa.arn
  description = "Annotate the capability-issuer ServiceAccount with this ARN."
}

output "gateway_role_arn" {
  value       = aws_iam_role.gateway_irsa.arn
  description = "Annotate the tool-gateway ServiceAccount with this ARN."
}

output "signing_key_arn" {
  value       = aws_kms_key.capability_signing.arn
  description = "ARN to set as AWS_KMS_KEY_ID for AWSKMSSigner."
}

output "signing_key_alias" {
  value       = aws_kms_alias.capability_signing.name
  description = "Human-friendly KMS alias for the signing key."
}

output "cognito_user_pool_id" {
  value       = aws_cognito_user_pool.main.id
  description = "Set as AWS_COGNITO_USER_POOL_ID."
}

output "cognito_app_client_id" {
  value       = aws_cognito_user_pool_client.agent_runtime.id
  description = "Set as AWS_COGNITO_CLIENT_ID."
}

output "ecr_repository_urls" {
  value       = { for k, v in aws_ecr_repository.service : k => v.repository_url }
  description = "ECR repository URLs for each service image."
}

output "runtime_log_group" {
  value       = aws_cloudwatch_log_group.runtime.name
  description = "Set as AWS_CLOUDWATCH_LOG_GROUP for the runtime logger."
}

output "audit_log_group" {
  value       = aws_cloudwatch_log_group.audit.name
  description = "CloudWatch log group for audit (logType=audit) entries."
}
