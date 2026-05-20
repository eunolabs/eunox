# ---------------------------------------------------------------------------
# Euno AWS Terraform — root module
#
# Wires the five sub-modules together:
#   network      → VPC, subnets, NAT gateways
#   compute      → EKS, Fargate profile, IRSA OIDC provider
#   data         → RDS PostgreSQL, ElastiCache Redis
#   security     → KMS, S3, Secrets Manager, Cognito, IRSA roles, ECR
#   observability→ CloudWatch, Security Hub, CloudTrail, alarms
#
# Quick start:
#   terraform init
#   terraform plan  -var-file=terraform.tfvars
#   terraform apply -var-file=terraform.tfvars
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

locals {
  cluster_name = "${var.name_prefix}-eks-${var.environment}"
}

# ── Network ───────────────────────────────────────────────────────────────────

module "network" {
  source = "./network"

  name_prefix  = var.name_prefix
  environment  = var.environment
  vpc_cidr     = var.vpc_cidr
  cluster_name = local.cluster_name
  tags         = var.tags
}

# ── Observability ──────────────────────────────────────────────────────────────

module "observability" {
  source = "./observability"

  name_prefix               = var.name_prefix
  environment               = var.environment
  aws_account_id            = var.aws_account_id
  aws_region                = var.aws_region
  log_retention_days        = var.log_retention_days
  alarm_notification_email  = var.alarm_notification_email
  enable_security_hub       = var.enable_security_hub
  audit_anchor_bucket_arn   = module.security.audit_anchor_bucket_arn
  tags                      = var.tags
}

# ── Compute ───────────────────────────────────────────────────────────────────

module "compute" {
  source = "./compute"

  name_prefix        = var.name_prefix
  environment        = var.environment
  cluster_name       = local.cluster_name
  kubernetes_version = var.kubernetes_version
  use_fargate        = var.use_fargate
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids
  tags               = var.tags
}

# ── Data ──────────────────────────────────────────────────────────────────────

module "data" {
  source = "./data"

  name_prefix         = var.name_prefix
  environment         = var.environment
  vpc_id              = module.network.vpc_id
  isolated_subnet_ids = module.network.isolated_subnet_ids
  eks_cluster_security_group_id = module.compute.cluster_security_group_id
  db_instance_class   = var.db_instance_class
  db_username         = var.db_username
  db_multi_az         = var.db_multi_az
  cache_node_type     = var.cache_node_type
  cache_num_replicas  = var.cache_num_replicas
  redis_auth_token    = var.redis_auth_token
  tags                = var.tags
}

# ── Security ──────────────────────────────────────────────────────────────────

module "security" {
  source = "./security"

  name_prefix               = var.name_prefix
  environment               = var.environment
  aws_account_id            = var.aws_account_id
  aws_region                = var.aws_region
  cluster_oidc_provider_arn = module.compute.cluster_oidc_provider_arn
  cluster_oidc_provider_url = module.compute.cluster_oidc_provider_url
  enable_cognito            = var.enable_cognito
  cognito_domain_prefix     = var.cognito_domain_prefix
  tags                      = var.tags
}
