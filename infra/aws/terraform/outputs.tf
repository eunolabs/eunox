output "cluster_name" {
  value       = module.compute.cluster_name
  description = "EKS cluster name."
}

output "cluster_endpoint" {
  value       = module.compute.cluster_endpoint
  description = "EKS cluster API server endpoint."
}

output "cluster_oidc_provider_arn" {
  value       = module.compute.cluster_oidc_provider_arn
  description = "OIDC provider ARN for IRSA bindings."
}

output "gateway_role_arn" {
  value       = module.security.gateway_role_arn
  description = "Annotate the tool-gateway ServiceAccount with this ARN."
}

output "issuer_role_arn" {
  value       = module.security.issuer_role_arn
  description = "Annotate the capability-issuer ServiceAccount with this ARN."
}

output "signing_key_arn" {
  value       = module.security.signing_key_arn
  description = "Set as AWS_KMS_KEY_ID for AWSKMSSigner."
}

output "audit_anchor_bucket" {
  value       = module.security.audit_anchor_bucket
  description = "Set as AUDIT_LEDGER_S3_BUCKET for cross-chain anchoring."
}

output "db_endpoint" {
  value       = module.data.db_endpoint
  description = "RDS endpoint for AUDIT_LEDGER_PG_URL and ISSUER_DB_URL."
}

output "redis_primary_endpoint" {
  value       = module.data.redis_primary_endpoint
  description = "ElastiCache primary endpoint for REDIS_URL (use rediss://)."
}

output "cognito_user_pool_id" {
  value       = module.security.cognito_user_pool_id
  description = "Set as AWS_COGNITO_USER_POOL_ID for capability-issuer."
}

output "cognito_client_id" {
  value       = module.security.cognito_client_id
  description = "Set as AWS_COGNITO_CLIENT_ID for capability-issuer."
}

output "hmac_key_secret_arn" {
  value       = module.security.hmac_key_secret_arn
  description = "AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET."
}

output "admin_api_key_secret_arn" {
  value       = module.security.admin_api_key_secret_arn
  description = "AWS_SECRETS_ARN_ADMIN_API_KEY."
}

output "ecr_repository_urls" {
  value       = module.security.ecr_repository_urls
  description = "ECR repository URLs keyed by service name."
}

output "alarm_topic_arn" {
  value       = module.observability.alarm_topic_arn
  description = "SNS topic ARN for CloudWatch alarm notifications."
}
