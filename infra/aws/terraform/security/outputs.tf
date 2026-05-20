output "signing_key_arn" {
  value       = aws_kms_key.capability_signing.arn
  description = "ARN to set as AWS_KMS_KEY_ID for AWSKMSSigner."
}

output "signing_key_id" {
  value       = aws_kms_key.capability_signing.key_id
  description = "KMS key ID."
}

output "audit_anchor_bucket" {
  value       = aws_s3_bucket.audit_anchor.bucket
  description = "Set as AUDIT_LEDGER_S3_BUCKET for cross-chain anchoring."
}

output "audit_anchor_bucket_arn" {
  value       = aws_s3_bucket.audit_anchor.arn
  description = "S3 audit anchor bucket ARN."
}

output "hmac_key_secret_arn" {
  value       = aws_secretsmanager_secret.hmac_key.arn
  description = "AWS_SECRETS_ARN_AUDIT_LEDGER_HMAC_SECRET."
}

output "admin_api_key_secret_arn" {
  value       = aws_secretsmanager_secret.admin_api_key.arn
  description = "AWS_SECRETS_ARN_ADMIN_API_KEY."
}

output "partner_did_pin_secret_arn" {
  value       = aws_secretsmanager_secret.partner_did_pin.arn
  description = "AWS_SECRETS_ARN_PARTNER_DID_PIN_SECRET."
}

output "issuer_role_arn" {
  value       = aws_iam_role.issuer_irsa.arn
  description = "Annotate the capability-issuer ServiceAccount with this ARN."
}

output "gateway_role_arn" {
  value       = aws_iam_role.gateway_irsa.arn
  description = "Annotate the tool-gateway ServiceAccount with this ARN."
}

output "cognito_user_pool_id" {
  value       = length(aws_cognito_user_pool.main) > 0 ? aws_cognito_user_pool.main[0].id : ""
  description = "Set as AWS_COGNITO_USER_POOL_ID for capability-issuer (empty when enable_cognito=false)."
}

output "cognito_client_id" {
  value       = length(aws_cognito_user_pool_client.agent_runtime) > 0 ? aws_cognito_user_pool_client.agent_runtime[0].id : ""
  description = "Set as AWS_COGNITO_CLIENT_ID for capability-issuer (empty when enable_cognito=false)."
}

output "ecr_repository_urls" {
  value       = { for k, v in aws_ecr_repository.service : k => v.repository_url }
  description = "ECR repository URLs keyed by service name."
}
