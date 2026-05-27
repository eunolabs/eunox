# ---------------------------------------------------------------------------
# Eunox security module — KMS, S3 Object Lock, Secrets Manager, Cognito, IRSA
# ---------------------------------------------------------------------------

locals {
  common_tags           = merge(var.tags, { environment = var.environment })
  # Treat empty-string the same as unset so the documented default is applied.
  cognito_domain_prefix = coalesce(nullif(var.cognito_domain_prefix, ""), "${var.name_prefix}-${var.environment}")
  oidc_issuer           = replace(var.cluster_oidc_provider_url, "https://", "")
  runtime_log_group_arn = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/${var.name_prefix}/runtime"
  audit_log_group_arn   = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/${var.name_prefix}/audit"
}

# ── KMS signing key ───────────────────────────────────────────────────────────

resource "aws_kms_key" "capability_signing" {
  description              = "Eunox capability-token signing key (${var.name_prefix}-${var.environment})"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false # asymmetric KMS keys do not support automatic rotation
  deletion_window_in_days  = var.kms_deletion_window_days
  tags                     = local.common_tags
}

resource "aws_kms_alias" "capability_signing" {
  name          = "alias/${var.name_prefix}-capability-signing"
  target_key_id = aws_kms_key.capability_signing.key_id
}

# ── S3 Object Lock audit anchor bucket ───────────────────────────────────────

resource "aws_s3_bucket" "audit_anchor" {
  bucket        = "${var.name_prefix}-audit-anchor-${var.environment}-${var.aws_account_id}"
  force_destroy = false
  tags          = merge(local.common_tags, { logType = "audit" })
}

resource "aws_s3_bucket_versioning" "audit_anchor" {
  bucket = aws_s3_bucket.audit_anchor.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_anchor" {
  bucket = aws_s3_bucket.audit_anchor.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.s3_audit_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit_anchor]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_anchor" {
  bucket = aws_s3_bucket.audit_anchor.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_anchor" {
  bucket                  = aws_s3_bucket.audit_anchor.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "audit_anchor_ssl" {
  bucket = aws_s3_bucket.audit_anchor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonSSL"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.audit_anchor.arn}", "${aws_s3_bucket.audit_anchor.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ── ECR repositories ──────────────────────────────────────────────────────────

resource "aws_ecr_repository" "service" {
  for_each             = toset(["capability-issuer", "tool-gateway", "api-key-minter", "db-token-service", "storage-grant-service", "posture-emitter"])
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

# ── Secrets Manager secrets ───────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "hmac_key" {
  name        = "${var.name_prefix}/${var.environment}/audit-ledger-hmac-secret"
  description = "AUDIT_LEDGER_HMAC_SECRET — 64-byte hex HMAC key for audit evidence signing."
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret" "admin_api_key" {
  name        = "${var.name_prefix}/${var.environment}/gateway-admin-api-key"
  description = "ADMIN_API_KEY — gateway operator API key (>=32 chars)."
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret" "redis_auth_token" {
  name        = "${var.name_prefix}/${var.environment}/redis-auth-token"
  description = "ElastiCache Redis auth token for TLS-encrypted cluster access."
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret" "partner_did_pin" {
  name        = "${var.name_prefix}/${var.environment}/partner-did-pin-secret"
  description = "PARTNER_DID_PIN_SECRET — PIN protecting the partner DID private key."
  tags        = local.common_tags
}

# ── Cognito User Pool ─────────────────────────────────────────────────────────

resource "aws_cognito_user_pool" "main" {
  count                    = var.enable_cognito ? 1 : 0
  name                     = "${var.name_prefix}-users-${var.environment}"
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
  count                         = var.enable_cognito ? 1 : 0
  name                          = "${var.name_prefix}-agent-runtime"
  user_pool_id                  = aws_cognito_user_pool.main[0].id
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

resource "aws_cognito_user_pool_domain" "main" {
  count        = var.enable_cognito ? 1 : 0
  domain       = local.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.main[0].id
}

resource "aws_cognito_user_group" "operators" {
  count        = var.enable_cognito ? 1 : 0
  name         = "operators"
  user_pool_id = aws_cognito_user_pool.main[0].id
  description  = "Privileged Eunox operators (mapped to admin capability)."
}

resource "aws_cognito_user_group" "agent_users" {
  count        = var.enable_cognito ? 1 : 0
  name         = "agent-users"
  user_pool_id = aws_cognito_user_pool.main[0].id
  description  = "Standard Eunox users (mapped to read/write capabilities)."
}

# ── IRSA role for capability-issuer ──────────────────────────────────────────

data "aws_iam_policy_document" "issuer_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:sub"
      values   = ["system:serviceaccount:eunox-system:capability-issuer"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "issuer_irsa" {
  name               = "${var.name_prefix}-issuer-irsa-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.issuer_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "issuer_policy" {
  statement {
    sid    = "SignCapabilityTokens"
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
    sid    = "ReadIssuerSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [
      aws_secretsmanager_secret.hmac_key.arn,
      aws_secretsmanager_secret.admin_api_key.arn,
      aws_secretsmanager_secret.partner_did_pin.arn,
    ]
  }

  statement {
    sid    = "IssuerLogs"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${local.runtime_log_group_arn}:*",
      "${local.audit_log_group_arn}:*",
    ]
  }

  dynamic "statement" {
    for_each = var.enable_cognito ? [1] : []
    content {
      sid    = "CognitoReadAccess"
      effect = "Allow"
      actions = [
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUsers",
        "cognito-idp:ListUsersInGroup",
        "cognito-idp:ListGroups",
        "cognito-idp:GetUser",
      ]
      resources = [aws_cognito_user_pool.main[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "issuer" {
  name   = "${var.name_prefix}-issuer-policy"
  role   = aws_iam_role.issuer_irsa.id
  policy = data.aws_iam_policy_document.issuer_policy.json
}

# ── IRSA role for tool-gateway ────────────────────────────────────────────────

data "aws_iam_policy_document" "gateway_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:sub"
      values   = ["system:serviceaccount:eunox-system:tool-gateway"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway_irsa" {
  name               = "${var.name_prefix}-gateway-irsa-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.gateway_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "gateway_policy" {
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
    sid    = "ReadGatewaySecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [
      aws_secretsmanager_secret.hmac_key.arn,
      aws_secretsmanager_secret.admin_api_key.arn,
      aws_secretsmanager_secret.redis_auth_token.arn,
    ]
  }

  statement {
    sid    = "AuditAnchorBucketAccess"
    effect = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention"]
    resources = ["${aws_s3_bucket.audit_anchor.arn}/*"]
  }

  statement {
    sid    = "GatewayLogs"
    effect = "Allow"
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${local.runtime_log_group_arn}:*",
      "${local.audit_log_group_arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "${var.name_prefix}-gateway-policy"
  role   = aws_iam_role.gateway_irsa.id
  policy = data.aws_iam_policy_document.gateway_policy.json
}
