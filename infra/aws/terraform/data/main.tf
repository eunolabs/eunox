# ---------------------------------------------------------------------------
# Eunox data module — RDS PostgreSQL, ElastiCache Redis, subnet groups
# ---------------------------------------------------------------------------

locals {
  common_tags = merge(var.tags, { environment = var.environment })
}

# ── Security groups ───────────────────────────────────────────────────────────

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-rds-sg-${var.environment}"
  description = "Eunox RDS PostgreSQL — allow EKS pods on port 5432 only."
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Name = "${var.name_prefix}-rds-sg" })

  # Ingress is restricted to the EKS cluster security group (rules below).
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["127.0.0.1/32"] # deny all egress by default
  }
}

resource "aws_security_group" "redis" {
  name        = "${var.name_prefix}-redis-sg-${var.environment}"
  description = "Eunox ElastiCache Redis — allow EKS pods on port 6380 (TLS) only."
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Name = "${var.name_prefix}-redis-sg" })

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["127.0.0.1/32"] # deny all egress by default
  }
}

resource "aws_security_group_rule" "rds_from_eks" {
  type                     = "ingress"
  security_group_id        = aws_security_group.rds.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_cluster_security_group_id
  description              = "Allow PostgreSQL traffic from EKS workloads."
}

resource "aws_security_group_rule" "redis_from_eks" {
  type                     = "ingress"
  security_group_id        = aws_security_group.redis.id
  from_port                = 6380
  to_port                  = 6380
  protocol                 = "tcp"
  source_security_group_id = var.eks_cluster_security_group_id
  description              = "Allow Redis TLS traffic from EKS workloads."
}

# ── RDS PostgreSQL ────────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnet-${var.environment}"
  subnet_ids = var.isolated_subnet_ids
  description = "Eunox RDS subnet group (isolated subnets)."
  tags       = local.common_tags
}

resource "aws_db_parameter_group" "postgres15" {
  name        = "${var.name_prefix}-pg15-${var.environment}"
  family      = "postgres15"
  description = "Eunox PostgreSQL 15 parameter group — connection logging enabled."

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "5000" # log queries > 5 s
  }

  tags = local.common_tags
}

resource "aws_db_instance" "postgres" {
  identifier             = "${var.name_prefix}-db-${var.environment}"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = var.db_instance_class
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_name                = "eunox"
  username               = var.db_username
  manage_master_user_password = true

  # Storage
  storage_type          = "gp3"
  allocated_storage     = var.db_allocated_storage_gib
  max_allocated_storage = var.db_max_allocated_storage_gib
  storage_encrypted     = true

  # HA + availability
  multi_az = var.db_multi_az

  # Backups
  backup_retention_period = var.db_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # Upgrade + protection
  auto_minor_version_upgrade  = true
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "${var.name_prefix}-db-final-snapshot"

  # Logging
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  parameter_group_name            = aws_db_parameter_group.postgres15.name

  # Performance Insights
  performance_insights_enabled = true

  tags = local.common_tags
}

# ── ElastiCache Redis ─────────────────────────────────────────────────────────

resource "aws_elasticache_subnet_group" "main" {
  name        = "${var.name_prefix}-cache-subnet-${var.environment}"
  subnet_ids  = var.isolated_subnet_ids
  description = "Eunox ElastiCache Redis subnet group (isolated subnets)."
  tags        = local.common_tags
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.name_prefix}-${var.environment}"
  description                = "Eunox HA Redis — ${var.name_prefix}-${var.environment}"
  node_type                  = var.cache_node_type
  num_cache_clusters         = var.cache_num_replicas + 1 # 1 primary + N replicas
  engine                     = "redis"
  engine_version             = "7.1"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_auth_token
  automatic_failover_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  snapshot_retention_limit   = 7
  snapshot_window            = "05:00-06:00"
  maintenance_window         = "Mon:06:00-Mon:07:00"

  log_delivery_configuration {
    destination      = "/aws/elasticache/${var.name_prefix}-${var.environment}/engine"
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }

  tags = local.common_tags
}
