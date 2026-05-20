output "db_endpoint" {
  value       = aws_db_instance.postgres.address
  description = "RDS endpoint address for AUDIT_LEDGER_PG_URL and ISSUER_DB_URL."
}

output "db_port" {
  value       = aws_db_instance.postgres.port
  description = "RDS port (5432)."
}

output "db_instance_id" {
  value       = aws_db_instance.postgres.id
  description = "RDS instance identifier."
}

output "redis_primary_endpoint" {
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  description = "ElastiCache Redis primary endpoint for REDIS_URL (use rediss://)."
}

output "redis_reader_endpoint" {
  value       = aws_elasticache_replication_group.redis.reader_endpoint_address
  description = "ElastiCache Redis reader endpoint for read-only connections."
}

output "rds_security_group_id" {
  value       = aws_security_group.rds.id
  description = "RDS security group ID (add EKS pod CIDR ingress rules from compute module)."
}

output "redis_security_group_id" {
  value       = aws_security_group.redis.id
  description = "Redis security group ID (add EKS pod CIDR ingress rules from compute module)."
}
