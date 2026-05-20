output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID."
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "Public subnet IDs (for ALB / public load balancers)."
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "Private subnet IDs (for EKS worker nodes)."
}

output "isolated_subnet_ids" {
  value       = aws_subnet.isolated[*].id
  description = "Isolated subnet IDs (for RDS and ElastiCache)."
}

output "nat_gateway_ids" {
  value       = aws_nat_gateway.main[*].id
  description = "NAT gateway IDs (one per AZ)."
}
