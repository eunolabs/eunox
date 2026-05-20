output "runtime_log_group_name" {
  value       = aws_cloudwatch_log_group.runtime.name
  description = "CloudWatch log group name for runtime (application) logs."
}

output "runtime_log_group_arn" {
  value       = aws_cloudwatch_log_group.runtime.arn
  description = "CloudWatch log group ARN for runtime logs."
}

output "audit_log_group_name" {
  value       = aws_cloudwatch_log_group.audit.name
  description = "CloudWatch log group name for audit ledger entries."
}

output "audit_log_group_arn" {
  value       = aws_cloudwatch_log_group.audit.arn
  description = "CloudWatch log group ARN for audit entries."
}

output "alarm_topic_arn" {
  value       = aws_sns_topic.alarms.arn
  description = "SNS topic ARN for CloudWatch alarm notifications."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.main.name
  description = "CloudTrail trail name."
}
