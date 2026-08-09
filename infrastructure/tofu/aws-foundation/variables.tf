variable "aws_region" {
  type = string
}


variable "recovery_bucket_region" {
  type = string
}

variable "state_bucket_name" {
  type = string
}

variable "recovery_bucket_name" {
  type = string
}

variable "backup_principal_arn" {
  type        = string
  description = "Protected ARN of the existing off-site backup principal allowed to use the recovery KMS key only through S3."
  sensitive   = true

  validation {
    condition     = can(regex("^arn:[^:]+:iam::[0-9]{12}:(user|role)/[A-Za-z0-9+=,.@_/-]+$", var.backup_principal_arn))
    error_message = "backup_principal_arn must be a valid IAM user or role ARN."
  }
}
