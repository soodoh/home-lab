# Supplied by the independent owner; this state must not create boundary policies.
# ARN shape/account checks cannot verify policy content or owner custody.
variable "controller_plan_permissions_boundary_arn" {
  type        = string
  nullable    = false
  description = "Required external owner-controlled plan boundary ARN. No unbounded fallback; owner must verify the exact approved policy before bootstrap."

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:iam::[0-9]{12}:policy/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$", var.controller_plan_permissions_boundary_arn))
    error_message = "Supply the exact external plan IAM managed-policy ARN, not null, an empty value, or a role ARN. Account/partition and distinctness are checked on the role."
  }
}

variable "controller_apply_permissions_boundary_arn" {
  type        = string
  nullable    = false
  description = "Required external owner-controlled apply boundary ARN, distinct from plan. Owner bootstrap and policy-content verification are required."

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:iam::[0-9]{12}:policy/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$", var.controller_apply_permissions_boundary_arn))
    error_message = "Supply the exact external apply IAM managed-policy ARN, not null, an empty value, or a role ARN. Account/partition and distinctness are checked on the role."
  }
}

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
