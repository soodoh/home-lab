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

variable "state_bucket_name" {
  type = string
}

variable "tail_ingress_zone_id" {
  type        = string
  nullable    = false
  description = "Independent AWS owner's reviewed ID of the existing public diloreto.com hosted zone."

  validation {
    condition     = can(regex("^Z[A-Z0-9]+$", var.tail_ingress_zone_id))
    error_message = "Supply the reviewed Route 53 public hosted-zone ID."
  }
}

variable "tail_ingress_ipv4" {
  type        = string
  description = "Reviewed Docker-host Tailscale IPv4 address for the private ingress. Verify against fresh node identity before each plan."

  validation {
    condition = (
      can(cidrnetmask("${var.tail_ingress_ipv4}/32")) &&
      can(regex("^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.[0-9]{1,3}\\.[0-9]{1,3}$", var.tail_ingress_ipv4))
    )
    error_message = "The private ingress requires a valid Tailscale IPv4 address in 100.64.0.0/10."
  }
}

variable "tail_ingress_user_boundary_arn" {
  type        = string
  nullable    = false
  description = "Independently owned permissions boundary for the dedicated ACME IAM user; no fallback."

  validation {
    condition     = can(regex("^arn:[a-z0-9-]+:iam::[0-9]{12}:policy/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$", var.tail_ingress_user_boundary_arn))
    error_message = "Supply the independent ACME IAM user boundary policy ARN."
  }
}
