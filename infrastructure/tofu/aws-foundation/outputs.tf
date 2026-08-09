output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "recovery_bucket" {
  value = aws_s3_bucket.recovery.id
}

output "kms_key_arn" {
  value = aws_kms_key.opentofu.arn
}


output "recovery_kms_key_arn" {
  value = aws_kms_key.recovery.arn
}


output "controller_plan_role_arn" {
  value = aws_iam_role.controller_plan.arn
}

output "controller_apply_role_arn" {
  value = aws_iam_role.controller_apply.arn
}

output "controller_plan_profile_arn" {
  value = aws_rolesanywhere_profile.controller_plan.arn
}

output "controller_apply_profile_arn" {
  value = aws_rolesanywhere_profile.controller_apply.arn
}

output "controller_trust_anchor_arn" {
  value = aws_rolesanywhere_trust_anchor.local_controller.arn
}
