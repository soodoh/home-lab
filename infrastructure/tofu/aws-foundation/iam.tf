locals {
  state_keys = local.active_state_keys
  state_arns = [for key in local.state_keys : "${aws_s3_bucket.state.arn}/${key}"]
  lock_arns  = [for key in local.state_keys : "${aws_s3_bucket.state.arn}/${key}.tflock"]
}

resource "aws_rolesanywhere_trust_anchor" "local_controller" {
  name       = "home-lab-local-controller"
  enabled    = true
  depends_on = [aws_iam_policy.state_apply]

  source {
    source_data {
      x509_certificate_data = file("${path.module}/../../local-controller/roles-anywhere-ca.pem")
    }
    source_type = "CERTIFICATE_BUNDLE"
  }
}

data "aws_iam_policy_document" "controller_plan_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
    principals {
      type        = "Service"
      identifiers = ["rolesanywhere.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_rolesanywhere_trust_anchor.local_controller.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/x509Subject/CN"
      values   = ["home-lab-local-controller-plan"]
    }
  }
}

data "aws_iam_policy_document" "controller_apply_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
    principals {
      type        = "Service"
      identifiers = ["rolesanywhere.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_rolesanywhere_trust_anchor.local_controller.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/x509Subject/CN"
      values   = ["home-lab-local-controller-apply"]
    }
  }
}


resource "aws_iam_role" "controller_plan" {
  name               = "home-lab-infrastructure-plan"
  assume_role_policy = data.aws_iam_policy_document.controller_plan_trust.json
}

resource "aws_iam_role" "controller_apply" {
  name               = "home-lab-infrastructure-apply"
  assume_role_policy = data.aws_iam_policy_document.controller_apply_trust.json
}

resource "aws_rolesanywhere_profile" "controller_plan" {
  name                     = "home-lab-local-controller-plan"
  enabled                  = true
  role_arns                = [aws_iam_role.controller_plan.arn]
  duration_seconds         = 3600
  accept_role_session_name = true
}

resource "aws_rolesanywhere_profile" "controller_apply" {
  name                     = "home-lab-local-controller-apply"
  enabled                  = true
  role_arns                = [aws_iam_role.controller_apply.arn]
  duration_seconds         = 3600
  accept_role_session_name = true
}

data "aws_iam_policy_document" "state_plan" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = concat(local.state_keys, [for key in local.state_keys : "${key}.tflock"])
    }
  }
  statement {
    actions   = ["s3:GetObject"]
    resources = concat(local.state_arns, local.lock_arns)
  }
  statement {
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = local.lock_arns
  }
  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.opentofu.arn, aws_kms_key.recovery.arn]
  }

  statement {
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketRequestPayment",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetBucketWebsite",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
      "s3:ListBucketVersions",
    ]
    resources = [aws_s3_bucket.state.arn, aws_s3_bucket.recovery.arn]
  }
  statement {
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
    ]
    resources = [aws_kms_key.opentofu.arn, aws_kms_key.recovery.arn]
  }
  statement {
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }
  statement {
    actions   = ["iam:Get*", "iam:List*"]
    resources = ["*"]
  }
  statement {
    actions   = ["rolesanywhere:Get*", "rolesanywhere:List*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "state_apply" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = concat(local.state_keys, [for key in local.state_keys : "${key}.tflock"])
    }
  }
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = concat(local.state_arns, local.lock_arns)
  }
  statement {
    actions   = ["s3:DeleteObject"]
    resources = local.lock_arns
  }
  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.opentofu.arn]
  }

  statement {
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketRequestPayment",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetBucketWebsite",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketTagging",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = [aws_s3_bucket.state.arn, aws_s3_bucket.recovery.arn]
  }
  statement {
    actions   = ["s3:CreateBucket"]
    resources = ["*"]
  }
  statement {
    actions = [
      "kms:CreateAlias",
      "kms:CreateKey",
      "kms:DescribeKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:ListAliases",
      "kms:PutKeyPolicy",
      "kms:TagResource",
      "kms:UpdateAlias",
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:CreateRole",
      "iam:CreateUser",
      "iam:Get*",
      "iam:List*",
      "iam:PutUserPolicy",
      "iam:TagPolicy",
      "iam:TagRole",
      "iam:TagUser",
      "iam:SetDefaultPolicyVersion",
      "iam:UpdateAssumeRolePolicy",
    ]
    resources = ["*"]
  }
  statement {
    actions   = ["rolesanywhere:Create*", "rolesanywhere:Delete*", "rolesanywhere:Disable*", "rolesanywhere:Enable*", "rolesanywhere:Get*", "rolesanywhere:List*", "rolesanywhere:Put*", "rolesanywhere:TagResource", "rolesanywhere:UntagResource", "rolesanywhere:Update*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "state_plan" {
  name   = "home-lab-opentofu-state-plan"
  policy = data.aws_iam_policy_document.state_plan.json
}

resource "aws_iam_policy" "state_apply" {
  name   = "home-lab-opentofu-state-apply"
  policy = data.aws_iam_policy_document.state_apply.json
}


resource "aws_iam_role_policy_attachment" "controller_plan" {
  role       = aws_iam_role.controller_plan.name
  policy_arn = aws_iam_policy.state_plan.arn
}

resource "aws_iam_role_policy_attachment" "controller_apply" {
  role       = aws_iam_role.controller_apply.name
  policy_arn = aws_iam_policy.state_apply.arn
}

resource "aws_iam_user" "recovery" {
  name = "home-lab-recovery"

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "recovery" {
  statement {
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [aws_s3_bucket.recovery.arn, aws_s3_bucket.state.arn]
  }
  statement {
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.recovery.arn}/*",
      "${aws_s3_bucket.state.arn}/*",
    ]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.opentofu.arn, aws_kms_key.recovery.arn]
  }
}

resource "aws_iam_user_policy" "recovery" {
  name   = "home-lab-recovery"
  user   = aws_iam_user.recovery.name
  policy = data.aws_iam_policy_document.recovery.json
}
