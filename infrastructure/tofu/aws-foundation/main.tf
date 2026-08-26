provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "OpenTofu"
      System    = "home-lab-recovery"
    }
  }
}


provider "aws" {
  alias  = "recovery"
  region = var.recovery_bucket_region

  default_tags {
    tags = {
      ManagedBy = "OpenTofu"
      System    = "home-lab-recovery"
    }
  }
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "recovery_kms" {
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowBackupPrincipalThroughS3"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [var.backup_principal_arn]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.recovery_bucket_region}.${data.aws_partition.current.dns_suffix}"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        aws_s3_bucket.recovery.arn,
        "${aws_s3_bucket.recovery.arn}/*",
      ]
    }
  }
}

resource "aws_kms_key" "opentofu" {
  description             = "Home lab OpenTofu state and recovery bundle"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  lifecycle {
    prevent_destroy = true
  }
}


resource "aws_kms_key" "recovery" {
  provider                = aws.recovery
  description             = "Home lab off-site recovery bundles"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.recovery_kms.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "recovery" {
  provider      = aws.recovery
  name          = "alias/home-lab-recovery"
  target_key_id = aws_kms_key.recovery.key_id
}

resource "aws_kms_alias" "opentofu" {
  name          = "alias/home-lab-opentofu"
  target_key_id = aws_kms_key.opentofu.key_id
}

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.opentofu.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket" "recovery" {
  provider = aws.recovery
  bucket   = var.recovery_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "recovery" {
  provider = aws.recovery
  bucket   = aws_s3_bucket.recovery.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "recovery" {
  provider = aws.recovery
  bucket   = aws_s3_bucket.recovery.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.recovery.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "recovery" {
  provider = aws.recovery
  bucket   = aws_s3_bucket.recovery.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "recovery" {
  provider                = aws.recovery
  bucket                  = aws_s3_bucket.recovery.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "recovery" {
  provider = aws.recovery
  bucket   = aws_s3_bucket.recovery.id

  dynamic "rule" {
    for_each = local.contract.backups.legacy_offen.migration_retention_hold.state == "retired" ? [] : [1]
    content {
      id     = "critical-backup-retention"
      status = "Enabled"

      filter {}

      expiration {
        days = local.contract.backups.legacy_offen.migration_retention_hold.state == "absent" ? local.contract.backups.legacy_offen.remote_retention_days : local.contract.backups.legacy_offen.migration_retention_hold.current_object_retention_days
      }

      noncurrent_version_expiration {
        noncurrent_days = local.contract.backups.legacy_offen.remote_noncurrent_retention_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = local.contract.backups.legacy_offen.incomplete_multipart_abort_days
      }
    }
  }

  dynamic "rule" {
    for_each = local.contract.backups.legacy_offen.migration_retention_hold.state == "retired" ? [1] : []
    content {
      id     = "incomplete-multipart-cleanup"
      status = "Enabled"

      filter {}

      abort_incomplete_multipart_upload {
        days_after_initiation = local.contract.backups.legacy_offen.incomplete_multipart_abort_days
      }
    }
  }

  rule {
    id     = "expired-delete-marker-cleanup"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }
}
