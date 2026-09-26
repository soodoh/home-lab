provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "OpenTofu"
      System    = "home-lab-recovery"
    }
  }
}


# Transitional provider: retain until externally retired recovery resources are
# verified absent and removed from the versioned remote state by the owner.
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
  state_object_manifest = jsondecode(file("${path.module}/state-objects.json"))
  active_state_keys     = local.state_object_manifest.active
}

check "state_object_manifest" {
  assert {
    condition = (
      length(local.active_state_keys) > 0 &&
      length(local.active_state_keys) == length(toset(local.active_state_keys)) &&
      alltrue([for key in local.active_state_keys : can(regex("^home-lab/[a-z0-9-]+/tofu\\.tfstate$", key))]) &&
      local.state_object_manifest.noncurrent_lock_retention_days == 1
    )
    error_message = "The OpenTofu state object manifest must contain unique exact active state keys with one-day noncurrent lock retention."
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

resource "aws_kms_key" "opentofu" {
  description             = "Home lab OpenTofu state and recovery bundle"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  lifecycle {
    prevent_destroy = true
  }
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

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  depends_on = [aws_s3_bucket_versioning.state]

  dynamic "rule" {
    for_each = toset(local.active_state_keys)

    content {
      id     = "expire-lock-history-${replace(replace(rule.value, "/", "-"), ".", "-")}"
      status = "Enabled"

      filter {
        prefix = "${rule.value}.tflock"
      }

      expiration {
        expired_object_delete_marker = true
      }

      noncurrent_version_expiration {
        noncurrent_days = local.state_object_manifest.noncurrent_lock_retention_days
      }
    }
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
