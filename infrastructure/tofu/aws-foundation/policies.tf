data "aws_iam_policy_document" "tls_only_state" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.tls_only_state.json
}

data "aws_iam_policy_document" "tls_only_recovery" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.recovery.arn,
      "${aws_s3_bucket.recovery.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "AllowBackupPrincipalVersionEvidence"
    effect    = "Allow"
    actions   = ["s3:ListBucketVersions"]
    resources = [aws_s3_bucket.recovery.arn]

    principals {
      type        = "AWS"
      identifiers = [var.backup_principal_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "recovery" {
  provider = aws.recovery
  bucket   = aws_s3_bucket.recovery.id
  policy   = data.aws_iam_policy_document.tls_only_recovery.json
}
