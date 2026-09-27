# The public hosted zone is independently owned. Read its identity; do not
# import or manage the zone or overwrite an unobserved record.
data "aws_route53_zone" "public" {
  zone_id = var.tail_ingress_zone_id
}

locals {
  tail_ingress_zone_arn   = "arn:${data.aws_partition.current.partition}:route53:::hostedzone/${data.aws_route53_zone.public.zone_id}"
  tail_ingress_user_arn   = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/home-lab-ts-ingress-acme"
  tail_ingress_policy_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/home-lab-ts-ingress-acme-dns01"
}

# This exact record takes precedence over the existing *.diloreto.com CNAME.
# Its address is a reviewed node identity, not an automatically copied observation.
resource "aws_route53_record" "tail_ingress" {
  zone_id         = data.aws_route53_zone.public.zone_id
  name            = "*.ts.diloreto.com"
  type            = "A"
  ttl             = 300
  records         = [var.tail_ingress_ipv4]
  allow_overwrite = false

  lifecycle {
    precondition {
      condition = (
        data.aws_route53_zone.public.zone_id == var.tail_ingress_zone_id &&
        data.aws_route53_zone.public.name == "diloreto.com." &&
        !data.aws_route53_zone.public.private_zone
      )
      error_message = "The independently reviewed zone must be the public diloreto.com hosted zone."
    }
  }
}

# A dedicated ACME writer can change only the TXT challenge for the wildcard.
# The user's boundary is supplied and owned independently; neither the access
# key nor its secret is generated in OpenTofu state.
data "aws_iam_policy_document" "tail_ingress_acme" {
  statement {
    actions   = ["route53:GetChange"]
    resources = ["arn:${data.aws_partition.current.partition}:route53:::change/*"]
  }
  statement {
    actions   = ["route53:ListHostedZonesByName"]
    resources = ["*"]
  }
  statement {
    actions   = ["route53:ListResourceRecordSets"]
    resources = [local.tail_ingress_zone_arn]
  }
  statement {
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = [local.tail_ingress_zone_arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = ["_acme-challenge.ts.diloreto.com"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsRecordTypes"
      values   = ["TXT"]
    }
  }
}

resource "aws_iam_user" "tail_ingress_acme" {
  name                 = "home-lab-ts-ingress-acme"
  permissions_boundary = var.tail_ingress_user_boundary_arn
  tags                 = { System = "home-lab-tail-ingress" }

  lifecycle {
    precondition {
      condition = startswith(var.tail_ingress_user_boundary_arn,
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/")
      error_message = "The independent owner must supply a permissions boundary in the current AWS account."
    }
  }
}

resource "aws_iam_policy" "tail_ingress_acme" {
  name   = "home-lab-ts-ingress-acme-dns01"
  policy = data.aws_iam_policy_document.tail_ingress_acme.json
  tags   = { System = "home-lab-tail-ingress" }
}

resource "aws_iam_user_policy_attachment" "tail_ingress_acme" {
  user       = aws_iam_user.tail_ingress_acme.name
  policy_arn = aws_iam_policy.tail_ingress_acme.arn
}
