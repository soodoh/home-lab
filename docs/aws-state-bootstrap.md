# AWS state and trusted-controller identity

The AWS foundation owns the encrypted OpenTofu state bucket, the separately regional KMS-encrypted recovery bucket, and the IAM Roles Anywhere identities used by the trusted MacBook controller. Every root uses native S3 lockfiles.

## Current state

The one-time hosted-to-local migration is complete:

- the local public CA is an enabled Roles Anywhere trust anchor;
- separate one-hour plan and apply profiles assume distinct IAM roles;
- each role trust is restricted to its exact certificate common name and trust-anchor ARN;
- the hosted OIDC provider is absent;
- the former DynamoDB mutation-lease table is absent;
- both IAM policies exclude the obsolete GitHub state key, OIDC management, and DynamoDB authority; and
- the AWS foundation has a verified no-op under the certificate-backed plan identity.

`scripts/configure-local-controller-aws` writes the two `credential_process` profiles and independently verifies both assumed-role identities without printing their ARNs. Private keys remain mode `0600` outside Git; only the public CA is tracked.

The foundation and off-site recovery bucket intentionally use separate reviewed regions. `TF_VAR_recovery_bucket_region` selects the aliased recovery provider, and the recovery bucket uses a region-local rotating KMS key.

Never print or infer bucket names, KMS identities, role ARNs, or certificate material. Keep protected coordinates in the mode-`0600` local controller credentials. Do not create state objects manually or replan during apply.
