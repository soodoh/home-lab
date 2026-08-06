# AWS state bootstrap and local-controller migration

The AWS foundation root owns the encrypted OpenTofu state bucket, the separately regional KMS-encrypted recovery bucket, and the IAM Roles Anywhere identities used by the trusted MacBook controller. Roots use native S3 lockfiles; the former DynamoDB lease is an explicit retirement tombstone.

## One-time Roles Anywhere transition

The reviewed `controller-bootstrap` plan is intentionally narrow:

- create one enabled trust anchor from the committed public controller CA;
- create separate plan and apply Roles Anywhere profiles;
- update the existing plan/apply role trust policies to Roles Anywhere;
- update their least-privilege IAM policies for local reconciliation;
- delete the obsolete GitHub OIDC provider; and
- delete the obsolete empty DynamoDB lease table.

Run the transition from any clean committed revision using the existing authorized AWS bootstrap session:

```sh
scripts/local-controller plan controller-bootstrap
scripts/local-controller review controller-bootstrap
scripts/local-controller approve controller-bootstrap --confirmation bootstrap-reviewed-local-controller
scripts/local-controller apply controller-bootstrap
scripts/configure-local-controller-aws
```

Plan policy permits only the reviewed nine-action shape and binds all resources to the expected names and trust-anchor source. Apply consumes the exact saved plan, verifies that the former lease key is absent immediately before deletion, and requires a fresh no-op afterward. A failed apply is non-authoritative; inspect state and create a new reviewed plan rather than retrying blindly.

`scripts/configure-local-controller-aws` writes short-lived certificate-backed `home-lab-plan` and `home-lab-apply` profiles to the controller's protected AWS files. It verifies that both identities assume the expected distinct role ARNs. Private keys remain mode `0600` outside Git; only the public CA is tracked.

The foundation and off-site recovery bucket intentionally use separate reviewed regions. `TF_VAR_recovery_bucket_region` selects the aliased recovery provider, and the recovery bucket uses a region-local rotating KMS key.

Never print or infer bucket names, KMS identities, role ARNs, or certificate material. Keep protected coordinates in the mode-`0600` local controller credentials. Do not create state objects manually or replan during apply.
