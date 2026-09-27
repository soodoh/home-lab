# AWS owner review: private ingress DNS and ACME (not an apply procedure)

This packet describes the **additional** permissions required by the proposed
[`aws-foundation`](../infrastructure/tofu/aws-foundation/tail-ingress.tf)
resources. It is not a complete replacement for an independently owned IAM
policy, and it does not authorize AWS writes. The authoritative existing plan
and apply roles, their attached policies and their external permissions
boundaries must be read afresh by the independent owner. Preserve their other
permissions, explicit denials, version history and rollback path. Use
[operations](operations.md#aws-foundation-owner-only-state-reconciliation) for
owner-only state reconciliation, never a targeted normal plan.

## Inputs to verify privately before approving

- The current `personal` profile is an IAM user in the same account as the
  independent controller roles. Its login is **not** an approval to mutate IAM.
- Observe exactly one *public* `diloreto.com.` Route 53 hosted zone. Verify its
  ID against the independently owned authoritative DNS delegation and supply
  that reviewed ID as `TF_VAR_tail_ingress_zone_id`; do not infer ownership from
  a public DNS lookup alone. The zone itself remains externally owned.
- Read **all** Route 53 records and verify there is no exact A/AAAA/CNAME at
  `*.ts.diloreto.com.` before allowing OpenTofu to create the A record. Route
  53 may render `*` as `\052` in its API listing; the existing parent wildcard
  is a different record. Observe the Docker host's own Tailscale IP, compare
  with the committed `tail_ingress_ipv4`, and refuse any mismatch.
- Check whether `home-lab-ts-ingress-acme` user, its `-dns01` managed policy,
  and the independently owned ACME **permissions boundary** already exist.
  Do not create/adopt an unexplained identity or provision an access key through
  OpenTofu state. Choose and protect the ACME user boundary ARN, then supply it
  as `TF_VAR_tail_ingress_user_boundary_arn` for a private saved plan.
- Verify the controller plan/apply role boundary policy **documents**, not just
  their names. The observed policies each have a `Deny` with `NotAction` on
  `Resource: "*"`: adding an `Allow` alone cannot grant a newly permitted
  action. Any owner change must update both the narrow `Allow` statements and
  the exact `NotAction` exemptions while retaining the deny for everything
  else. Also check the managed-policy version count/limit before creating a
  version. Do not remove a protected before-image.

## Proposed controller permissions (owner-controlled boundaries)

The managed controller policy documents in
[`iam.tf`](../infrastructure/tofu/aws-foundation/iam.tf) declare the desired
scopes. The external owner must review and independently bootstrap matching
boundary permissions for the existing roles. `ZONE_ARN` means the reviewed
`arn:aws:route53:::hostedzone/<ZONE_ID>`; `USER_ARN` and `POLICY_ARN`
mean the *one* ACME IAM user and managed policy in this account.

| Role | Action(s) to add to `Allow` **and** `Deny.NotAction` exemption | Resource/condition |
| --- | --- | --- |
| Plan | `route53:GetHostedZone`, `route53:ListResourceRecordSets`, `route53:ListTagsForResource` | `ZONE_ARN`; the data source looks up the reviewed zone **by ID** and the AWS provider also reads its tags (the provider returns `diloreto.com` without the trailing dot from Route 53's API) |
| Apply | The plan Route 53 reads | Same scope |
| Apply | `route53:ChangeResourceRecordSets` | `ZONE_ARN`; **all** names `\052.ts.diloreto.com`, types `A`, actions `CREATE` or `UPSERT` via `ForAllValues:StringEquals` conditions |
| Apply | `iam:CreateUser`, `iam:PutUserPermissionsBoundary`, `iam:TagUser` | `USER_ARN` only; the created user must receive the owner-controlled ACME boundary |
| Apply | `iam:CreatePolicy`, `iam:TagPolicy` | `POLICY_ARN` only |
| Apply | `iam:AttachUserPolicy` | `USER_ARN` only, conditioned with `iam:PolicyARN == POLICY_ARN` |

`\052` above represents a **literal backslash followed by 052** in the
normalized Route 53 condition value. JSON encodes this as `\\052`. The DNS name is not an IAM glob: using `*.ts.diloreto.com` as the
condition value would be wrong. See [AWS Route 53 condition normalization](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html).
Do not add `iam:CreateAccessKey`, wildcard Route 53 writes, other IAM role
writes, or a general IAM action wildcard. Existing owner identity guards still
apply to the actual OpenTofu saved plan. Controller IAM policy version writes
remain owner-only; the apply role does **not** gain those actions.

## Independently owned ACME user boundary

Review an external permissions-boundary policy for only the DNS-01 runtime
calls. It should permit `route53:GetChange` on `arn:aws:route53:::change/*`,
`route53:ListHostedZonesByName` on `*`,
`route53:ListResourceRecordSets` on `ZONE_ARN`, and
`route53:ChangeResourceRecordSets` on `ZONE_ARN` **only** with
`ForAllValues:StringEquals` on
`route53:ChangeResourceRecordSetsNormalizedRecordNames` =
`_acme-challenge.ts.diloreto.com` and
`route53:ChangeResourceRecordSetsRecordTypes` = `TXT`. The in-repo
`aws_iam_policy.tail_ingress_acme` must match these write limits: effective
permissions are the intersection of its attachment and the boundary. Review
ACME issuance and renewal behavior before optionally narrowing change actions.
The boundary itself is not an OpenTofu-owned resource in this root. The runtime
key, when issued separately by the owner, must enter protected SOPS deployment
material, **never** state, Git or a command log. Do not reuse the live DDNS
identity or revoke its key.

## Ownership sequence requiring separate approvals

1. Independently review the entire current external boundary documents and the
   generated in-repo controller policy deltas. The controller **apply** role
   cannot write its own IAM policy and must never gain that ability as part of
   this change. Prepare protected before-images and exact owner-approved
   external policy versions, including the `Deny.NotAction` updates. The apply
   boundary is near AWS's [6,144-character managed-policy limit](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length);
   an additive seven-statement draft exceeded it. To fit while preserving
   behavior, the owner must verify the equivalence of compacting existing
   unconditional `Resource: "*"` Allow statements and combining new typed
   user/policy-create actions on their exact two ARNs. Do **not** replace any
   resource list with a wildcard, drop the explicit deny, or introduce
   `iam:*`/`route53:*` exemptions merely to fit. The zone-by-ID lookup also
   requires `route53:ListTagsForResource` on `ZONE_ARN`; independently review
   its incremental policy versions before updating the owner-controlled
   boundaries and state policies. The compact apply boundary then has only a
   few characters of quota headroom, and each fifth version fills the managed
   policy version quota; preserve the older versions for rollback and redesign
   rather than deleting a version without a new owner review. Establish the
   ACME user boundary independently. Stop on any unexpected existing identity,
   public-zone record, policy size/version limit or unrelated change.
2. After owner bootstrap, the tracked state policies may drift from the live
   owner-updated documents. The normal inspector must refuse such identity
   drift. Follow the separately reviewed *refresh-only* state reconciliation
   in [operations](operations.md#aws-foundation-owner-only-state-reconciliation)
   with plan and apply identities, protected state before-image and only
   approved state changes. Do not use the owner login as a shortcut for a normal
   plan/apply; a state-only refresh must not change AWS resources.
3. Reobserve IAM, DNS, node IP and host/Compose/backup admission. Save a normal
   complete OpenTofu plan under the controller **plan** identity; inspect with
   the default refusing gate first. The independent owner must privately
   verify the *full* policy JSON, zone ID, user boundary, proposed DNS record
   and exact IAM identity/action set. Only then use the current-run private
   `--approve-identity-file` for that one saved plan. Apply only with the
   controller **apply** identity after separate explicit approval and require
   a fresh no-op plan. No approval file is reusable across plans.
4. A later, separately reviewed runtime credential issuance and private
   Traefik deployment must pass DNS-01 staging, strict TLS, public-ingress
   negative tests and fresh recovery admission before migrating clients or
   retiring Serve. See [the ingress migration](ts-ingress-migration.md).
