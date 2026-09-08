# INERT proposal: controller identity isolation

**Not ready for deployment.** These historical before/after policy Documents and
candidate owner-controlled boundaries are review inputs, not active infrastructure.
This directory is outside `infrastructure/tofu` and contains no `.tf`, role attachment,
controller, workflow, owner policy or deployment wiring. The only runner integration
executes offline structural tests. Nothing here assigns privileges to a new owner,
changes trust/profile/role identities, moves state or authorizes AWS operations.

**Superseding local implementation checkpoint:** the user selected **retain state,
split execution**, with existing personal/profile `personal`, IAM user `paul`, account
`658271954302`, on an independently controlled machine as the nominated owner. This
is not live authority/custody verification or a new grant. Active foundation source now
narrows apply's identity actions and requires two distinct, non-null same-account
external boundary references. The ordinary controller gate now rejects IAM/RA
mutation/import, observed drift, unknown/malformed and deferred identity changes in
every mode; managed OIDC ownership remains unconditionally forbidden. These changes
are authored/tested locally, **not deployed**; no boundaries were created/attached,
no backend/state/address moved, and no owner executor or privilege override was added.
The JSON files here remain inert historical evidence, never active configuration.
See [selected split and exact future gates](../../../../docs/shared-oidc-ownership.md#selected-controllerowner-execution-split--authored-locally-not-deployed).

Owner custody/authority, exact boundary content/ARN inputs, bootstrap/recovery,
independent source/state/plan verification and separately authorized live verification
remain **deployment blockers**. The selected direction removes routine IAM and Roles Anywhere (RA) mutation entirely;
it does not implement delegated IAM or boundary propagation to newly created roles.
The bounded controller could not create those roles at all. This is not a claim of
account-wide isolation against other credentials or retained storage/KMS authority.

## Documents and exact delta

`*-before.json` is the structurally exact `data.Document` of the retained filtered
plan v11 / apply v13 audit (not regenerated from desired HCL). Key, statement, action
and resource ordering are retained; only the enclosing audit wrapper/indent changes.
`provenance.json` records audit paths, version/timestamps, raw audit SHA256, canonical
Document SHA256, and file SHA256/size. Tests pin historical Document digests independently
of the manifest. The audit was bounded and non-atomic, not fresh effective-permissions
evidence. No audit API was rerun. The source operation matrix below is not live inventory.

| Document | Non-whitespace characters | Purpose |
| --- | ---: | --- |
| `plan-before.json` | 3393 | Historical v11 |
| `plan-after.json` | 3393 | Byte-identical to plan-before; no grant delta |
| `plan-boundary.json` | 4223 | Exact plan Allows plus unconditional action ceiling |
| `apply-before.json` | 3936 | Historical v13 |
| `apply-after.json` | 3485 | Only the two identity Action arrays narrowed |
| `apply-boundary.json` | 4641 | Exact reduced apply Allows plus unconditional action ceiling |

Each potential customer-managed policy Document independently fits AWS's **6144
characters excluding whitespace** quota. Tests count final file text and cross-check
compact JSON; these ASCII documents have no whitespace inside string values. This is
not AWS validation or a role-inline-policy aggregate quota check. Boundary names/ARNs,
attachments and owner grants are deliberately not invented.

Apply removes exactly these 20 action strings/patterns (not 20 concrete APIs):

- IAM: `UpdateAssumeRolePolicy`, `TagUser`, `TagRole`, `TagPolicy`,
  `SetDefaultPolicyVersion`, `PutUserPolicy`, `DeletePolicyVersion`, `CreateUser`,
  `CreateRole`, `CreatePolicyVersion`, `CreatePolicy`, `AttachRolePolicy`.
- RA: `Update*`, `UntagResource`, `TagResource`, `Put*`, `Enable*`, `Disable*`,
  `Delete*`, `Create*`.

The two apply identity statements keep `Resource: "*"`, `Effect: Allow`, no conditions,
and only `iam:List*`, `iam:Get*`, `rolesanywhere:List*`, `rolesanywhere:Get*` in their
original relative order. **No new Allows.** All other statement objects are unchanged.
Plan's identity policy remains unchanged. Read wildcards are broad metadata access,
including outside principals/providers/profiles; not a promise all reads are harmless.

Each boundary copies its role's after-policy Allows, with exactly their resources and
conditions, then adds `DenyActionsOutsideRetainedBaseline`: unconditional `Effect: Deny`,
`NotAction` equal to the sorted unique retained action strings, `Resource: "*"`.
No principal, condition, NotResource, or service-wide non-identity wildcard weakens that
Deny. Boundary Allows are ceiling coverage, not independent grants. A deny-only boundary
would block ordinary legitimate identity grants; `Allow retained-actions Resource *`
would unnecessarily broaden ceiling coverage. Neither alternative is used.

This explicitly denies **all actions outside the per-role exception list**, not merely
those removed from apply. It includes OIDC mutations (creation and all issuers, including
`arn:aws:iam::658271954302:oidc-provider/token.actions.githubusercontent.com`), policy
attachment/detachment, inline policy changes, both policy-version escalation routes,
trust changes, users/roles/groups/access-key mutations, boundary creation/replacement/
removal/versioning, IAM tagging, role passing, outgoing STS assumption/session actions,
RA mutation/alternate-profile administration, and all CloudFormation actions including
`diloreto-amplify-hosting` access. Even CloudFormation reads are outside the baseline.
No target-role exception or owner bypass is added to the controller. Actions within the
four retained Get*/List* patterns can include future actions; other future actions are
outside the action ceiling. Finite test cases do not enumerate the whole AWS API surface.

## AWS semantics and limits of the claim

The supplied official-document research is retained at
`/private/tmp/websites-oidc-policy-draft.5X26h5/boundary-semantics.md`.
Its direct excerpts support this design; its automated source checks returned unclear,
not corroboration. No new network research or live verification was performed here.

- [Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
  explicitly says same-account resource-policy grants directly to an IAM role **session**
  are not limited by implicit deny in identity policies, boundaries or session policies.
  Therefore merely removing mutation Allows or using an allow-only boundary is insufficient.
- [Request evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
  includes boundaries in applicable explicit-deny evaluation: one applicable explicit deny
  returns Deny. The unconditional action ceiling addresses that direct-session implicit-deny
  exception for actions outside the exception list. It is not a new resource-policy grant.
- [NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html)
  with Deny denies actions not listed; exceptions are **not** granted. `Resource: "*"`
  avoids a resource-scoped hole, including creation actions without an existing ARN.
  No guessed per-action resource/condition support is required for an OIDC-only ARN deny.
- [Managed versioning](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html)
  requires denying both CreatePolicyVersion and SetDefaultPolicyVersion to prevent default
  policy edits; both are outside the ceiling. Boundary replacement/removal and all IAM/RA
  mutation are too. Once enforced, the controller cannot rewrite its policy, remove or
  replace its boundary, edit trust or reconfigure a profile to evade it **using its bounded
  IAM/RA authority**. The owner is outside that bounded principal; this is not immutability
  against an account owner or an alternate unbounded identity.
- [RA trust model](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html)
  requires incoming AssumeRole, TagSession and SetSourceIdentity by the RA service principal.
  These trust actions are unchanged. An outgoing STS deny on the assumed controller role is
  not a trust-policy edit and does not justify adding STS Allows to its identity policy.
  Exact RA issuance compatibility of this boundary is still an approval/verification gate,
  not demonstrated by the docs or tests. Certificate-authenticated CreateSession is not
  proven disabled merely by writing a string in an IAM deny; CA/key custody remains crucial.
- [Quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
  specifies the per-managed-policy 6144-character limit excluding whitespace.

**Action ceiling, not full resource perimeter:** direct-session resource grants for an
excepted action can exceed the resource scope of the copied Allows. The request-evaluation
document also has principal-form-specific wording about wildcard Principal plus
`aws:PrincipalArn` and identity-policy explicit denies; this proposal does not claim to
resolve every such resource-policy combination. Subsequent resource-policy review is a
blocker, not replaced by these tests. Boundaries do not constrain requests made by other
principals after the controller changes a bucket/key policy or obtains other credentials.

## Source operations / address matrix

Paths in this table are relative to `infrastructure/tofu/aws-foundation/`. Brace notation
expands only the named instances. API names map historical source intent/grants, **not** a
complete provider RPC trace; AWS provider source pin is 6.58.0. No speculative ancillary
read/tag-removal grant is added. Exact source references and coupling analysis are retained
in `/private/tmp/websites-oidc-policy-draft.5X26h5/source-operations.md`.
Line references below identify that pre-alignment source snapshot, not current line numbers.

| Exact managed addresses | Source intent / disposition | Source |
| --- | --- | --- |
| `aws_iam_role.controller_plan`, `aws_iam_role.controller_apply` | CreateRole, UpdateAssumeRolePolicy, TagRole become owner-only | `iam.tf:20–69,229–247` |
| `aws_iam_policy.state_plan`, `aws_iam_policy.state_apply` | CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion, DeletePolicyVersion, TagPolicy become owner-only, including future state-key permission edits | `iam.tf:87–262` |
| `aws_iam_role_policy_attachment.controller_plan`, `aws_iam_role_policy_attachment.controller_apply` | AttachRolePolicy becomes owner-only; historical wildcard attachment grant was not pair-restricted | `iam.tf:265–273` |
| `aws_rolesanywhere_trust_anchor.local_controller` | Create/Update/Enable/DisableTrustAnchor, tags, CA-bundle rotation become owner-only | `iam.tf:7–18,248–251` |
| `aws_rolesanywhere_profile.controller_plan`, `aws_rolesanywhere_profile.controller_apply` | Create/Update/Enable/DisableProfile, tags become owner-only | `iam.tf:71–85,248–251` |
| `aws_iam_user.recovery`, `aws_iam_user_policy.recovery` | CreateUser, TagUser, PutUserPolicy become owner-only; prevent_destroy stays; no source access-key resource | `iam.tf:275–309` |
| `aws_s3_bucket.{state,recovery}`, `aws_s3_bucket_versioning.{state,recovery}`, `aws_s3_bucket_server_side_encryption_configuration.{state,recovery}`, `aws_s3_bucket_ownership_controls.{state,recovery}`, `aws_s3_bucket_public_access_block.{state,recovery}`, `aws_s3_bucket_lifecycle_configuration.{state,recovery}`, `aws_s3_bucket_policy.{state,recovery}` | Preserve baseline bucket refresh and CreateBucket / PutBucketOwnershipControls / PutBucketPolicy / PutBucketPublicAccessBlock / PutBucketTagging / PutBucketVersioning / PutEncryptionConfiguration / PutLifecycleConfiguration | `main.tf:132–316`, `policies.tf:1–64`, `iam.tf:179–212` |
| `aws_kms_key.opentofu`, `aws_kms_key.recovery`, `aws_kms_alias.opentofu`, `aws_kms_alias.recovery` | Preserve baseline crypto/refresh and CreateKey/CreateAlias/EnableKeyRotation/PutKeyPolicy/TagResource/UpdateAlias; key prevent_destroy stays | `main.tf:50–130`, `iam.tf:213–228` |

There are **11 identity managed addresses**. `data.aws_iam_policy_document.*` produces JSON,
not separate managed IAM objects. No OIDC provider, managed boundary policy or owner role is source-declared
here; active roles now require external boundary references. No CRL, access key or instance profile is managed in this root. Removal of broad RA
Delete*/Put* does not imply these are legitimate routine source operations.

Preserved identities (no trust or profile Documents are rewritten in this proposal):

- Roles `home-lab-infrastructure-plan` / `home-lab-infrastructure-apply`, account 658271954302;
  attached policies `home-lab-opentofu-state-plan` / `home-lab-opentofu-state-apply`.
- Trust principal only `rolesanywhere.amazonaws.com`, exact anchor
  `arn:aws:rolesanywhere:us-east-1:658271954302:trust-anchor/d71248a9-878e-4d49-b0e8-cd5c45c6bb30`,
  respective exact CN `home-lab-local-controller-plan` / `home-lab-local-controller-apply`.
- Profiles `home-lab-local-controller-plan` (`ff219908-a4ff-4bf3-9507-820ff314faca`) and
  `home-lab-local-controller-apply` (`47ae8371-5564-4ed5-9be0-cc4024f1dcb2`), each retaining
  its sole matching role, enabled, duration 3600 and acceptRoleSessionName true. Historical
  GetProfile returned no sessionPolicy/managedPolicyArns ceiling. Other profiles were not audited.

### Legitimate baseline and retained risks

- State prefixes/objects remain exactly the five source keys for authentik, aws-foundation,
  omada, proxmox and tailscale under `home-lab/<root>/tofu.tfstate`, plus their `.tflock`
  objects in `home-lab-opentofu-state-658271954302`. Plan reads state/locks and can put/delete
  locks. Apply reads/writes state/locks and deletes locks only. **Plan is not wholly read-only.**
- Bucket refresh retains ListBucket/ListBucketVersions, GetAccelerateConfiguration,
  GetBucketAcl/CORS/Location/Logging/ObjectLockConfiguration/OwnershipControls/Policy/
  PublicAccessBlock/RequestPayment/Tagging/Versioning/Website, GetEncryptionConfiguration,
  GetLifecycleConfiguration and GetReplicationConfiguration for both state and
  `paul.diloreto.backups`. The separate unconditional ListBucket statement means the prefix
  condition is not an overall listing boundary.
- Crypto Decrypt/Encrypt/GenerateDataKey/DescribeKey keeps plan's two keys and apply's single
  opentofu key exactly. Plan key refresh includes GetKeyPolicy/GetKeyRotationStatus/
  ListResourceTags on both and ListAliases on `*`. Apply administration stays on `*`.
  No recovery-key data grant is added to apply. Recovery-user crypto/object-version access
  is a distinct principal's existing policy, not a controller recovery grant.
- **Unresolved KMS/bucket/data authority:** apply keeps `kms:PutKeyPolicy` on `*`, alias/key
  administration and bucket-policy/lifecycle/encryption writes. These can affect other
  principals, availability, encryption/decryption authority and data retention. They are
  deliberately not silently reduced in an identity-only delta. Action denies on this role
  do not prevent another principal using a newly changed resource policy. Do not place owner
  policy source, credentials, CA material or owner recovery backend under this authority.
- Controller state writes remain an integrity hazard: owner execution must not blindly trust
  controller-written state, plans, source or outputs. Actual resource policies, SCP/RCP,
  endpoints/session policies, alternate roles/profiles, recovery-user attachments/keys and
  CA/private-key custody were not inspected. Broad Get*/List* may expose additional metadata.
  Stolen independent credentials/CA authority can bypass the bounded principal altogether.

## Staged external-owner transition — design ordering, not commands

1. **Freeze identity convergence; verify nominated owner and recovery first.** Personal
   owner `paul` on a separate owner-controlled machine is now selected, but its authority,
   execution mechanism and independent credential/CA custody are not live-verified.
   Review bounded bootstrap/repair authority separately; no owner grants are contained here. Protect source, CA/private
   authority, recovery artifacts and any owner backend from retained controller S3/KMS paths.
   Resolve resource-policy risks above or stop; do not claim owner isolation while its
   credentials/artifacts are controller-writable/readable. Establish exclusive writers.
2. **Review authored source alignment before resuming routine runs.** Current `iam.tf`
   now requests reduced apply grants and external per-role boundaries; it does not manage
   boundary policies. Required inputs are `controller_plan_permissions_boundary_arn` and
   `controller_apply_permissions_boundary_arn`, without defaults or null fallback.
   Shape validation and role preconditions require distinct policy ARNs in the caller's
   account/partition, not proof of owner provenance/content. The owner must supply exact
   verified ARNs and approved current ceiling policy content later. Historical JSON here
   must not be wired as active configuration. Trust/profile/role identities stay intact.
   The owner validates exact changes against then-current resources/state; retain addresses,
   attachments, outputs and non-identity grants. Reject destruction, replacement, imports or
   unrelated drift; do not use an unreviewed full foundation apply to install these drafts.
3. **Retain state, split execution — selected.** All 11 identity addresses and existing
   resource tracking remain. The new fail-closed controller gate permits only known,
   well-formed managed identity read/no-op, rejecting **every** IAM/RA mutation/import
   before modes/allowlists, plus observed identity drift and deferred/unknown/malformed
   identity changes. Explicit data remains eligible for the prior controls. Mutations
   require separate owner-controlled execution, not a routine override flag. The stronger
   unconditional managed-OIDC prohibition remains; the owner is not a home-lab OIDC
   ownership bypass. Removing addresses from the selective allowlist is not isolation.
4. **State splitting is not selected or implemented.** Any future reconsideration must
   separately approve all 11 origin/destination addresses,
   dependencies, owner-isolated backend/key policies, setup-output compatibility and exclusive
   writer coordination. Under later authorization preserve protected recovery versions,
   lineage/serial and transfer receipts. Use explicit non-destructive tracking handoff, then
   verify destination ownership and source non-destruction before resuming either runner.
   Never remove source blocks against old state, silently state-rm, or retire the foundation
   state key as a migration mechanism: current/noncurrent retirement expires after one day.
   Neither a state move nor `removed`/import blocks are supplied by this inert slice.
5. **Owner-controlled bootstrap during quiescence.** After source/transition/recovery approval,
   an owner can prepare both exact ceiling documents outside controller ownership, attach
   the reviewed per-role boundary, and narrow the apply identity policy (plan policy unchanged).
   Boundary-first in this stopped transition establishes the ceiling before relying on grant
   removal; this is not an atomic cutover or instruction to execute APIs. Do not rely on an
   attach-then-self-repair controller step: boundary attachment already removes its mutation
   ability even while the old broad identity policy remains. Only the independent owner can
   complete/repair intermediate stages. Boundaries are not ordinary attached permission
   policies. Approve exact live operations/sequence/readback separately with freshness checks.
6. **Verify before releasing the freeze.** Separately authorize bounded policy/attachment
   readback and fresh RA issuance, expected state/lock/refresh and no-op behavior, caller
   identity/credential selection and existing-session behavior. Current setup reads five
   outputs and validates caller once; runtime does not continuously attest every caller.
   After out-of-band owner bootstrap/repair, the owner must refresh and independently
   verify retained identity tracking before resuming: observed resource_drift still
   blocks even an otherwise no-op proposed plan. Source alignment alone is insufficient.
   No assumptions/simulations/live mutation-denial canaries are authorized here. Offline
   cases and one read-only success cannot prove mutation denial or full operation continuity.

`reconcile-infrastructure` always plans foundation, applies it **first**, replans under apply
credentials, and tailnet-only preflight also replans it (`scripts/reconcile-infrastructure`,
lines 278–292, 867–970). After isolation the controller cannot converge roles, policy versions,
attachments, profiles/anchor or recovery-user policy. Identity drift can therefore block
unrelated work even if read-only refresh succeeds. Policy changes for new state keys likewise
need owner action. Source alignment and blocked-owner-drift reporting are now authored;
owner bootstrap and independent execution/verification remain unperformed. No continuity
claim or blanket ignore_changes workaround.

### Sessions, propagation and forward recovery

[AWS temporary-permission guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)
states that permissions are evaluated on each request and policy changes affect credentials
issued before the change; updates may take a few minutes.
[Eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html#troubleshoot_general_eventual-consistency)
requires verification before depending on propagation. This is not a hard SLA or proof of
exact boundary-attachment timing. Do not assume old sessions keep old permissions until expiry,
or trust edits alone revoke issued credentials. Preserve the existing 3600-second trust/profile
configuration; quiescence, session containment and propagation verification require owner
approval. No sessions were minted, inspected, revoked or tested here.

If cutover verification fails, keep routine execution stopped and preserve exact failure and
partial-stage evidence. The approved independent owner diagnoses stale propagation, source
misalignment, missing legitimate baseline RPC evidence or recovery-path failures, then makes
only separately reviewed **forward** repairs and revalidates. No automatic broad rollback,
unbounded policy restore, controller self-repair or full-foundation apply. Any emergency
relaxation must be narrowly time/scoped, explicitly approved, independently controlled and
followed by restoration/readback; no such authority is assigned by this README.

## Offline validation

`test-controller-identity-isolation.py` uses standard-library unittest only. It checks pinned
historical documents, exact non-identity preservation and action removal, exact boundary Allow
coverage and unconditional NotAction shape, final document quotas/hashes, state/lock/KMS/bucket
contracts, inert filenames and bounded named forbidden-action exception membership. Target
labels document intent; `Resource: "*"`/no condition is asserted independently. It does **not**
resolve resources, principals, conditions, trust, API support or effective permissions. It is
not a custom IAM evaluator, simulator or AWS proof. Direct-session exceptions are addressed by
the reviewed explicit-deny construction, not a fabricated session-policy simulation.

The original proposal slice added one offline runner invocation; a later local identity-gate
slice adds synthetic admission tests and extends the OIDC envelope walk to drift/deferred
changes. One prior non-OIDC IAM-mutation test now intentionally expects owner denial,
while preserving its payload-not-envelope control separately. Historical JSON/provenance
and proposal structural tests are unchanged; no allowlist bypass is introduced. Tests accept `--proposal-dir` only to
run against temporary synthetic copies for intentional red mutations (never active config).
Red checks deliberately remove/weaken the deny, add forbidden/wildcard exceptions, widen
boundary resources/grants, restore identity mutation, alter baseline state/lock/KMS statements,
change historical pins and exceed quota. Logs must show actual test failures, not merely a
success message claiming mutations were tested. Test execution for this slice uses pinned
Python 3.14.7 with `-B -E -s -S`, `env -i`, temporary HOME and explicit safe PATH; shell-runner
`python3` resolves to a temporary wrapper outside the repository with those exact flags.
The original proposal validation used no dependencies, cloud calls, network,
state/credential/certificate reads, Docker, OpenTofu, commits, staging or deployment.
The later local source-alignment slice also uses pinned OpenTofu 1.12.5 **version/fmt-check
only** on the two changed `.tf` files under an isolated environment; no provider-backed
validation, init, plan, apply, output or state/backend operations are authorized.

See also [shared OIDC ownership](../../../../docs/shared-oidc-ownership.md) and the separately
maintained websites document at
`/Users/pauldiloreto/Projects/websites/main/docs/migration/shared-oidc-iam-plan.md`.
This proposal changes no websites files and does not alter the provider's sole owner,
`diloreto-amplify-hosting` / `GitHubOidcProvider`, or infer who historically deleted it.
