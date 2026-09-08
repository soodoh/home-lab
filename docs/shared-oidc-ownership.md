# Shared GitHub OIDC provider ownership

## One lifecycle owner

In AWS account `658271954302`, the sole lifecycle owner of
`arn:aws:iam::658271954302:oidc-provider/token.actions.githubusercontent.com`
is the websites repository's existing CloudFormation stack
`diloreto-amplify-hosting`, logical resource `GitHubOidcProvider`.
Do not create a second managed declaration or import in home-lab.

Home-lab's controller uses **Roles Anywhere**, not GitHub federation. Home-lab
must not manage or import **any** `aws_iam_openid_connect_provider`, regardless
of issuer, resource name, module, or allowlist, unless a later explicitly reviewed
ownership design changes this rule. Future consumers may use a read-only data
lookup or supplied ARN, with separately reviewed role trust.

The companion record is `docs/migration/shared-oidc-ownership.md` in the websites
repository. Its approved recovery evidence records recreation of the same ARN
on 2026-09-07 at 01:07:07Z and provider-only CloudFormation `IN_SYNC` at 01:07:09Z.
This is prior evidence, not a new live query or proof of a successful federation job.
The historical home-lab declaration/removal establishes conflicting ownership,
**not who deleted the provider**; no deletion principal was established.

## Local safeguards

[`inspect-plan.py`](../infrastructure/policy/inspect-plan.py) rejects managed OIDC
resource envelopes by type before mode selection, allowlist processing, and
import/no-op/read shortcuts. It inspects:

- `resource_changes`, `resource_drift`, and deferred resource changes, including
  creates, updates, deletes, replacements, imports, no-ops, and managed reads;
- `prior_state.values` and `planned_values`, recursively through child modules,
  even without resource changes;
- `configuration.root_module`, recursively through `module_calls`, including
  configuration-only declarations such as `count = 0` when present in plan JSON.

Only explicit `mode = data` envelopes are exempt from this ownership rule;
missing/unrecognized modes do not bypass it. Resource values and expression
references are not scanned as ownership declarations. Existing deletion,
replacement, protected/unknown-field, and import restrictions remain in force.
The [foundation allowlist](../infrastructure/policy/allow/aws-foundation.txt)
cannot override the OIDC rule.

The existing offline [`test-policy.sh`](../infrastructure/policy/test-policy.sh)
runner includes [`test-oidc-ownership.py`](../infrastructure/policy/test-oidc-ownership.py).
It tests broadly allowlisted ownership attempts and legitimate data/control cases.
It also checks direct `aws-foundation/*.tf` and `*.tf.json` source files without
reading state, backend metadata, variable values, or credentials. JSON source
resource/import blocks are checked structurally. Native HCL uses the repository's
literal header/traversal source-check convention: this is a **formatting-sensitive
early warning, not an HCL parser or security boundary**. Comments/templates can
cause false positives; escaped labels, unusual syntax, and modules outside that
source directory are not comprehensively covered by the source check. Data
headers and ordinary data references remain permitted. The generated-plan
structural check is the authoritative local ownership gate, including child
module configuration supplied by the plan producer; it cannot infer configuration
omitted from an input JSON document. These fixtures are synthetic, not a new
OpenTofu/provider schema or live-plan verification.

## State and enforcement limits

The previously approved default-workspace foundation snapshot (serial **43**,
39 resources, last modified 2026-09-03T03:48:47Z) contained **zero OIDC entries**.
No `state rm`, `removed` block, or other state change is needed for that observation.
It does not establish all alternate backends/workspaces or stale-controller state.
If another binding is discovered, stop and separately review the exact backend,
workspace, address, and nondestructive handoff. Never relax deletion gates or
blanket-delete state to resolve ownership. See [state-object cleanup](opentofu-state-cleanup.md).

These are **local source/plan guardrails, not deployed IAM enforcement**. They do
not stop a caller bypassing the controller, editing the gate, using CLI import,
or using different credentials. Active home-lab source now requests reduced apply
identity grants and required external boundary references, as described below.
No live role policies, boundary
creation/attachment, state, backend, or deployed CloudFormation retention were changed.
Owner-side source retention work in websites requires separate review/deployment;
source `Retain` is not live retention and does not prevent direct IAM deletion.

## Selected controller/owner execution split — authored locally, not deployed

The selected architecture **retains the existing foundation state and all 11 IAM/RA
resource addresses**, but reserves identity mutation to an independent owner. The
nominated existing owner is personal/profile `personal`, IAM user `paul`, account
`658271954302`, on a separate owner-controlled machine outside the controller.
This is a user selection, **not live verification of authority, credential/CA custody,
or a new privilege grant**. Routine runs must not use this personal identity.
No owner executor, credential-selection change, override flag, state handoff, import,
removal, `ignore_changes`, backend move or new boundary-policy resource is supplied.

[`iam.tf`](../infrastructure/tofu/aws-foundation/iam.tf) now narrows only apply's
IAM/RA Action arrays to the existing Get*/List* patterns. Plan grants, all non-identity
grants, trust/CN/anchor conditions, roles/profiles, attachments, outputs and recovery
principal remain intact. Each controller role references a **required, non-null external
boundary ARN** via `controller_plan_permissions_boundary_arn` and
`controller_apply_permissions_boundary_arn`. There are no defaults. Variable validation
checks policy-ARN shape; blocking role preconditions require the current caller's
account/partition and distinct ARNs. These checks cannot prove existence, approved
policy content, ownership or caller custody. Missing inputs fail before convergence;
missing boundary resources or bootstrap are not repaired by the controller.

The owner must later supply both exact verified ARNs through separately reviewed
foundation inputs, with provenance and approved current policy versions/content.
Do not invent ARN values, attach the ordinary permissions policies as boundaries, or
load historical proposal JSON as active configuration. The
[inert proposal](../infrastructure/policy/proposals/controller-identity-isolation/README.md)
remains historical review evidence: the intended owner-controlled ceilings copy each
role's retained Allows plus an unconditional Deny/NotAction on `Resource: "*"` with
exact retained action exceptions. Approve concrete owner policy content separately;
ARN syntax alone cannot enforce that ceiling.

The local gate now denies every managed `aws_iam_*` / `aws_rolesanywhere_*` mutation
or import **before every controller mode and allowlist/import/no-op shortcut**. Only
explicit data envelopes and well-formed, known managed read/no-op changes are eligible
for existing admission checks. Managed OIDC ownership remains more restrictive: even
read/no-op or configuration-only ownership is denied. Identity mode/type uncertainty,
malformed envelopes, unknown results, deferred managed identity work and incomplete or
errored plans fail closed with owner-intervention diagnostics. Observed identity drift
also blocks, even if the proposed changes are otherwise no-op. Resource values and
expression references are not treated as declarations. Synthetic tests in
[`test-controller-identity-gate.py`](../infrastructure/policy/test-controller-identity-gate.py)
exercise these structural admission rules, not IAM authorization or live plans.

### Required future approval gates and operational coupling

1. Independently review this exact local source/gate/test diff. Then approve owner
   custody, bounded existing bootstrap/repair authority and recovery; do not infer
   authority from the prior personal audit caller. Resolve access to owner artifacts,
   credentials and CA private authority outside controller storage/KMS control.
2. Quiesce routine execution and establish exclusive writers. Independently verify
   trusted source, then-current live identity configuration and exact retained state
   lineage/serial/recovery versions before any owner plan. Controller-written state,
   plans and outputs are not trustworthy owner instructions. No such reads or writes
   are authorized by this local change.
3. Separately approve exact external boundary creation/content/ARNs, boundary-first
   attachment and apply-policy narrowing by the owner, with intermediate-stage recovery
   and freshness checks. Preserve trust, profiles, outputs and all addresses. Reject
   unrelated drift, destruction, replacement and imports; **no unreviewed full-foundation
   apply**. The routine gate intentionally cannot admit this bootstrap; any separate
   owner admission/execution interface needs its own review, not a bypass here.
4. If owner bootstrap or repair is done out of band, **owner refresh/verification of
   retained identity tracking is required before resuming**. Otherwise resource_drift
   can still deny an otherwise no-op plan. Source alignment alone is insufficient.
   Do not suppress drift or use blanket `ignore_changes` to resume.
5. Separately authorize exact policy/boundary readback, caller/credential-path checks,
   RA fresh issuance and existing-session/propagation verification, plus bounded
   legitimate state/lock/refresh/no-op operations. Offline tests and one read success
   prove neither effective denial nor continuity. Any assumption, simulation or live
   probe requires explicit scope; no mutation/deletion canary is authorized here.
6. Keep routine execution stopped on failed verification. Owner performs only reviewed
   forward recovery, not automatic restoration of broad self-administration. Website
   owner-template retention changes and their exact change set remain a separate gate.

Foundation is always planned, applied **first**, and replanned under apply credentials;
**tailnet-only preflight also replans foundation**. This intentionally means identity
bootstrap/change/drift can block unrelated work. New state-key policy grants also need
owner convergence. No controller continuity or enforced AWS isolation is claimed.
Retained state-write authority is an integrity risk; KMS `PutKeyPolicy` on `*`, bucket
policy/lifecycle writes and alternate-principal resource grants remain unresolved.
An action ceiling is not a complete resource perimeter: excepted actions and other
principals can still have resource-policy access. CA/private-key custody, alternate
profiles/roles, recovery-user access and active sessions remain unverified.

Durable runtime protection requires separately reviewed effective identities,
attached policies/boundaries and assumption paths, including closure of IAM
self-escalation, privileged PassRole/AssumeRole, boundary removal, and access to
the owning stack. A consumer-editable deny is not durable enforcement. No live
mutation/deletion canary or deployment is authorized by this document. Websites
production release locks remain intact and migration remains **0/4**.
