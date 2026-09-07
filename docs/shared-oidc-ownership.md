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

- `resource_changes`, including creates, updates, deletes, replacements, imports,
  no-ops, and managed reads;
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
or using different credentials. No live/source role policies, permissions
boundaries, state, or deployed CloudFormation retention were changed here.
Owner-side source retention work in websites requires separate review/deployment;
source `Retain` is not live retention and does not prevent direct IAM deletion.

Durable runtime protection requires separately reviewed effective identities,
attached policies/boundaries and assumption paths, including closure of IAM
self-escalation, privileged PassRole/AssumeRole, boundary removal, and access to
the owning stack. A consumer-editable deny is not durable enforcement. No live
mutation/deletion canary or deployment is authorized by this document. Websites
production release locks remain intact and migration remains **0/4**.
