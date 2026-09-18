# Decisions and deliberate exceptions

## Approved direction

Manage existing infrastructure with native OpenTofu, hosts with standard
SSH/Ansible become, and applications with Compose. Adopt the existing server
before expanding rebuild coverage. Keep high-risk storage, access, firewall,
reboot, database migration and recovery operations explicit and separate.
This supersedes the old controller/admission ADRs. There is no requirement to
finish their deferred successor before simplifying unrelated source.

Source cleanup removes universal launchers, abandoned admission/reporting machinery,
inert experiments and isolated unconsumed helpers/schema definitions. Published
forward recipes remain in Git, not current setup guidance. Retained evidence records
and installed/recovery consumers are a separate boundary; no new universal manifest,
launcher or qualification platform replaces the old controller.

## Disposable controllers and live validation

New native workflows must work from a fresh checkout on a disposable runner.
Desired configuration and repeatable checks belong in source; current readiness
comes from fresh host observations and operation-specific postconditions, not
agent-session inventories, developer-local plans or committed success receipts.
CI logs are diagnostic history, not authorization inputs. Missing historical
completion records do not by themselves block unrelated source retirement.

Keep recovery state separate from validation results. Required interruption
journals, ownership, before-images and autonomous rollback belong durably on the
host or in independently available protected storage. Remote OpenTofu state and
reviewed saved-plan handling remain native tool responsibilities. Runner loss
must not lose recovery intent or disable watchdogs. Fresh observation is not
exclusive ownership: recheck preconditions under the operation's coordination.

This direction does not waive surviving legacy consumer checks, resolve a live
interruption, prove backup restorability or authorize artifact deletion. Migrate
those consumers deliberately rather than fabricating receipts, pinning new checks
to old observations, or introducing another admission framework. Production CI
needs trusted workflows, protected approval, reviewed short-lived access and
coordination with host-local writers; none is configured by this decision.

## Built-in-first Nix retirement

Preserve useful package, reboot and low-risk operations, not the legacy planning
framework or its exact CLI. Prefer core Ansible package facts/APT, copy/template,
service and reboot modules. Native check/review/apply replaces the custom saved
solver-plan model; it is not an immutable transaction. No custom APT display-output
parser, redacted production transition or replacement receipt system is required.

Keep inventory separate from mutation previews: even Ansible APT check mode can
repair missing/corrupt metadata. Retain operation-specific host coordination and
necessary interruption recovery, but do not reconstruct a universal controller
around built-ins. Durable native tool state may support forward repair; it is not
proof of automatic rollback. Autonomous firewall recovery and genuine hardware
safety functions remain narrow exceptions, not reasons to preserve unused writers.
Existing capabilities/recovery stay until replacements are qualified. Source work
and the checkpoint commit do not approve package actions, reboots or access changes.

## First native adoption

Native SSH/become deliberately reuses Tailscale access, accounts and keys.
Manual-install policy is independent of the legacy contract: the old unattended
retirement (disable timers/list updates) and cloud-init automatic-install defaults
must not undo it.

`configure-backups.yml` owns narrowly guarded existing-host configuration, not
bootstrap or activation. Native variables own unit inputs and tool pins; shared
render/install/account/copy declarations keep legacy entrypoint guards intact.
The `restic_systemd_legacy_contract` bridge remains necessary for legacy convergence
and the bounded post-NFS single-unit repair. Byte parity is not a permanent
obligation to match old receipt hashes.
Runtime policy, backup scope and retained-journal reconciliation remain legacy
responsibilities: tool upgrades and content rollout need coordinated policy/journal
review, not independent pin bumps or receipt regeneration.

[Operations](operations.md#latest-scoped-deployment) is canonical for dated outcomes
and supported scope, including [unit-state exclusions](operations.md#backup-unit-definitions),
[existing-account refusal](operations.md#confined-backup-account) and
[same-content metadata limits](operations.md#same-content-backup-runtime-files).
These adoptions confer no general host convergence, upgrade, restart, reboot,
firewall, data migration or backup-health authority. The
[native Proxmox capability observation](operations.md#native-proxmox-capability-observation)
now checks protected identities without installed Nix helpers or prior runner
artifacts. Native maintenance variables also replace selected Nix data reads in
current source, but that activator change is not deployed and the wider legacy
audit/maintenance/recovery consumers remain.

The [native Compose workflow](operations.md#native-compose-qualification) uses
fresh tracked source plus actual remote state and limits mutation to an explicit
`flaresolverr` canary. Host-side SOPS decryption, same-content environment refusal,
production ownership, current/previous generations and image locks remain the
safety boundary. It creates no approval receipt and consumes no previous runner
result. Live observation and its source-bound check mode are qualified. The one
authorized normal `flaresolverr` attempt refused an out-of-scope undeployed
LiteLLM config before publication or container mutation and retained production
ownership. That attempt is consumed. The exact owner was subsequently released
under separate authorization while preserving the failed candidate; the narrower
candidate then passed fresh observation and same-commit check mode, but its one
new normal attempt stopped before ownership or staging when a Restic interruption
journal appeared. A later read-only audit found the journal absent and performed no
recovery. The attempt is consumed; retry, database, Restic and LiteLLM activation
remain unauthorized. This is sufficient to refuse the legacy **general** deployment lane,
but not to remove operation-specific migration/recovery code or the installed
image-pruning helper.

## Why legacy code remains

| Retained source | Actual reason / retirement boundary |
| --- | --- |
| `infrastructure/contract/`, schemas, renderers and validators | HCL, host roles, Restic and recovery still read these values. Migrate each consumer into typed native inputs before removing the global contract. |
| Compose artifact/model/action/diff/image helpers, operation-specific staging/deploy/rollback roles | Legacy migration, data recovery and installed image-retention consumers remain. General staging/deployment is refused; native check qualification deliberately does not replace those operation-specific recovery consumers. |
| Restic runner, bootstrap/init/first-run/qualification helpers and recovery plays | Writer quiescence, interrupted-backup recovery, repository identity, pending-copy retention and retained operation journals remain real dependencies. |
| Proxmox deploy activator/transport | The final read found all boot/network/storage/NFS/Tailscale/package ownership journals committed. The retained prepared package record is preserved as historical evidence. The installed activator was removed in the approved September 17 cleanup; the deploy transport is now the source-owned Restic-only route. |
| Installed Proxmox observer/private preparer/plan transport | Active source callers and installed helper/access generations are retired. The approved cleanup preserved root-only before-images, removed obsolete helpers/sudo, disabled obsolete shells and passed a zero-change second normal run. The known PVE root key remains inert behind the checked root-specific effective sshd public-key/root-login refusals and is checked by native observation. |
| Firewall transaction, boot recovery and persistent watchdog | Autonomous rollback must survive controller/network loss; Ansible rescue cannot provide that. Its source/runtime is independent of the removed Nix tree. |
| Historical Nix recovery material | Active `nix/`, bundle/planner/bootstrap and protected-input writer source is retired. Preserve the old host checkout, previous generation, install manifest, sealed inputs and historical Git checkpoint until their explicit disposition; do not reintroduce them as current automation. |
| VM9900 qualification and recovery roots/helpers | Possible live VM, disks, snippets, ACLs, keys and failed-operation state require separately authorized inventory/retirement. |
| JS dependencies and provider locks | Contract and policy consumers still need AJV/js-yaml. Retiring the Proxmox projection does not eliminate Node/Bun dependencies. |

### Qualification and provider-adoption retirement boundary

The September 18 source and live audit confirms that VM9900 still belongs to the
Debian lifecycle root. Its preserved local state binds the qualification image,
VM 9900 and firewall options/rules; the live stopped VM uses the Debian lifecycle
name, root-disk serial and cloud-init snippet. Its dedicated ACL, account, sudo rule,
snippet transport, transaction helper, diagnostic directory and snippet remain
installed. The preserved Restic reconciliation state separately binds the still
present recovery image, while the Restic snippet is absent. Those different state
lineages do not isolate the shared hypervisor identity. Keep both VM9900 roots,
provider locks, inventories, snippets, evidence, installed capability source and
recovery consumers until the recovery-image and failed-operation lineage receive a
separate retirement decision.

The disposable disk-adoption source is retired. Its current local state is empty;
the immediately preceding state generation records VM9951 and four disks on the
`qual-lvmthin` datastore. A bounded live read found VM9951 absent, no matching ACL,
and the qualification datastore itself absent. The ignored provider cache and both
state generations remain as historical evidence; no VM, disk or datastore was
changed.

The production Proxmox candidate move is also retired after remote state showed the
sole VM address as `proxmox_virtual_environment_vm.debian`, with no
`proxmox_virtual_environment_vm.debian_readopted` or `arch` address; a fresh
provider-backed plan then reported zero changes. VM100's disk tombstone, imports and
resource address are unchanged. Tailscale remote state still binds only
`terraform_data.tailscale_policy[0]`, while a protected API read confirmed that live
policy differs from source. The selected native ownership path restores the pinned
Tailscale provider and declares `tailscale_acl.policy[0]` as the complete policy-file
owner. The placeholder remains protected until adoption is complete so source work
does not rewrite its existing state address. The old custom ETag evidence helpers are
retired because they cannot apply the native resource. Provider updates overwrite the
complete policy without an ETag precondition, so import, a fresh reviewed plan and
apply require separate authorization and a freeze on concurrent dashboard edits.

Omada remote state exactly matches its one network and eight reservations, and
Authentik remote state exactly matches all 79 declared managed addresses plus two
data lookups. Fresh provider-backed plans for both roots reported zero changes.
Their roots, imports, encrypted inputs and preparation tooling remain active. Only
Authentik's one-shot account-creation bootstrap and hard-coded inventory normalizer
were removed: neither was a state, rotation or recovery consumer. Omada's export
and hostname-alias tooling still feed its retained root.

An exact state-bucket inventory found zero versions or delete markers for every
formerly retired key. Those five entries and their expired-object lifecycle-rule
scaffolding are removed from desired source. The live bucket lifecycle configuration
is unchanged. The required boundary ARNs and reviewed boundary manifest are absent,
and the live roles have no attached permissions boundary. The similarly named
`home-lab-opentofu-state-plan` and `home-lab-opentofu-state-apply` policies are the
roles' controller-owned permissions policies; the boundary validator explicitly
forbids using them as their own boundaries. A diagnostic plan produced with those
invalid inputs was not applied and is not review or authorization evidence. No
plausible external boundary policy currently exists in the account. The owner must
supply distinct policy ARNs, reviewed content hashes and provenance before a valid
AWS foundation plan can be produced.

The AWS foundation root is the first isolated provider leaf removed from the
global contract seam. It owns the fixed one-day incomplete multipart-upload cleanup
as a local safety invariant. Active state-object retention and resource addresses
remain unchanged; only lifecycle rules for already absent retired keys leave desired
source. No provider apply was run. The legacy Offen field remains because
recovery-hold proof and first-run recovery still consume it; this change is not
authority to prune that contract subtree.

Do not regenerate historical hashes, fabricate receipts, clear journals, stop
watchdogs or erase locks to make the reduced source pass legacy admission. A
persistent lock inode is not necessarily contention; its owner/journal and actual
flock state matter. Deleting an installer does not retire its installed copy.
Unknown operation state requires inspection and a specific recovery decision.

Backup schedule activation still checks the exact Restic restore-proof hash and
terminal Offen receipt. Keep those evidence files and the retirement manifest.
The contract also references `infrastructure/evidence/restic-first-run-aws.json`,
which is excluded by `.git/info/exclude` locally and untracked. `validate-contract`
no longer reads this receipt or any other historical inputs: its historical modes
were removed, and both retired flags fail explicitly rather than silently selecting
[offline source validation](operations.md#offline-contract-source-validation).
The pre-removal tracked-caller recheck found only documentation, not operational
callers; the isolated regression test covers flag rejection. First-run run/resume/finalize
playbooks separately produce or verify this receipt; their requirements, shared
policy validators and runtime/recovery gates are unchanged. Do not publish it
blindly or substitute a fake proof. Source tests are not current backup health.

## Custody is separate from receipt cleanup

The read-only custody audit is closed. Ordinary provider state is remote in the
five configured S3 backends, not dependent on developer-local state copies.
Remote object/version metadata establishes existence, not correct contents,
decryptability or successful recovery. Bundle B's restricted HEAD access is not
absence. Current state objects use SSE-S3 despite KMS bucket defaults; this is
not authorization to rewrite encryption or a prerequisite for safe source work.

Two local qualification-state dependencies remain unresolved: Debian lifecycle's
`.local/qualification-route/clean-first-boot-foundation-final/state.tfstate` and
Restic recovery's `.reconcile/restic-recovery-vm/09d091e5c9f44eafaf5a8b89576c9929e1fa5644/tofu.tfstate`.
Preserve both and their recovery inputs. Leave VM9900 unchanged; neither state
migration nor retirement is authorized by closing this audit.

The recovery key is currently on this developer machine; **off-machine custody
is not verified and remains an open gap**. The operator will verify external escrow
and independently available recovery access, including required credentials and
backend coordinates. Current automation still consumes developer-local credentials;
documentation and additional copies
on that same machine are not verified independent custody. Retrieval, decryption
and recovery exercises require separate approval.

Keep working logging and backup configuration unchanged. Explicit journald policy
is optional follow-up. These custody gaps, further historical evidence collection
and KMS changes are **not prerequisites for receipt-dependency source cleanup**.
Such cleanup must still preserve operational guards and supported scope.

## Ownership and evidence limits

- The shared AWS GitHub OIDC provider
  `arn:aws:iam::658271954302:oidc-provider/token.actions.githubusercontent.com`
  belongs to websites' CloudFormation stack `diloreto-amplify-hosting`, logical
  resource `GitHubOidcProvider`. Home-lab must not manage/import an OIDC provider.
  The prior foundation serial 43 observation had zero OIDC entries, not proof
  about every backend. No deletion principal was established by that history.
- Roles Anywhere IAM resources remain useful native credential infrastructure;
  names containing `local_controller` are not permission to delete them. External
  boundary ARNs do not establish the deployed policy contents or custody.
- `state-objects.json` drives exact active backend IAM keys and noncurrent lock
  lifecycle prefixes. Active state history remains retained. The September 18
  exact-key inventory proved every formerly retired version and delete marker
  absent before their entries were removed from source. Prefix matching is not
  equality; any future retirement needs the same exact inventory gate. No
  bucket-wide expiration or state deletion.
- Historical aggregate Ansible ownership and bounded Nix-runtime retirement
  (2026-09-11, no removals) did not qualify clean boot, new-source convergence or
  universal recovery. Completed key/domain handoffs are not repeatable setup steps.
- A saved OpenTofu plan is not a cross-system transaction. `prevent_destroy` does
  not prevent every in-place data loss or external action. Ansible check mode is
  a preview, and Compose cannot reverse database migrations.

Retain `.local`, `.reconcile`, `.terraform`, recovery bundles, state, credentials,
images, failed plans and lock/journal artifacts. No ignored operational artifacts
were cleaned during this source pass. Live retirement and native replacement
require separate review; see [migrations](migrations.md) and
[recovery](../recovery/README.md).
