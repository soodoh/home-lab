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
candidate is source-qualified only. Retry, database, Restic and LiteLLM activation
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
- `state-objects.json` drives exact backend IAM keys and S3 lifecycle prefixes.
  Active state history is retained; retired state and noncurrent lock versions
  expire after one day. Prefix matching is not equality. Retire manifest entries
  only after a separately authorized exact-key inventory proves every retired
  version/delete marker absent. No bucket-wide expiration or state deletion.
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
