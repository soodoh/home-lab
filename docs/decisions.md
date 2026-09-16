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
firewall, data migration or backup-health authority.

## Why legacy code remains

| Retained source | Actual reason / retirement boundary |
| --- | --- |
| `infrastructure/contract/`, schemas, renderers and validators | HCL, host roles, Restic and recovery still read these values. Migrate each consumer into typed native inputs before removing the global contract. |
| Compose artifact/model/action/diff/image helpers, staging/deploy/rollback roles | Legacy migration, data recovery and installed image-retention consumers remain. Offline admission-only reducers were removed; native deployment is not yet implemented. |
| Restic runner, bootstrap/init/first-run/qualification helpers and recovery plays | Writer quiescence, interrupted-backup recovery, repository identity, pending-copy retention and retained operation journals remain real dependencies. |
| Proxmox observers, check-evidence, package/reboot/access executors and transports | Surviving maintenance and recovery consumers still use them. Source hash/receipt requirements are unchanged, not waived to admit deletions. |
| Firewall transaction, boot recovery and persistent watchdog | Autonomous rollback must survive controller/network loss; Ansible rescue cannot provide that. |
| Selected `nix/` Python/data, VFIO, bootstrap/session recovery | Installed activators, before-images and emergency protocols still depend on them. Source ownership transfer did not remove installed copies. |
| VM9900 qualification and recovery roots/helpers | Possible live VM, disks, snippets, ACLs, keys and failed-operation state require separately authorized inventory/retirement. |
| JS dependencies and provider locks | Contract/projection/policy consumers still need AJV/js-yaml. Removing reporting does not eliminate Node/Bun dependencies. |

Do not regenerate historical hashes, fabricate receipts, clear journals, stop
watchdogs or erase locks to make the reduced source pass legacy admission. A
persistent lock inode is not necessarily contention; its owner/journal and actual
flock state matter. Deleting an installer does not retire its installed copy.
Unknown operation state requires inspection and a specific recovery decision.

Backup schedule activation still checks the exact Restic restore-proof hash and
terminal Offen receipt. Keep those evidence files and the retirement manifest.
The contract also references `infrastructure/evidence/restic-first-run-aws.json`,
which is excluded locally and untracked: a clean checkout cannot satisfy that
legacy validation dependency. Do not publish it blindly or substitute a fake
proof. Historical source tests are not current backup health.

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
