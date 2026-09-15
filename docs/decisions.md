# Decisions and deliberate exceptions

## Approved direction

Manage existing infrastructure with native OpenTofu, hosts with standard
SSH/Ansible become, and applications with Compose. Adopt the existing server
before expanding rebuild coverage. Keep high-risk storage, access, firewall,
reboot, database migration and recovery operations explicit and separate.
This supersedes the old controller/admission ADRs. There is no requirement to
finish their deferred successor before simplifying unrelated source.

The first pass removes universal launchers, abandoned Compose admission and
source-only LiteLLM deployment machinery, advisory reporting workflows/platform,
inert experiments/proposals and completed one-shot handoff/incident entrypoints.
Published history remains in Git; abandoned unpublished work is not archived.
No new universal manifest, launcher or qualification platform replaces it.

## First native adoption

On September 14, ordinary SSH/become over existing Tailscale access was verified
on both hosts without changing accounts/keys. `observe-hosts.yml` is read-only.
The operator then approved `update-policy.yml`: disable Debian unattended package
installation and Proxmox Tailscale auto-apply while retaining update checks. Apply
changed exactly those two settings; a second run changed nothing.

This native play now owns those settings independently of the legacy contract.
The older unattended-retirement planner (which disables apt timers/list updates)
and cloud-init automatic-install defaults are superseded for the existing hosts.
Do not run them to undo the adopted policy. No general host convergence, package
upgrade, service restart, reboot, firewall or data migration was authorized by
this narrow change. Legacy source can be removed as its remaining consumers retire.

The confined Proton maintenance unit was also adopted through native
`configure-backups.yml` on September 14 after a reproduced `mount_identity` failure.
It uses the daily unit's read-only temporary games filesystem and repository-only
binds. The approved apply changed only that unit and reloaded systemd definitions;
no maintenance was started, no repository was modified and no timer was reconfigured.
The runner and its mount/UUID validation remain unchanged. Linux mount probes and
an unchanged second Ansible run prove this narrow fix, not full maintenance success.

The subsequent source-only consolidation expands `configure-backups.yml` to all
nine existing unit definitions, sharing render-only tasks with legacy convergence.
Native host variables own these unit inputs; the deprecated contract retains
transitional duplicate values for legacy/recovery consumers through
`restic_systemd_legacy_contract`. Local before/after rendering proves current byte
parity, not a permanent requirement to match the old contract or receipt hashes.
The historical single-unit post-NFS recovery repair still uses that bridge without
expanding its repair scope. No active-state or boot-enable management is adopted.
Independent review passed; a live check-mode preview reported zero changes, so no
expanded apply was performed. This is configuration parity, not backup bootstrap.

The next slice adds the same pinned Restic/rclone tools to that native play.
Independent review and the combined live preview passed with zero changes; no
installation, download or reload was needed or performed. Native variables own pins;
a no-log comparison with only the installed runtime policy's tools prevents
incompatible replacement. No policy is installed or rewritten. Native and legacy
callers share one installer, but legacy exact contract guards remain at their
original entrypoint. Versions, runner, unit templates, credentials and activation
are unchanged. Future tool upgrades need coordinated runtime-policy changes and
Proton qualification, not independent automated pin bumps or receipt regeneration.

The confined service account is also adopted: an existing `restic-proton` UID/GID
60000 is required before shared core account declarations. Source review passed,
and the combined live preview changed nothing; no account apply was performed.
Missing or renumbered identities are not repaired implicitly. Human access, home
creation/movement and recursive data ownership remain outside this slice. See
[account validation status](operations.md#confined-backup-account).

The September 15 (PDT) runtime-file slice passed source review and a zero-change
full live preview; no apply was performed. It shares copy declarations with legacy main,
preserving its inputs → policy → runner → remaining helpers order and safeguards.
Native adoption refuses missing/unsafe files and all content drift before those
copies; it may maintain metadata only when source bytes and installed policy agree.
Policy/scope ownership and retained-journal reconciliation are not migrated. Future
content rollout requires coordinated policy/journal review; no backup-health claim
or activation authority follows. See [runtime-file limits](operations.md#same-content-backup-runtime-files).

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
