# Outstanding migrations

This file records unresolved live predicates, not completed actions. Observe every
condition again before deciding whether work remains.

## Restic runtime policy normalization

The installed policy and runner now contain only recurring backup and recovery
behavior. First-run, initialization and qualification compatibility was removed in a
coordinated rollout under the production and backup locks, and terminal host evidence
was removed. The runner retains only the consistency adapter that pauses and recovers
Compose writers. Restic directly creates the local snapshot, copies it to NFS and
Proton, and performs monthly forget, prune and data checks; no parallel replication
queue or custom retention planner remains. Backup admission requires a complete chain
bound to the exact current policy and Compose artifact.

The native role validates the adopted files and interruption journal, then converges
reviewed policy, runner and tool pins while the production lock excludes backup
writers. Use `site.yml` or `configure-backups.yml`; do not copy runtime files
independently.

The simplified workflow was qualified live with idempotent convergence, a fresh
local → NFS → Proton chain bound to the current policy and Compose artifact, and a
verified private `identity` restore. The restore workspace and obsolete accepted and
maintenance replication state were removed after verification.

## Legacy AWS recovery-stack retirement

Desired state: recurring managed Restic backups remain local → NFS → Proton. The
AWS recovery bucket is not a Restic destination. The `aws-foundation` root still
owns a separate versioned bucket, recovery KMS key and alias, and IAM recovery
principal. Treat these as retained recovery material, not disposable drift, until
an independent owner completes the gates below. Use the separate
[owner cutover plan](aws-recovery-retirement.md) for the exact ordering and
state-tracking boundary; it is not authorization to perform the cutover. This retirement is separate from
Proxmox firewall adoption. An owner may explicitly retain the **unchanged** legacy
AWS resources during firewall adoption: privately verify the temporary foundation
inputs against tracked state and live provider, reconcile only reviewed identity
tracking, and require a no-op foundation plan. This is not renewed approval for an
S3 Restic writer, broader access, or deletion. Return to the retirement gates once
firewall adoption is complete.

1. Reobserve the current Restic chain and AWS recovery resources. Privately inspect
   **all** bucket versions, delete markers, multipart uploads, retention controls,
   bucket policy, both the managed recovery IAM user **and** the independently
   supplied backup principal, and KMS dependencies. That principal may have an
   active credential and wildcard permissions outside this bucket. Identify its
   consumers first: IAM's last-used service does not attribute S3 activity to a
   bucket, and absent object audit events or key-ID matches on managed hosts
   cannot prove there are no stale writers behind the same network egress. An
   NFS export exposes shared data, not the NAS's local jobs or credential store.
   Do not disable or delete that external principal or credential as an
   incidental effect of the bucket teardown. Handle its access through a
   separately approved owner cutover, retaining the inactive credential for
   rollback until the recovery KMS key is finally deleted. An object-free
   listing, absent keys on only one user, or Proton backup alone does not prove
   safe deletion. Keep filenames, versions, policy documents and receipts
   out of Git.
2. Determine which encrypted recovery-bundle versions must be retained. Confirm
   independent custody of the selected encrypted bundle and its age decryption
   identity, then qualify a private restore on a disposable recovery host using
   fresh repository and snapshot identities. Do not retire the only usable copy.
3. Design a separate owner-reviewed AWS decommission with explicit rollback and
   ordering: freeze and verify writes to the recovery bucket without revoking an
   external principal used elsewhere, resolve recovery-only access, dispose of
   every approved bucket version only after custody is verified, and retire KMS
   **last** so retained copies remain decryptable. Both bucket and key have
   `prevent_destroy`; do not remove those safeguards to force an OpenTofu apply.
   The controller plan gate forbids IAM identity mutation or drift. Use a bounded
   independent-owner procedure and separately reviewed state reconciliation;
   if its attached policy is broad, replace it only through a separate reviewed
   access migration that preserves other consumers; remove obsolete recovery-only
   grants after attribution. Guard against stale clients writing to a reused
   bucket name. Never target around refusals or abandon resources silently in
   remote state.
4. Prepare the removal of the bucket and configuration, bucket policy, KMS key
   and alias, managed recovery user and inline policy, protected recovery
   inputs/outputs, and recovery references in controller IAM policies as a
   separately reviewed source migration. Retain the transitional recovery
   provider alias until externally retired resources are reconciled out of
   remote state. Inspect the exact identity and
   state-tracking changes with the independent owner; retain the active state
   bucket, its KMS key, and the firewall state-key grants. Require fresh provider
   observations and a no-op `aws-foundation` plan before firewall adoption, even
   if retirement is temporarily deferred. The firewall root must not treat
   legacy recovery values as an approved new backup design or bypass its
   foundation no-op prerequisite.

## Recovery activation

Desired state: a complete production restore has a reviewed activation and rollback
procedure.

Current supported scope stops at verified private staging. Qualification must begin
from newly discovered repository and snapshot identities and must not reuse stored
observations from an earlier attempt.

## Controller artifact retirement

Ignored controller state was retired after refreshing every active remote-backed
OpenTofu root, observing host owners and journals, resolving historical provider
identities, proving recovery resources absent, and confirming independent custody of
the encrypted recovery bundle and decryption identity.

Repeat those live checks before deleting future `.local/`, `.reconcile/`, saved plans
or obsolete local state. Migrate or retire any live identity first, and preserve any
ambiguous or nonterminal operation until live inspection resolves it.
