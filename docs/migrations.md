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
