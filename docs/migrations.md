# Outstanding migrations

This file records unresolved live predicates, not completed actions. Observe every
condition again before deciding whether work remains.

## Authentik PostgreSQL rollback retirement

Desired state: PostgreSQL 18 is healthy and the PostgreSQL 16 rollback generation is
removed only after rollback is no longer required.

Observe:

- the active database image, mount and `PG_VERSION`;
- Authentik server, worker and Redis health;
- admin and representative protected-application authentication;
- current database/application logs without printing private values;
- a fresh Restic snapshot containing the active database and a successful isolated
  restore.

Until all checks pass in one reviewed window, retain the old cluster and independent
rollback material. Never start PostgreSQL 16 against the PostgreSQL 18 directory.
Cleanup requires an exact live path inventory and separate authorization.

## Nextcloud recovery and old application copies

Desired state: current database, config, custom apps and themes are restorable through
the generic `nextcloud` recovery group; superseded application copies are then
removed. External user data remains independently managed.

Observe:

- `occ status --output=json`, cron PID 1 and current mounts;
- login, WebDAV, representative read and upload behavior;
- a fresh isolated restore of the `nextcloud` group;
- current external-data identity and representative hashes without mounting it into
  the restore target.

`/mnt/storage/media/nextcloud/data` is outside Restic and outside automated cleanup.
Any old-path deletion requires a fresh exact-path allowlist that excludes user data.

## Calibre NFS generation

Desired state: `/srv/home-lab-state/calibre-data/books` remains the active library and
the older NFS generation has an explicit retain-or-delete decision.

Observe both generations live, verify the active library through a fresh snapshot and
isolated restore, then prepare an exact private disposition list. Never treat the NFS
copy as a current mirror or replay an old synchronization command.

## Proxmox VM disk ownership

Desired state: the production OpenTofu root and remote state fully express the VM's
current managed disks without changing existing bus addresses or importing an
unexplained disk.

Observe the live VM configuration, remote state and a fresh provider plan together.
The source contains an intentional list-position tombstone; remove or reorder it only
as part of an explicit provider/state migration.

## Restic runtime policy normalization

The installed policy and runner now contain only recurring backup and recovery
behavior. First-run, initialization and qualification compatibility was removed in a
coordinated rollout under the production and backup locks, and terminal host evidence
was removed. Backup admission now requires a complete chain bound to the exact current
policy and Compose artifact.

The native role permits same-content adoption only and requires the installed policy
to match reviewed source exactly. Future runner or policy changes require another
coordinated rollout; do not bypass the guard by changing an installed hash or copying
a new runner independently.

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
