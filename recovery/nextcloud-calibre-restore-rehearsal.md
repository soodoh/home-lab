# Nextcloud and Calibre restore rehearsal

## Purpose and boundary

This plan proves that one **new natural Restic daily snapshot** can be restored into
private staging with native `restic restore --verify`, and that the restored
Nextcloud application state and Calibre library are structurally usable for migration
retirement review. It does not activate services, overwrite production, delete old
paths, test Nextcloud login/WebDAV/upload, or authorize removal of recovery source.

Use the local games repository for this rehearsal. It avoids Proton/rclone
credentials and proves the original snapshot before replication. Do not substitute
the retained September 18 snapshot: it predates the current active Compose marker and
the latest observed Calibre library state, so it cannot close the current retirement
gate.

The execution requires separate operational approval. This document is a plan only.

## Required fresh evidence

Before approval, create and review one new secret-free passive observation for a
naturally completed daily chain. Do not trigger a backup merely to satisfy this plan.
The evidence must establish:

- no production apply owner, backup interruption journal, pending replication, or
  active backup/restore process;
- all backup writer units loaded, successful and inactive;
- original snapshot age below 24 hours and `cadence=daily`;
- policy SHA-256
  `81b1f0dd0f1a2fd596c13ee3b6a79e7bb181ae5d0b80e3e942ab69f96d77a6ff`;
- either the active artifact tag or a retained predecessor whose exact
  Nextcloud/Calibre service files, runtime environment and scoped image locks are
  proven equal to the active artifact;
- games repository ID
  `b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f`;
- one exact new 64-hex games snapshot ID, copied ancestry through NFS and Proton,
  and zero pending copies.

Record the reviewed observation path and SHA-256 in the execution authorization.
Never infer the snapshot from `latest` during execution. The September 19
[admission observation](../infrastructure/evidence/restic-restore-rehearsal-admission-2026-09-19.json)
is accepted for this narrow rehearsal: its exact prior artifact is retained, and the
relevant Compose files, runtime environment and scoped image locks are equal to the
active artifact. This exception does not admit unrelated services or arbitrary prior
artifacts.

## Fixed execution inputs

| Input | Required value |
| --- | --- |
| Repository | `/mnt/games/restic/home-lab` |
| Repository ID | `b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f` |
| Policy SHA-256 | `81b1f0dd0f1a2fd596c13ee3b6a79e7bb181ae5d0b80e3e942ab69f96d77a6ff` |
| Snapshot artifact SHA-256 | `2f12e384fdc0ce759d23b0bd9e16ad402d3ecd2985b4ecdfe048127f1c5748be` |
| Active equivalent artifact SHA-256 | `3e5600bfa5ff9441d729e4e81634854435cea13f15568337adbc87911468569e` |
| Restic binary SHA-256 | `20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639` |
| Restore helper | `scripts/restore-critical-backup` from the reviewed clean commit |
| Target | `/srv/home-lab-recovery/restic-migration-retirement` |
| Snapshot | `abbf7d3543bb031ab80d97b69dde24de3b8c1a23ad47e4bb8c471a8dbbde128f` |
| Password file | Existing reviewed games-repository password file; never print or copy it into Git |

The target parent must be a real root-owned mode-0700 or mode-0750 directory. The
target must be newly created, root-owned, mode 0700, non-symlink and empty. Refuse an
existing proof lock. Confirm available space against the selected snapshot before
creating the target.

## Reviewed execution shape

Run on the production credential host as root from the exact clean reviewed commit.
Supply protected values without shell tracing or command-line secret values:

```sh
export RECOVERY_TARGET=/srv/home-lab-recovery/restic-migration-retirement
export RECOVERY_RESTIC_REPOSITORY=/mnt/games/restic/home-lab
export RECOVERY_RESTIC_PASSWORD_FILE=<reviewed-root-only-password-file>
export RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID=b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f
export RECOVERY_EXPECTED_POLICY_SHA256=81b1f0dd0f1a2fd596c13ee3b6a79e7bb181ae5d0b80e3e942ab69f96d77a6ff
export RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256=2f12e384fdc0ce759d23b0bd9e16ad402d3ecd2985b4ecdfe048127f1c5748be
export RECOVERY_EXPECTED_RESTIC_SHA256=20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639
scripts/restore-critical-backup \
  --restic-snapshot-id abbf7d3543bb031ab80d97b69dde24de3b8c1a23ad47e4bb8c471a8dbbde128f \
  --confirmed-empty-target
```

The helper must verify repository identity, exact snapshot identity and tags, pinned
binary identity, target isolation and password-file metadata before running
`restic restore --verify`. Any nonzero result leaves production untouched and blocks
retirement. Preserve the staging target and proof output for diagnosis; cleanup is a
separate reviewed action.

## Staging validation

Perform validation only below the canonical staging target. Never follow a symlink
out of it and never start restored services.

### Calibre

Require these restored paths:

- `srv/home-lab-state/calibre-data/config`;
- `srv/home-lab-state/calibre-data/plugins`;
- `srv/home-lab-state/calibre-data/books`;
- `srv/home-lab-state/calibre-data/books/metadata.db`;
- `srv/home-lab-state/calibre-web-data`.

Record only file count, logical bytes and a manifest SHA-256 derived from sorted
relative path, type and size records. Open restored `metadata.db` read-only and
require `PRAGMA integrity_check` to return exactly `ok`. Compare those path/type/size
records to an exact `restic ls --json` listing for the selected snapshot; rely on the
successful `restic restore --verify` result for restored-content verification. Do not
compare the snapshot to the live library, which can legitimately receive writes after
the snapshot.

### Nextcloud

Require restored local state:

- `srv/home-lab-state/nextcloud-db-data`;
- `srv/home-lab-state/nextcloud-config`;
- `srv/home-lab-state/nextcloud-custom-apps`;
- `srv/home-lab-state/nextcloud-themes`.

Record bounded counts and manifest hashes without printing configuration contents,
usernames, file names or database values. Confirm the restored MariaDB tree contains
its expected engine metadata and is non-empty, but do not start MariaDB or claim
logical database integrity from file presence alone.

The external tree `/mnt/storage/media/nextcloud/data` is deliberately outside this
restore target. Verify the rehearsal neither creates a staged substitute nor changes
the live external tree's device/inode identity.

## Acceptance and remaining blockers

A successful rehearsal proves native extraction and byte verification of the selected
backup generation. It is sufficient supporting evidence to delete the obsolete
Calibre NFS-to-local reconciliation code after a separate source-retirement review.
It does **not** by itself retire Nextcloud rollback or old paths. Nextcloud still
requires:

- isolated MariaDB/application recovery or another reviewed database-integrity proof;
- login, representative listing/read, WebDAV and reversible upload acceptance;
- explicit rollback retirement and old-path cleanup decisions.

Record only snapshot/repository/policy/artifact identities, target identity, counts,
hashes, SQLite result and the helper's bounded success line. Never commit credentials,
restored plaintext or a rendered Compose configuration.

## Recorded outcome — September 19, 2026

The authorized rehearsal completed with native byte verification at the fixed target.
Both application manifest comparisons passed, Calibre `metadata.db` passed read-only
integrity checking, expected MariaDB engine metadata was present, and all current live
Calibre path/size records were represented in the snapshot. Production container and
external Nextcloud data identities remained unchanged. See the
[secret-free outcome evidence](../infrastructure/evidence/restic-restore-rehearsal-2026-09-19.json).

The target remains private and retained for review. It consumes approximately 19.35
GB and must not be activated, treated as a fresh-server rebuild, passed to the older
archive activator, or deleted without a separate decision.
