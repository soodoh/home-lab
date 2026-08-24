# Restic backup migration

## Current state

The checked-in Restic implementation is **inert**. Offen’s two scheduler containers are quiesced but remain defined, both protected Offen archive generations remain intact, and the AWS recovery hold remains managed at 365-day current-object retention. Restic repository IDs are deliberately `null`, credential provisioning is contract-backed, Proton qualification is `ready` but has not run, and all Restic timers plus reboot recovery remain disabled. This state does not authorize a Proton login, qualification, repository initialization, or snapshot.

The final accepted Offen recovery point is:

- basename `daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg`;
- 2,411,062,883 bytes;
- SHA-256 `8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08`;
- protected replicas under `/mnt/games/backups/.migration-preserved-offen` and `/mnt/storage/backups/.migration-preserved-offen`; and
- successful full-stream restore proof recorded in `infrastructure/evidence/offen-final-archive-2026-08-23-restore-proof.json` (SHA-256 `89712ec78f8724730d2e3eeb07c3929db0b7c2fad7cb30410d517cc115f7eff1`).

The proof verified archive integrity, safe paths, all 39 required state classes, absence of all 17 excluded classes, and integrity of all six selected SQLite databases. The 7,019,884,389-byte expanded restore completed in 41 seconds and decrypted staging was removed. Both the 2026-08-21 historical fallback and 2026-08-23 final archive are independently copied and verified under each protected directory; their original top-level copies also remained exact at acceptance.

## Policy authority

`infrastructure/contract/home-lab.yml` is the single policy authority. `scripts/render-restic-policy.js` deterministically renders `services/data/restic/files-from` and `services/data/restic/excludes`; `scripts/validate-contract` rejects drift and unsafe path relationships. The contract separately records the transitional `legacy_offen` policy.

Path classes have these activation meanings:

- `replace-tree`: the complete managed tree may be activated while its writers are stopped;
- `replace-entries`: only managed staged entries may be activated; excluded transient paths are not a reason to replace the parent;
- `preserve`: existing user data is never mutated by the restore workflow;
- `regenerate`: transient state is cleared before application restart;
- `retain`: operational state remains in place during in-place recovery and is absent on fresh recovery; and
- `external`: readiness remains gated until the independently managed data is mounted or restored.

Nextcloud data remains at `${MEDIA_PATH}/nextcloud/data`. The active Compose artifact uses `${MEDIA_PATH}/calibre/books` and `${MEDIA_PATH}/caro-tachidesk` for Calibre books and Caro downloads. The guarded preserved-data migration verified capacity, copied through private NFS staging, verified complete file hashes/counts/bytes, atomically activated only absent destinations, restarted previously running services, and retained the old source trees. Old sources require a later explicit cleanup approval.

## Pinned tools and credentials

The Ansible `restic_backup` role installs official Linux amd64 binaries only:

- Restic 0.19.1 archive SHA-256 `f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c`;
- rclone 1.75.0 archive SHA-256 `aa2804e08f48250e71009c727124b6341cd0288465804a9a09d14663cabafbaa`.

The role verifies archive and installed-binary hashes, exact versions, architecture, ownership, modes, and non-symlink destinations. `restic-proton` has no login shell, home creation, Docker group, sudo, or production-source access. Its service sandbox can read the games repository and write only its native `locks/` directory, replication evidence, and protected rclone state.

`restic-proton` is fixed at UID/GID `60000`; automatic system-account allocation is forbidden. The first inert deployment auto-selected UID `999`, which aliased 504 pre-existing Nextcloud Redis/MariaDB state entries even though numeric ownership never changed. The deployment was therefore held after audit. UID/GID `60000` was verified absent from the local root filesystem, `/srv/home-lab-state`, and `/mnt/games` before selection. Ordinary convergence now rejects a conflicting account/group or matching ownership in protected local source trees, and the audit proves the exact numeric identity and absence of source-tree aliases. `/mnt/storage` remains inaccessible to the confined service and is not recursively scanned during routine convergence.

Check mode reports the account/group change but cannot resolve all ownership updates against the future name mapping. The reviewed live remediation also reassigns `/var/lib/restic-proton` and its empty cache from UID `999`/GID `989` to `60000`, changes group ownership on the managed Restic directories and generated files from `989` to `60000`, and reconciles `/run/lock/home-lab-backup.lock` to root:`60000`. These mutations are confined to inert Restic artifacts. The 504 protected source entries retain numeric UID `999`; neither repository, credential, runner, unit activation, Offen, nor application state is mutated.

Before credential bootstrap can be explicitly enabled, the canonical SOPS dotenv must contain:

- `RESTIC_LOCAL_PASSWORD`;
- `RESTIC_PROTON_PASSWORD`;
- `PROTON_BACKUP_USERNAME`;
- `PROTON_BACKUP_PASSWORD`;
- `PROTON_BACKUP_TOTP_SEED`; and
- optional `PROTON_BACKUP_MAILBOX_PASSWORD` only for two-password mode.

`bootstrap-restic-credentials` receives decrypted dotenv only on standard input under Ansible `no_log`. It writes password files without command-line secrets. It creates an absent rclone config using `rclone obscure -`; on later runs it validates static account/backend options without overwriting rotating fields or cached state. Obscured values remain plaintext-equivalent.

Credential bootstrap is governed by `backups.restic.credentials`, not an independent Ansible switch. A reviewed transition may set it to `bootstrap_enabled: true` and `state: provisioned` only while Offen is quiesced, archive preservation and the AWS hold remain applied, and qualification moves from `pending` to `ready` with the SHA-256 of the exact Proton username. The username itself, passwords, TOTP seed, mailbox password, and cached client tokens must never be logged or committed.

`qualify-proton-backup` is installed inertly but cannot run while qualification is `pending`. The separately gated `ansible/playbooks/qualify-proton-backup.yml` requires the exact contract confirmation, a complete quiesced audit, exact mounts, absent repository configs, provisioned protected credential files, inactive Restic units, and zero Restic/rclone processes. Under both the production mutation lock and shared backup mutex it removes only rclone’s four cached `client_*` fields, forces password-plus-TOTP reauthentication, proves the exact username hash and decimal 1 TB quota, and exercises only `about`, bounded `lsjson`, `copyto`, `cat`, `moveto`, `deletefile`, and `rmdir` against `Backups/.home-lab-rclone-qualification`. It writes bounded JSON evidence without account names, credentials, tokens, remote listings, or raw provider errors; provider failures retain only the command label, exit status, and stderr SHA-256. Proton Trash is never emptied.

A failed qualification deliberately retains the owner-bearing production lock as operation `proton-qualification`. Do not rerun qualification, remove the lock, delete a remote object, or edit cached fields manually. Inspect the protected host result/evidence paths, rclone config metadata, exact dedicated remote directory, process state, mounts, Offen state, and AWS hold first. Generic rclone deletion, cleanup, purge, sync, bisync, and mount operations remain prohibited.

The generic `clear-failed-apply-lock.yml` transaction explicitly rejects `proton-qualification`. After inspection and fresh AWS/access proofs, plan the dedicated recovery transaction with the exact retained lock. Its only live remote mutations are `deletefile` for `fixture.bin` and/or `fixture-renamed.bin` when an exact bounded listing contains no other entry, followed by `rmdir` for the now-empty qualification directory:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/recover-proton-qualification.yml --check --diff \
  -e proton_qualification_recovery_confirmed=true \
  -e proton_qualification_recovery_confirmation=recover-only-proton-qualification-fixtures

ansible-playbook -i inventory/production.yml playbooks/recover-proton-qualification.yml \
  -e proton_qualification_recovery_confirmed=true \
  -e proton_qualification_recovery_confirmation=recover-only-proton-qualification-fixtures
```

The live recovery command requires separate authorization. It rejects unknown files or directories, published qualification evidence, a differing lock owner, stale policy/helper/rclone hashes, unexpected mounts or processes, resumed Offen schedulers, or an expired AWS hold. It hashes the exact retained owner record, passes that transaction SHA-256 to the recovery helper, and retains root-owned redacted evidence at a transaction-specific path containing the same hash before releasing only the exact failed lock. Historical recovery evidence cannot satisfy a newer lock.

If qualification or its exact recovery was interrupted after the helper atomically wrote a valid transient result—or after host/controller evidence publication—the cleanup playbook intentionally refuses it. Use the separate resume/attestation transaction instead. It accepts either byte-identical transient and published evidence or one surviving validated copy, proves the dedicated remote directory is absent through the pinned helper, completes only missing evidence publication/fetch, removes only the validated transient result, and releases the exact retained lock:

```sh
ansible-playbook -i inventory/production.yml playbooks/resume-proton-qualification.yml --check --diff \
  -e proton_qualification_resume_action=qualification \
  -e proton_qualification_resume_confirmed=true \
  -e proton_qualification_resume_confirmation=attest-interrupted-proton-qualification

# Use action=recovery and confirmation=attest-interrupted-proton-recovery
# only for a validated interrupted exact-fixture recovery.
```

The corresponding live resume command requires separate authorization. A differing result/evidence pair, wrong evidence type, non-absent remote directory, stale artifact, or unexpected recovery/qualification evidence fails closed and retains the lock.

## Units and runner

One fixed-subcommand runner accepts only `preflight`, `daily-local`, `daily-proton`, `maintenance`, and `status`. It never invokes `rclone sync`, mounts, purge, cleanup, or account-wide deletion. It treats every nonzero Restic status as failure and specifically rejects backup exit code 3.

The only daily timer starts `home-lab-restic-daily.target` at 05:00. The target requires local snapshot/NFS acceptance before the `restic-proton` service can run. There is no independent Proton or weekly timer. The monthly target runs bounded local maintenance before confined Proton maintenance. Both timers are non-persistent so enabling them outside a trigger window cannot immediately replay a missed run; all units remain disabled in inert state.

Repository initialization is a later operator-approved operation. Games, NFS, and Proton are independent repositories; NFS and Proton must be initialized from games using `init --from-repo ... --copy-chunker-params`. Record the full non-secret repository IDs in the contract before any runner mutation can pass preflight. Never copy repository directories with rclone and never use `rclone sync`.

## Restore boundary

`restore-critical-backup` retains the Offen fallback and additionally accepts an exact 64-character Restic snapshot ID. Restic mode requires an empty private `/srv/home-lab-recovery/restic-*` target, the exact repository ID, expected policy hash, and expected Compose artifact hash, then runs native `restic restore <id> --target <target> --verify`. It refuses arbitrary repositories and never restores directly over `/srv/home-lab-state` or uses `restore --delete`.

The contract intentionally advertises only verified staging while migration state is `inert`. Whole-tree and selective in-place activation remain unavailable until implementation plus the isolated Phase 16 fixtures prove preserve/regenerate/retain behavior and rollback. External-data-dependent services must remain `state-restored-user-data-pending`; the old archive activator must never be used on a Restic staging tree.

## Live gates not satisfied by Git

Repository validation does not satisfy these operator gates:

1. Proton backend create/read/range-read/move/delete-draft/error-redaction qualification with the exact pinned rclone build.
2. Safe invalidation and automatic reauthentication from SOPS password plus TOTP seed.
3. Empty-path, exact-account, 1 TB quota, and exclusive-client proof.
4. Repository initialization, copied chunker parameters, and wrong-identity fail-closed tests.
5. Two physically independent recovery bundles, each tested without host tokens.
6. One complete chained migration snapshot and exact NFS/Proton copy proof.
7. Full fresh Proton restore on an isolated recovery system.
8. Isolated in-place preservation and interrupted-activation rollback proof.
9. A separately approved Offen retirement manifest and later two-stage AWS retirement transaction.

No automated workflow may empty Proton Trash. The warning threshold is 100 GB used or ten times active repository size, whichever is greater; new Proton copies hard-fail before 900 GB used while local backups remain available.

## Inert deployment failure recovery

A failed `restic_backup` convergence deliberately retains `/var/lib/iac-ansible-production.lock` and its exact owner record. Do not remove the directory manually and do not delete partially installed inert artifacts. First prove that no `restic` or `rclone` process exists, both Offen schedulers remain defined and match the committed scheduler state, the games and NFS mount identities remain exact, repository `config` files match the contract, credential and qualification paths match the committed credential state, and every installed Restic unit is inactive and disabled or static. Inspect the lock as operation `restic_backup`, then plan and separately confirm only its exact clearance:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/clear-failed-apply-lock.yml --check \
  -e iac_failed_lock_expected_operation=restic_backup
ansible-playbook -i inventory/production.yml playbooks/clear-failed-apply-lock.yml \
  -e iac_failed_lock_expected_operation=restic_backup \
  -e iac_lock_clear_confirmed=true
```

After clearance, rerun check mode and review its complete scope before separately authorizing the same single-tag idempotent convergence. Lock acquisition prepares an exact owner-bearing directory off-path and atomically publishes it under the shared backup mutex; interruption cannot create an ownerless blocking lock. Successful release and failed-lock clearance revalidate and atomically detach that exact directory under the same mutex before cleanup. Recovery from a partial inert deployment is forward convergence—not repository initialization or artifact deletion. Postconditions require pinned binary hashes and versions, safe fixed ancestors, no cleartext credentials, absent repository configs, zero Restic/rclone processes, all nine units inactive and disabled/static, Offen unchanged, the production lock absent, and a complete read-only audit no-op.

## Static validation

```sh
./scripts/render-restic-policy.js --check
./scripts/validate-contract
python3 scripts/test-restic-tools.py
python3 scripts/test-proton-qualification.py
./scripts/test-recovery-tools
docker compose config --no-interpolate --quiet
cd ansible && ansible-playbook -i inventory/infrastructure.yml --syntax-check playbooks/site.yml
```

Run `./scripts/reconcile-infrastructure validate` before review. An Ansible apply, Compose deploy, repository operation, Proton login, restore, or OpenTofu action always requires its separate reviewed approval path.
