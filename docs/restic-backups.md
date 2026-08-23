# Restic backup migration

## Current state

The checked-in Restic implementation is **inert**. Offen remains the production backup and AWS recovery resources remain managed. The Restic repository IDs are deliberately `null`, credential bootstrap is disabled, and all Restic timers plus reboot recovery are installed disabled. This state must fail closed rather than initialize a repository, stop a container, authenticate Proton, or create a snapshot during ordinary Ansible convergence.

The final reviewed Offen recovery point remains:

- basename `daily-local-backup-2026-08-21T22-32-08.tar.gz.gpg`;
- 2,319,938,554 bytes;
- SHA-256 `0b46561cf52c15bfababef0f75fe3bbe2cf1f7e1305eb1f7cfe4c1ca0db5c431`;
- replicas under `/mnt/games/backups` and `/mnt/storage/backups`; and
- restore proof through `scripts/run-backup-restore-proof.fish`.

Do not delete either replica until the Proton fresh restore and isolated in-place preservation proofs pass.

## Policy authority

`infrastructure/contract/home-lab.yml` is the single policy authority. `scripts/render-restic-policy.js` deterministically renders `services/data/restic/files-from` and `services/data/restic/excludes`; `scripts/validate-contract` rejects drift and unsafe path relationships. The contract separately records the transitional `legacy_offen` policy.

Path classes have these activation meanings:

- `replace-tree`: the complete managed tree may be activated while its writers are stopped;
- `replace-entries`: only managed staged entries may be activated; excluded transient paths are not a reason to replace the parent;
- `preserve`: existing user data is never mutated by the restore workflow;
- `regenerate`: transient state is cleared before application restart;
- `retain`: operational state remains in place during in-place recovery and is absent on fresh recovery; and
- `external`: readiness remains gated until the independently managed data is mounted or restored.

Nextcloud data remains at `${MEDIA_PATH}/nextcloud/data`. Calibre books and Caro downloads are changed in Compose to `${MEDIA_PATH}/calibre/books` and `${MEDIA_PATH}/caro-tachidesk`. Before deploying that Compose artifact, run the separately approved `ansible/playbooks/migrate-preserved-backup-data.yml`. It verifies capacity, stops only owning services, copies through private NFS staging, verifies complete file hashes/counts/bytes, atomically activates only absent destinations, restarts previously running services, and retains the old sources. Old sources require a later explicit cleanup approval.

## Pinned tools and credentials

The Ansible `restic_backup` role installs official Linux amd64 binaries only:

- Restic 0.19.1 archive SHA-256 `f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c`;
- rclone 1.75.0 archive SHA-256 `aa2804e08f48250e71009c727124b6341cd0288465804a9a09d14663cabafbaa`.

The role verifies archive and installed-binary hashes, exact versions, architecture, ownership, modes, and non-symlink destinations. `restic-proton` has no login shell, home creation, Docker group, sudo, or production-source access. Its service sandbox can read the games repository and write only its native `locks/` directory, replication evidence, and protected rclone state.

Before credential bootstrap can be explicitly enabled, the canonical SOPS dotenv must contain:

- `RESTIC_LOCAL_PASSWORD`;
- `RESTIC_PROTON_PASSWORD`;
- `PROTON_BACKUP_USERNAME`;
- `PROTON_BACKUP_PASSWORD`;
- `PROTON_BACKUP_TOTP_SEED`; and
- optional `PROTON_BACKUP_MAILBOX_PASSWORD` only for two-password mode.

`bootstrap-restic-credentials` receives decrypted dotenv only on standard input under Ansible `no_log`. It writes password files without command-line secrets. It creates an absent rclone config using `rclone obscure -`; on later runs it validates static account/backend options without overwriting rotating fields or cached state. Obscured values remain plaintext-equivalent.

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

## Static validation

```sh
./scripts/render-restic-policy.js --check
./scripts/validate-contract
python3 scripts/test-restic-tools.py
./scripts/test-recovery-tools
docker compose config --no-interpolate --quiet
cd ansible && ansible-playbook -i inventory/infrastructure.yml --syntax-check playbooks/site.yml
```

Run `./scripts/reconcile-infrastructure validate` before review. An Ansible apply, Compose deploy, repository operation, Proton login, restore, or OpenTofu action always requires its separate reviewed approval path.
