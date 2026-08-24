# Restic live migration plan

## Status and authority

This is a **non-mutating operator plan**. No production backup schedule, credential, repository, container, systemd unit, Proton object, restore target, or AWS resource was changed while preparing it.

The policy authority remains `infrastructure/contract/home-lab.yml`. Every live phase requires a clean, reviewed commit; a fresh read-only observation; exact confirmation; bounded postconditions; and a separately approved rollback. Offen definitions, both known-good archive replicas, and AWS recovery resources remain intact until all Restic restore proofs pass.

## Read-only observation — 2026-08-23T18:00:23Z

- Host: `docker-host`, Linux `x86_64`.
- Games mount: `/mnt/games`, `/dev/sdb1`, `ext4`, UUID `31602ce7-0054-498a-9f24-f51ca491e7b3`.
- NFS mount: `/mnt/storage`, `192.168.0.123:/storage/docker`, `nfs4`.
- `daily-local-backup` and `weekly-remote-backup` are both running with restart policy `unless-stopped`.
- Restic and rclone processes, binaries, repositories, units, users, credentials, and state directories are absent.
- Calibre, Calibre Web Automated, Bookshelf, and Caro Tachidesk are running on their legacy mounts.
- Preserved source bytes:
  - Calibre books: `8,004,780,051`;
  - Caro downloads: `9,516,160,589`;
  - total: `17,521,940,640`.
- NFS free bytes: `23,398,108,364,800`.
- New preserved-data destinations and both private staging paths are absent.
- The two reviewed 2026-08-21 Offen archive replicas still have the contract size and mode.
- A newer unreviewed archive now exists on both replicas:
  - basename `daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg`;
  - bytes `2,411,062,883`;
  - actual SHA-256 on both replicas `8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08`;
  - its manifests agree, but no restore proof was run during planning.
- The five required Restic/Proton key names are absent from `secrets/production.sops.env`.
- The Tailscale drift was traced to a Tailscale-managed automatic update at `2026-08-23T05:25:10Z` from `1.98.4` to `1.102.3`. The live client and daemon hashes exactly match Tailscale’s official `1.102.3` amd64 archive (archive SHA-256 `36ddd9b51be57ffc2990cf76323cfa13643bfbb1b8a969f6183fa164741cdef5`). The contract adopts those binaries but requires automatic update application disabled; run the separately guarded no-restart preference reconciliation and require a complete audit no-op before further migration mutation.
- A read-only Restic-role Ansible check predicts ten changed tasks and no host failures after the local readiness fixes described below.

## Blocking repository work before any live mutation

Do not stop Offen yet. Complete and review these repository gates first:

1. Commit the local readiness fixes discovered by the live check:
   - use Python standard-library `bz2`/`zipfile` extraction because production lacks `/usr/bin/bzip2` and `/usr/bin/unzip`;
   - hide the canonical SOPS ciphertext task from Ansible diff output; and
   - include `restic_backup` in steady Debian convergence.
2. Parameterize `scripts/run-backup-restore-proof.fish`, prove the 2026-08-23 archive, and update the contract/docs only from successful evidence.
3. Add a contract-backed Offen scheduler transition and guarded quiesce playbook. Health and audit currently require all 42 Compose services to be running, so stopping the two Offen containers now would make convergence fail. The transition must require:
   - 42 declared services and containers;
   - exactly 40 running services;
   - exactly the two declared Offen services stopped;
   - both Compose definitions retained; and
   - both reviewed archive replicas unchanged.
4. Add a reviewed AWS migration retention hold before stopping weekly Offen uploads. The current lifecycle expires current recovery objects after 14 days; the hold must extend current-object retention to at least 365 days, bind the migration to a 30-day completion/review deadline, and prove the exact current object remains recoverable before quiescence.
5. Add an `active` Restic transition. The current role intentionally disables every Restic unit regardless of repository readiness; enabling timers or reboot recovery must be a separate reviewed change after restore proofs.
6. Add guarded Proton qualification and native repository-initialization tooling. Do not improvise account or repository mutation from an interactive shell.
7. Add an exact-confirmation first-run playbook that invokes `/usr/local/libexec/home-lab/restic-backup preflight` and starts the daily target under the production mutation lock.
8. Implement the two independent recovery bundles and isolated in-place activation fixtures before advertising in-place recovery.
9. Reconcile the Tailscale version drift through its normal reviewed infrastructure path and require a complete audit no-op before qualifying or quiescing Offen.

After each repository change:

```sh
./scripts/reconcile-infrastructure validate
git diff --check
git status --short
```

Commit only a clean, reviewed result before proceeding.

## Phase 1 — qualify the final Offen recovery point

1. Reobserve that no Offen backup process is currently active.
2. Run the parameterized restore proof against the newest exact archive from one replica.

```sh
./scripts/run-backup-restore-proof.fish \
  --archive /mnt/storage/backups/daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg \
  --sha256 8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08 \
  --bytes 2411062883
```
3. Verify ciphertext size and SHA-256 against both replicas after the proof.
4. Record restore evidence, exact basename, bytes, SHA-256, verifier identity, start/end time, and cleanup proof.
5. Update `backups.legacy_offen.final_archive` and commit.

Fail closed if either replica, manifest, ciphertext hash, restore pipeline, decrypted cleanup, or durable preservation differs. Phase 1 is accepted: the 2026-08-23 full-stream verifier processed 22,877 members and 7,019,884,389 uncompressed bytes; all required, excluded, safe-path, archive, and selected SQLite checks passed; decrypted cleanup passed; and both original replicas were rehashed. The proof ran from `2026-08-23T12:16:17Z` through `2026-08-23T12:16:58Z` with verifier SHA-256 `e78f1f009d89af872fe2d48b2f091597c66a309f657842f1e522c221f643ac5c`. Evidence is `infrastructure/evidence/offen-final-archive-2026-08-23-restore-proof.json` with SHA-256 `89712ec78f8724730d2e3eeb07c3929db0b7c2fad7cb30410d517cc115f7eff1`. At `2026-08-23T19:51:45Z`, both the 2026-08-21 fallback and 2026-08-23 final archive had exact independent copies under each root’s `.migration-preserved-offen` directory, outside Offen’s active top-level seven-day pruning.

The preservation operation exposed and repaired two fail-closed lock-cleanup defects before final acceptance: shell-PID identity was replaced with exact process discovery, then the shared `/tmp` PID-file collision was replaced with container-scoped files. After each failed attempt, the sole exact remaining lock holder was inspected and removed, both schedulers were verified back to their single `backup` process, and the exact failed production lock was cleared through `clear-failed-apply-lock.yml`. The final idempotent retry reported `created=0 copies=4`, released both internal locks, verified both scheduler process inventories, and released the production mutation lock.

### AWS retention hold required before quiescence

Weekly Offen uploads currently replenish the AWS recovery object, while the active lifecycle expires current objects after 14 days. Before Phase 2, first merge a `planned` contract transition that extends current-object expiration to at least 365 days while Offen remains `active`. Produce and review an exact saved OpenTofu plan whose only AWS recovery change is the retention extension, apply it through the existing locked plan/apply transaction, then verify the bucket lifecycle and exact current recovery object/version. Commit the resulting plan hash, version-ID hash, verification time, 30-day review deadline, and `state: applied`; only then may a separate reviewed commit set `scheduler_state: quiesced`. Do not stop Offen if the hold or object proof is absent. Do not shorten or remove this hold until Phase 8 evidence is accepted through a later saved plan.

Read-only pre-plan observation confirmed bucket versioning `Enabled`, current-object expiration `14` days, noncurrent expiration `1` day, incomplete multipart abort `1` day, and exactly one current object: `weekly-backup-2026-08-23T06-00-00.tar.gz.gpg`, 2,399,491,160 bytes, modified `2026-08-23T13:03:53Z`, storage class `STANDARD`. The plan identity can list current objects but is intentionally denied `s3:ListBucketVersions`; therefore the planned contract keeps recovery version evidence `null`, and transition to `applied` remains blocked until separately approved post-apply version proof.

## Phase 2 — stop Offen schedules without deleting definitions

After the AWS retention hold and exact recovery-object proof pass, commit `scheduler_state: quiesced`, reconcile the Tailscale drift, and require a complete source-state audit. Export `AWS_HOLD_PLAN_SHA256` and `RECOVERY_OBJECT_VERSION_ID_SHA256` from the exact reviewed contract evidence, then use the guarded quiesce playbook—not ad-hoc `docker stop`:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/quiesce-offen-backups.yml \
  --check --diff \
  -e offen_scheduler_action=quiesce \
  -e offen_scheduler_transition_confirmed=true \
  -e "offen_scheduler_expected_aws_hold_plan_sha256=$AWS_HOLD_PLAN_SHA256" \
  -e "offen_scheduler_expected_recovery_object_version_id_sha256=$RECOVERY_OBJECT_VERSION_ID_SHA256" \
  -e offen_scheduler_transition_confirmation=stop-offen-keep-definitions-and-archives

ansible-playbook -i inventory/production.yml playbooks/quiesce-offen-backups.yml \
  -e offen_scheduler_action=quiesce \
  -e offen_scheduler_transition_confirmed=true \
  -e "offen_scheduler_expected_aws_hold_plan_sha256=$AWS_HOLD_PLAN_SHA256" \
  -e "offen_scheduler_expected_recovery_object_version_id_sha256=$RECOVERY_OBJECT_VERSION_ID_SHA256" \
  -e offen_scheduler_transition_confirmation=stop-offen-keep-definitions-and-archives
```

Rollback requires a separately reviewed commit returning `scheduler_state: active`, followed by the same playbook with `offen_scheduler_action=resume` and confirmation `resume-offen-existing-definitions`. The resume path deliberately does not require the AWS or full-audit gate so it remains available for partial-transition recovery.

Required postconditions:

- both Offen containers exist but report `running=false`;
- no Restic or rclone process is active;
- Compose still declares 42 services;
- health/audit accepts only those two stopped services;
- both final archive hashes remain exact; and
- no file under either backup root is deleted.

Rollback before Restic activation: use the guarded inverse transition to start exactly those two existing containers, then verify all 42 services and the archive hashes.

## Phase 3 — deploy the inert Restic foundation

Keep repository IDs `null`, credential bootstrap `false`, and migration state `inert`.

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/site.yml \
  --check --diff --tags restic_backup

ansible-playbook -i inventory/production.yml playbooks/site.yml \
  --tags restic_backup \
  -e iac_apply_confirmed=true \
  -e iac_apply_tag=restic_backup

ansible-playbook -i inventory/production.yml playbooks/site.yml \
  --check --diff --tags restic_backup
```

The second check must be a no-op. Verify pinned binary hashes/versions, exact mount identities, protected ownership/modes, no repositories, no credentials, and every Restic unit stopped/disabled. `/usr/local/libexec/home-lab/restic-backup preflight` is expected to fail closed on uninitialized repository IDs.

Rollback means preservation, not removal: keep all Restic artifacts installed but inert, verify every unit stopped/disabled, leave credentials absent and repositories uninitialized, and restart Offen only through its guarded inverse transition. No inert teardown exists; removing binaries, users, units, or directories requires a separately implemented and reviewed teardown.

## Phase 4 — migrate preserved data, then deploy the Compose artifact

Reconfirm source/destination identities and capacity. The guarded playbook retains legacy sources.

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/migrate-preserved-backup-data.yml \
  --check --diff \
  -e preserved_data_migration_confirmed=true \
  -e preserved_data_migration_confirmation=migrate-preserved-data-keep-old-sources

ansible-playbook -i inventory/production.yml playbooks/migrate-preserved-backup-data.yml \
  -e preserved_data_migration_confirmed=true \
  -e preserved_data_migration_confirmation=migrate-preserved-data-keep-old-sources
```

Require exact hashes, counts, bytes, metadata dry-run, fresh NFS identity checks, healthy restarted owners, absent staging markers, and untouched old sources.

Then use the existing staged Compose deployment transaction: generate one exact artifact, stage it, run two reproducible `deploy-compose.yml --check --diff` plans, apply the accepted hash, and require the postcheck to be a no-op. Do not use broad `docker compose up -d`.

Postconditions:

- Calibre, Calibre Web Automated, and Bookshelf mount `/mnt/storage/media/calibre/books`;
- Caro mounts `/mnt/storage/media/caro-tachidesk` at its downloads subpath;
- owner services are healthy;
- Offen remains stopped but declared; and
- legacy source trees remain untouched.

Rollback: run the exact previous-artifact `rollback-compose.yml` transaction and verify the services again use the retained legacy source trees. Do not delete the new NFS copies during rollback.

## Phase 5 — provision credentials and qualify Proton

The operator must add these values through SOPS without exposing them in Git, shell history, arguments, or logs:

- `RESTIC_LOCAL_PASSWORD`;
- `RESTIC_PROTON_PASSWORD`;
- `PROTON_BACKUP_USERNAME`;
- `PROTON_BACKUP_PASSWORD`;
- `PROTON_BACKUP_TOTP_SEED`;
- optional `PROTON_BACKUP_MAILBOX_PASSWORD` only for two-password mode.

Enable credential bootstrap in a reviewed commit, rerun only the `restic_backup` tag, and verify protected files. Units remain disabled.

The guarded qualification tool must use the pinned rclone build and a unique dedicated path. It may use only bounded operations equivalent to:

```text
about --json
copyto <one random local fixture> <dedicated qualification object>
cat <that exact object> --offset <n> --count <n>
moveto <that exact object> <one exact renamed object>
deletefile <that exact renamed object>
rmdir <the now-empty dedicated qualification directory>
```

It must never use `mount`, `sync`, `bisync`, `cleanup`, or `purge`. It must prove exact account identity, `1,000,000,000,000` allocated bytes, initial remote path emptiness, expected draft replacement behavior, original file sizes, bounded deletion, redacted errors, safe cache invalidation, and automatic password+TOTP reauthentication. Proton Trash remains manual.

## Phase 6 — initialize three native Restic repositories

After Proton qualification and an exclusive-client attestation, initialize games first. Initialize NFS and Proton from games with native Restic `init --from-repo ... --copy-chunker-params`. Use protected environment files; never put passwords on command lines and never mirror repository bytes with rclone.

Conceptual command shapes for the guarded tool:

```sh
RESTIC_PASSWORD_FILE=/etc/home-lab/restic/credentials/local-password \
restic -r /mnt/games/restic/home-lab init

RESTIC_FROM_REPOSITORY=/mnt/games/restic/home-lab \
RESTIC_FROM_PASSWORD_FILE=/etc/home-lab/restic/credentials/local-password \
RESTIC_PASSWORD_FILE=/etc/home-lab/restic/credentials/local-password \
restic -r /mnt/storage/restic/home-lab init \
  --from-repo /mnt/games/restic/home-lab --copy-chunker-params

RESTIC_FROM_REPOSITORY=/mnt/games/restic/home-lab \
RESTIC_FROM_PASSWORD_FILE=/etc/home-lab/restic/credentials/local-password \
RESTIC_PASSWORD_FILE=/etc/home-lab/restic/credentials/proton-password \
RCLONE_CONFIG=/var/lib/restic-proton/rclone.conf \
restic -r rclone:proton-backup:Backups/home-lab-restic init \
  --from-repo /mnt/games/restic/home-lab --copy-chunker-params
```

The actual guarded tool must also set each destination password file, verify empty destinations, reject symlinks/hard links, fsync local evidence, and stop on any nonzero status.

Read each full ID and chunker polynomial with `restic cat config`. Require three distinct 64-character IDs and equal chunker polynomials. Record the IDs in the contract immediately, commit, rerun the inert role to normalize games-repository permissions, and require exact wrong-ID failures before any snapshot.

Repository initialization is not rolled back by deletion. On failure, keep all units disabled, preserve every created repository for forensic review, and restart Offen only through the scheduler rollback transition.

## Phase 7 — create the first chained recovery point through an exact gate

Keep timers disabled. Publish the exact active Compose artifact hash, then use the future guarded first-run playbook—not an ad-hoc runner or `systemctl` command:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/run-first-restic-backup.yml \
  --check --diff \
  -e restic_first_run_confirmed=true \
  -e restic_first_run_confirmation=run-one-reviewed-games-nfs-proton-chain

ansible-playbook -i inventory/production.yml playbooks/run-first-restic-backup.yml \
  -e restic_first_run_confirmed=true \
  -e restic_first_run_confirmation=run-one-reviewed-games-nfs-proton-chain
```

The playbook must hold the production mutation lock, invoke `/usr/local/libexec/home-lab/restic-backup preflight`, start exactly `home-lab-restic-daily.target`, capture exact journal/evidence identities, and leave both timers disabled.

Acceptance requires:

1. one exact games snapshot while declared writers were stopped;
2. all previously running writers restarted and healthy;
3. one exact NFS copied snapshot whose `original` points to the games snapshot;
4. one exact Proton copied snapshot whose `original` points to the games snapshot;
5. accepted evidence containing exact policy/artifact hashes and snapshot IDs;
6. `restic check` on all repositories;
7. retention dry-run and actual behavior preserving pending evidence; and
8. Proton quota/headroom evidence.

An NFS or Proton failure must not invalidate the committed games snapshot. Keep timers disabled and process only validated pending evidence on retry.

## Phase 8 — recovery bundles and restore proofs

Create two physically independent, encrypted recovery bundles containing only the minimum repository locators, passwords, pinned binaries/hashes, policy/artifact identities, and instructions. Test each without host tokens.

Then perform:

1. a full fresh restore from Proton on an isolated recovery system using one exact snapshot ID and `restic restore <id> --target <private-target> --verify`;
2. service-level validation with external data explicitly pending;
3. isolated in-place preserve/regenerate/retain fixtures; and
4. interrupted-activation rollback proof.

No restore target may be production. A failed proof leaves Offen archives, stopped Offen definitions, and AWS recovery resources intact.

## Phase 9 — activate schedules

Only after every Phase 8 proof passes, merge the reviewed `active` transition. It must enable only:

- `home-lab-restic-daily.timer`;
- `home-lab-restic-maintenance.timer`; and
- `home-lab-restic-recover.service`.

There is no independent Proton timer. Verify non-persistent timers, the next trigger times, one manual status run, and an audit no-op. Keep Offen stopped but defined, and retain both final Offen archive replicas.

## Phase 10 — later retirement

Offen definitions/archive cleanup and AWS retirement are separate changes. They require a reviewed retirement manifest, completed Restic restore evidence, explicit archive-retention approval, and a two-stage AWS plan/apply transaction. The temporary AWS retention hold may be shortened or removed only in that later transaction. No migration phase may empty Proton Trash.

## Global stop conditions

Stop immediately on mount identity drift, an active backup process, an absent/shortened AWS retention hold, unrecognized repository content, repository-ID/chunker mismatch, missing or exposed credentials, Proton quota mismatch, non-redacted errors, incomplete snapshot exit status, unhealthy writers, stale deployment locks, differing repeated plans, unexpected Compose service state, restore verification failure, or any proposal to delete Offen/AWS recovery data.

## Documentation references

- Restic repository initialization and copy guidance: <https://github.com/restic/restic/blob/master/doc/045_working_with_repos.md>
- Restic repository configuration inspection: <https://github.com/restic/restic/blob/master/doc/view_repository.rst>
- rclone Proton Drive backend documentation: <https://github.com/rclone/rclone/blob/master/docs/content/protondrive.md>
- rclone manual: <https://github.com/rclone/rclone/blob/master/MANUAL.md>
