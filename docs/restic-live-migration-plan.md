# Restic live migration plan

## Status and authority

Phases 1–9 are a historical record of the completed Restic migration and activation. Their completed Offen-only helper commands are no longer installed or retained in current source after the reviewed Phase 10 R1 transition; their committed evidence remains immutable.

The policy authority remains `infrastructure/contract/home-lab.yml`. Every live retirement phase requires a clean, reviewed commit; a fresh read-only observation; exact confirmation; bounded postconditions; and retained operation-specific owner locks. Restic repositories, recovery bundles A/B, AWS recovery infrastructure, access recovery, historical evidence, and Proton Trash remain preserved.

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

The exact retention plan `6239f3c0a67c66d2a3b23ca7dfa84853391fca98bf8b5b9d116004925d6684ae` applied the safe-direction 365-day hold, and verification confirmed lifecycle `365/1/1`, versioning enabled, delete-marker cleanup retained, and the same current object. Two separately reviewed read-only IAM plans enabled version listing for both controller roles and the existing protected Offen backup principal without granting object reads. Fresh plan, apply, and backup-principal sessions each observed exactly one current non-delete-marker version for `weekly-backup-2026-08-23T06-00-00.tar.gz.gpg`, 2,399,491,160 bytes, modified `2026-08-23T13:03:53Z`, and independently produced version-ID SHA-256 `3e42bf4017bedaaac231ce234cc8be64536a87da0ba8e401b90967864c73a8c0` without logging the raw ID. The hold is accepted as `applied`, verified at `2026-08-24T16:48:02Z`, with mandatory review deadline `2026-09-23T16:48:02Z`. Offen remains active until a separate reviewed quiescence commit and guarded transition.

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

Rollback requires first inspecting exact partial container/archive/inventory state, then a separately reviewed and pushed commit returning `scheduler_state: active`. If quiescence failed and retained the production ownership lock, check and separately authorize `clear-failed-apply-lock.yml` only for exact operation `offen-scheduler-quiesce` before running the same playbook with `offen_scheduler_action=resume` and confirmation `resume-offen-existing-definitions`. Never remove the lock manually. The resume path deliberately does not require the AWS or full-audit gate so it remains available for partial-transition recovery.

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
- optional `PROTON_BACKUP_MAILBOX_PASSWORD` only for two-password mode.

The two Restic repository passwords must be distinct and at least 32 UTF-8 bytes each. The dedicated password-only Proton login password must contain at least 40 ASCII alphanumeric bytes and differ from both Restic passwords; materialization validates these conditions before writing protected files.

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

It must never use `mount`, `sync`, `bisync`, `cleanup`, or `purge`. It must prove exact account identity, at least the contracted `1,000,000,000,000` decimal bytes, a 100 GB free-space reserve, initial remote path emptiness, reviewed draft-recovery configuration, original file sizes, bounded deletion, redacted errors, safe cache invalidation, and automatic password-only reauthentication. Larger future allocations remain valid. Proton Trash remains manual.

The reviewed credential transition sets `credentials.bootstrap_enabled: true`, credential state `provisioned`, and qualification state `ready`, records only the SHA-256 of the exact decrypted Proton username, and keeps qualification evidence fields `null`. Its SOPS ciphertext and contract change must be committed before a separately authorized credential apply. The transition leaves migration `inert`, all repository IDs `null`, and every Restic unit disabled; it does not authorize a Proton login or qualification.

The account was later changed to an explicitly reviewed permanent password-only mode after pinned rclone authenticated with TOTP but failed during Drive/key initialization. The contract records `proton.authentication_mode: password-only`, the obsolete TOTP seed is absent from SOPS and `credential_refs`, and qualification evidence records `password_reauthentication`. Before another provider request, a separate transaction-bound local-only transition must remove only `otp_secret_key` from the installed config, prove all other static fields unchanged, require no cached client fields, preserve prior diagnostic/rotation evidence, and retain the failed qualification lock.

The tagged check plan intentionally reports only the rendered policy and canonical SOPS ciphertext changes because protected credential materialization is skipped in Ansible check mode. Authorization for the subsequent apply must separately include create-or-update access to `/etc/home-lab/restic/credentials/local-password`, `/etc/home-lab/restic/credentials/proton-password`, and `/var/lib/restic-proton/rclone.conf`. The `no_log` helper receives decrypted values only on standard input, preserves protected ownership and modes, and uses local `rclone obscure`; this deferred materialization does not perform a Proton login or any remote operation.

Run and review the exact single-tag credential plan before separately authorizing its apply:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/site.yml --check --diff \
  --tags restic_backup \
  -e iac_apply_confirmed=true \
  -e iac_apply_tag=restic_backup \
  -e ssh_access_proven=true

ansible-playbook -i inventory/production.yml playbooks/site.yml \
  --tags restic_backup \
  -e iac_apply_confirmed=true \
  -e iac_apply_tag=restic_backup \
  -e ssh_access_proven=true
```

After a zero-change credential postcheck, fresh access proofs, fresh AWS version evidence, and confirmation that Offen remains stopped, review the guarded qualification plan. The live command requires a second separate authorization:

```sh
ansible-playbook -i inventory/production.yml playbooks/qualify-proton-backup.yml --check --diff \
  -e proton_qualification_confirmed=true \
  -e proton_qualification_confirmation=qualify-proton-bounded-operations

ansible-playbook -i inventory/production.yml playbooks/qualify-proton-backup.yml \
  -e proton_qualification_confirmed=true \
  -e proton_qualification_confirmation=qualify-proton-bounded-operations
```

A successful run fetches only bounded redacted JSON to `infrastructure/evidence/proton-qualification.json`. The evidence schema, helper SHA-256, exact account hash, quota, operation list, fixture parameters, and timestamp must validate before a reviewed commit can move qualification state to `qualified`. Pending and ready states reject a committed evidence file.

A failure retains the exact `operation=proton-qualification` lock. The generic failed-lock clearer rejects this operation. If no result or published evidence exists, use only the separately authorized `recover-proton-qualification.yml` transaction after inspecting protected state, exact remote entries, processes, mounts, Offen, AWS hold, and recovery access. It refuses unknown remote entries and can delete only the two fixed fixture names before removing the empty dedicated directory.

If qualification or recovery was interrupted after atomic result creation or evidence publication, use only `resume-proton-qualification.yml` with its exact `qualification` or `recovery` attestation. It validates one surviving evidence source or byte-identical retained copies, proves the remote qualification directory absent, completes only missing publication/fetch, removes only the validated transient result, and releases the exact lock. Never clear the lock merely to retry.

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

The implemented `initialize-restic-repositories` helper exposes only `initialize`, `resume`, and `verify`. `initialize-restic-repositories.yml` requires the exact initialization and exclusive-client confirmations, exact installed policy/helper/binary hashes, qualified evidence, fresh destinations, quiesced Offen, current AWS hold, and inactive units. It retains `operation=restic-repository-initialization` after success. The helper owns the shared backup mutex, writes and fsyncs a durable marker before each native init, initializes games and NFS as root, safely normalizes the games tree, and runs Proton Restic only via `runuser --user restic-proton`. Raw provider output is never exposed.

Read each full ID and chunker polynomial with `restic cat config`. Require three distinct 64-character IDs and equal chunker polynomials. Commit the fetched bounded evidence together with the IDs, exact source-policy hash, evidence hash, and completion time. Then use `finalize-restic-repository-initialization.yml` from that exact clean reviewed commit. It converges the ID-bearing policy and normalizes permissions while the retained owner-bound lock still exists, verifies the three exact IDs/common polynomial, removes only transient journal/result files, and releases only the matching lock.

Repository initialization is not rolled back by deletion. On failure, keep all units disabled and preserve every created repository. Only `resume-restic-repository-initialization.yml` may adopt a repository, and only when the exact retained owner, source-policy hash, and durable pre-init marker bind it. A partial tree without a valid config or a repository appearing before its marker remains preserved and fails closed for separate review. Generic failed-lock clearance rejects this operation.

## Phase 7 — create the first chained recovery point through an exact gate

Keep timers disabled. Publish the exact active Compose artifact hash, then use the implemented guarded first-run playbook—not an ad-hoc runner or `systemctl` command:

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

Set the controller-only `restic_first_run_sops_binary`, `restic_first_run_aws_binary`, and `restic_first_run_age_key_file` inputs to reviewed hash-pinned, single-link, root-owned, non-writable tools and the protected age key for each check, live, resume, and finalize invocation. The playbook holds `operation=restic-first-run`, obtains a fresh bounded repository-backed AWS proof without persisting plaintext credentials, invokes `/usr/local/libexec/home-lab/restic-backup preflight`, starts exactly `home-lab-restic-daily.target`, captures exact journal/evidence identities, and leaves both timers disabled. The fixed-subcommand runner accepts that deploy lock only when exact owner bytes, policy/artifact/runner hashes, repository IDs, journal stage, and next command bind the transaction; every other deploy lock remains rejected.

Acceptance requires:

1. one exact games snapshot while declared writers were stopped;
2. all previously running writers restarted and healthy;
3. one exact NFS copied snapshot whose `original` points to the games snapshot;
4. one exact Proton copied snapshot whose `original` points to the games snapshot;
5. accepted evidence containing exact policy/artifact hashes and snapshot IDs;
6. `restic check` on all repositories;
7. retention dry-run and actual behavior preserving pending evidence; and
8. Proton quota/headroom evidence.

An NFS or Proton failure does not invalidate the committed games snapshot. The durable first-run journal checkpoints writer stops/restarts, the committed games ID, NFS acceptance, Proton acceptance, checks, retention, and quota. `resume-first-restic-backup.yml` adopts only the exact post-baseline chain under the retained owner lock and never creates a second games snapshot after `games_committed`. The sole pre-journal exception requires all three repositories to equal the committed empty baseline with no acceptance, interruption, result, host-evidence, authorization, or token state; it can replay interrupted AWS host/controller publication and then creates the owner-bound baseline journal. Any nonempty or mismatched state stays locked. After evidence is committed, `finalize-first-restic-backup.yml` runs no-lock/no-cache repository verification against the pending completed policy even in check mode, removes only transient first-run state outside check mode, re-audits protections, and releases only the exact owner-bound lock outside check mode.

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

Offen retirement is governed by `infrastructure/retirement/offen-retirement-manifest.json`. The operator accepted the completed first Restic chain and isolated Proton restore proof as the retirement gate, explicitly waiving scheduled daily history. R1 removes the Offen Compose source definitions but leaves the two stopped materialized containers and all twelve exact local archive files and eight checksum sidecars intact until the dedicated transaction.

The local `plan`, `apply`, and `resume` actions require the exact manifest-bound confirmation through `ansible/playbooks/retire-offen-local.yml`. Apply renames the exact stopped containers and atomically renames all twelve archives and eight bound checksum sidecars to transaction tombstones under the shared backup mutex. It deliberately retains its production owner lock; resume, rollback, and finalize adopt that exact owner by SHA-256 instead of reacquiring it. Rollback revalidates the saved action plan, transaction owner, exact container IDs, and every tombstone and is permitted only before irreversible unlink begins. Irreversible finalize requires schema-valid committed evidence whose phase is `retirement-finalizing`, the authoritative journaled `apply_complete`, exact saved owner/action-plan hashes, and all twenty tombstones. It journals before every removal, adopts only identity-verified response-loss states, and publishes a terminal local result with manifest-derived counts only after every exact file, container, protected directory, and Offen image is absent.

The AWS half temporarily grants `s3:DeleteObjectVersion` only on the committed Offen object key while retirement is `retirement-planned`. The normal hash-bound saved-plan controller derives `grant` from that state and derives `finalize` only from the separately committed `retirement-finalizing` state; no environment switch can disable or select the specialized inspection. The inspector verifies the complete shared recovery IAM policy, exact recovery-bucket/KMS relationships, and exact lifecycle rule shapes—including the absence of unreviewed filters, transitions, and alternate expirations—before plan acceptance and again before apply. `scripts/retire-offen-aws-object` privately selects the single exact version by its committed SHA-256, requires the exact live `/var/lib/iac-ansible-production.lock/owner` bytes, binds bundle-B key/version/size to committed restore evidence, and re-proves unchanged encrypted bundle metadata after deletion. The finalizing transition removes the temporary delete authorization and bucket-wide current/noncurrent expiration while retaining one-day multipart cleanup and expired-delete-marker cleanup. The bucket, KMS key, versioning, IAM recovery identity, canonical AWS SOPS values, encrypted bundles A/B, shared SOPS-recovery public key, Restic repositories and timers, historical evidence, and Proton Trash remain preserved.

No ordinary Compose, Ansible, or OpenTofu convergence may unlink archives or delete an AWS version. R1 must be reviewed, committed, and pushed before any live action. Live R1 stages local tombstones, applies the temporary grant, and deletes only the exact Offen version. R2 then commits the non-terminal `retirement-finalizing` contract, applies its separately reviewed final AWS lifecycle plan, and commits schema-valid finalizing evidence before local irreversible finalize. R3 commits schema-validated terminal evidence binding the production lock owner, both transaction owners, both journals, saved-plan hashes, unchanged bundle-B metadata, and the terminal local result. `finalize-offen-retirement.yml` revalidates terminal absence and every local binding before releasing the exact production owner and local transaction; the AWS helper independently schema-validates and binds that same committed evidence before releasing its transaction.

Phase 10 completed on 2026-08-26. R1 staged and published the isolated 40-service Compose artifact, tombstoned every exact local Offen file, granted exact-version deletion temporarily, deleted the exact AWS Offen version, and preserved bundle B. R2 removed the temporary deletion grant and bucket-wide current/noncurrent expiration, retained one-day multipart cleanup and expired-marker cleanup, and bound committed finalizing evidence. R3 irreversibly removed the local tombstones, stopped containers, protected directories, and Offen image, committed terminal evidence, and released the exact production lock. After terminal revalidation, the local/AWS transaction executors, recovery preflight, temporary plan normalizer/inspector, dedicated playbooks, tests, installed host helper, and temporary IAM delete grant were retired. The immutable manifest, terminal contract/evidence, retained journals, Restic recovery bundles A/B, shared SOPS recovery, AWS recovery infrastructure, Restic repositories/timers, and Proton Trash remain.

## Global stop conditions

Stop immediately on mount identity drift, an active backup process, an absent/shortened AWS retention hold outside the exact finalizing transition, unrecognized repository content, repository-ID/chunker mismatch, missing or exposed credentials, Proton allocation below the minimum or free space below the reserve, non-redacted errors, incomplete snapshot exit status, unhealthy writers, stale deployment locks, differing repeated plans, unexpected Compose service state, restore verification failure, or any Offen/AWS deletion outside the exact reviewed retirement manifest.

## Documentation references

- Restic repository initialization and copy guidance: <https://github.com/restic/restic/blob/master/doc/045_working_with_repos.md>
- Restic repository configuration inspection: <https://github.com/restic/restic/blob/master/doc/view_repository.rst>
- rclone Proton Drive backend documentation: <https://github.com/rclone/rclone/blob/master/docs/content/protondrive.md>
- rclone manual: <https://github.com/rclone/rclone/blob/master/MANUAL.md>
