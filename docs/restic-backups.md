# Restic backup migration

## Current state

Restic is **active**. The daily and maintenance timers are enabled, active, and non-persistent; interrupted-backup recovery is enabled. The first games → NFS → Proton chain and isolated Proton `restore --verify` proof passed. Offen is fully retired: its Compose definitions and stopped containers are absent, all twelve manifest-bound local archives and eight checksum sidecars were removed, the exact AWS Offen version is absent, and the temporary bucket-wide expiration hold was replaced with multipart-only and expired-marker cleanup. Terminal evidence is `infrastructure/evidence/offen-retirement.json` with SHA-256 `5bd285796ab04d9cc7370768fae2ed284215492c76791cd75b01d22950fde2d0`.

The final retired Offen recovery point was:

- basename `daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg`;
- 2,411,062,883 bytes;
- SHA-256 `8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08`;
- formerly protected replicas under `/mnt/games/backups/.migration-preserved-offen` and `/mnt/storage/backups/.migration-preserved-offen`, now removed by the terminal retirement transaction; and
- successful full-stream restore proof recorded in `infrastructure/evidence/offen-final-archive-2026-08-23-restore-proof.json` (SHA-256 `89712ec78f8724730d2e3eeb07c3929db0b7c2fad7cb30410d517cc115f7eff1`).

The historical proof verified archive integrity, safe paths, all 39 required state classes, absence of all 17 excluded classes, and integrity of all six selected SQLite databases. The 7,019,884,389-byte expanded restore completed in 41 seconds and decrypted staging was removed. Historical archive identities and proof evidence remain committed even though every manifest-bound local copy has been retired.

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
- `PROTON_BACKUP_PASSWORD`; and
- optional `PROTON_BACKUP_MAILBOX_PASSWORD` only for two-password mode.

The two Restic repository passwords must each contain at least 32 UTF-8 bytes and must be distinct. The dedicated password-only Proton login password must contain at least 40 ASCII alphanumeric bytes and differ from both Restic passwords. Credential materialization rejects these conditions before writing any protected target.

`bootstrap-restic-credentials` receives decrypted dotenv only on standard input under Ansible `no_log`. It writes password files without command-line secrets. It creates an absent rclone config using `rclone obscure -`; on later runs it validates static account/backend options without overwriting rotating fields or cached state. Obscured values remain plaintext-equivalent.

Credential bootstrap is governed by `backups.restic.credentials`, not an independent Ansible switch. A reviewed transition may set it to `bootstrap_enabled: true` and `state: provisioned` only while Offen is quiesced, archive preservation and the AWS hold remain applied, and qualification moves from `pending` to `ready` with the SHA-256 of the exact Proton username. The username itself, passwords, mailbox password, and cached client tokens must never be logged or committed.

`qualify-proton-backup` is installed inertly but cannot run while qualification is `pending`. The separately gated `ansible/playbooks/qualify-proton-backup.yml` requires the exact contract confirmation, a complete quiesced audit, exact mounts, absent repository configs, provisioned protected credential files, inactive Restic units, and zero Restic/rclone processes. Under both the production mutation lock and shared backup mutex it removes only rclone’s four cached `client_*` fields, forces password-only reauthentication, proves the exact username hash, verifies at least the contracted decimal 1 TB allocation and a 100 GB free-space reserve, and exercises only `about`, bounded `lsjson`, `copyto`, `cat`, `moveto`, `deletefile`, and `rmdir` against `Backups/.home-lab-rclone-qualification`. Larger future account allocations remain valid. It writes bounded JSON evidence without account names, credentials, tokens, remote listings, or raw provider errors; provider failures retain only the command label, exit status, and stderr SHA-256. Proton Trash is never emptied.

Repository initialization is a separate owner-bound transaction. `initialize-restic-repositories` exposes only `initialize`, `resume`, and `verify`; it never widens the fixed backup-runner subcommands. Both initial and resume playbooks require a fresh exclusive-client confirmation. The helper requires `restic-proton` to remain exact UID/GID `60000` with no supplementary groups, journals before every native `restic init`, initializes games first, then NFS with copied chunker parameters, normalizes only the validated games repository tree, and invokes Proton Restic only through `runuser --user restic-proton`. Immediately before publishing `proton_init_started`, it re-proves that the Proton target is absent. It publishes byte-identical bounded evidence but deliberately retains `operation=restic-repository-initialization` until IDs and evidence are reviewed and committed.

An interruption never deletes a repository. `resume-restic-repository-initialization.yml` requires the exact retained owner SHA-256, journal/source-policy binding, unexpired 365-day retention hold, and fresh exclusive-client confirmation. A valid repository can be adopted only after its durable `*_init_started` marker; a target appearing before that marker, malformed partial data, identity drift, duplicate IDs, or a chunker mismatch fails closed under the retained lock. The journal durably records quota observations and `completed_at` before publication. Complete replay reconstructs identical canonical evidence; an absent result or host copy may be filled, but an existing differing copy is never overwritten. After a clean reviewed commit records all three IDs, source-policy hash, evidence hash, and completion time, `finalize-restic-repository-initialization.yml` converges the ID-bearing policy while the same lock remains held, verifies all repositories, removes only the journal and transient result, and releases only the exact owner-bound lock.

A failed qualification deliberately retains the owner-bearing production lock as operation `proton-qualification`. Do not rerun qualification, remove the lock, delete a remote object, or edit cached fields manually. If a reviewed helper fix is needed while the retained lock prevents ordinary convergence, only the hash-pinned root `supervise-staged-proton-recovery` path may invoke `recover-installed`. The supervisor derives and verifies the exact retained owner hash, requires the transaction-specific staged helper to be root-owned `0755` with the reviewed SHA-256, verifies the protected config and empty cache, acquires the shared mutex through `/usr/bin/flock`, invokes the helper through `runuser` as `restic-proton`, validates the transaction-bound recovery result, checks post-state drift, and removes the staged helper. The helper independently validates the installed helper against the still-installed policy before using the same bounded recovery operations. Inspect the protected host result/evidence paths, rclone config metadata, exact dedicated remote directory, process state, mounts, Offen state, and AWS hold first. Generic rclone deletion, cleanup, purge, sync, bisync, and mount operations remain prohibited.

When a provider failure is reduced to only an opaque stderr hash, use the separate `diagnose-proton-auth.yml` plan before considering another cleanup attempt. It requires the exact retained transaction, inert contract, stopped Offen schedulers, pinned helper/rclone hashes, exact protected mutex/config/evidence-directory metadata, no result or prior evidence, and zero Restic/rclone processes. Its live supervisor acquires the existing backup mutex through root-authorized `/usr/bin/flock`, atomically claims transaction evidence, revalidates the lock owner and full static rclone configuration under the mutex, then performs exactly one non-mutating `lsjson` against `Backups/.home-lab-rclone-qualification` through `runuser` as `restic-proton`. It never releases the production lock:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/diagnose-proton-auth.yml --check --diff \
  -e proton_auth_diagnostic_confirmed=true \
  -e proton_auth_diagnostic_confirmation=diagnose-only-proton-authentication \
  -e proton_auth_diagnostic_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730

# Requires separate authorization after reviewing the fresh plan.
ansible-playbook -i inventory/production.yml playbooks/diagnose-proton-auth.yml \
  -e proton_auth_diagnostic_confirmed=true \
  -e proton_auth_diagnostic_confirmation=diagnose-only-proton-authentication \
  -e proton_auth_diagnostic_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730
```

The controlled categories are `reachable`, `api_captcha`, `invalid_credentials`, `two_factor_rejected`, `account_key_incompatible`, `rate_limited`, `network_failure`, and `rclone_unclassified`. Raw provider output and remote listings remain only in the root supervisor’s memory, are reduced to SHA-256 values, and never reach Ansible output or evidence. The supervisor validates an execution marker created as `restic-proton`, preserves optional mailbox-password mode, requires static config values to remain byte-identical, and permits only an absent or complete four-field rclone `client_*` cache. It atomically replaces the initial `started` marker with redacted `observed` evidence only after revalidating the exact lock owner; interruption or local validation failure leaves the marker to prohibit a second request. Diagnosis performs no remote write, delete, move, cleanup, sync, mount, qualification, recovery, or lock-release operation.

If a reviewed account password rotation must be reconciled while the failed qualification lock is retained, never run the ordinary credential bootstrap or edit `rclone.conf` manually. `rotate-proton-login-credential.yml` requires the exact retained owner hash and immutable authentication-diagnostic evidence hash. It stages only ephemeral encrypted SOPS ciphertext and a hash-pinned supervisor under `/run`; SOPS plaintext flows only through a protected stdin pipe. Under the existing backup mutex it validates the account identity and static config, requires a 40-byte minimum ASCII alphanumeric Proton login password distinct from both Restic passwords, atomically claims rotation evidence, changes only the obscured `password` field, removes only the complete four-field `client_*` cache when present, and proves every other static field is byte-identical. It makes no Proton request and never releases the production lock:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/rotate-proton-login-credential.yml --check --diff \
  -e proton_credential_rotation_confirmed=true \
  -e proton_credential_rotation_confirmation=rotate-only-proton-login-password \
  -e proton_credential_rotation_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_credential_rotation_expected_auth_evidence_sha256=b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed

# Requires separate authorization after reviewing the fresh plan.
ansible-playbook -i inventory/production.yml playbooks/rotate-proton-login-credential.yml \
  -e proton_credential_rotation_confirmed=true \
  -e proton_credential_rotation_confirmation=rotate-only-proton-login-password \
  -e proton_credential_rotation_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_credential_rotation_expected_auth_evidence_sha256=b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed
```

Interruption after the atomic claim leaves `state=started` evidence and prohibits another credential mutation until separately reviewed. Successful rotation retains root-owned `state=rotated` evidence bound to both the original diagnostic and retained transaction. Ordinary task success or failure removes both staged `/run` inputs; controller termination or host failure can leave only the encrypted ciphertext and root-only script until explicit cleanup or reboot clears `/run`.

The dedicated account was changed to permanent password-only authentication after pinned rclone `1.75.0` authenticated successfully with TOTP but failed during Drive/key initialization. This is an explicit availability/security trade-off: Restic still encrypts repository contents, but password-only compromise can threaten remote availability. Recovery codes remain offline. The guarded `transition-proton-password-only.yml` transaction removes only the obsolete `otp_secret_key` from the installed rclone config, requires the client cache to be absent, preserves all other fields and prior evidence, makes zero Proton requests, and retains the failed qualification lock:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/transition-proton-password-only.yml --check --diff \
  -e proton_password_only_confirmed=true \
  -e proton_password_only_confirmation=remove-only-obsolete-proton-totp-field \
  -e proton_password_only_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_password_only_expected_auth_evidence_sha256=b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed \
  -e proton_password_only_expected_rotation_evidence_sha256=8e8f2b932ab436e0fb67eeeecbfd97253cf1ff945d21acd1465119a0d5873249

# Requires separate authorization after reviewing the fresh plan.
ansible-playbook -i inventory/production.yml playbooks/transition-proton-password-only.yml \
  -e proton_password_only_confirmed=true \
  -e proton_password_only_confirmation=remove-only-obsolete-proton-totp-field \
  -e proton_password_only_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_password_only_expected_auth_evidence_sha256=b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed \
  -e proton_password_only_expected_rotation_evidence_sha256=8e8f2b932ab436e0fb67eeeecbfd97253cf1ff945d21acd1465119a0d5873249
```

An interrupted transition leaves only transaction-bound `state=started` evidence. The same reviewed transaction can resume safely whether the config still contains the legacy field or the atomic config replacement already completed; any other evidence/config shape fails closed. A first-use transaction must observe the legacy field before claiming evidence. Ordinary Restic convergence fails before replacing the installed legacy policy, helper, or ciphertext until this dedicated transition succeeds. Ordinary task completion removes the root-only staged supervisor.

After the installed config transition succeeds, the retained production lock prevents ordinary site convergence while recovery still requires the new policy and qualification-helper hash. Use the separate local-only artifact deployment transaction. It accepts only the exact legacy seam or a transaction-claimed mix of exact old/new artifacts, installs only the policy, bootstrap helper, qualification helper, and 93-key encrypted ciphertext, requires credential materialization to be a no-op, writes resumable deployment evidence, makes zero Proton requests, and retains the lock:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/deploy-proton-password-only-artifacts.yml --check --diff \
  -e proton_password_only_deployment_confirmed=true \
  -e proton_password_only_deployment_confirmation=deploy-only-password-only-proton-artifacts \
  -e proton_password_only_deployment_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_password_only_deployment_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c

# Requires separate authorization after reviewing the fresh plan.
ansible-playbook -i inventory/production.yml playbooks/deploy-proton-password-only-artifacts.yml \
  -e proton_password_only_deployment_confirmed=true \
  -e proton_password_only_deployment_confirmation=deploy-only-password-only-proton-artifacts \
  -e proton_password_only_deployment_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_password_only_deployment_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c
```

A `state=started` deployment marker permits exact idempotent artifact reconciliation after interruption; completed `state=deployed` evidence is immutable. This deployment does not authorize transaction recovery, qualification, repository initialization, or timer activation.

The generic `clear-failed-apply-lock.yml` transaction explicitly rejects both `proton-qualification` and `restic-repository-initialization`. After inspection and fresh AWS/access proofs, plan the dedicated recovery transaction with the exact retained lock. Its only live remote mutations are `deletefile` for `fixture.bin` and/or `fixture-renamed.bin` when an exact bounded listing contains no other entry, followed by `rmdir` for the now-empty qualification directory:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/recover-proton-qualification.yml --check --diff \
  -e proton_qualification_recovery_confirmed=true \
  -e proton_qualification_recovery_confirmation=recover-only-proton-qualification-fixtures \
  -e proton_qualification_recovery_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_qualification_recovery_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c \
  -e proton_qualification_recovery_expected_deployment_evidence_sha256=c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230 \
  -e proton_qualification_recovery_expected_account_reset_evidence_sha256=<reviewed-account-reset-evidence-sha256>

ansible-playbook -i inventory/production.yml playbooks/recover-proton-qualification.yml \
  -e proton_qualification_recovery_confirmed=true \
  -e proton_qualification_recovery_confirmation=recover-only-proton-qualification-fixtures \
  -e proton_qualification_recovery_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_qualification_recovery_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c \
  -e proton_qualification_recovery_expected_deployment_evidence_sha256=c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230 \
  -e proton_qualification_recovery_expected_account_reset_evidence_sha256=<reviewed-account-reset-evidence-sha256>
```

The live recovery command requires separate authorization. It rejects unknown files or directories, published qualification evidence, a differing lock owner, stale policy/helper/rclone hashes, unexpected mounts or processes, resumed Offen schedulers, or an expired AWS hold. It hashes the exact retained owner record, passes that transaction SHA-256 to the recovery helper, and retains root-owned redacted evidence at a transaction-specific path containing the same hash before releasing only the exact failed lock. Historical recovery evidence cannot satisfy a newer lock.

If password-only recovery still fails before cleanup, do not replace stable rclone or retry recovery. The final Proton-compatible experiment is `diagnose-proton-beta.yml`. It downloads official beta `1.76.0-beta.10192.6ee1d851e` under executable `/var/tmp` and stages only its root supervisor under noexec `/run`, verifies archive SHA-256 `f37f14b7922280dd5b9352e2d1c3101f94739f57d3786132e517fc106cb4c245` and binary SHA-256 `b64e72891b07b0f55462121090e9e200e8e75c7d0b95530ba9c1f06517daeac5`, supplies the existing password-only remote through process memory with credential caching disabled, and runs exactly one non-mutating `lsjson`. It never replaces `/usr/local/bin/rclone`, writes provider output, mutates the remote, or releases the production lock; all ephemeral files are removed after ordinary task completion:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/diagnose-proton-beta.yml --check --diff \
  -e proton_beta_diagnostic_confirmed=true \
  -e proton_beta_diagnostic_confirmation=diagnose-only-proton-with-official-beta \
  -e proton_beta_diagnostic_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_beta_diagnostic_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c \
  -e proton_beta_diagnostic_expected_deployment_evidence_sha256=c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230

# Requires separate authorization after reviewing the fresh plan.
ansible-playbook -i inventory/production.yml playbooks/diagnose-proton-beta.yml \
  -e proton_beta_diagnostic_confirmed=true \
  -e proton_beta_diagnostic_confirmation=diagnose-only-proton-with-official-beta \
  -e proton_beta_diagnostic_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_beta_diagnostic_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c \
  -e proton_beta_diagnostic_expected_deployment_evidence_sha256=c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230
```

The first execution atomically claims single-use beta evidence before the provider request. `/var/tmp` must be executable, `/run` must remain noexec, and `get_url` temporary data is confined to `/var/tmp`. Both supervisor layers create bounded process groups with TERM/KILL cleanup; the Ansible `always` path independently terminates any process still executing the exact beta binary before deleting ephemeral files. Interruption or local failure after the evidence claim prohibits a second request. A reachable result proves only that the beta can initialize and list the dedicated path; adopting it for recovery or backups remains a separate pinned-version policy decision.

After the beta failed, the disposable password-only Proton account was reset without restoring old encrypted data and its locked Drive was deleted before a new empty Drive was initialized. This operator action is not provider evidence. Before any new provider request, `reconcile-proton-account-reset.yml` must locally reconcile only the installed obscured login password. It binds the exact retained lock, all five immutable prior evidence files, the installed prior SOPS ciphertext, the reviewed target ciphertext, and the exact prior `rclone.conf` hash. In protected `no_log` memory it requires every decrypted SOPS value except `PROTON_BACKUP_PASSWORD` to remain byte-identical, rejects TOTP/mailbox/cache fields, makes zero provider requests, retains the lock, and publishes resumable transaction evidence:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/reconcile-proton-account-reset.yml --check --diff \
  -e proton_account_reset_confirmed=true \
  -e proton_account_reset_confirmation=reconcile-only-password-after-disposable-proton-account-reset \
  -e proton_account_reset_expected_transaction_sha256=ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730 \
  -e proton_account_reset_expected_target_ciphertext_sha256=0021c5d9a9b246d822d6e2e1f460d9f1afc6e6cace25453447c25ac051fbbdbf \
  -e proton_account_reset_expected_prior_config_sha256=40529a3487b54d1412829fe8a0beb433a8e753a90ab2f2b82ab8a7e4ecacc340 \
  -e proton_account_reset_expected_auth_evidence_sha256=b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed \
  -e proton_account_reset_expected_rotation_evidence_sha256=8e8f2b932ab436e0fb67eeeecbfd97253cf1ff945d21acd1465119a0d5873249 \
  -e proton_account_reset_expected_transition_evidence_sha256=1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c \
  -e proton_account_reset_expected_deployment_evidence_sha256=c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230 \
  -e proton_account_reset_expected_beta_evidence_sha256=3329ac4cae644b4b9604ff69bce8a6122ce624eefddcb9c061aa5c78789c816b

# The live command requires separate authorization after a fresh plan and AWS proof.
```

The operation does not install the target canonical SOPS ciphertext; ordinary convergence remains blocked by the retained lock. A `state=started` claim permits only exact-input resume. Successful evidence records the current installed config hash, and subsequent recovery requires both that evidence hash and byte-identical `rclone.conf` before making its bounded request.

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

The only daily timer starts `home-lab-restic-daily.target` at 05:00. The target requires local snapshot/NFS acceptance before the `restic-proton` service can run. There is no independent Proton or weekly timer. The monthly target runs bounded local maintenance before confined Proton maintenance. Both timers are non-persistent so enabling them outside a trigger window cannot immediately replay a missed run; all units remain disabled in inert state. The first chain may be launched only by `run-first-restic-backup.yml`, which starts the daily target exactly once under its owner-bound production transaction. Its resume playbook normally binds the retained owner, journal, policy, and preserved AWS-proof bytes before recreating lost `/run` authorization. If interruption occurred before the first journal, resume instead requires the committed empty baseline in all three repositories and absent acceptance, interruption, result, host-evidence, authorization, and token state; only then may it replay durable host/controller AWS publication, recreate authorization, journal the baseline, and continue. Any snapshot or state mismatch retains the lock. The root local stage inventories and adopts at most one existing NFS mapping, then publishes one owner-and-lock-inode-bound Proton token; the nonroot Proton stage atomically renames, validates, and durably removes it, and exact retry handles interruption after either rename or validation while rejecting a replaced production lock.

Games, NFS, and Proton are independent repositories. Their guarded owner-bound initialization completed with NFS and Proton created from games using `init --from-repo ... --copy-chunker-params`; the full non-secret repository IDs are recorded in the contract. Never copy repository directories with rclone and never use `rclone sync`.

## Restore boundary

`restore-critical-backup` retains the Offen fallback and additionally accepts an exact 64-character Restic snapshot ID. Restic mode requires an empty private `/srv/home-lab-recovery/restic-*` target, the exact repository ID, expected policy hash, and expected Compose artifact hash, then runs native `restic restore <id> --target <target> --verify`. It refuses arbitrary repositories and never restores directly over `/srv/home-lab-state` or uses `restore --delete`.

The contract intentionally advertises only verified staging while migration state is `inert`. Whole-tree and selective in-place activation remain unavailable until implementation plus the isolated Phase 16 fixtures prove preserve/regenerate/retain behavior and rollback. External-data-dependent services must remain `state-restored-user-data-pending`; the old archive activator must never be used on a Restic staging tree.

### Disposable Proton recovery VM

`scripts/prove-restic-recovery-vm` owns the separate local-state transaction for disposable VMID `9900`. Its committed OpenTofu root cannot address VM `100`, production disks, passthrough devices, NFS, or production state. The dedicated plan inspector accepts only the exact VMID `9900` lifecycle; updates, replacements, additional resources, and altered lifecycle, disk, or network values fail closed. The root imports the fixed pre-staged Debian image ID. That image is trusted from its earlier checksum-verified provider download and retained host observation; the final VM plan does not re-download or independently re-hash the image.

Run only from the clean pushed revision used to build bundle B:

```sh
scripts/prove-restic-recovery-vm plan-create
RESTIC_RECOVERY_VM_CONFIRMATION=apply-reviewed-disposable-restic-recovery-vm-9900 scripts/prove-restic-recovery-vm apply-create
RESTIC_RECOVERY_VM_CONFIRMATION=run-reviewed-proton-restore-in-disposable-vm-9900 scripts/prove-restic-recovery-vm run
scripts/prove-restic-recovery-vm plan-destroy
RESTIC_RECOVERY_VM_CONFIRMATION=destroy-reviewed-disposable-restic-recovery-vm-9900 scripts/prove-restic-recovery-vm apply-destroy
```

The controller uses the separately protected unrestricted Proxmox root SSH key only for provider image-import reads and for the exact cloud-init snippet path. It writes the manifest-bound snippet through root SSH/SCP because the `local` datastore does not advertise `snippets`, then removes it after boot. The run transfers only bundle B ciphertext, its independent age identity, the reviewed consumer, the checksum-pinned Linux age binary, and the reviewed activation fixture pair into the VM. Cloud-init installs a transaction-generated deterministic VM SSH host key, root-only recovery access, and a root-only compatibility wrapper for the minimal image; its public-key and cloud-init hashes are manifest-bound, and SSH never learns an arbitrary key. A fresh exact VMID `9900` API configuration is paired with repeated strict host-key and client-key authenticated LAN discovery immediately before transfer. No Proxmox, AWS, SOPS, or production-host credential enters the VM, and decryption occurs only inside it.

The exact serial-bound 128 GiB disk is formatted only after its full-device signatures are absent and bounded first/last/evenly distributed samples prove zero data; a retained filesystem is accepted only after its local preparation checkpoint. No service is started. Process, container-runtime, and container observations bracket native `restic restore --verify`; representative SQLite, PostgreSQL, MariaDB, and configuration state is validated structurally while external user data remains pending. SIGINT and SIGTERM supervise the local and remote restore process groups and run the same mandatory plaintext cleanup path as ordinary failure.

Create and destroy write owner-preserving checkpoints before saved-plan apply. Exact completed state can be adopted after interruption; partial or expired state must be replanned through the same dedicated root and exact inspector. Input credentials and all `bundle.*` plaintext workspaces are removed before evidence is accepted. Destroy remains available after a failed run or partial destroy and must prove VMID `9900` absent and the normalized VM `100` hash unchanged. Retain the transaction directory when any cleanup phase fails.

The live proof completed on 2026-08-26. Bundle A remains in protected local recovery storage; bundle B was published as a new checksum-verified, KMS-encrypted version in protected AWS recovery storage and its local staging ciphertext was removed. The disposable VM restored Proton snapshot `95be7e9b0a03cedd06340fdcf63055c67205c3a6c28687ffd2dc99e733bfa71e` with native `restic restore --verify`: 22,031 files and 6,982,221,998 bytes. Service configuration and database integrity passed, service/process observations stayed at zero, external user data remained explicitly pending, and the isolated activation/rollback fixture passed. Plaintext workspaces were removed and VMID `9900` was destroyed. Evidence is `infrastructure/evidence/restic-restore-proof.json` with SHA-256 `b68550eb34e3c8b3832ae9ddf64857364b54538a719cc9501620cb3fd0735f0f`.

The active schedule transition completed on 2026-08-26. The daily and maintenance timers are enabled, active, non-persistent, and have future trigger times; the conditional interruption-recovery service is enabled and inactive. Runner `status` reports active migration, all repository identities ready, no pending copy, and no interruption. A complete read-only host audit passed with zero changes. There remains no independent Proton timer. Evidence is `infrastructure/evidence/restic-schedule-activation.json` with SHA-256 `7ee44bf6b4ab5e146f820e14212852b2b7788af2432f6021c4df108e38256e72`.

## Live gates not satisfied by Git

Repository validation does not satisfy these operator gates:

1. Proton backend create/read/range-read/move/delete/error-redaction qualification with the exact pinned rclone build.
2. Safe cache invalidation and automatic password-only reauthentication from the dedicated SOPS credential.
3. Empty-path, exact-account, minimum 1 TB allocation, 100 GB free-space reserve, and exclusive-client proof.
4. Repository initialization, copied chunker parameters, and wrong-identity fail-closed tests.
5. Two physically independent recovery bundles, each tested without host tokens.
6. One complete chained migration snapshot and exact NFS/Proton copy proof.
7. Full fresh Proton restore on an isolated recovery system.
8. Isolated in-place preservation and interrupted-activation rollback proof.
9. The approved Offen retirement manifest, followed by its separately reviewed local and two-stage AWS transactions.

No automated workflow may empty Proton Trash. The warning threshold is 100 GB used or ten times active repository size, whichever is greater. New Proton copies hard-fail before their bounded size would reduce free space below the 100 GB reserve; increasing the account allocation does not invalidate qualification or waste the added capacity.

## Failed convergence recovery

A failed `restic_backup` convergence deliberately retains `/var/lib/iac-ansible-production.lock` and its exact owner record. Do not remove it manually or delete repository or retirement artifacts. Inspect the lock as operation `restic_backup`, then plan and separately confirm only its exact clearance:

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/clear-failed-apply-lock.yml --check \
  -e iac_failed_lock_expected_operation=restic_backup
ansible-playbook -i inventory/production.yml playbooks/clear-failed-apply-lock.yml \
  -e iac_failed_lock_expected_operation=restic_backup \
  -e iac_lock_clear_confirmed=true
```

After clearance, rerun check mode and review its complete scope before authorizing the same single-tag convergence. A retirement transaction is different: its operation-specific owner lock must remain until exact R2 evidence authorizes finalize. Generic lock clearance, archive deletion, AWS version deletion, and Proton Trash cleanup are forbidden recovery actions.

## Static validation

```sh
./scripts/render-restic-policy.js --check
./scripts/validate-contract
python3 scripts/test-restic-tools.py
python3 scripts/test-proton-qualification.py
python3 scripts/test-offen-retirement.py
./scripts/test-restic-recovery-bundle
docker compose config --no-interpolate --quiet
cd ansible && ansible-playbook -i inventory/infrastructure.yml --syntax-check playbooks/site.yml
```

Run `./scripts/reconcile-infrastructure validate` before review. An Ansible apply, Compose deploy, repository operation, Proton login, restore, or OpenTofu action always requires its separate reviewed approval path.
