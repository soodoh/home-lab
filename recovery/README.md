# Recovery

Recovery begins with live repository discovery and ends at a verified private staging
directory. Production activation is not yet qualified.

## Scope

[`groups.json`](groups.json) maps named service groups to managed paths. The common
protected Compose environment is included in every scope. The `nextcloud` group does
not include external user data at `/mnt/storage/media/nextcloud/data`; recover and
validate that storage independently.

Validate the resolver and recovery tools locally:

```sh
scripts/test-recovery-tools
```

## 1. Observe current repositories

From a fresh reviewed checkout:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-backups.yml
```

The observer refuses active owners, opens each live repository and reports current
repository IDs, policy/artifact identities and latest snapshots. Select one chain
from this output. Do not use a snapshot ID copied from Git history or a previous run.

Before restoring, independently confirm:

- the selected snapshot's `policy=` and `artifact=` tags;
- Proton copied-snapshot ancestry where Proton is the source;
- tool checksums against the current reviewed host variables;
- the target is a new empty root-owned directory directly below
  `/srv/home-lab-recovery`.

## 2. Stage a restore

[`scripts/restore-critical-backup`](../scripts/restore-critical-backup) accepts either
`--all` or one or more `--recovery-group NAME` arguments plus the exact
`--restic-snapshot-id`. It requires protected environment bindings for the repository,
password file, repository ID, policy/artifact identities and tool checksums.

Example shape, with values supplied from the current observation through a private
environment rather than shell history:

```sh
RECOVERY_TARGET=/srv/home-lab-recovery/restic-<reviewed-name> \
RECOVERY_RESTIC_REPOSITORY=<live-repository> \
RECOVERY_RESTIC_PASSWORD_FILE=<protected-file> \
RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID=<live-id> \
RECOVERY_EXPECTED_POLICY_SHA256=<live-policy> \
RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256=<live-artifact> \
RECOVERY_EXPECTED_RESTIC_SHA256=<reviewed-tool-digest> \
  scripts/restore-critical-backup \
    --restic-snapshot-id <live-snapshot-id> \
    --recovery-group identity \
    --confirmed-empty-target
```

Proton additionally requires the current protected rclone configuration or the
explicit recovery-only `RCLONE_CONFIG_PROTON_BACKUP_*` environment and current rclone
digest. The helper validates repository identity, snapshot identity, copied ancestry,
tags, target ownership and restored data before success.

Keep the restore private. Inspect application paths, database integrity and
representative content without printing private filenames or values.

## 3. Optional encrypted recovery bundle

[`scripts/build-restic-recovery-bundle`](../scripts/build-restic-recovery-bundle)
builds one deterministic plaintext archive and encrypts it directly to an age
recipient. Its metadata is a current observation projection with exactly:

- version and repository path;
- current repository and snapshot IDs;
- original snapshot ID for a copied Proton snapshot;
- current policy and Compose artifact digests;
- current Restic, rclone and restore-runner digests.

Historical receipt or qualification hashes are intentionally absent. Build metadata
in a mode-0600 file inside a new mode-0700 temporary directory, using the current live
observation. Supply bundle credentials only through the documented
`RECOVERY_BUNDLE_*` environment. Store the encrypted result and its age identity in
independent protected locations; neither belongs in Git.

[`scripts/run-restic-recovery-bundle`](../scripts/run-restic-recovery-bundle) is for a
fresh disposable recovery VM. It refuses host tokens and host recovery state,
verifies every member and binding, and stages the selected groups into the fixed
private target.

## Interruption and cleanup

A recovery lock or workspace on a managed host remains authoritative while the
operation is incomplete or ambiguous. Inspect and resolve it on that host. Do not
replace it with a controller-side receipt.

After a verified terminal run, remove plaintext credentials, decrypted bundles and
temporary workspaces. Retain only independently protected recovery material required
for the next disaster. Logs and Git history provide historical context; no outcome
file is committed.

## Production activation

A Git revert followed by authoritative site convergence rolls back configuration;
it does not restore application data.

Do not copy staged data over production or start services from this runbook.
Activation must define writer exclusion, database validation, external-storage
handling, exact before-images, rollback and post-activation health for the selected
scope. Until that interface is implemented and qualified from a fresh snapshot,
private staging is the supported completion boundary.
