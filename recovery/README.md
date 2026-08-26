# Home lab disaster recovery

Recovery assets restore exact Restic snapshots into fresh staging roots and activate reviewed Compose artifacts through the guarded recovery roles. They never format protected storage, restore directly over production state, or bypass the steady infrastructure controller.

## Preserved capabilities

- exact games, NFS, or Proton Restic snapshot restoration with native `restic restore --verify`;
- independently encrypted recovery bundles and SOPS/age access recovery;
- exact Compose artifact staging, activation, and rollback;
- Proxmox firewall and infrastructure rollback; and
- mount, ZFS, VFIO, and hardware-identity assertions.

## Required inputs

Copy `recovery/extra-vars.example.yml` to an ignored owner-only mode-`0600` file. Keep repository passwords, age identities, Proton credentials, provider tokens, and recovery remote fields outside Git and shell history.

Before restoration, verify the exact repository ID, snapshot ID, source-policy hash, Compose artifact hash, pinned tool hashes, repository mount or environment-only Proton remote, and an empty private `/srv/home-lab-recovery/restic-*` target. No production apply lock or backup transaction may conflict with recovery.

## Procedure

1. Select one exact snapshot and repository from reviewed evidence.
2. Build or retrieve an independently encrypted recovery bundle when the host installation is unavailable.
3. Run `scripts/restore-critical-backup --restic-snapshot-id <64-hex-id> --confirmed-empty-target` with the protected variables in `extra-vars.example.yml`.
4. Require native restore verification and inspect the restored service/database state without starting applications.
5. Generate and review the Compose recovery plan, then stage the exact artifact with builds and pulls disabled.
6. Activate only through the guarded Compose recovery role; preserve retained external user-data boundaries.
7. Run the production audit, Compose simulation, Restic status, and service health checks.

Nextcloud external user data under `/mnt/storage/media/nextcloud/data` is retained and never populated, replaced, or recursively deleted by application-state recovery. For infrastructure or VM hardware drift, return to `scripts/local-controller plan steady`; destructive host work remains a separate reviewed transaction.

Record only secret-free commit, repository, snapshot, artifact, and health evidence.
