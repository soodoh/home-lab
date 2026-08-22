# Home lab disaster recovery

Recovery assets in this repository restore application data and guarded production services on the Debian Docker host. They do not recreate a retired operating system, repartition disks, format protected storage, or bypass the steady infrastructure controller.

## Preserved recovery capabilities

- encrypted local and remote backup verification;
- SOPS/age key and credential recovery;
- restore into inventoried fresh target directories;
- exact Compose artifact staging and rollback;
- Proxmox firewall transaction rollback;
- VFIO and hardware-mapping recovery; and
- ZFS/import assertions that never create or overwrite storage.

## Required inputs

Use an ignored, owner-only mode-`0600` extra-vars file based on `recovery/extra-vars.example.yml`. Keep backup passphrases, age identities, object-store credentials, and provider tokens outside the repository and shell history.

Before restoration, verify:

1. VM 100 is the Debian `docker-host` and production guards are active;
2. `/srv/home-lab-state`, `/mnt/games`, and `/mnt/storage` resolve to their exact expected filesystems;
3. no infrastructure or Ansible apply lock is active;
4. the selected archive identity and checksum match reviewed evidence; and
5. the exact Compose artifact and local image override are available without registry pulls.

## Procedure

1. Build and inspect the recovery bundle with `scripts/build-recovery-bundle`.
2. Verify candidate archives with `scripts/verify-backup-archive.py`.
3. Rehearse restoration into fresh isolated targets using `scripts/rehearse-recovery` and the Ansible recovery planning playbooks.
4. Restore only the reviewed archive with `scripts/restore-critical-backup` or `scripts/restore-critical-archive.py`.
5. Stage and review the exact Compose artifact with `ansible/playbooks/plan-compose-recovery.yml` and `review-compose-stage.yml`.
6. Activate through `ansible/playbooks/recover-compose.yml`; builds and pulls remain disabled.
7. Run the Debian production audit, Compose simulation, backup checks, and service health checks.

## Nextcloud recovery boundary

Nextcloud recovery treats the five mounts independently:

- `/srv/home-lab-state/nextcloud-html` is regenerable application code reconstructed from the exact pinned image;
- `/srv/home-lab-state/nextcloud-config`, `/srv/home-lab-state/nextcloud-custom-apps`, and `/srv/home-lab-state/nextcloud-themes` are restored application state;
- `/mnt/storage/media/nextcloud/data` is retained external user data and is never populated, replaced, recursively deleted, or treated as a child of application-state recovery.

Stage Compose first so SOPS recreates the root-owned mode-`0600` files under `/etc/docker-compose/credentials`. Fresh recovery must find the external data directory on its expected NFS filesystem before creating Nextcloud containers. It reconstructs the application tree, restores the three managed boundaries, restores MariaDB, then starts MariaDB and Redis before the web and cron services. Any archive containing an old parent-style `backup/nextcloud` or `backup/nextcloud-data` tree is rejected rather than merged.

For infrastructure drift or VM hardware changes, return to steady `scripts/local-controller plan steady`. Disk, boot, passthrough, and host-reboot work still requires a separate reviewed plan and physical-console boundary.

Record only secret-free commit, artifact, archive, and health evidence.
