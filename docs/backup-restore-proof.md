# Backup and restore proof

## Status

Phase 1 and the guarded full-data local rehearsal are complete. Local encrypted-backup freshness, external recovery-key use, archive integrity, complete isolated extraction, application-level readability, cleanup, remote-object metadata, KMS upload authorization, retention behavior, and post-restore server baselines are verified.

Observed on 2026-08-01:

- At the time of this observation, separate `daily-local-backup` and `weekly-remote-backup` jobs were running `ghcr.io/offen/docker-volume-backup:v2.48.2`.
- Both historical jobs used GPG public-key encryption. The public recipient fingerprint is `5B14A67EC89DBA1F4C0FEE7CA678E17443DBD7A4`.
- The server's default GPG keyring contains zero secret keys, and Git tracks no private-key candidate.
- The external recovery copy was used successfully on `Paul's MacBook`; the private key and passphrase never entered the server, repository, command arguments, or logs.
- Seven local `.gpg` archives exist under `/mnt/storage/backups`.
- The newest archive is `daily-backup-2026-08-01T06-00-00.tar.gz.gpg`, 46,229,834,775 bytes, with mtime `2026-08-01T06:38:29-07:00`.
- The daily job retains five days under the current `daily-backup-` prefix. Older files using the previous `backup-` prefix still exist and were not removed.
- The weekly job runs Sunday at 06:00 local time and retains 14 days under the current `weekly-backup-` prefix.
- The first scheduled run uploaded `weekly-backup-2026-08-02T06-00-00.tar.gz.gpg` and completed its remote prune step without a logged error.
- The credential-safe inventory helper at [`scripts/inventory-s3-backups.py`](../scripts/inventory-s3-backups.py) independently verified one current encrypted object in `us-west-2`: 46,308,530,007 bytes, last modified `2026-08-02T13:35:54Z`, with multipart ETag metadata.
- `ListObjectVersions` independently reported the same object as the sole current version with no delete marker. Its observed age was approximately 29 hours, within the configured 14-day retention window.
- No manual backup, upload, prune, container lifecycle, volume, or production-path mutation was performed during verification.

The current design retains separate jobs. `daily-local-backup` writes to `/mnt/storage/backups` and must replicate the verified ciphertext and checksum sidecar to `/home/docker/backups` and `/mnt/games/backups`; storage and games keep seven days, home keeps two days, and any failed replica fails the run. `/mnt/storage` is the existing NFS mount, not local LVM; `/mnt/games` is the separate local ext4 disk, while `/home/docker` resides on `/dev/sda1` on the host root filesystem. The reviewed Proxmox operation grows VM 100's local-LVM-backed `scsi0` from 400 to 550 GiB, followed by exact online partition and ext4 growth. `weekly-remote-backup` creates a distinct weekly S3 archive and disables local retention. Recovery tries the newest valid local archive globally, using home, games, then storage as the tie-break order, and uses the reviewed latest version-bound weekly archive only when every local candidate fails.

## Backup-job inventory commands

These commands inspect only service metadata, configured variable names, mount paths, and ciphertext metadata. They must never print container environment values or use `backup print-config`.

```sh
docker inspect --format 'status={{.State.Status}} image={{.Config.Image}} started={{.State.StartedAt}}' daily-local-backup weekly-remote-backup
for path in /home/docker/backups /mnt/games/backups /mnt/storage/backups; do find "$path" -maxdepth 1 -type f -name '*.gpg' -printf '%p\t%s\t%T@\t%TY-%Tm-%TdT%TH:%TM:%TS%Tz\n'; done
gpg --show-keys --with-colons services/data/backup-gpg-public.asc
gpg --batch --with-colons --list-secret-keys
```

The S3 checks use credentials already present inside `weekly-remote-backup`, loaded through `docker inspect` into process memory. The helper emits only region, object count, filename, size, last-modified time, ETag, version-ID hash, and truncation state. It never emits the bucket name, access key, secret key, session token, signed request, headers, or response body.

## Selected restore candidate

Use the newest local ciphertext:

```text
/mnt/storage/backups/daily-backup-2026-08-01T06-00-00.tar.gz.gpg
```

The application-level target is Vaultwarden's SQLite database. Production metadata, inspected without reading database content, is:

```text
/data/db.sqlite3 uid=0 gid=0 mode=0644 bytes=1933312
```

The restore verifier at [`scripts/verify-backup-archive.py`](../scripts/verify-backup-archive.py):

1. accepts a GPG-decrypted gzip/tar stream on standard input;
2. validates every archive path and reads the complete stream;
3. restores only `vaultwarden-data/db.sqlite3` and its SQLite sidecars into a new isolated directory;
4. checks archive-recorded UID `0`, GID `0`, and mode `0644`;
5. checks restored byte size; and
6. runs SQLite `PRAGMA integrity_check`, emitting only pass/fail and non-secret metadata.

A synthetic archive test passed and its disposable destination was removed. A second synthetic test proved that the verifier safely normalizes the backup tool's leading `/` archive paths while continuing to reject `..` traversal.

## External-workstation restore result

The Fish runner at [`scripts/run-backup-restore-proof.fish`](../scripts/run-backup-restore-proof.fish) was fetched over the already trusted SSH path and executed locally on `Paul's MacBook`. The GPG passphrase was collected through hidden terminal input and passed to GPG through a temporary FIFO; it was never persisted or placed in process arguments.

The selected 46,229,834,775-byte ciphertext streamed from the server to the workstation. The verification completed in 679 seconds and reported:

```text
archive integrity: pass
archive path safety: pass
archive members: 140125
regular files: 112201
total uncompressed bytes: 50666388771
Vaultwarden db.sqlite3: uid 0, gid 0, mode 0644, 1933312 bytes
Vaultwarden SQLite integrity: pass
restored SQLite sidecars: db.sqlite3-shm, db.sqlite3-wal
```

The isolated destination was created under the workstation's private temporary directory and then removed with an exact-path guard. No decrypted archive or private key was written to the server, and no production path, container, volume, or service was changed.

## Full local disaster-recovery rehearsal

Observed on 2026-08-05:

- The protected pipeline applied the exact reviewed recovery-KMS policy plan and proved an immediate no-op in run `31046872606`.
- A disposable object written by the existing backup principal inherited `aws:kms` encryption and its exact version was deleted afterward. This proved the repaired S3/KMS upload path without triggering another disruptive backup.
- The latest local encrypted archive was selected by mtime, hashed in full, and bound to the then-current guarded local-rehearsal confirmation. The later local-first design removes that special mode: an available verified daily local archive is always preferred, while the separate weekly S3 archive is an explicit fallback identity.
- `scripts/restore-critical-backup` verified the 46,277,041,740-byte ciphertext hash, decrypted it with the external recovery identity, and passed the decrypted archive to the safe extractor.
- The extractor validated 140,292 members and restored 112,372 files totaling 50,788,119,836 bytes into a new isolated `/srv/home-lab-recovery/qualification-local-*` target.
- Three absolute cache/runtime symlinks were deliberately omitted. Contained relative symlinks were restored; path traversal, escaping symlinks, hard links, devices, FIFOs, duplicate destinations, and non-backup roots remain rejected by fixtures.
- All six critical classes were present, the restored `.env` retained mode `0600`, and the restored Vaultwarden database passed read-only SQLite `PRAGMA integrity_check`.
- The guarded restore completed in 986 seconds, below the eight-hour critical RTO.
- The exact rehearsal target, temporary GPG export, passphrase file, host-side recovery identity, diagnostic status, and production apply lock were removed after verification.

No recovered bind, Docker volume, Compose project, or production service was activated or overwritten.

## Cleanup and post-check

After the verifier result has been recorded, remove only the exact external-workstation restore destination and its evidence file:

```sh
rm -rf -- "$restore_root"
rm -f -- "${restore_root}.evidence.json" ./verify-backup-archive.py
[ ! -e "$restore_root" ]
```

The post-cleanup server checks passed:

```text
local audit: ok=45 changed=0 unreachable=0 failed=0
local site check: ok=35 changed=0 unreachable=0 failed=0
41 running project containers
30 declared volumes
33 project volumes
29 unique bind sources
8 unique device sources
0 missing runtime sources
Gluetun healthy
Seerr healthy
Tailscale health empty
zero CI peers
host apply lock absent
```

## Recovery limitations

- The full rehearsal deliberately used an existing local encrypted archive. The current recovery path automatically orders all local candidates by timestamp with deterministic path tie-breaking, binds the selected ciphertext identity, and requires an explicitly confirmed latest version-bound weekly HTTPS fallback only when no local candidate verifies and decrypts.
- No recovered bind, Docker volume, or Compose project was activated, so the drill does not prove application migrations or a cold boot of all 41 services.
- Daily local archives target the 24-hour critical RPO. The cost-controlled off-site cadence is weekly, so remote-only recovery may lose up to seven days; qualification must record the latest successful weekly object rather than require a daily upload.
- Future expiration timing is not yet proven across a full retention window; current/version metadata and successful pruning prove only the active retention path.
- No manual backup was triggered because it would stop labeled production services while reading mounted plaintext configuration.
