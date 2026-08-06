# Home lab disaster recovery

The recovery boundary is deliberately split: OpenTofu recreates control-plane resources and VM 100; Ansible reconciles Proxmox and Arch; the protected Compose pipeline restores workloads. ZFS import and critical-data restore are assertion-oriented and never create, format, or overwrite storage.

## Required offline inputs

- recovery age identity and the future CI age **public** recipient
- AWS recovery credentials, region, state bucket, recovery bucket, and KMS access
- separate read-only plan and mutation-capable apply Proxmox API tokens, account-specific bootstrap SSH public keys, and verified SSH host-key fingerprints
- `PROXMOX_HARDWARE_MAPPINGS_ENABLED=true` after adoption qualification or recovery, so later steady plans retain token-compatible mappings
- Tailscale workload identity, GitHub token, and Omada credentials
- SOPS-protected `/dev/disk/by-id` identities and USB serial mappings
- ignored Omada export matching `infrastructure/tofu/omada/EXPORT_SCHEMA.md`
- exact latest weekly S3 fallback ID, checksum, version, short-lived HTTPS URL, and explicit latest-object confirmation
- GPG recovery private key and, when applicable, a passphrase file

Never place these values in Git, a plan artifact, command-line history, or recovery evidence.

## Recovery order

1. Install Proxmox manually and retain console access. Do not create/import pools in the installer.
2. Copy `ansible/inventory/proxmox-local.yml` and the repository to the host. Run `playbooks/proxmox-bootstrap.yml` locally only with console, LAN rollback, and storage identity gates satisfied. This stage intentionally leaves SSH password policy unchanged. Escrow the separated tokens, prove a `tofu-apply` connection over Tailscale from the recovery controller, and only then set `proxmox_ssh_access_proven=true` for the later steady-site play.
3. Configure the existing encrypted S3 backend. Copy `recovery/extra-vars.example.yml` to an ignored, root-only file and review every false gate. Inventory the three local paths in their documented order and record the newest candidate's basename and checksum in a mode-`0600` JSON file (`source`, `backup_id`, and `ciphertext_sha256`). If no local candidate is usable, use `source: remote` and also record `remote_version_id` for the independently reviewed latest weekly S3 object. Run `scripts/derive-recovery-backup-identity.py --input <protected-json>` and place its output hash in `recovery_expected_backup_identity_sha256`. Supply the exact latest versioned weekly S3 fallback ID, checksum, short-lived HTTPS URL, version ID, and `recovery_remote_backup_latest_confirmed=true` regardless. Record the GPG key paths, `/srv/home-lab-recovery/<id>` target, empty-target approval, restore approval, and surviving-bind choice. Recovery forces creation and use of token-compatible Proxmox hardware mappings; retain both mapping variables as `true` for later steady plans.
4. Run `scripts/reconcile-infrastructure plan --phase recovery` from a trusted controller. Review every policy result and saved-plan hash. The plan operation is read-only and does not download or decrypt the backup.
5. Run the matching `apply --phase recovery` only after confirming no other protected mutation is active. It applies the exact saved plans, bootstraps Arch, stages the exact Compose artifact, tries local archives newest-first across the three ordered filesystems, and downloads the reviewed latest weekly S3 fallback only when no local candidate is valid. The selected, verified candidate must match `recovery_expected_backup_identity_sha256`; a newer or different selection fails closed and requires review of a new identity. It activates data only into inventoried fresh targets, starts Compose, removes decrypted staging after health passes, and performs no-op checks and the full audit.
6. Record secret-free evidence: commit, plan hashes, backup object ID hash, archive checks, service health, and elapsed recovery time.

The restore target is an approved empty staging root. The extractor rejects traversal, device nodes, hard links, escaping relative symlinks, duplicate writes, and archives missing critical classes. Absolute cache/runtime symlinks are omitted and counted rather than materialized. Recovery creates and inventories a fresh Compose volume set before activation, refuses existing Docker volumes, and refuses nonempty bind targets. When ZFS-backed Home Assistant or Wolf data intentionally survived, `recovery_retain_existing_bind_data=true` may retain only those modeled nonempty binds; it never permits overwriting them or a nonempty recovered SSH target.

The daily job creates one GPG-encrypted archive under `/mnt/storage/backups`, then its mandatory copy-post hook verifies and replicates the exact ciphertext plus checksum sidecar to `/home/docker/backups` and `/mnt/games/backups`; any failed replica marks the run failed. Storage and games retain seven days, while home retains two days. Ansible requires three distinct writable filesystems and capacity for the incoming archive plus each tier's retention: 150 GB on home and 400 GB each on games and storage at the estimated 50 GB archive size. The weekly job separately uploads to S3 without retaining another local copy. The contract records a 24-hour local critical RPO and a 168-hour remote-only RPO.
## Encrypted recovery bundle

After every qualified change, fetch the root-only current/previous image locks, refresh the secret-free recovery proof, and run:

```sh
scripts/build-recovery-bundle \
  --output .local/recovery/home-lab.tar.gz.age \
  --omada-export .local/omada/export.json \
  --current-image-lock .local/recovery/current-images.json \
  --previous-image-lock .local/recovery/previous-images.json \
  --recovery-evidence .local/recovery/recovery-proof.json
```

The builder requires a clean commit, fresh commit-bound evidence, the ignored Omada export, both generic Compose image locks, the protected recovery age recipient, and the exact tracked Coral local-build identity. Every Compose image retains a readable upstream tag and an immutable digest; Wolf has no separate publication path. The builder creates a deterministic inner archive and checksum manifest, then encrypts the entire bundle to the recovery recipient. Upload only the encrypted `.age` file to the versioned KMS-protected recovery bucket.

Renovate maintains each Compose tag and matching digest. Wolf's dynamically launched child applications remain upstream-managed and intentionally sit outside the Compose image-lock guarantee.

## Operational blockers

Recovery intentionally stops while protected contract values are unavailable or qualification gates are false. The Coral package is built locally from tracked checksum-pinned sources; supply AWS bucket identities through the protected controller configuration and keep Omada management disabled until the ignored export and three consecutive qualified no-op plans exist.

CT 101 is adopted in its separate protected state. It is neither rebuilt nor decommissioned by recovery mode. Only after direct Tailscale paths and every other OpenTofu/Ansible/Compose check are no-ops, load the protected `PROXMOX_CT_DECOMMISSION_CONFIRMATION` from the controller credential file. In separate reviewed changes, move the durable contract stage from `protected` to `unprotected`, then use `scripts/local-controller plan ct-unprotect`; require a converged steady proof before moving from `unprotected` to `retired` and planning `ct-delete`. Each exact local plan requires a separate explicit operator approval before apply. Finish with another steady no-op proof.
