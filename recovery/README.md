# Home lab disaster recovery

The recovery boundary is deliberately split: OpenTofu recreates active control-plane resources and VM 100, controller-side Nix reconciles the Proxmox host, Ansible reconciles Arch, and the protected Compose pipeline restores workloads. ZFS import and critical-data restoration are assertion-oriented; they never create, format, or overwrite storage.

Recovery does not recreate retired CT 101. The empty `proxmox-legacy` and completed `proxmox-lxc-qualification` backends remain tombstones outside the recovery root set.

## Required offline inputs

Keep these in protected offline storage, never Git, a plan artifact, command-line history, or recovery evidence:

- recovery age identity and the recovery age public recipient;
- AWS recovery credentials, regions, state/recovery bucket identities, and KMS access;
- separate read-only plan and mutation-capable apply Proxmox API tokens;
- account-specific bootstrap SSH public keys and verified SSH host fingerprints;
- separate Tailscale plan/apply OAuth clients and the required one-use node enrollment keys;
- distinct Omada viewer/administrator credentials, the controller CA PEM, and the current desired-state export matching `infrastructure/tofu/omada/EXPORT_SCHEMA.md`;
- SOPS-protected `/dev/disk/by-id` identities, ZFS pool/member identities, and USB serial mappings;
- the exact reviewed backup source, backup ID, ciphertext checksum, and, for S3 fallback, object version and short-lived HTTPS URL;
- GPG recovery private key and any required passphrase file; and
- an ignored root-only recovery extra-vars file based on `recovery/extra-vars.example.yml`.

The local controller stores provider capabilities in separate mode-`0600` plan/apply JSON files under a mode-`0700` directory. Recovery gates are supplied only through `RECONCILE_ANSIBLE_EXTRA_VARS_FILE`; they are never passed as shell text.

## Recovery order

1. **Install Proxmox manually.** Retain physical console and tested LAN root access. Do not create or import ZFS pools in the installer.

2. **Bootstrap Proxmox locally.** Check out the exact reviewed pushed commit and follow [`../docs/proxmox-bootstrap.md`](../docs/proxmox-bootstrap.md) in order: establish only the console-asserted network/storage/package/Tailscale baseline; run `bootstrap-proxmox-nix-access install`; create protected inputs; run `bootstrap-proxmox-nix-host check`, explicitly approved `install`, and `verify`; then perform the separately reviewed isolated firewall activation from [`../docs/proxmox-firewall-cutover.md`](../docs/proxmox-firewall-cutover.md). Prove fixed plan/apply/firewall identities and arbitrary-command denial before controller recovery.

3. **Prepare protected recovery identity.** Configure the encrypted S3 backend and copy `recovery/extra-vars.example.yml` to an ignored mode-`0600` file. Review every false mutation gate. Inventory the two local backup paths in documented order and record the newest candidate in a protected JSON object containing `source`, `backup_id`, and `ciphertext_sha256`. For a remote fallback, also bind `remote_version_id`.

   Derive the exact selection identity:

   ```sh
   scripts/derive-recovery-backup-identity.py --input <protected-json>
   ```

   Put the resulting hash in `recovery_expected_backup_identity_sha256`. Supply the independently reviewed latest weekly S3 ID, checksum, short-lived URL, version ID, and `recovery_remote_backup_latest_confirmed=true` even when a local candidate is expected. Record the GPG paths, empty staging target under `/srv/home-lab-recovery/<id>`, restore approval, and any explicitly retained surviving binds.

4. **Configure Omada strict TLS.** Put the exact Omada export and CA PEM in both capability-appropriate controller files, and restore the reviewed export to `.local/omada/export.json` as a mode-`0600` file before recovery planning. The endpoint remains `https://Omada:8043`. Configure and verify the marked local alias if needed:

   ```sh
   scripts/prepare-omada-plan-input configure-alias
   scripts/prepare-omada-plan-input verify-alias
   ```

5. **Plan and review recovery.** Export only the protected extra-vars filename, then run the public plan command. It performs validation, creates the exact saved plans, and displays all provider-redacted plan details:

   ```sh
   export RECONCILE_ANSIBLE_EXTRA_VARS_FILE=<ignored-mode-0600-yaml>
   scripts/local-controller plan recovery
   ```

   Recovery plans the Proxmox Nix host plus `aws-foundation`, `proxmox`, `omada`, and `tailscale` when the latter providers are enabled. The Proxmox plan uses the exact `recovery` policy, forces token-compatible hardware mappings, and binds a mode-`0600` contract/runtime expectations projection into the manifest. Every other root uses `normal` policy. Planning does not download, decrypt, or activate a backup.

6. **Apply the exact plan.** After reviewing the displayed plans and confirming that no other protected mutation is active:

   ```sh
   scripts/local-controller apply recovery
   ```

   Apply reruns static validation, verifies the commit-bound manifest and saved-plan hashes, then prompts for the exact manifest stage: `apply-reviewed-recovery-converge` or `apply-reviewed-recovery-external-owner-prerequisite`. Mutation credentials are loaded only afterward. The reconciler revalidates the exact root plans, Compose artifact, recovery expectations, and backup identity before mutation. The controller-wide lock spans all OpenTofu, Ansible, Compose, and verification work. Apply never generates a replacement apply plan; later plan commands are mandatory no-op verification.

7. **Verify and record evidence.** An ordinary recovery whose VM already exists is a single `converge` stage: Tailscale/Proxmox owner plans run, then exact guarded Nix runs before Arch/Compose. On fresh PVE, the first reviewed manifest may instead be `external-owner-prerequisite`, containing a canonical blocked Nix plan whose only blockers are OpenTofu-owned VM prerequisites. Apply consumes only the exact saved AWS/Tailscale/Proxmox plans, stops successfully with `requires_new_reviewed_plan=true`, and performs no Nix, Arch, or Compose work. Run `scripts/local-controller plan recovery` again and independently review the new ready `converge` manifest before the second apply. Apply never replans.

   The second `converge` apply stages the exact Compose artifact and tries valid local archives newest-first across the two ordered filesystems. It downloads the reviewed S3 fallback only when no local candidate is usable. The selected candidate must match the manifest-bound recovery identity. After activation, it verifies services, maintenance, live Tailscale policy/state equality, every enabled OpenTofu root no-op, a fresh zero-action Proxmox Nix plan, Arch audit no-op, and Arch bootstrap no-op.

   Record only secret-free commit, plan/artifact/backup hashes, health outcomes, and elapsed time. The adopted contract keeps managed mappings in both recovery and steady phases. Refresh the protected serial-to-port runtime inputs before planning so Zigbee and Z-Wave mappings follow their adapters. Never change managed mode back to raw.

## Restore safety

The restore target must be an approved empty staging root. The extractor rejects traversal, device nodes, hard links, escaping relative symlinks, duplicate writes, and archives missing critical classes. Absolute cache/runtime symlinks are omitted and counted rather than materialized.

Recovery inventories a fresh Compose volume set before activation, refuses existing Docker volumes, and refuses nonempty bind targets. If Home Assistant or Wolf data deliberately survived, `recovery_retain_existing_bind_data=true` may retain only modeled nonempty binds; it never authorizes overwriting them or a nonempty recovered SSH target.

The daily backup creates one GPG-encrypted archive under `/mnt/storage/backups`. Its mandatory post-hook verifies and replicates the exact ciphertext and checksum sidecar to `/mnt/games/backups`; a failed replica fails the job. The two paths must be distinct writable filesystems with the contract-required capacity. The weekly job uploads separately to versioned KMS-protected S3. The contract records a 24-hour local critical RPO and 168-hour remote-only RPO.

## Compose activation and rollback

Recovery stages only the deterministic artifact selected by `scripts/compose-artifact.py`, decrypts SOPS only on the host, inventories fresh targets, and runs the recovery Compose plan twice. Both secret-free plan hashes must match before activation. No builds, orphan removal, or volume pruning are permitted.

The current and previous image locks and artifact generations are recovery inputs. Rollback is separately reviewed and hash-bound; it is never automatic. A failed apply retains the production lock for inspection. See [`../docs/compose-deployment.md`](../docs/compose-deployment.md).

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

The builder requires a clean commit, fresh commit-bound evidence, the ignored Omada export, both Compose image locks, and the protected age recipient. It creates a deterministic inner archive and checksum manifest, encrypts the complete bundle, and emits only the encrypted `.age` artifact for upload to the versioned KMS-protected recovery bucket.

Every Compose image keeps a readable upstream tag and immutable digest. Renovate updates the matching pair. Wolf's dynamically launched child applications remain upstream-managed and intentionally sit outside the Compose image-lock guarantee.

## Remaining live gates

Static rehearsal and steady no-op evidence do not prove production recovery. A protected live exercise must still qualify:

- disposable Proxmox VM provider behavior;
- a full cold boot with storage, mappings, passthrough, networking, and workloads healthy; and
- the eight-hour recovery-time objective.

See [`../docs/recovery-rehearsal.md`](../docs/recovery-rehearsal.md) and [`../docs/qualification-status.md`](../docs/qualification-status.md). Never revive retired CT/gateway transition instructions as a recovery path, and never delete the empty tombstone backends without a separate state/backend retirement design.
