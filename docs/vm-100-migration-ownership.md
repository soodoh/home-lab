# VM 100 migration ownership inventory

This inventory records ownership before removing the cancelled guest-NixOS migration. It is intentionally conservative: mixed-purpose files are retained until reusable safety logic is extracted and live state is reconciled.

## Shared Proxmox infrastructure — preserve

- `nix/proxmox/**` and the Proxmox bundle, application, and checks that consume it.
- `nix/flake.lock` and the Proxmox-only portions of `nix/flake.nix`.
- `scripts/controller/proxmox-nix-projection.js`, Proxmox package projection, policy, bootstrap, and tests.
- The Proxmox OpenTofu root, protected VM 100 address, hardware mappings, and state-address protections.
- The unified controller lock, protected preparation, exact plan binding, and final no-op verification.

The VM-100 candidate attachment records inside the Proxmox root are not safe to delete as ordinary source cleanup. The existing `scsi2` disk is being retained and repurposed as application state, while the remote state still contains candidate attachment and boot-normalization records.

## Reusable generic safety logic — preserve or extract

- `scripts/controller/controller-apply-lock.py` and its tests.
- `scripts/controller/validate-protected-file.py` and its tests.
- Canonical Compose artifact, image-lock, stage, deploy, rollback, and health controls.
- `scripts/verify-backup-archive.py`, `scripts/restore-critical-archive.py`, `scripts/restore-critical-backup`, backup selection, and recovery validation.
- No-follow file handling, protected run roots, mount ancestry checks, capacity checks, metadata-preserving transfer, rsync verification, and evidence hashing currently embedded in `vm_100_execution.py` and `vm-100-data-transfer.py`.
- Generic VM cutover policy controls that can be retargeted to Flatcar without retaining a NixOS execution path.

## Guest-NixOS-specific — remove after controller refactoring

- `nix/hosts/vm-100/**`.
- `nix/vm-100/**`.
- Guest-only `nixosConfigurations`, candidate, Disko, ephemeral Nix, closure-signing, migration, installation, update, Compose-qualification, Gate-C, and cutover outputs in `nix/flake.nix`.
- `nix/compose-artifact/**`, `nix/compose-artifact.sha256`, `nix/secrets/**`, and guest-only dotenv reconstruction copies.
- Guest-NixOS projections, schemas, fixtures, tests, controller runners, and migration documentation.
- NixOS-only qualification resources after their live VM/image and state are explicitly retired.

## Coral-specific — remove consumer outward

- Frigate EdgeTPU configuration and `/dev/apex_0` Compose device access.
- `ansible/roles/coral/**`, Coral handlers/tags, package and audit expectations.
- `nix/modules/coral.nix` and `nix/packages/coral-driver/**`.
- `recovery/coral/**` and associated build/test paths.
- Coral VM passthrough, Proxmox mapping, VFIO/initramfs expectations, contract fields, projections, and tests.

The physical card remains installed but unused.

## Abandoned application OpenTofu adoption — remove only after empty-state proof

- `infrastructure/tofu/authentik/**`.
- `infrastructure/tofu/media-apps/**`.
- `infrastructure/applications/**`.
- Application API tunnels, Authentik bootstrap tooling, import inventories, schemas, tests, and adoption documentation.
- Application backend IAM permissions and provider credentials.

At reconciliation, Authentik state contained 44 imported instances and media state contained 9. Both controller capabilities enabled both roots. Source, permissions, and credentials must remain until reviewed state-only detachment produces empty remote states and evidence.

## Protected local credentials and evidence

Preserve:

- the active Arch identity at `/etc/sops/age/keys.txt` and its external recovery copy;
- the independent recovery age identity and escrow, even if its current directory name references migration;
- current and previous Compose artifacts, environments, image locks, and rollback evidence;
- backup identities, encrypted archives, restore evidence, provider CAs, and controller lock state; and
- production facts and evidence required to verify later cleanup.

Revoke or remove only after their dependency is retired:

- `.reconcile/vm-100/authentik-provider-token`;
- `.reconcile/vm-100/media-api-credentials.json`;
- application provider values and enable flags in protected plan/apply credentials; and
- the NixOS runtime age identity after SOPS recipient removal and decryption proof.

Candidate-install, ephemeral-Nix, Gate-C, and migration transfer artifacts under `.reconcile/` may be deleted only after evidence classification. No bulk deletion of `.reconcile` or `.local` is permitted.

## Current reconciliation blockers

- The application states are nonempty.
- The NixOS qualification root owns a VM and downloaded image.
- The Proxmox Nix host plan is blocked by a protected-access observation mismatch.
- The Arch steady SSH check reports one check-mode change even though the full audit is clean.
- The supported controller validation path directly executes guest-NixOS and application-adoption tests.

These blockers prevent Gate A from being claimed until resolved.
