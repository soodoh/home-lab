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
- No-follow file handling, protected run roots, canonical JSON, exclusive output creation, transfer locks, and evidence hashing retained in `scripts/controller/protected_execution.py`.
- Generic VM cutover policy controls that can be retargeted to Flatcar without retaining a NixOS execution path.

## Guest-NixOS-specific — retired after controller refactoring

Guest configurations, projections, Compose mirrors, secrets copies, candidate/Disko/ephemeral-Nix/closure-signing/Gate-C executors, schemas, fixtures, tests, and detailed migration documentation were removed. The isolated flake now exports only Proxmox host management. VM 9900, its downloaded image, temporary ACL, backend state, candidate execution records, and backend permission are retired with secret-free evidence.

## Coral-specific — remove consumer outward

- Frigate EdgeTPU configuration and `/dev/apex_0` Compose device access.
- `ansible/roles/coral/**`, Coral handlers/tags, package and audit expectations.
- `nix/modules/coral.nix` and `nix/packages/coral-driver/**`.
- `recovery/coral/**` and associated build/test paths.
- Coral VM passthrough, Proxmox mapping, VFIO/initramfs expectations, contract fields, projections, and tests.

The physical card remains installed but unused.

## Abandoned application OpenTofu adoption — retired after empty-state proof

- `infrastructure/tofu/authentik/**`.
- `infrastructure/tofu/media-apps/**`.
- `infrastructure/applications/**`.
- Application API tunnels, Authentik bootstrap tooling, import inventories, schemas, tests, and adoption documentation.
- Application backend IAM permissions and provider credentials.

At reconciliation, Authentik state contained 44 imported instances and media state contained 9. A state-only transition detached those objects without deleting them, proved both remote states empty at serial 2, revoked the temporary Authentik provider token, and removed controller/local application credentials. Secret-free evidence is recorded in `infrastructure/evidence/vm-100-application-state-retirement.json`; the source, execution paths, and backend permissions are now retired.

## Protected local credentials and evidence

Preserve:

- the active Arch identity at `/etc/sops/age/keys.txt` and its external recovery copy;
- the independent recovery age identity and escrow under `~/.config/sops/home-lab-recovery`;
- current and previous Compose artifacts, environments, image locks, and rollback evidence;
- backup identities, encrypted archives, restore evidence, provider CAs, and controller lock state; and
- production facts and evidence required to verify later cleanup.

Retired application provider tokens and credentials are represented only by secret-free cleanup evidence. The cancelled NixOS runtime recipient was removed from the SOPS policy and ciphertext, retained-recipient decryption passed, and its private identity and escrow were deleted.

Candidate-install, ephemeral-Nix, Gate-C, and migration transfer artifacts under `.reconcile/` may be deleted only after evidence classification. No bulk deletion of `.reconcile` or `.local` is permitted.

## Current reconciliation blockers

The Phase 0 source/state cleanup blockers are resolved. Gate A still requires the final full repository validation, Proxmox/OpenTofu no-op plan, and complete Arch steady no-op at the cleanup commit.
