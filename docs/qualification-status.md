# Qualification status

This file separates implemented safeguards, completed historical evidence, protected operational inputs, and unresolved live gates. Static validation is not production readiness.

The VM 100 Arch-to-NixOS migration is cancelled by [ADR 0001](decisions/0001-vm-100-flatcar.md). Existing NixOS candidate, installation, transfer, and qualification evidence is historical only and cannot authorize further execution. The replacement Arch-to-decoupled-state-to-Flatcar gates are tracked in the [migration ownership inventory](vm-100-migration-ownership.md).

## Statically implemented

- authoritative contract and JSON Schema validation
- provider lock validation for supported controller platforms
- isolated OpenTofu roots with policy-inspected, commit-bound saved plans
- separate protected plan/apply credentials with interactive confirmation before mutation credentials load
- controller-wide local apply lock plus native S3 state lockfiles
- Tailscale canonical policy SHA/ETag concurrency checks
- Proxmox and Arch bootstrap, steady convergence, and no-op audit gates
- strict Omada TLS, protected desired-state export, and marked hostname-alias verification
- exact backup ID/version/checksum/archive/fresh-target recovery controls
- current/previous Compose artifacts and image locks with readable tag plus digest pins
- deterministic Compose staging, private plan identity, health checks, and rollback inputs
- static recovery fixtures, hostile archive tests, and playbook syntax rehearsal
- schema validation for the completed disposable-LXC qualification evidence
- empty backend tombstones for retired CT 101 and completed LXC qualification
- pinned Flatcar Stable image/tool digests, deterministic strict Butane-to-Ignition rendering, and disabled-by-default state/Compose activation

## Completed live evidence

- Omada strict-TLS adoption of the existing LAN and reservations, disposable reservation create/read/delete qualification, cleanup, and repeated protected no-op plans
- disposable Proxmox LXC create/protection/unprotect/delete/absence/empty-state qualification recorded in `infrastructure/evidence/proxmox-lxc-qualification.json`
- separately reviewed CT 101 unprotection, no-op proof, deletion, and empty `proxmox-legacy` state
- deletion of the retired CT's Omada reservation while preserving the LAN and every other reservation
- removal of stale Tailscale gateway/controller transition policy and convergence of the terminal policy with a full no-op proof
- direct local-controller reachability to Omada over Tailscale TCP 8043 with strict hostname and CA verification
- three-path encrypted local backup deployment with distinct filesystems and matching newest-archive metadata
- state-only detachment of 44 Authentik and 9 media application instances, empty serial-2 remote-state proof, temporary Authentik provider-token revocation, and controller/local application credential retirement recorded in `infrastructure/evidence/vm-100-application-state-retirement.json`
- guarded retirement of the NixOS qualification VM 9900 and downloaded image, empty serial-60 state, temporary ACL absence, and restored Proxmox protected-access `6/6` match recorded in `infrastructure/evidence/vm-100-nixos-qualification-retirement.json`
- consumer-outward Coral retirement with a protected Frigate configuration backup, CPU inference proof, exact Compose deployment, Arch package/module/device absence, guarded VM shutdown/start, preserved disks and GPU mappings, empty Coral state references, and full no-op verification recorded in `infrastructure/evidence/vm-100-coral-retirement.json`
- OS-independent application-state migration to the exact `scsi2` ext4 filesystem at `/srv/home-lab-state`, zero active Docker-volume mounts, preserved source volumes, repeated cold-boot health, three verified encrypted replicas, and a cleaned isolated restore of the final bind-backed archive recorded in `infrastructure/evidence/vm-100-state-disk-migration.json`
- exact-policy VFIO GPU recovery installation and rehearsal with one guarded recovery cycle, a second unassisted VM cold start, unchanged VM configuration, 41 restored containers, preserved state UUID and bind mounts, healthy critical services, Arch audit no-op, and Proxmox Nix zero-action proof recorded in `infrastructure/evidence/vm-100-vfio-recovery.json`
- physical-console staging and SHA-512 verification of the pinned Flatcar Stable 4593.2.5 image with VM 100 still running on unchanged `scsi0`/`scsi1`/`scsi2`, no `scsi3`, no unused disks, unchanged boot order, and a complete post-stage Proxmox observation recorded in `infrastructure/evidence/vm-100-flatcar-image-staging.json`
- physical-console, pinned-TLS staging and exact SHA-256 verification of the protected production Ignition snippet as `root:root` mode `0600`, followed by ephemeral transport cleanup and proof that VM 100 remained running with unchanged disks and boot order, recorded in `infrastructure/evidence/vm-100-flatcar-ignition-staging.json`

These records justify removal of completed transition executables. They do not authorize state/backend deletion or recreation of retired resources.

## Protected operational invariants

The undeclared Compose volumes `docker-compose_happier-data`, `docker-compose_nzbget-data`, and `docker-compose_nzbhydra2-data` remain protected legacy data. Steady audit requires them to exist, and routine deployment must never prune, rename, recreate, or delete them. Current/previous artifacts and environments remain the only rollback inputs; rollback is separately reviewed and never automatic.

## Protected inputs

Backend coordinates, provider credentials, SSH fingerprints and keys, hardware identities, Omada export and CA, backup object/version/checksum, GPG material, SOPS recipients, and recovery evidence are intentionally absent from Git. Controller credential and extra-vars files remain mode `0600` under protected local storage.

## Unresolved live qualification

The following remain operational gates rather than static claims:

- disposable Proxmox **VM** behavior across create, update, protection, delete, raw disk, hardware mappings, PCI/USB, ACL, and cloud-image paths;
- a complete cold boot with storage, passthrough devices, networking, host configuration, and workloads healthy; and
- a timed recovery proving the eight-hour recovery-time objective.
- replacement-disk Flatcar qualification with production hardware parity; and
- seven stable days with the Arch root disk retained.

Scheduled daily/weekly backup execution evidence also remains an ongoing operational observation. A static rehearsal or successful steady no-op must not be represented as proof of these live outcomes.

Update this document only from protected, reviewed evidence. Record secret-free hashes and outcomes; never paste credentials or protected identifiers.
