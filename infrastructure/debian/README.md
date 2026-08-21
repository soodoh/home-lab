# Debian 13 replacement design for VM 100

This directory defines the low-maintenance Debian 13 Stable qualification and production path for VM 100. Debian became production authority after the guarded cutover and physical-reboot verification recorded in `infrastructure/evidence/vm-100-debian-production.json`. Arch `scsi0` remains unchanged and bootable, and `scsi2` remains the authoritative application-state filesystem during the required rollback-retention period.

## Why Debian

The pinned Debian `generic` image uses the full `linux-image-amd64` kernel rather than the reduced cloud kernel. Debian's generic kernel package contains `amdgpu`, `uhid`, and `uinput`, while `firmware-amd-graphics` is installed during inert provisioning. This directly addresses the hardware-parity failure recorded for Flatcar Stable 4593.2.5 without introducing a custom kernel-module supply chain.

## Pinned image

The contract pins the official Debian cloud build `20260810-2566`:

- Debian 13.6 (`trixie`)
- `debian-13-generic-amd64-20260810-2566.qcow2`
- SHA-512 `f6978100d8031c266d55d7815ceea7fcdeacf28e1e5834fdb9c94ac96880a054a6e6f8681c2d3b0584e0057eaf3ef7353856b85212d04134744faa9b3bb1f24f`
- Full generic `linux-image-amd64`, not `linux-image-cloud-amd64`

A newer image requires a reviewed contract update and a new qualification cycle.

## Inert cloud-init

The committed cloud-init inputs contain no private keys, passwords, runtime environment, Tailscale enrollment secret, or application credentials. They configure only:

- the static VM identity and controller SSH public key;
- QEMU Guest Agent and hardened SSH;
- the generic Debian kernel's AMD GPU, UHID, and UINPUT modules;
- AMD firmware and read-only hardware diagnostic tools;
- security-only unattended upgrades with automatic reboot disabled;
- exact state, games, and NFS mount units left disabled; and
- no Docker Engine, Compose unit, application image, or application state activation.

The three source files and their exact sizes and SHA-256 digests are pinned in the contract. Their Proxmox copies must be `root:root` mode `0600`.

## Disk and rollback topology

| Interface | Purpose | Qualification rule |
| --- | --- | --- |
| `scsi0` | Existing Arch root | Never image, format, detach, or modify |
| `scsi1` | Existing games disk | Preserve exact attachment and filesystem UUID |
| `scsi2` | Application-state disk | Never image or format; keep unmounted during inert qualification |
| `scsi3` | 64 GiB candidate OS disk | Replace only the hardware-blocked Flatcar contents with the pinned Debian image |
| `ide2` | Existing cloud-init drive | Regenerate only from the three exact Debian snippets |

The candidate boot order is `scsi3;scsi0;net0`; fallback is `scsi0;net0`.

## Minimal physical-console boundary

All rendering, source validation, contract validation, tests, plans, and post-boot inspection are controller-driven. The physical command may be offered only after the controller has produced zero-action plans for the exact current commit. The controller re-hashes every saved OpenTofu plan and the saved Proxmox host plan, rejects plan artifacts older than one hour, then publishes a JSON attestation to `refs/notes/debian-qualification`. Destructive preflight refreshes both `origin/main` and that note, then requires the exact commit, all five zero-action OpenTofu roots with exact plan digests, a zero-action Proxmox host plan, and an attestation age no greater than 24 hours. The Proxmox host does not hold the protected controller credentials needed to reproduce that plan. The remaining privileged operation is intentionally one physical-console command. Its guarded helper will:

1. require exact VM, disk, lock, repository, and Arch-health preconditions;
2. download and verify the pinned Debian image before stopping Arch;
3. atomically install the exact cloud-init snippets;
4. stop Arch and overwrite only the exact `local-lvm:vm-100-disk-2` block device;
5. verify the converted disk against the pinned qcow2 image;
6. regenerate and verify the cloud-init ISO;
7. boot Debian with existing guarded VFIO recovery;
8. require cloud-init, QGA, LAN, SSH, kernel modules, `amdgpu`, `/dev/dri/renderD128`, and inert mount/Compose postconditions; and
9. restore verified Arch automatically on any failure; and
10. leave a fully qualified Debian candidate inert for independent inspection on success.

After evidence is recorded, `scripts/run-debian-inert-arch-restore` provides the separate physical-console boundary that verifies the exact Debian configuration, restores the pinned Arch cloud-init payload and boot order, and requires Arch identity plus full workload health before reporting success.

This physical boundary is retained because disk imaging and boot-path mutation cannot be safely authorized by repository state or remote root access alone. Repository state, plan evidence, and the physical confirmation are cumulative gates; none independently authorizes mutation.

## Qualification gates

An inert Debian boot proves only the replacement OS and hardware baseline. It must show:

- OS ID `debian`, hostname `docker-host`, interface `ens18`, and IPv4 `192.168.0.100/24`;
- QGA and SSH ready;
- `amdgpu`, `uhid`, and `uinput` available and loaded;
- RX 7900 XTX device `1002:744c` bound to `amdgpu`;
- `/dev/dri/renderD128` present;
- no protected filesystem mounted;
- state, games, and NFS mount units disabled and inactive;
- no Docker executable, containers, or Compose activation; and
- security updates enabled with automatic reboot disabled.

Mounting state, installing Docker, enrolling Tailscale, rendering production credentials, starting Compose, and enabling guarded maintenance reboots remain separate approvals. Arch must remain unchanged and bootable for at least seven stable Debian days after eventual activation.

## Production status

The full production cutover completed from attested commit `f34c7d07b862ea3a2f5552664ff527d8d8bb0d1e` on 2026-08-21. Post-reboot verification proved Debian booted with `amdgpu.runpm=0`, 41 healthy containers, 115 state bind mounts, zero Docker volume mounts, all required LAN endpoints, the expected tagged Tailscale identity, and no matching GPU, storage, or NFS kernel errors. The boot order remains `scsi3;scsi0;net0`; Arch `scsi0`, its named volumes, and its recovery assets must remain intact until the separately accepted seven-day stability period completes.

The first finalization attempt exposed a production-capacity issue: `daily-local-backup` retained a deleted 34.2 GB temporary archive on the 64 GiB Debian root filesystem. Restarting only that container released the file, and restarting the guarded Compose unit restored all 41 services before finalization. The reviewed follow-up now binds `/mnt/games/backups/.tmp` to `/tmp` for both backup services with automatic source creation disabled. Deployment recreated only those two services with exact local image IDs and pulls disabled; `infrastructure/evidence/vm-100-debian-backup-temp-storage.json` records the zero-action post-plan and healthy runtime.
