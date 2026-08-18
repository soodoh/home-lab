# VM 100 Debian production cutover

## Status

Debian 13 inert qualification and hardware parity passed. Arch remains production authority. Debian is preserved on externally managed `scsi3`; `scsi0` and application-state `scsi2` remain protected rollback assets.

The selected path is a staged cutover. This document authorizes preparation work only. It does not authorize mounting application storage read-write, decrypting production credentials, enrolling Tailscale, starting Docker, starting Compose, or changing the production boot path.

## Non-negotiable invariants

- Never image, format, detach, resize, or write filesystem metadata to `scsi0` or `scsi2`.
- Resolve and verify every protected disk by VM attachment, canonical host device, filesystem UUID, size, and non-aliasing immediately before mutation.
- Arch and Debian must never run concurrently.
- Only one OS may mount the games or state filesystems; only one Compose project may run.
- `/srv/home-lab-state` remains the application-state authority. Docker named volumes are rollback-only and are never shared across operating systems.
- A candidate failure must restore the pinned Arch cloud-init payload, `scsi0;net0`, Arch QGA identity, 41 running containers, zero unhealthy containers, 115 state bind mounts, zero active Docker volume mounts, and the exact state UUID.
- Every boot-path mutation retains the reconciliation and transition locks, requires the exact reviewed commit, and begins at the physical Proxmox console.
- The Arch disk, its retained Docker volumes, and the encrypted recovery archive remain preserved for at least seven stable Debian production days.

## Stages

### 0. Qualified

Completed. Debian boots with QGA, LAN, SSH, the required kernel and hardware, but protected mounts, Docker, Compose, Tailscale, and production credentials are inactive.

### 1. Packages prepared

A physical-console transition boots the existing Debian `scsi3` without reimaging it. The guarded coordinator:

1. verifies healthy Arch production, free locks, exact attachments, and the reviewed commit;
2. cleanly shuts down Arch;
3. boots Debian using the existing qualified cloud-init;
4. re-verifies the qualified inert baseline;
5. installs Debian Stable `docker.io` and `docker-compose` with service autostart blocked;
6. requires Docker, containerd, and their sockets to remain disabled and inactive;
7. requires zero containers, images, and volumes and no protected mounts;
8. records package and Compose versions as durable pending evidence without credentials;
9. cleanly stops Debian and restores the exact Arch boot configuration with `onboot: 1`; and
10. requires a physical Proxmox host reboot because the passed-through GPU cannot reliably reset between guests.

After the reboot, a separate physical-console finalizer requires a changed host boot ID, exact pending/current Arch configuration, Arch QGA identity, 41 running containers, zero unhealthy containers, 115 state bind mounts, zero Docker volume mounts, the exact state UUID, healthy Proxmox firewalls, and zero failed host units. Only then does it atomically promote pending package evidence to complete. Package installation or an unfinalized reboot does not authorize a Docker daemon start.

### 2. Storage rehearsal

Boot Debian under the same coordinator, keep Docker stopped, and mount the exact games and state UUIDs read-only with `noload`. Mount NFS read-only. Verify source identities, ownership compatibility for UID/GID 1000, expected state directories, free space, and absence of filesystem or kernel errors. Unmount all three and restore Arch. No `fstab` activation occurs in this stage.

### 3. Credentials and Compose staged

Generate a Debian-specific age identity on `scsi3`, expose only its public recipient, and add that recipient to the SOPS creation rule while retaining the independent recovery and Arch recipients. Re-encrypt without changing plaintext. Install pinned SOPS/age tooling, a root-only candidate environment, and the immutable Compose artifact. Validate `docker compose config` and the secret-free model inventory while Docker remains stopped. A one-use Tailscale auth key is not created yet.

### 4. Production canary

Require fresh backup evidence and an exact reviewed cutover manifest. Shut down Arch cleanly, boot Debian, verify disks again, activate exact `fstab` entries, and start Docker. Start only the reviewed canary service with pulls disabled and require health plus mount correctness. Any failure stops Docker, unmounts protected filesystems, and restores Arch.

### 5. Production cutover

Start the complete reviewed Compose artifact with image digests locked and pulls disabled. Require exactly 41 running containers, zero unhealthy containers, 115 state bind mounts, zero Docker volume mounts, expected hardware mappings, LAN service checks, and zero failed units. Only after LAN production passes may the controller create and consume a short-lived one-use Tailscale key. The previous Arch Tailscale node is retained for rollback until Debian stability is established.

### 6. Observation

Observe Debian for at least seven days. Keep `scsi0`, Arch Docker volumes, backups, recovery tooling, and credentials intact. Any accepted rollback returns boot authority to Arch and does not attempt dual-writer recovery.

## Rollback boundaries

- Before a protected mount: stop Debian and restore Arch.
- After read-only rehearsal: unmount, stop Debian, and restore Arch.
- After read-write mount but before Docker: unmount cleanly, stop Debian, and restore Arch.
- After Docker or Compose starts: stop Compose, stop Docker, verify no open protected devices, unmount, stop Debian, then restore and fully audit Arch.
- If the passed-through GPU cannot reset after a clean guest-agent shutdown, remain at the physical console and use a host reboot only after exact Arch boot configuration and `onboot: 1` are verified.
- Package preparation treats this GPU limitation as a planned two-command continuation: the first command leaves VM 100 stopped with exact Arch boot authority and durable pending evidence; the post-reboot finalizer promotes that evidence only after full Arch and host verification.

No stage may infer authorization for the next stage from a successful prior stage.
