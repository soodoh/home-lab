# VM 100 Debian production cutover

## Status

Debian 13 inert qualification, hardware parity, Stage 1 package preparation, Stage 2 read-only storage rehearsal, and all Stage 3 credential and immutable Compose staging checks passed. Evidence is recorded under `infrastructure/evidence/vm-100-debian-*.json`. Arch remains production authority. Debian is preserved on externally managed `scsi3`; `scsi0` and application-state `scsi2` remain protected rollback assets.

Stage 3 completion authorizes only the retained root-readable staged environment and artifact on `scsi3`. It does not authorize production mounts, installing the runtime environment, Tailscale enrollment, Docker/containerd startup, Compose activation, a production canary, or a production boot-path change. Stage 4 remains separately gated.

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
5. installs Debian Stable `docker.io`, `docker-cli`, and `docker-compose` with service autostart blocked;
6. requires Docker services and sockets to remain disabled and inactive, while the static containerd unit remains masked and inactive;
7. requires zero containers, images, and volumes and no protected mounts;
8. records package and Compose versions as durable pending evidence without credentials;
9. cleanly stops Debian and restores the exact Arch boot configuration with `onboot: 1`; and
10. requires a physical Proxmox host reboot because the passed-through GPU cannot reliably reset between guests.

After the reboot, a separate physical-console finalizer requires a changed host boot ID, exact pending/current Arch configuration, Arch QGA identity, 41 running containers, zero unhealthy containers, 115 state bind mounts, zero Docker volume mounts, the exact state UUID, healthy Proxmox firewalls, and zero failed host units. Only then does it atomically promote pending package evidence to complete. Package installation or an unfinalized reboot does not authorize a Docker daemon start.

### 2. Storage rehearsal

Boot Debian under the same coordinator and keep Docker/containerd inert. Resolve state and games by exact UUID, label, parent serial, size, canonical host attachment, and non-aliasing. Mount both ext4 filesystems only below `/run/home-lab-storage-rehearsal` with `ro,noload,nodev,nosuid,noexec` (the active mount table may report the canonical `norecovery` alias); mount exact NFS source `192.168.0.123:/storage/docker` there with read-only hard NFSv4.2 options. Verify read-only and no-journal-replay mount flags, UID/GID 1000 compatibility, exact active state ownership manifests, expected games/NFS directories, minimum free space, and no new kernel storage errors. Unmount all three before writing candidate evidence, restore exact Arch boot authority, require the planned physical host reboot, and promote evidence only after full Arch verification. No production mountpoint, persistent mount unit, Docker runtime, credentials, or Tailscale state is activated.

### 3. Credentials and Compose staged

Stage 3 is split across two independently attested physical-reboot continuations. First, install checksum-pinned SOPS/age tooling on `scsi3`, generate a Debian-only age identity at `/etc/sops/age/keys.txt`, and expose only its public recipient; the private identity is never exported. After Arch recovery, add that recipient to the SOPS creation rule while retaining the independent recovery and Arch recipients, then re-encrypt without changing plaintext. A second Debian boot may then install the root-only candidate environment and immutable Compose artifact and validate `docker compose config --quiet` plus the secret-free model inventory while Docker/containerd remain inactive. A one-use Tailscale auth key is not created.

### 4. Production canary

Use the newest existing encrypted local backup no older than seven days. Require three replicas across home, games, and NFS with the same filename, size, recorded SHA-256 sidecar, and matching first/last MiB sample hash; do not generate a new archive, recompute all 47 GB hashes, or inspect S3. The prior encrypted restore proof remains the recovery test. Export Openfit's exact digest-pinned image to the state disk without private data, shut down Arch, boot Debian, and activate all three exact mount units transiently. Load the transferred image without a registry pull, start only Openfit using the staged environment and immutable artifact with `--no-deps --pull never`, and require healthy status plus its exact read-write state bind and zero Docker volumes. The coordinator then removes the canary, image, and non-default network; stops and re-inerts Docker/containerd; removes transfer files; unmounts all protected filesystems; restores exact Arch boot authority; and requires a physical host reboot. Stage 4 does not install the runtime environment, enroll Tailscale, retain a running container, persist mount activation, or authorize production boot.

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
