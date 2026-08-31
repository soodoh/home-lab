# Debian 13 production host

VM 100 runs Debian 13 (`trixie`) as the sole production and deployment authority. The canonical host identity is `docker-host` on LAN address `192.168.0.100` and Tailscale address `100.116.163.42`.

## Managed platform

- Debian cloud build `20260810-2566`, generic image variant
- Kernel `6.12.107+deb13-amd64`
- Docker Engine and Compose from Debian packages
- QEMU Guest Agent, hardened OpenSSH, and unattended security updates
- RX 7900 XTX through `amdgpu`, plus `uhid` and `uinput`
- Exact local production image IDs; registry pulls remain disabled

The committed cloud-init files contain no private keys, passwords, runtime environment, Tailscale enrollment secret, or application credentials. Their source paths and digests remain pinned in the infrastructure contract.

## Storage topology

| Interface | Purpose | Protection rule |
| --- | --- | --- |
| `scsi1` | Games filesystem | Preserve its exact attachment and UUID |
| `scsi2` | Application state at `/srv/home-lab-state` | Preserve its exact attachment and UUID |
| `scsi3` | Debian system disk | Preserve its exact volume, serial, and size |
| `ide2` | Debian cloud-init drive | Render only from the committed snippets |


## Production invariants

- 41 Compose services
- zero unhealthy containers
- 126 state-backed bind mounts
- zero Docker volume mounts
- backup temporary files on `/mnt/games/backups/.tmp`, owned `root:root` with mode `0700`
- exact local image override at `/var/lib/home-lab/production-image-override.json`
- automatic reboots disabled

Generic encrypted backup and restore, SOPS/age, Compose rollback, firewall recovery, and hardware-mapping recovery remain documented under `recovery/` and `docs/`.
