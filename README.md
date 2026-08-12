# Home lab

## Infrastructure reconciliation and recovery

The authoritative desired-state contract is [`infrastructure/contract/home-lab.yml`](infrastructure/contract/home-lab.yml). OpenTofu owns isolated infrastructure roots, controller-side Nix owns Proxmox host configuration, Ansible owns the Arch host, and Compose owns applications. The only controller operations are `steady` and `recovery`; use the guarded workflow documented in [`docs/local-controller.md`](docs/local-controller.md).

[`scripts/local-controller`](scripts/local-controller) exposes only `plan` and `apply`. Both require a clean committed revision and run validation; plan uses protected read-only credentials and displays policy-inspected, manifest-bound saved plans, while apply requires interactive confirmation before loading separate mutation credentials. Apply executes the exact saved OpenTofu and Proxmox Nix host plans without replanning, preserves the controller-wide and native S3 locks plus host and Tailscale concurrency checks, deploys the exact Compose artifact, and finishes with fresh Nix/OpenTofu no-op verification and Arch Ansible audit.

Steady reconciliation covers AWS foundation, the empty legacy-CT tombstone, Proxmox VM 100, Omada, and Tailscale. Recovery deliberately omits the legacy tombstone and uses the active AWS, Proxmox, Omada, and Tailscale roots plus guarded host and Compose restoration. See [`docs/infrastructure-reconciliation.md`](docs/infrastructure-reconciliation.md), [`recovery/README.md`](recovery/README.md), and [`docs/qualification-status.md`](docs/qualification-status.md).

The PostgreSQL 18 image and storage-layout change for Authentik requires the guarded [`docs/authentik-postgres-18-migration.md`](docs/authentik-postgres-18-migration.md) dump-and-restore procedure before Compose convergence.

## Coral Edge TPU driver on Linux 7.1+

Frigate uses a PCIe Coral passed through to the Arch VM. Proxmox binds the PCI function to `vfio-pci`; Arch loads `gasket` and `apex`. The exact upstream source commit and the three reviewed compatibility patches are tracked under [`recovery/coral`](recovery/coral):

- Linux 6.13+ quoted `DMA_BUF` namespace import;
- Linux 6.0+ removal of `no_llseek`; and
- Linux 7.1+ replacement of `zap_vma_ptes()` with `zap_special_vma_range()`.

The `coral` Ansible role copies the exact tracked `recovery/coral` recipe to the Docker host, builds it twice in a digest-pinned Arch environment with a fixed source epoch, requires byte identity and the contract package SHA-256, installs the local package, and removes the temporary build. It then verifies DKMS status, running-kernel vermagic, PCI binding, `/dev/apex_0` ownership/mode, and Frigate health. No package registry, GitHub OIDC identity, or persistent Coral artifact is required.

Do not reinstall the mutable AUR package or use `SKIP` checksums. To verify the converged runtime:

```sh
dkms status gasket/r236.5815ee3 -k "$(uname -r)"
modinfo -F vermagic apex
lspci -Dnnk -d 1ac1:089a
stat -c '%U %G %a' /dev/apex_0
docker inspect frigate
```

## Wolf game streaming

Wolf runs Steam and other graphical apps in on-demand containers and streams them to Moonlight clients. The Radeon RX 7900 XTX is exposed as `/dev/dri/renderD128`; Wolf, Jellyfin, and Frigate share that render node.

The dedicated game disk is mounted through `/etc/fstab`:

```fstab
UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 /mnt/games ext4 defaults,noatime 0 2
```

Wolf keeps its generated configuration, client pairings, profiles, and Steam home directories under `/mnt/games/wolf`. Set `GAMES_PATH` to override the default `/mnt/games` base path.

The ES-DE app mounts `${GAMES_PATH}/roms` read-only at `/ROMs`, `${GAMES_PATH}/bioses` read-only at `/bioses`, and `${GAMES_PATH}/es-de-media` read-write at `/media`. Emulator applications come from the upstream Games on Whales ES-DE image, while RetroArch cores downloaded through its Online Updater persist in `${GAMES_PATH}/wolf/profile-data/paul/WolfES-DE/.config/retroarch/cores`. The complete `${GAMES_PATH}/wolf/profile-data/paul/WolfES-DE` profile is included in encrypted backups at the matching `/backup/wolf/profile-data/paul/WolfES-DE` path, excluding caches, logs, downloadable RetroArch assets, and thumbnails. Steam game data, ROMs, BIOS files, and regenerable scraped media are intentionally excluded.

Steam and ES-DE run under Sway. Their Wolf app mounts replace Waybar with the `${GAMES_PATH}/wolf/cfg/waybar-disabled` no-op and load `sway-borderless-frontends.conf`, which removes frontend borders and main-workspace gaps while leaving game launchers and dialogs under normal Sway window management.

Install the tracked Wolf host configuration:

```sh
sudo install -m 0644 services/data/wolf/wolf-input.conf /etc/modules-load.d/wolf-input.conf
sudo install -m 0644 services/data/wolf/85-wolf-virtual-inputs.rules /etc/udev/rules.d/85-wolf-virtual-inputs.rules
sudo install -D -m 0755 services/data/wolf/waybar-disabled "${GAMES_PATH:-/mnt/games}/wolf/cfg/waybar-disabled"
sudo install -D -m 0644 services/data/wolf/sway-borderless-frontends.conf "${GAMES_PATH:-/mnt/games}/wolf/cfg/sway-borderless-frontends.conf"
sudo install -D -m 0644 services/data/wolf/es-de/es_systems.xml "${GAMES_PATH:-/mnt/games}/wolf/cfg/es-de/es_systems.xml"
sudo install -D -m 0644 services/data/wolf/es-de/wolf-xbox-one.cfg "${GAMES_PATH:-/mnt/games}/wolf/cfg/es-de/wolf-xbox-one.cfg"
sudo install -D -m 0755 services/data/wolf/es-de/dolphin-config.sh "${GAMES_PATH:-/mnt/games}/roms/dolphin-config/Configure Dolphin.sh"
sudo modprobe uinput uhid
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc --subsystem-match=hidraw --subsystem-match=input
```

Pull the upstream ES-DE image, then start and verify Wolf:

```sh
docker pull ghcr.io/games-on-whales/es-de:edge
docker compose up -d wolf
docker compose logs -f wolf
```

ES-DE uses its bundled GBA, Nintendo DS, and Nintendo 64 definitions. The tracked GameCube override launches the image's standalone Dolphin AppImage, the Dolphin Configuration system opens its full settings interface, and the tracked RetroArch autoconfiguration supports Wolf's virtual Xbox One controller. Install and update mGBA, melonDS DS, and Mupen64Plus-Next through **RetroArch → Online Updater**; the persistent core directory takes precedence over system cores.

The startup log should report VA-API H.264, H.265, and AV1 encoders and an AMD zero-copy pipeline on `/dev/dri/renderD128`. In Moonlight, add the server's internal IP, select Wolf, then open the pairing URL printed in `docker compose logs wolf` and enter Moonlight's PIN.

Wolf has read-write access to the Docker socket so it can create application containers. Keep its ports restricted to the trusted LAN.

## Rollback-safe image cleanup

Ansible manages the weekly prune command only after both the current and previous Compose image-lock documents exist. The helper verifies every locked image locally, resolves its registry digest, and creates temporary stopped container references so Docker cannot prune either rollback set. Compose deployment captures the pre-change and converged image sets; rollback verifies and exchanges both locks with the artifacts.

Never run an unrestricted `docker system prune`. Use the managed helper after reviewing its verification output:

```sh
sudo /usr/local/sbin/home-lab-safe-image-prune
```
