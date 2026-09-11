# Home lab

## Infrastructure reconciliation and recovery

The authoritative desired-state contract is [`infrastructure/contract/home-lab.yml`](infrastructure/contract/home-lab.yml). OpenTofu owns infrastructure resources, Ansible owns both the Proxmox and Debian hosts, and Compose owns applications. The [Proxmox ownership cutover](docs/proxmox-aggregate-authority-cutover-2026-09-04.md) is complete.

Bounded existing-host Nix-runtime retirement completed **2026-09-11**, with no removals or configuration changes, under [ADR 0004](docs/adr/0004-operational-nix-retirement.md) and the [completion checklist](docs/host-lifecycle-completion-plan.md). This is not universal Nix absence, new-source convergence, or fresh boot/backup/recovery proof; a clean rebuild remains uncertified. Retain required Nix-free Python/data under `nix/`, current and previous Compose artifacts/images, and all backup/firewall/storage/access recovery assets and credentials. Historical work remains in the [archive index](docs/archive/host-lifecycle/README.md).

The [attended controller source](docs/local-controller.md) and older v6 candidate are **deferred, undeployed and unqualified**, not current maintenance defaults. The complete accepted source snapshot is preserved on local, unpublished branch `wip/deferred-attended-controller-3491395-01`, including its independent improvements—not a controller-only patch. Local `main` integrates the non-controller docs/archive, Docker safety and manual-update changes; its older v6 implementation remains deferred too. Clean committed source is not installed capability or operational readiness. [ADR 0005](docs/adr/0005-attended-operational-admission.md) still binds every invocation. Its admission currently rejects the legitimate persistent firewall-recovery `operation.lock`; compatibility is not fixed. Do not clear locks, stop watchdogs or bypass guards. Unknown pending operations and uncertain independent recovery access still bar relevant writes. Generic encrypted restoration and Compose rollback remain separately guarded; see [`docs/infrastructure-reconciliation.md`](docs/infrastructure-reconciliation.md) and [`recovery/README.md`](recovery/README.md).

The PostgreSQL 18 image and storage-layout change for Authentik requires the guarded [`docs/authentik-postgres-18-migration.md`](docs/authentik-postgres-18-migration.md) dump-and-restore procedure before Compose convergence.

## Update policy

OS changes require reviewed exact transactions, with no automatic apply or reboot. Tailscale declares update checking on and auto-apply off; live preferences and unattended-upgrade settings are unverified. Renovate Docker updates are digest-pinned, isolated and manually merged after at least three days; FlareSolverr retains its canary label and seven-day age but no source automerge permission. Manual merge is not deployment authority.

Tracked GitHub workflows contain only weekly/monthly advisory artifact jobs; [ADR 0002](docs/adr/0002-advisory-maintenance-reporting.md) still defers daily host collection and issue sending. Actual remote CI/Renovate activation is unverified. The [historically authorized and proven FlareSolverr deployment lane](docs/compose-deployment.md#renovate-canary-lane-historical) is preserved as history: cached workflow absence and this source-policy change do not prove remote automation disabled.

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
