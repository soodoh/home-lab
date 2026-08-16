# Flatcar replacement design for VM 100

This directory defines the replacement-OS design for VM 100. It does not authorize a production mutation. The Arch root disk and the bind-backed application-state disk remain independent rollback assets throughout qualification.

## Pinned release inputs

The authoritative pins are in [`infrastructure/contract/home-lab.yml`](../contract/home-lab.yml):

- Flatcar Stable `4593.2.5`, build `2026-08-11-2350`
- Proxmox VE image `flatcar_production_proxmoxve_image.img`
- Image SHA-512 `21fdba07ffc73aac80aa40f1f99e0460e2d53b1c2815a774d5e2940d2b5cfa78fb2c86391fbf3bb76e28e8ece1ca41333f30ce18d1dd3f0c016e95bed120aba8`
- Butane `0.29.0` with Flatcar config schema `1.1.0`
- Docker Compose `5.3.1` standalone binary, verified by SHA-256
- Tailscale `1.98.10` static archive, verified by SHA-256

Every fetched executable or image must match its contract digest before it can be staged. A newer Stable release requires a separate reviewed contract change and a fresh qualification cycle.

## Image staging

[`scripts/stage-flatcar-image`](../../scripts/stage-flatcar-image) is the only approved image download path. `check` is read-only and reports `absent` or `verified`. `stage` requires root, a physical Proxmox console, the exact confirmation, an exclusive host lock, an empty target, and the pinned SHA-512. It downloads to a private pending file and publishes by hard link only after verification. It never invokes `qm`, `pvesm`, or `pvesh`, and therefore cannot create, import, attach, resize, or boot a disk.

```bash
scripts/stage-flatcar-image check
export HOME_LAB_FLATCAR_STAGE_CONFIRMED=stage-reviewed-flatcar-4593.2.5-image
scripts/stage-flatcar-image stage
```

A divergent target or interrupted pending file is a stop condition and is never replaced automatically. Successful staging of the pinned image is recorded in [`infrastructure/evidence/vm-100-flatcar-image-staging.json`](../evidence/vm-100-flatcar-image-staging.json); that evidence authorizes no disk import or VM mutation.

## Ignition staging

The deterministic production render is bound in the contract by exact Ignition version, size, and SHA-256. [`scripts/stage-flatcar-ignition`](../../scripts/stage-flatcar-ignition) accepts the protected render only on standard input, requires root and a physical Proxmox console, limits the input size, validates JSON and Ignition version, and installs `/var/lib/vz/snippets/vm-100-flatcar.ign` as `root:root` mode `0600` only after the exact digest matches. It never prints the input and never invokes a VM or disk command. A divergent target or pending file is a stop condition.

`check` is read-only. `stage` requires the exact `stage-reviewed-vm-100-flatcar-ignition` confirmation in `HOME_LAB_FLATCAR_IGNITION_CONFIRMED`. The protected source must be delivered over an authenticated encrypted transport and piped directly into the helper; it must not be placed in command arguments, shell history, or a world-readable temporary file. Successful staging is recorded in [`infrastructure/evidence/vm-100-flatcar-ignition-staging.json`](../evidence/vm-100-flatcar-ignition-staging.json); it authorizes no disk import, Ignition attachment, or VM mutation.

## Disk and boot topology

Qualification uses the existing VM 100 hardware identity so networking, PCI passthrough, USB passthrough, firmware, CPU, memory, and QEMU machine type remain identical:

| Interface | Purpose | Qualification rule |
| --- | --- | --- |
| `scsi0` | Existing Arch root | Never modify; retain for at least seven stable Flatcar days |
| `scsi1` | Existing games disk | Preserve exact attachment and filesystem UUID |
| `scsi2` | Existing application-state disk | Preserve UUID `d4a19647-7879-4079-9fc9-b3e79711b449`; never image or format |
| `scsi3` | New 64 GiB Flatcar OS disk | Import only from the pinned verified image |
| `ide2` | Proxmox cloud-init drive carrying Ignition | Use `cicustom`; do not combine with cloud-init user data |

The qualification boot order is `scsi3`, `scsi0`, `net0`. The fallback boot order is the existing `scsi0`, `net0`. Changing boot order or disk attachments is a separate protected execution step and requires an interactive approval after a read-only reconciliation.

[`scripts/import-flatcar-disk`](../../scripts/import-flatcar-disk) performs only the approved replacement-disk import. It requires a physical console, the exact confirmation, the shared Proxmox operation lock, the VFIO lock, verified image and Ignition inputs, VM 100 running and unlocked, protected configuration parity, no `ide2` or unused disk, and either no `scsi3` or the one exact reconcilable partial-import state. A fresh run requires at least 64 GiB free on active `local-lvm`. It imports directly to `scsi3`, applies the exact serial and disk options, expands it to 64 GiB, rescans only VM 100, and verifies the effective desired configuration plus the running volume identity and size without changing the Arch boot order. Disk options that Proxmox cannot hot-apply remain explicitly `pending-reboot`. The helper has no stop, start, unlink, delete, or storage-free path; after any partial import it preserves the new disk for explicit reconciliation.

During qualification, the exact staged `scsi3` volume is governed by the contract, guarded import helper, and reviewed evidence rather than a fourth nested OpenTofu `disk` block. The provider does not adopt an externally hot-added nested disk into state during refresh; declaring it would produce a protected VM update and risk allocating or reattaching a disk. The existing provider settings retain unreferenced disks and prohibit destructive cleanup. OpenTofu must remain zero-action while `scsi3` adoption is deferred to a separately reviewed state transition before final authority changes.

The verified import outcome and zero-action reconciliation are recorded in [`infrastructure/evidence/vm-100-flatcar-disk-import.json`](../evidence/vm-100-flatcar-disk-import.json). The effective configuration is complete; disk-option activation remains pending the separately approved controlled reboot. This evidence does not authorize attaching `ide2`, changing boot order, or booting Flatcar.

[`scripts/attach-flatcar-ignition`](../../scripts/attach-flatcar-ignition) is the separate `ide2` attachment gate. It requires the verified image and protected snippet, exact effective and running `scsi3` identities, physical-console confirmation, shared Proxmox/VFIO locks, a running protected VM, unchanged Arch boot order, and no unused disks. It allocates only the `local-lvm` cloud-init drive and sets only `cicustom=user=local:snippets/vm-100-flatcar.ign`. It has no boot-order, stop, start, disk-import, resize, unlink, delete, or storage-free path. Any settings Proxmox cannot hot-apply remain explicitly pending the controlled qualification reboot.

The verified attachment and zero-action reconciliation are recorded in [`infrastructure/evidence/vm-100-flatcar-ignition-attachment.json`](../evidence/vm-100-flatcar-ignition-attachment.json). The OpenTofu initialization block now manages this exact attachment while the externally staged `scsi3` remains contract- and evidence-governed. This evidence does not authorize changing boot order or restarting into Flatcar.

## Inert first boot

[`scripts/boot-flatcar-first`](../../scripts/boot-flatcar-first) is the first operation allowed to stop Arch or change boot order. It requires a physical console, exact confirmation, the protected operation lock, verified image and Ignition inputs, a healthy Arch QEMU guest agent, exact `scsi3`/`ide2`/`cicustom`, VM protection, no Proxmox lock, and no unused disks. It gracefully shuts down Arch, changes boot order to `scsi3`, `scsi0`, `net0`, and starts the candidate. A failed start invokes only the exact guarded VFIO recovery before one retry. Success requires VM running, QEMU guest agent reporting OS ID `flatcar`, the production IP responding, SSH port 22 reachable, and the qualification boot order unchanged.

Each attempt captures the VM serial socket to `/var/lib/home-lab/flatcar/first-boot-console.log` as `root:root` mode `0600`. On failure, the helper reports the exact stage, candidate ping and SSH reachability, console-log SHA-256, and only filtered Ignition/failure/error lines before fallback. The protected full log remains local for explicit diagnosis.

Transition lock descriptors are released and closed before every `qm start`, then reacquired by the controller after QEMU starts, so the long-lived VM process cannot inherit them. [`scripts/release-flatcar-inherited-lock`](../../scripts/release-flatcar-inherited-lock) is the one-time recovery for an already affected Arch fallback: it requires the operation and first-boot locks to be held only by the exact live VM 100 QEMU PID, gracefully restarts Arch without changing configuration, and verifies both locks remain unowned after QEMU restarts.

Any error after Arch stops triggers automatic fallback: stop the inert candidate (gracefully when possible), restore `scsi0`, `net0`, start Arch with guarded VFIO recovery if required, and require its QEMU guest agent to report OS ID `arch`. The forced-stop fallback is restricted to an unqualified candidate for which application mounts and Compose were never activated. Failure to restore is a physical-console stop condition.

Passing this helper proves only an inert first boot. It does not prove mount absence by itself and does not authorize state, games, NFS, or Compose activation; those require controller-side read-only qualification and a later approval.

## Deterministic Ignition rendering

[`scripts/controller/render-flatcar-ignition.js`](../../scripts/controller/render-flatcar-ignition.js) generates a strict Butane config and compiles it with the pinned Butane binary. It rejects:

- an unverified Butane executable;
- missing, duplicate, or malformed protected USB identities;
- a non-private runtime environment or controller credential file;
- a Compose artifact containing symlinks or non-regular files;
- output outside the ignored, protected `.reconcile` tree; and
- any Butane warning or validation error.

The generated Butane and Ignition files contain the decrypted production runtime environment. They are mode `0600`, must remain below `.reconcile`, and must never be committed, logged, or copied to a shared location. The final Proxmox Ignition snippet is likewise protected runtime material.

Example design render on the Apple Silicon controller:

```bash
umask 077
mkdir -p .local/flatcar-tools .reconcile/flatcar/compose .reconcile/flatcar/render

curl --fail --location --silent --show-error \
  https://github.com/coreos/butane/releases/download/v0.29.0/butane-aarch64-apple-darwin \
  --output .local/flatcar-tools/butane
printf '%s  %s\n' \
  9d27a4093e4908d6a66b3996ccf4aaf2ea6123972809c4d47dc1b14ac05d8417 \
  .local/flatcar-tools/butane | shasum -a 256 --check
chmod 0755 .local/flatcar-tools/butane

scripts/compose-artifact.py copy .reconcile/flatcar/compose
ssh ansible-deploy@docker-host \
  'sudo -n cat /etc/docker-compose/production.env' \
  > .reconcile/flatcar/production.env
chmod 0600 .reconcile/flatcar/production.env

node scripts/controller/render-flatcar-ignition.js \
  --ssh-key-file "$HOME/.ssh/id_ed25519.pub" \
  --runtime-env-file .reconcile/flatcar/production.env \
  --credentials-file "$HOME/.config/home-lab/controller/plan-credentials.json" \
  --compose-artifact-dir .reconcile/flatcar/compose \
  --butane .local/flatcar-tools/butane \
  --output-dir .reconcile/flatcar/render
```

A second render from identical inputs must produce the same Butane and Ignition SHA-256 values.

## First-boot safety posture

Ignition configures the static VM 100 network identity, SSH key access, Docker, qemu-guest-agent, Tailscale binaries, hardware modules, AMD GPU runtime-power policy, USB rules, sysctls, exact filesystem mount units, and the exact Compose artifact.

The state, games, NFS, and Compose units are deliberately **disabled** in Ignition. Therefore a first Flatcar boot cannot activate application state automatically. Qualification must first prove, read-only:

1. the running OS is the pinned Flatcar version and kernel;
2. the booted root is `scsi3`, not the Arch disk;
3. `scsi0`, `scsi1`, and `scsi2` still match the expected Proxmox identities;
4. the unmounted state disk has the exact UUID and ext4 type;
5. the games disk has its exact UUID and ext4 type;
6. the GPU, GPU audio function, Bluetooth device, Zigbee device, and Z-Wave device are present;
7. `/dev/dri/renderD128`, `uhid`, and `uinput` are available with expected permissions;
8. LAN SSH and qemu-guest-agent access work; and
9. the rendered Compose model validates without starting containers.

Only a separately approved activation may mount the three filesystems, enroll Tailscale, pull digest-pinned images, and start `home-lab-compose.service`.

## Guarded VFIO recovery prerequisite

The Proxmox Nix bundle installs `/usr/local/sbin/home-lab-vfio-recover` and its exact root-owned policy. The helper is inert unless a root operator supplies the exact recovery confirmation. Observation is read-only. Recovery is blocked unless VM 100 is stopped, IOMMU group 14 contains only `0000:03:00.0`, the device identity is `1002:744c`, the driver is `vfio-pci`, `/dev/vfio/14` exists, and no process has that device open.

Recovery holds both its dedicated host lock and Proxmox's VM 100 operation lock. It unbinds only the GPU from `vfio-pci`, immediately binds it back, verifies every postcondition, and attempts a full rebind rollback on failure. It does not write VM configuration, disk configuration, or PVE-owned state.

After a separately approved VM stop, the exact rehearsal is:

```bash
sudo /usr/local/sbin/home-lab-vfio-recover observe
sudo /usr/local/sbin/home-lab-vfio-recover recover \
  --confirm recover-vm-100-vfio-group-14
sudo /usr/local/sbin/home-lab-vfio-recover observe
```

VM 100 may be restarted only after the final observation reports `state` as `ready`. This prerequisite passed on 2026-08-16: one guarded recovery/start and a second unassisted stop/start preserved the VM configuration, state disk, 41 containers, and critical health. See [`infrastructure/evidence/vm-100-vfio-recovery.json`](../evidence/vm-100-vfio-recovery.json).

## Qualification and rollback gates

Flatcar cannot become authoritative until evidence proves:

- all 41 expected containers run;
- active state sources are bind mounts below `/srv/home-lab-state` and no runtime mount uses `/var/lib/docker/volumes`;
- Gluetun, Seerr, Frigate CPU inference, GPU workloads, USB integrations, NFS, backups, and an isolated restore all pass;
- repeated cold boots pass without manual VFIO recovery;
- Proxmox, OpenTofu, Nix, and controller plans return zero unauthorized actions; and
- the Arch root disk remains unchanged and bootable.

Any failure stops qualification. The rollback sequence stops the Flatcar Compose unit, stops VM 100, restores the Arch boot order without detaching or modifying `scsi2`, verifies the VM configuration, and boots Arch. The Flatcar disk and protected Ignition snippet remain evidence until the incident is reconciled.

Automatic Flatcar rebooting is disabled during qualification with `REBOOT_STRATEGY=off`. Update policy may be enabled only after the seven-day rollback window and a separately reviewed operational decision.
