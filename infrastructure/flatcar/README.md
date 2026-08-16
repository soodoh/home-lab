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
