# Proxmox appliance maintenance migration

This migration is deliberately split from normal convergence. Ansible never creates or reshapes the protected ZFS pool, never initiates a reboot, never retains a distinct fallback kernel without evidence, and never deletes unknown packages, repository definitions, network snippets, or root-local paths.

## Repository-only qualification

Run before contacting the host:

```sh
scripts/reconcile-infrastructure validate
```

Then run `ansible/playbooks/proxmox-site.yml` in check mode from the protected controller. Review all changed tasks and every reported unknown package, APT source, network snippet, and root-local path. Add an item to the contract or a reviewed migration inventory only when it is intentional; do not broaden deletion patterns.

## Required evidence

Before any storage or network cutover, retain protected evidence for:

- current `zpool status -P storage`, scrub completion, SMART results, pool GUID, and checksum count;
- local console access and the tested LAN rollback path;
- the exact active `interfaces.d` snippet inventory as `SHA256  /etc/network/interfaces.d/name` records;
- VM 100 guest-agent ownership of `192.168.0.100` and its existing NFS mount;
- resolved Zigbee and Z-Wave serial-to-port paths; and
- when a distinct fallback is configured, boot history for `proxmox.kernels.fallback` or a console-backed boot test of that exact release.

## Existing raw attachment transition

Proxmox rejects an API-token update that rewrites existing raw `hostpci` devices, even after the reviewed mappings have been created. On the one-time migration, the exact OpenTofu apply can therefore stop after creating all six mappings with `only root can set ... config for non-mapped devices`. Do not retry that stale saved plan.

After verifying the six mapping definitions and the exact existing raw VM 100 attachments, use the root SSH path to perform only the reviewed transition:

```sh
qm set 100 \
  --hostpci0 mapping=coral-tpu,rombar=1 \
  --hostpci1 mapping=rx-7900-xtx,pcie=1,rombar=1,x-vga=1 \
  --hostpci2 mapping=rx-7900-xtx-audio,pcie=1,rombar=1 \
  --usb0 mapping=zigbee-cp210x \
  --usb1 mapping=zwave-cp210x \
  --usb2 mapping=realtek-bluetooth,usb3=1
```

Require VM 100 and its guest agent to remain responsive. `qm pending 100` should show the three PCI mappings as pending until the separately approved reboot; USB mappings can become current immediately. Generate a fresh steady plan and require zero OpenTofu changes before continuing.

## Gate sequence

All gates default to `false` in `recovery/extra-vars.example.yml`.

1. Apply reviewed repository, PVE storage registration, ARC staging, serial USB mapping, and main-interface changes with the normal steady apply gate. Use `proxmox_network_snippet_migration_confirmed` only with the exact reviewed snippet checksums. Use `proxmox_passthrough_usb_mapping_cleanup_confirmed` only after OpenTofu has converged both serial-driven USB mappings.
2. Set `proxmox_storage_migration_confirmed` only after SMART/scrub evidence and VM 100 access are proven. The role disables `sharenfs`, installs the `/32` export, removes only the known subnet export, reloads exports, validates the effective export set, performs the VM 100 read/write test, and records completion.
3. Stop VM 100. Set `proxmox_passthrough_legacy_cleanup_confirmed` with console access to remove duplicate VFIO state, every stale Gasket DKMS build, and the Coral udev rule. Repository and package ownership remain centralized in `proxmox_host` and `proxmox_cleanup`.
4. When a distinct fallback is configured, boot it manually if boot history does not prove it. Set `proxmox_cleanup_fallback_verification_confirmed` only while either the running kernel is the fallback or journal evidence proves a prior boot. A single-retained-kernel policy skips this gate. No role performs the reboot.
5. Boot `proxmox.kernels.current` manually. Set both `proxmox_storage_post_reboot_validation` and `proxmox_passthrough_post_reboot_validation`; these gates validate effective ARC, complete ZFS topology, PCI drivers, and unloaded Coral modules before recording evidence.
6. With VM 100 still stopped, set `proxmox_cleanup_migration_confirmed`. The cleanup role requires all prior evidence, removes only contract-listed packages and root paths, retains only exact retained-kernel package owners and headers, refreshes Proxmox boot entries, and fails on unknown manual packages or root-local paths.
7. Restart VM 100, run full postflight checks, and rerun Ansible check mode. Managed drift should be zero; unknown drift remains a failure requiring review.

Never set multiple destructive gates merely to make a check pass. Preserve `/root/.ssh`, `/root/.config/home-lab`, and both Proxmox token files throughout the migration.
