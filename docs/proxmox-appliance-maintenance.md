# Proxmox appliance maintenance migration

This migration is deliberately split from normal convergence. Ansible never creates or reshapes the protected ZFS pool, never initiates a reboot, never selects a fallback kernel without evidence, and never deletes unknown packages, repository definitions, network snippets, or root-local paths.

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
- boot history for `proxmox.kernels.fallback`, or a console-backed boot test of that exact release.

## Gate sequence

All gates default to `false` in `recovery/extra-vars.example.yml`.

1. Apply reviewed repository, PVE storage registration, ARC staging, serial USB mapping, and main-interface changes with the normal steady apply gate. Use `proxmox_network_snippet_migration_confirmed` only with the exact reviewed snippet checksums. Use `proxmox_passthrough_usb_mapping_cleanup_confirmed` only after OpenTofu has converged both serial-driven USB mappings.
2. Set `proxmox_storage_migration_confirmed` only after SMART/scrub evidence and VM 100 access are proven. The role disables `sharenfs`, installs the `/32` export, removes only the known subnet export, reloads exports, validates the effective export set, performs the VM 100 read/write test, and records completion.
3. Stop VM 100. Set `proxmox_passthrough_legacy_cleanup_confirmed` with console access to remove duplicate VFIO state, every stale Gasket DKMS build, and the Coral udev rule. Repository and package ownership remain centralized in `proxmox_host` and `proxmox_cleanup`.
4. If boot history does not prove the fallback, boot that exact kernel manually. Set `proxmox_cleanup_fallback_verification_confirmed` only while either the running kernel is the fallback or journal evidence proves a prior boot. No role performs the reboot.
5. Boot `proxmox.kernels.current` manually. Set both `proxmox_storage_post_reboot_validation` and `proxmox_passthrough_post_reboot_validation`; these gates validate effective ARC, complete ZFS topology, PCI drivers, and unloaded Coral modules before recording evidence.
6. With VM 100 still stopped, set `proxmox_cleanup_migration_confirmed`. The cleanup role requires all prior evidence, removes only contract-listed packages and root paths, retains only package owners of the exact current/fallback kernels and headers, refreshes Proxmox boot entries, and fails on unknown manual packages or root-local paths.
7. Restart VM 100, run full postflight checks, and rerun Ansible check mode. Managed drift should be zero; unknown drift remains a failure requiring review.

Never set multiple destructive gates merely to make a check pass. Preserve `/root/.ssh`, `/root/.config/home-lab`, and both Proxmox token files throughout the migration.
