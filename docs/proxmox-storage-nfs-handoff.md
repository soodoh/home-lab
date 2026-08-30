# Proxmox ZFS dataset and NFS handoff

## Scope

This phase separates two ownership domains that share a data path but have different failure modes:

- `zfs_dataset`: the `storage/docker` dataset, its `/storage/docker` mountpoint, and the contracted dataset properties.
- `nfs_export_service`: `/etc/exports.d/home-lab.exports`, the active kernel export table, and `nfs-server.service` state.

The ZFS pool topology, pool import/export, disk replacement, resilver, scrub, pool GUID, and twelve protected member identities are audit-only prerequisites. They are not routine Ansible mutation targets. The Proxmox `storage` registration remains owned by OpenTofu/PVE API. The ZFS ARC boot option is already part of the transferred boot-configuration domain.

## Current evidence

Read-only discovery observed:

- pool `storage` healthy with six mirrors and twelve member rows;
- no member checksum-error rows;
- dataset `storage/docker` mounted at `/storage/docker`, `canmount=on`, `mounted=yes`, `readonly=off`, and `sharenfs=off`;
- PVE storage registration `storage` present and active;
- root-owned, regular, single-link mode-`0644` export file;
- active export table contains exactly the contracted export/client boundary;
- `nfs-server.service` and `rpcbind.service` enabled and active;
- VM 100 running;
- Debian client `/mnt/storage` mounted from `192.168.0.123:/storage/docker` as NFSv4.

The legacy broad Debian audit has unrelated blockers: its expected running-kernel baseline is stale and its state-disk check expects `/dev/sda1` while the adopted filesystem is currently exposed as `/dev/sdc1`. The storage-specific check still proves the NFS mount identity. These unrelated device-name assumptions must not be used as NFS handoff authorization.

## Ownership sequence

Both domains begin `pending` with Nix as current owner and Ansible as target owner. They transfer separately:

1. Build deterministic read-only Ansible parity with check-mode `changed=0`.
2. Prove pool health/topology, dataset/mount properties, export-file metadata/content, active export table, services, VM 100, Debian NFS mount, Compose consumers, and Restic chain.
3. Move one domain to `ready`; install and verify the exact frozen Nix bundle.
4. Prove Nix has no mutation action for that domain.
5. Commit a source-only ownership transfer.
6. Apply one separately authorized no-mutation ownership receipt.

`zfs_dataset` and `nfs_export_service` must not share one authorization or journal.

## Mutation boundaries

Read-only parity never runs `zfs set`, `zfs mount`, `zpool import`, `zpool export`, `zpool scrub`, `exportfs -r`, `exportfs -u`, `systemctl reload`, `systemctl restart`, or any VM/Compose/Restic action.

A future ZFS dataset transaction may alter only an exact allowlisted property proposal with saved before/after values. It must reject pool-topology operations, destructive properties, recursive mutation, unmounting, and implicit replanning. Rollback restores the exact previous property values and independently verifies the dataset remains mounted.

A future NFS transaction may replace only the contracted export file, validate candidate syntax before activation, durably back up the previous file, and journal the exact before/after hashes. Export-table reload and service restart are separate operations. A healthy NFS service is never restarted automatically.

Any export-table activation requires fresh VM 100, Debian mount, Compose, Restic, firewall canary, access, console, backup, and lock evidence. Failure must restore the previous file and export table under a watchdog while preserving console access. Firewall policy remains owned by the existing fixed PVE firewall transaction.

## Locks and recovery

Planning is read-only. Future activation must acquire the controller transaction lock and host locks conflicting with Nix reconciliation, Ansible production apply, protected boot/storage work, PVE storage work, firewall NFS changes, Compose deployment, and Restic maintenance. Unknown or active locks stop the transaction.

Journals and backups are root-owned, regular, single-link mode-`0600`, fsynced before activation, and retained for explicit recovery. Recovery recognizes only exact before, exact committed-after, or a narrowly defined in-progress state; ambiguous state stops for physical-console recovery.

## Current status

Provider and consumer parity are complete in check mode with `changed=0`: pool/dataset, export file/table, services, PVE registration, VM 100, Debian mount, Compose, and Restic all match. `zfs_dataset` is now `ready` with Nix still the current owner. Nix already has no representable dataset-property mutation action, so the existing installed bundle bytes are the frozen dataset bundle; they must be independently reverified before a source-only transfer. `nfs_export_service` remains separately `pending` under Nix.
