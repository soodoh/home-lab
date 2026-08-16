# ADR 0001: Replace the cancelled VM 100 NixOS migration with Flatcar

- Status: Accepted
- Date: 2026-08-15

## Decision

The Arch-to-NixOS migration for VM 100 is cancelled. Git history is retained, but no guest-NixOS installer, activation, cutover, or application-adoption path is authorized for further use.

VM 100 will move from Arch to Flatcar Stable only after application state is decoupled from the operating-system disk. The transition has three durable storage roles:

- a retained Arch root disk until all qualification gates and seven stable days pass;
- an OS-neutral 256 GiB ext4 application-state disk mounted at `/srv/home-lab-state`; and
- a separate 128 GiB Flatcar OS/runtime disk whose Docker engine metadata is disposable.

The state disk will hold bind-backed data for all active Compose volumes and Home Assistant. Docker's `metadata.db`, images, layers, containers, and logs remain on the OS disk. The three protected legacy volumes remain copied, present, unattached, and undeleted.

Coral is retired from Frigate, Arch, VM passthrough, Proxmox mappings and host policy, recovery tooling, and repository configuration. Frigate must use an explicit CPU detector before any outer Coral layer is removed.

Flatcar must provide full GPU/Wolf, Bluetooth, Zigbee, Z-Wave, Tailscale, NFS, QEMU-agent, backup, deployment, and fail-closed storage parity. Material Butane changes are activated through replacement OS disks. Updates may stage automatically, but reboot activation is guarded and limited to Sunday at 08:00 local time.

## Retained controls

The following remain architectural requirements:

- controller-side Nix management of the Proxmox host;
- the unified controller mutation lock and native OpenTofu state locks;
- exact saved plans, policy inspection, protected inputs, and post-apply no-op checks;
- generic protected-file, archive, transfer, backup, and restore validation;
- current and previous Compose artifacts, environments, and image locks;
- the existing Arch deployment and recovery path until Flatcar qualification completes; and
- Git history and justified historical evidence.

## State and credential boundary

Application OpenTofu configuration, state permissions, and provider credentials may be removed only after both application states are proven to contain no managed resources. Imported live objects must be detached from state without deleting the applications. Temporary provider tokens must then be revoked and protected local credentials removed.

The active Arch SOPS identity, independent recovery identity, current Compose rollback inputs, and backup/recovery evidence are protected. The cancelled NixOS runtime identity may be retired only after ciphertext recipient changes and decryption evidence prove it is no longer required.

## Operational authorization

Repository commits do not authorize production mutation. Disk formatting, disk resizing, passthrough removal, hardware mapping deletion, state mutation, service restart, reboot, and credential revocation require their guarded execution path and retained evidence. Any disk identity mismatch, nonempty abandoned state, or unresolved hardware-parity uncertainty is a stop condition.
