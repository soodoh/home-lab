# Proxmox appliance maintenance

Proxmox host configuration is owned by the controller-side Nix `proxmox-host` workflow. OpenTofu continues to own VM 100 and PVE hardware mappings. The protected ZFS pool is assertion-only: neither workflow creates, formats, or reshapes it, and reboot remains a separate reviewed operation.

Run repository validation before contacting the host:

```sh
scripts/reconcile-infrastructure validate
```

Use `scripts/local-controller plan steady` to create and review the exact manifest-bound Nix host plan together with the OpenTofu plans. Apply consumes that same Nix plan through guarded `prepare` and `apply`; it never replans. A fresh zero-action Nix plan is mandatory during final verification.

For access-critical or watchdog-required host actions, preserve physical-console access, a tested LAN rollback path, and reviewed backups. Supply the explicit guarded confirmations documented in [`proxmox-guarded-apply.md`](proxmox-guarded-apply.md). Never weaken or bypass the host ownership lock, controller lock, private sidecar, fixed transport, or exact plan approval.

PVE firewall policy remains API-owned and is maintained by the fixed host transaction under `infrastructure/proxmox-firewall/host`. Its watchdog and boot-recovery units are installed and verified by the local Nix bootstrap. Firewall policy changes still require the isolated console-authorized procedure in [`proxmox-firewall-cutover.md`](proxmox-firewall-cutover.md).

Before storage, networking, boot, or passthrough work, retain protected evidence for ZFS health and topology, console/LAN access, VM 100 availability, USB mapping resolution, and the reviewed rollback route. Protected identities and stable hashes must not enter Git, Nix outputs, saved plans, logs, or shareable evidence.
