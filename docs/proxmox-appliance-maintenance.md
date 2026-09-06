# Proxmox appliance maintenance

Ansible owns the declared Proxmox host lifecycle under the accepted [ADR](adr/0001-ansible-host-lifecycle.md). OpenTofu continues to own VM 100 and PVE hardware mappings. The protected ZFS pool is assertion-only: neither workflow creates, formats, or reshapes it, and reboot remains a separate reviewed operation.

Run repository validation before contacting the host:

```sh
scripts/reconcile-infrastructure validate
```

Once its capability migration is qualified, use `scripts/local-controller plan steady --generation <name>` to review the exact manifest-bound, complete, zero-change Proxmox audit alongside the OpenTofu plans. Apply selects that same generation, rechecks the host under descriptor locks immediately before the external-owner boundary, and consumes only the saved OpenTofu plans. Final verification requires another complete zero-change audit. See [the local controller guide](local-controller.md) for the current setup gates.

For access-critical or watchdog-required host actions, preserve physical-console access, a tested LAN rollback path, and reviewed backups. Use the current ADR and the specific host transaction's approvals, not the superseded Nix apply path. Never weaken or bypass the host ownership lock, controller lock, private sidecar, fixed transport, or exact plan approval.

PVE firewall policy remains API-owned and is maintained by the fixed host transaction under `infrastructure/proxmox-firewall/host`. Its watchdog and boot-recovery units originated in the historical bootstrap; verify their exact installed bytes and ownership before changes. Firewall policy changes still require the isolated console-authorized procedure in [`proxmox-firewall-cutover.md`](proxmox-firewall-cutover.md).

Before storage, networking, boot, or passthrough work, retain protected evidence for ZFS health and topology, console/LAN access, VM 100 availability, USB mapping resolution, and the reviewed rollback route. Protected identities and stable hashes must not enter Git, Nix outputs, saved plans, logs, or shareable evidence.
