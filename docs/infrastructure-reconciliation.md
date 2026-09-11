# Infrastructure reconciliation

[`infrastructure/contract/home-lab.yml`](../infrastructure/contract/home-lab.yml) is the desired-state boundary. OpenTofu owns infrastructure resources, Ansible owns the declared Proxmox and Debian host lifecycle, and Compose owns applications. Bounded existing-host Nix-runtime retirement completed 2026-09-11 with no removals or configuration changes under [ADR 0004](adr/0004-operational-nix-retirement.md) and the [completion checklist](host-lifecycle-completion-plan.md); this does not prove universal Nix absence, new-source convergence, fresh boot/backup/recovery success or a clean rebuild. The attended controller/helpers and older v6 candidate remain deferred, undeployed and unqualified; see [the local controller source reference](local-controller.md). [ADR 0005](adr/0005-attended-operational-admission.md) remains binding whenever its controller is invoked.

## Deferred steady-reconciliation source reference

These examples and the v7 protocol below describe the complete accepted snapshot on local, unpublished branch `wip/deferred-attended-controller-3491395-01`, **not supported current maintenance commands or main's implementation**. That snapshot also preserves independent improvements; local `main` integrates only the non-controller work and retains older v6 code, also deferred. A clean committed checkout is not installed capability or operational readiness. Admission wrongly rejects the legitimate persistent firewall-recovery `operation.lock` pathname, and compatibility is not fixed. Preserve locks, journals and watchdogs; unknown pending operations and uncertain independent recovery access still block relevant writes. No ordinary `observe`, legacy private-preparer `summary`, v6, raw OpenTofu or direct ungated Ansible bypass is permitted.

```text
scripts/local-controller plan steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
scripts/local-controller apply steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
```

Planning validates the contract, provider locks, policies, neutral host projection, Ansible, and Compose model. It creates exact binary plans for enabled OpenTofu roots and a complete zero-change Proxmox check under `.reconcile/plans/<commit>/steady/<generation>/`. The v7 manifest explicitly binds `attended-operational-v1`, the commit, backend, plan paths/hashes, checked host source/trust/scope and sampled interval, Compose artifact, protected inputs and Tailscale identity. Old or mixed assurance artifacts are rejected. Failed or expired generations are retained; explicitly select a new generation for a new observation.

Apply accepts only a clean checkout at the manifest commit. It verifies saved hashes and policy, uses the controller-wide descriptor lock, asks for the exact operation confirmation, and loads mutation credentials only afterward. It never replaces a consumable plan during apply; unrelated-root read-only drift checks and final no-op verification remain mandatory.

The candidate's declared production order is:

1. immediate attended, complete, zero-change Proxmox audit recheck (not a host mutation);
2. AWS foundation;
3. Proxmox OpenTofu;
4. bounded Debian Ansible tags;
5. Omada and Tailscale OpenTofu;
6. exact Compose artifact activation;
7. Authentik API configuration OpenTofu; and
8. full zero-change verification.

VM 100 is Debian-authoritative. Retired Arch, Flatcar, inert-qualification, migration cutover, and infrastructure-recovery modes are not supported controller paths.

## Safety boundaries

- S3 native lockfiles and `-lock-timeout=5m` protect each OpenTofu backend.
- Exact state-object allowlists and lifecycle cleanup for retired prefixes are documented in [`opentofu-state-cleanup.md`](./opentofu-state-cleanup.md).
- The existing controller-wide descriptor spans plan/apply/verify across providers, Ansible and Compose. The operator maintains the acknowledged quiet window through final verification; before/after host lock samples are not exclusion leases or queued-reboot custody. No Nix runtime or permanent host operation lock is introduced.
- VM protection, disk topology, hardware mappings, and boot changes remain protected fields.
- Registry pulls and Compose builds remain disabled.
- Ansible normal runs require one approved tag and matching confirmation.
- Success requires every enabled OpenTofu root, the complete Proxmox audit, the Debian audit, and Compose simulation to be no-op. Authentik remains disabled until the import-first bootstrap in [`authentik-opentofu.md`](./authentik-opentofu.md) is complete.

Generic encrypted backup restoration, Compose rollback, SOPS/age recovery, firewall recovery, and hardware-mapping recovery remain separate procedures under [`recovery/`](../recovery/) and the dedicated recovery documentation.
