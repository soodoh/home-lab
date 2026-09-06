# Infrastructure reconciliation

[`infrastructure/contract/home-lab.yml`](../infrastructure/contract/home-lab.yml) is the desired-state boundary. OpenTofu owns infrastructure resources, Ansible owns the declared Proxmox and Debian host lifecycle, and Compose owns applications. The neutral controller's host capability migration and live acceptance remain gated; see [the local controller guide](local-controller.md).

## Steady reconciliation

Run from the repository root:

```bash
scripts/local-controller plan steady --generation baseline-1
scripts/local-controller apply steady --generation baseline-1
```

Planning validates the contract, provider locks, policies, neutral host projection, Ansible, and Compose model. It creates exact binary plans for enabled OpenTofu roots and a complete zero-change Proxmox check under `.reconcile/plans/<commit>/steady/<generation>/`. The v6 manifest binds the commit, backend, plan paths/hashes, checked host source/trust/scope, Compose artifact, protected inputs and Tailscale identity. Failed or expired generations are retained; explicitly select a new generation for a new observation.

Apply accepts only a clean checkout at the manifest commit. It verifies saved hashes and policy, uses the controller-wide descriptor lock, asks for the exact operation confirmation, and loads mutation credentials only afterward. It never replaces a consumable plan during apply; unrelated-root read-only drift checks and final no-op verification remain mandatory.

The production order is:

1. AWS foundation;
2. immediate locked, complete, zero-change Proxmox audit (not a host mutation);
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
- A controller-wide lock spans all providers, Nix, Ansible, and Compose work.
- VM protection, disk topology, hardware mappings, and boot changes remain protected fields.
- Registry pulls and Compose builds remain disabled.
- Ansible normal runs require one approved tag and matching confirmation.
- Success requires every enabled OpenTofu root, the Proxmox host plan, the Debian audit, and Compose simulation to be no-op. Authentik remains disabled until the import-first bootstrap in [`authentik-opentofu.md`](./authentik-opentofu.md) is complete.

Generic encrypted backup restoration, Compose rollback, SOPS/age recovery, firewall recovery, and hardware-mapping recovery remain separate procedures under [`recovery/`](../recovery/) and the dedicated recovery documentation.
