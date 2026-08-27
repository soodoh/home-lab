# Infrastructure reconciliation

[`infrastructure/contract/home-lab.yml`](../infrastructure/contract/home-lab.yml) is the desired-state boundary. OpenTofu owns infrastructure resources, controller-side Nix owns the Proxmox host, Ansible owns the Debian Docker host, and Compose owns applications.

## Steady reconciliation

Run from the repository root:

```bash
scripts/local-controller plan steady
scripts/local-controller apply steady
```

Planning validates the contract, provider locks, policies, Nix projection, Ansible, and Compose model. It creates one saved binary plan for each enabled OpenTofu root and a canonical Proxmox host plan under `.reconcile/plans/<commit>/steady/`. The manifest binds the exact commit, backend, plan paths and hashes, Compose artifact, protected inputs, and Tailscale policy identity.

Apply accepts only a clean checkout at the manifest commit. It verifies every saved hash and policy, acquires the controller-wide lock, asks for the exact operation confirmation, and only then loads mutation credentials. It never replans during apply.

The production order is:

1. AWS foundation and legacy tombstone verification;
2. guarded Proxmox Nix preparation;
3. Proxmox OpenTofu;
4. bounded Debian Ansible tags;
5. Omada and Tailscale OpenTofu;
6. exact Compose artifact activation;
7. Authentik API configuration OpenTofu; and
8. full zero-change verification.

VM 100 is Debian-authoritative. Retired Arch, Flatcar, inert-qualification, migration cutover, and infrastructure-recovery modes are not supported controller paths.

## Safety boundaries

- S3 native lockfiles and `-lock-timeout=5m` protect each OpenTofu backend.
- A controller-wide lock spans all providers, Nix, Ansible, and Compose work.
- VM protection, disk topology, hardware mappings, and boot changes remain protected fields.
- Registry pulls and Compose builds remain disabled.
- Ansible normal runs require one approved tag and matching confirmation.
- Success requires every enabled OpenTofu root, the Proxmox host plan, the Debian audit, and Compose simulation to be no-op. Authentik remains disabled until the import-first bootstrap in [`authentik-opentofu.md`](./authentik-opentofu.md) is complete.

Generic encrypted backup restoration, Compose rollback, SOPS/age recovery, firewall recovery, and hardware-mapping recovery remain separate procedures under [`recovery/`](../recovery/) and the dedicated recovery documentation.
