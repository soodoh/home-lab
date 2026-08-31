# Proxmox package-set and controller handoff

Package-set ownership and controller-engine retirement are separate lifecycle steps. `infrastructure/contract/home-lab.yml` remains the policy authority. OpenTofu, Compose, Restic, SOPS/age, the PVE firewall transaction, VM 100, and reboot activation retain their existing owners and are not absorbed into package convergence.

## Package-set boundary

The Proxmox package set is the exact 1,355-record reviewed manifest referenced by the contract. Read-only Ansible parity now distinguishes installed `ii` records from dpkg `config-files` records, binds the exact name/version map and manifest hash, verifies an empty hold set, reuses existing APT metadata without refreshing it, and requires a zero-removal, zero-downgrade solver.

Metadata refresh, package apply, and reboot remain separate transactions. Package apply may use only the existing fixed `ansible-deploy` package schema and activator. It cannot refresh metadata, replan, remove or downgrade packages, download missing archives during apply, accept conffile prompts, or reboot. Ownership transfer itself must be a no-mutation receipt with `changed: false`.

The retained Nix planner observes the package set but already refuses aggregate package actions, and its activator has no package mutation action. Moving `package_set` to `ready` therefore freezes an already closed Nix mutation surface while preserving read-only audit and historical recovery evidence.

## Controller dependency and access ordering

The Nix planner currently reaches the host through the conventional LAN-only `tofu-plan` capability, while the historical Nix apply engine depends on `tofu-apply`. The replacement `ansible-plan` and `ansible-deploy` Tailscale transports are already fixed and proven, but controller-engine retirement is not implied by package ownership.

The safe order is:

1. prove exact package parity and empty solver;
2. freeze and source-transfer `package_set`, install its fixed no-mutation ownership capability, and commit a separately authorized receipt;
3. keep Nix only as an audit/recovery engine and switch its read-only observation transport from `tofu-plan` LAN SSH to the fixed `ansible-plan` Tailscale observer;
4. prove no remaining Nix action domain needs `tofu-apply`;
5. retire tofu identities and conventional keys through the separate access transactions; and
6. retire the remaining Nix controller/bundle only after equivalent saved-plan, freshness, lock, rollback, and recovery behavior is bound into the lifecycle controller.

No controller source change authorizes host mutation. Apply-time Ansible replanning and broad multi-tag convergence are forbidden; each mutating domain needs a saved exact plan, one-tag apply, and exact confirmation.

## Current evidence

The live Proxmox host has exactly 1,355 installed package records matching the reviewed manifest. The package solver reports zero installs, upgrades, downgrades, or removals; APT metadata is within the contracted age; holds and lifecycle locks are empty; and check mode reports `changed=0`. Debian also has a valid empty package proposal, but Debian package authority is not part of this Proxmox ownership transfer.

`package_set` is operationally transferred to Ansible after Nix freeze, fixed capability installation, source transfer, and separately authorized no-mutation ownership receipt `6b0f77137db3d19c84c16e5d38ca468723a85393c4f6209b46a190a026003055`. The root-owned mode-`0600`, regular, single-link receipt records `changed: false`, `packages_mutated: false`, and installed manifest SHA-256 `8c6bdedf058907fcb3cc731f7b79b5b6f9d39cf019e4149d79838a5892456861`. Controller-engine retirement remains later and must not be combined with package operations or access cutover.

The fixed package ownership controller, transport grammar, and host activator are installed through authorized deploy-upgrade plans `746154de1959064dab043995a9c2d0dea7a9304484fa8acdca30bde8800542e6` and stable-evidence correction `d75b72b9fff29ab8b9e1bc2e97085b506fc7f98582ddd7bb360b2f2cd560f3d2`. Installed activator SHA-256 is `2abde7321ddf8383b465be8aa7d8c56bdc6b9b154d609dececd619425b331092`; transport SHA-256 is `1f2446e25153e9e238bae5743d0763843f6383a97aa281e224928a5555a79090`. The reduced host observer checks exact installed `ii` name/version records, manifest hashes/counts, dpkg audit, holds, APT metadata freshness, a read-only solver, APT locks, and lifecycle locks. The ownership operation can write only the no-mutation receipt; it has no package, service, or reboot mutation command.
