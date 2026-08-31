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

`package_set` is now `ready`: Nix remains the declared owner, its already-closed package mutation surface is frozen, and read-only audit remains available. The fixed package ownership capability, source transfer, and separately authorized no-mutation receipt are still required. Controller-engine retirement remains later and must not be combined with the package receipt or access cutover.

The source now contains a fixed package ownership controller, transport grammar, and host activator path. The reduced host observer checks exact installed `ii` name/version records, manifest hashes/counts, dpkg audit, holds, APT metadata freshness, a read-only solver, APT locks, and lifecycle locks. The ownership operation can write only a root-owned mode-`0600` receipt recording `changed: false` and `packages_mutated: false`; it has no package, service, or reboot mutation command. These helper bytes are not yet installed on the host, so `package_set` must remain `ready` and no activation may be built.
