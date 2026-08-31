# Proxmox networking and Tailscale handoff

## Purpose

Transfer Proxmox host networking and local Tailscale node state from Nix to Ansible without combining two access-critical ownership domains or weakening the physical-console, LAN, Tailscale SSH, OpenTofu, PVE firewall, VM 100, Compose, Restic, or recovery boundaries.

The contract has two independent lifecycle domains:

- `network_interfaces`: `/etc/network/interfaces`, absence of active snippets, and the live physical-port/bridge/address/default-route relationship;
- `tailscale_node`: `tailscaled.service` enabled/active state and the exact non-secret local node preferences already declared under `proxmox.tailscale`.

Both begin `pending` with Nix as current owner. They must move independently through `pending → ready → transferred`, with separate freeze, capability installation, source transfer, authorization, and no-mutation ownership receipt.

## Read-only discovery

The live Proxmox host currently matches the Nix projection:

- `/etc/network/interfaces` is a root-owned, mode-`0644`, regular, single-link file with the exact projected bytes;
- `/etc/network/interfaces.d` has no active entries;
- the physical port is up and enslaved to the expected bridge;
- the bridge is up with the expected static IPv4 address and default route;
- the physical and bridge MAC match the contract;
- `networking.service` is enabled and active;
- VM 100 is running and its OpenTofu-owned NIC uses the expected bridge, MAC, model, and firewall flag;
- `tailscaled.service` is enabled and active, the backend is running, and the node is online;
- hostname, tag, advertised routes, DNS acceptance, route acceptance, netfilter mode, and Tailscale SSH preferences match the contract;
- the package version matches the package manifest;
- PVE firewall parity and the guarded OpenTofu Tailscale policy plan remain complete;
- the Debian consumer retains its LAN route and NFS mount to Proxmox, Docker is active, and the Tailscale peer path is reachable;
- no conflicting controller, Ansible, or firewall transaction lock is active.

Read-only evidence must reduce Tailscale state to booleans, counts, preference equality, and service metadata. Node keys, node IDs, tailnet addresses, endpoint addresses, peer identities, SSH host keys, state-directory bytes, and auth material must never appear in ordinary Ansible output, source, controller arguments, or journals.

## Ownership boundaries

### `network_interfaces`

Ansible may eventually own only:

- exact bytes and metadata of `/etc/network/interfaces`;
- the contracted empty active-snippet set under `/etc/network/interfaces.d`;
- audit expectations for the physical port, bridge, static address, and default route.

This handoff does not own `/etc/resolv.conf`, `/etc/hosts`, hostname mutation, DNS service configuration, NIC firmware, PVE firewall policy, tailnet policy, VM NIC configuration, DHCP reservations, router configuration, or physical switching. The live resolver state differs from the contract-wide DNS list, and its authority is not proven; the contract therefore marks resolver and hosts-file management `excluded-from-this-handoff`. Any later resolver handoff requires independent authority discovery and parity.

Pool/storage traffic, VM 100, NFS, Compose, and Restic are consumers and health gates, not network mutation targets.

### `tailscale_node`

Ansible may eventually own only:

- `tailscaled.service` enabled/active state;
- exact local preferences for hostname, tag, advertised routes, DNS/route acceptance, netfilter mode, and Tailscale SSH;
- reduced health observation.

The Tailscale package remains in the separate package lifecycle. `/var/lib/tailscale` is protected runtime state and is never projected or replaced. Auth-key enrollment, logout/reset, identity replacement, package upgrade, service restart, and preference mutation are separate transactions. Tailnet grants, SSH policy, tags, tests, and policy ETag/CAS remain OpenTofu/controller-owned.

PVE firewall options/rules remain exclusively owned by the fixed PVE firewall transaction. Neither networking domain may call that transaction or edit `/etc/pve/firewall/cluster.fw`.

## Read-only parity

Planning must run in check mode and report `changed=0`. It must verify provider and consumer state independently while setting `mutation_authorized: false`.

Provider checks include:

- file metadata and content hashes with `O_NOFOLLOW`/single-link checks;
- active-snippet absence;
- bridge/port/address/route parity;
- networking and Tailscale service state without restart;
- reduced Tailscale preference and backend parity;
- VM 100 NIC and running state;
- PVE firewall observation and lock absence.

Consumer checks include Debian LAN routing, NFS mount, Docker health, required storage paths, recent Restic chain evidence, and a reduced Tailscale peer-path canary. Planning must not expose protected network or tailnet identities.

Planning cannot write files, invoke `ifup`, `ifdown`, `ifreload`, mutate links/routes/addresses, edit resolver state, call `tailscale up/set/down/logout`, restart/reload services, change firewall policy, act on VM 100, install packages, or reboot.

## Future activation and rollback

A future network-file activation must use exact before/after bytes, root-owned mode-`0600` durable backups/journals, controller and host locks, fsync-before-rename, `ifquery` validation, and a watchdog. Writing an already-matching file and activating runtime networking are separate authorizations. Runtime activation is contractually `separately-authorized-watchdog`; it requires physical-console confirmation, an open LAN rollback session, an open Tailscale session, VM/storage/Compose/Restic gates, and automatic rollback unless all postconditions pass.

A future Tailscale preference or service activation must be separate from network-file activation. It requires physical-console and LAN recovery, fresh tailnet policy/ETag evidence, strict host-key proof, protected state metadata checks, exact before/after preferences, and watchdog rollback. A healthy service is never restarted merely to record ownership.

Rollback restores captured file bytes or exact captured local preferences/service state only. It never rewrites Tailscale state-directory bytes, re-enrolls a node, changes tailnet policy, changes firewall rules, or modifies VM networking. Ambiguous state stops for physical-console recovery.

Final ownership transfer for each domain is a separately authorized no-mutation receipt with `changed: false`. The receipt cannot write network configuration, activate links, change routes, alter Tailscale, restart services, change firewall policy, act on VM 100, install packages, or reboot.

## Current status

Read-only provider and consumer parity is complete with `changed=0`. `network_interfaces` is operationally transferred to Ansible after the Nix freeze, exact capability installation, source transfer, and committed no-mutation ownership receipt `ab53a8144b9a5f102919f7698f033d14a64c151ecfbe0a5be6d8825338436a3f`. The root-owned mode-`0600`, regular, single-link receipt records `changed: false` and `runtime_activated: false`; no network file or runtime state changed. `tailscale_node` is separately `ready` with Nix still the current owner and all Nix Tailscale preference/service mutation frozen. Resolver and hosts-file ownership remain excluded.

The installed network ownership capability must be fixed before source transfer. Its controller binds a clean pushed commit, contract/schema, inventory, provider and consumer roles, playbook, transport, activator, strict host key, fresh reduced host parity, and a fresh two-host check-mode run. The host independently verifies exact interface bytes, empty snippets, bridge/port/address/route state, networking service, external-owner summaries, VM 100 networking, and lock absence. It can write only a root-owned mode-`0600` receipt with `changed: false` and `runtime_activated: false`.
