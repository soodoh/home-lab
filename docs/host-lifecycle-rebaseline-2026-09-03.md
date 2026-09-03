# Host lifecycle completion rebaseline — 2026-09-03

This is the Gate 0 read-only rebaseline for completing the plan in `~/Desktop/ansible-debian-cloud-init-refactor.md`. The source plan SHA-256 is `1e74b68607cc3ee940059e6e8363b9cd05f970b5690ef2666fa52424fe352d7b`. Observation began from clean, pushed commit `98287a11dc0d3af5f6440d672f3eac1ed8bbc3c4`.

This document is evidence and backlog authority only. It does not authorize production mutation.

## Current authority

- `infrastructure/contract/home-lab.yml` remains the only policy authority.
- Debian's current and target host mutation owner is Ansible.
- Proxmox's global current mutation owner remains Nix and its target owner remains Ansible.
- Proxmox domain handoffs for timezone, APT repositories, chrony, boot configuration, ZFS dataset policy, NFS export/service, networking, Tailscale, and package-set policy are recorded as transferred, but the Nix mutation engine and controller cutover are not transferred.
- OpenTofu, Compose, Restic, SOPS/age, PVE firewall, and controller locking retain their existing boundaries.

## Read-only production observation

`ansible/playbooks/lifecycle-observe.yml` completed with zero changes and zero failures on both production hosts.

- Debian reports lifecycle `production`, mutation owner `ansible`, no conventional authorized-key files, no active lifecycle locks, and current lifecycle compliance.
- Proxmox reports lifecycle `production`, mutation owner `nix`, no conventional authorized-key files, no active lifecycle locks, and current lifecycle compliance.
- Strict host-key verification remained enabled through the production inventory.

`ansible/playbooks/packages-plan.yml` used existing APT metadata only and performed no refresh or mutation.

- Debian: 373 installed package records, zero simulated changes, zero security changes, no holds, stale metadata, and `apply_authorized: false`.
- Proxmox: 1,355 installed package records matching the committed manifest, zero simulated changes, zero security changes, no holds, fresh metadata, and `apply_authorized: false`.

## Discovered policy conflict

The Debian `apt-daily-upgrade.timer` is active and enabled. Its last trigger was 2026-09-02 06:18 PDT and its next scheduled run was 2026-09-03 06:31 PDT.

The current completion program requires separate exact authorization for every production package mutation, including security updates. Therefore the active unattended-upgrade timer is transitional live-state drift. This rebaseline does not disable it. Disabling it requires a separately reviewed production transaction after repository policy, Ansible ownership, check evidence, rollback, and postconditions are complete.

## Confirmed completion blockers

1. The main controller still requires, builds, tests, and invokes the Nix Proxmox host stage.
2. Final Proxmox bootstrap/production inventories, direct contract group variables, complete independent site/audit entrypoints, and controller integration are incomplete.
3. Active Debian cloud-init still owns durable packages, repositories, hardware, SSH, unattended-upgrade, mount, and workload-user configuration instead of only first contact.
4. Normal Debian `site.yml` does not yet gate production-only roles through an explicit lifecycle profile.
5. Package and reboot roles are observation-only; exact package locks, fixed apply identity/transport, reboot execution state machine, release monitor, and workflows remain incomplete.
6. Restic/Compose recovery proves data/application recovery on a prepared disposable host, not the complete minimal-cloud-init cold-host lifecycle.
7. Nix source, schemas, tests, controller fields, and runtime validation remain active.

## Safe completion order

1. Finish repository-only contract, schema, inventory, role, transaction, and validation boundaries.
2. Prove complete Proxmox Ansible parity and Debian inert/cold-recovery behavior on disposable targets.
3. Re-run read-only production parity and protected-state observations.
4. Execute production corrections and ownership handoffs only as separately authorized exact transactions.
5. Retire Nix and migration-only assets only after all callers, rollback windows, and evidence gates close.
6. Produce one revision-bound final acceptance evidence set.
