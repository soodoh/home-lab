# Proxmox APT repository and chrony handoff

## Scope

This phase transfers two independent low-risk domains from the guarded Nix host workflow to Ansible:

1. `apt_repositories`: the inactive `/etc/apt/sources.list` notice and the four contracted Deb822 files in `/etc/apt/sources.list.d`.
2. `chrony_service`: only the enabled and active state of `chrony.service`.

The domains require separate saved plans and separate exact authorization. Neither transaction transfers package activation, APT metadata refresh, archive-keyring ownership, chrony configuration, networking, Tailscale, OpenSSH, NFS, ZFS, GRUB, VFIO, or reboot authority.

The infrastructure contract remains the only policy authority. While each domain is `pending`, Nix is its sole mutation owner and Ansible is read-only.

## Read-only parity

`ansible/playbooks/proxmox-low-risk-plan.yml` runs in check mode and must report `changed=0`. It independently proves:

- all five repository files are root-owned, mode `0644`, regular files with one link, and byte-for-byte equal to the contract;
- `/etc/apt/sources.list.d` contains no unrecognized regular source file;
- every referenced Debian, Proxmox, and Tailscale keyring has the contracted type, symlink target where applicable, and SHA-256;
- `chrony.service` is enabled and active;
- `chronyc tracking` succeeds with `Leap status: Normal` and a valid synchronized stratum;
- no lifecycle lock is active.

Volatile NTP peer addresses, offsets, and reference timestamps are evidence, not desired configuration. `/etc/chrony/chrony.conf` remains package/default runtime state and is not adopted in this phase.

## Repository transaction boundary

The reviewed but not yet installed fixed `ansible-deploy` action may manage only the five contracted repository files. It must:

- consume a canonical, commit-bound, 30-minute saved plan with exact before/after SHA-256 values;
- hold the controller lifecycle lock and a root host lock;
- reject symlinks, non-regular files, multiple links, wrong ownership/mode, unknown source files, source drift, contract drift, inventory drift, and active package managers;
- preserve a root-only durable journal and rollback copy before any replacement;
- stage files on the same filesystem, `fsync`, validate the staged Deb822 set without refreshing metadata, and atomically replace one exact path at a time;
- roll back every replaced file if validation or postconditions fail;
- never run `apt-get update`, resolve packages, install packages, alter keyrings, or reboot.

Archive keyrings remain Nix/package-owned dependencies during this transaction. Their hashes are mandatory preconditions, not mutation targets.

## Chrony transaction boundary

The reviewed but not yet installed fixed `ansible-deploy` action may manage only enablement and start state for `chrony.service`. It must:

- bind exact before-state, unit provenance, no-drop-in evidence, contract and source state, locks, and synchronized `chronyc tracking` evidence;
- record whether the service was enabled and active for rollback;
- avoid restarting or reloading an already healthy service;
- if convergence is required, use only the fixed enable/start operation and verify healthy tracking before commit;
- restore the prior enablement and active state on failure;
- never edit chrony configuration, networking, firewall, DNS, Tailscale, or system time directly.

The ownership-only handoff is expected to require no host mutation because current parity is exact. Later drift repair still requires its own exact saved plan.

## Single-writer sequence

For each domain independently:

1. Keep the contract state `pending` and Nix as current owner while Ansible parity is developed and exercised.
2. Add the fixed deploy schema, activator, rollback journal, adversarial tests, and negative command canaries while the action remains unreachable.
3. Install and verify the reviewed helper bundle in a separately authorized helper-only transaction.
4. Create one source commit that removes the domain from Nix projection/planning/activation, activates the Ansible writer gate, and changes the contract state to `transferred` with `current_owner: ansible`.
5. Prove live parity, zero Nix actions, no locks, and exact source exclusion, then authorize the immutable ownership handoff. Do not combine the two domains.
6. Re-run Ansible check mode, the Nix host plan, all OpenTofu plans, and full infrastructure reconciliation.

A `ready` state may be used only while reviewed capability is installed and live parity remains exact. It does not authorize host mutation or create two writers.

## Current readiness

Read-only parity is complete for both domains. Mutation remains blocked by:

- Nix still being the contracted current writer;
- fixed deploy schemas, authority checks, durable rollback/recovery, locks, and negative command canaries are implemented in source but not installed on the host;
- a saved reviewed handoff not yet existing;
- separate exact authorization not yet being granted.
