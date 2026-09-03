# Lifecycle-aware Ansible design

This is the target design. Phase 0 authorizes documentation only; role/playbook implementation begins after review of this document and ADR 0001.

## State model

Each host has one explicit lifecycle state in the contract and one root-owned runtime marker whose content is validated against the contract. A marker never grants authority by itself; live invariants must also pass.

| State | Purpose | Required invariants | Permitted transition |
|---|---|---|---|
| `inert` | Newly provisioned host with no production activation | Host identity and SSH host keys exist; storage activation token absent; workload mounts/Compose/Restic timers absent or inactive; no production secrets decrypted | `inert -> bootstrap` from physical console/local inventory only |
| `bootstrap` | Bounded first contact and management enrollment | Console path proven; temporary ingress explicitly recorded; Tailscale enrolled with SSH initially disabled; plan/apply identities and host keys independently verified | `bootstrap -> production` after tailnet policy, Tailscale SSH, storage identity, backup/recovery and controller canaries pass |
| `production` | Steady convergence | Tailscale SSH only; conventional key files absent; exact mounts/packages/services; controller and host locks clear; Compose/Restic healthy; OpenTofu ownership intact | `production -> maintenance` or `production -> recovery`; never back to bootstrap |
| `maintenance` | Time-bounded package, reboot, network, storage or access transaction | Reviewed saved plan, exact confirmation, recent backup, rollback/watchdog, console where required, owner lock held | `maintenance -> production` after postchecks or rollback |
| `recovery` | Fresh-host or disaster-recovery staging | Empty private staging target; exact backup/artifact identity; production paths not overwritten; network/storage activation separately gated | `recovery -> production` only through a new saved activation plan and health proof |
| `retired` | Host no longer authoritative | Workloads evacuated, credentials/tailnet node revoked, OpenTofu disposition reviewed, recovery retention preserved | Terminal except separately designed recovery |

Proxmox bootstrap remains console-led. Debian cloud-init may establish only inert prerequisites. VM creation is not host convergence and stays in OpenTofu.

## Target inventories and entry points

| Entry point | Connection/authority | Behavior |
|---|---|---|
| `inventory/bootstrap.yml` | localhost/console or explicitly attested first-contact endpoint | Only inert/bootstrap observation and transition roles; no Compose or broad package upgrade |
| `inventory/production.yml` | Transitional `proxmox` identity over Tailscale MagicDNS with strict host keys | Ordinary Ansible check-mode remains transitional; `ansible-plan` is a purpose-built fixed observer endpoint, not a normal Ansible shell |
| saved apply transport | Tailscale MagicDNS, strict host keys, fixed `ansible-deploy` activator | Consumes one immutable saved plan; it never exposes an ordinary shell or generic Ansible sudo |
| `playbooks/lifecycle-observe.yml` | Any state, read-only | Emits normalized lifecycle, access, lock, package/reboot, storage and service evidence |
| `playbooks/lifecycle-transition.yml` | One host, one transition | Requires exact from/to state, transition plan SHA, console/access gates and host owner lock |
| `playbooks/site.yml` | Production | Keeps the existing exactly-one-approved-tag rule; no implicit all-role mutation |
| `playbooks/packages-plan.yml` | Plan identity | Current fixture reads existing metadata and emits exact candidate evidence without installing; a future bounded metadata refresh remains an explicit reviewed operation |
| `playbooks/packages-apply.yml` | Apply identity | Installs only the saved candidate set; never resolves `latest` during apply |
| `playbooks/reboot.yml` | Apply identity plus console gate where required | One host, no package changes, exact expected boot/kernel identity, timeout and post-boot audit |
| `playbooks/recover-host.yml` | Recovery inventory | Builds verified staging and a recovery activation plan; does not restore over live production |

`inventory/infrastructure.yml` should be removed or become a nonduplicating alias after all callers move to the explicit plan/apply inventories.

## Role boundaries

| Role family | Responsibility | Explicit non-responsibility |
|---|---|---|
| `lifecycle_state` | Validate state marker, contract state, allowed transitions and state-specific absence/presence invariants | Does not create disks, restore data or infer a transition |
| `transaction_guard` | Bind commit, contract, inventory, normalized plan, exact tag, confirmation, locks and freshness | Does not replan during apply |
| `transaction_journal` | Root-only owner record, captured before-state, ordered checkpoints, rollback and ambiguous-response recovery | Does not store secrets or unbounded command output |
| `base` | Shared locale/timezone/package repository primitives | No host-specific network/storage mutation |
| `proxmox_host` | PVE host files, services, packages, accounts, health and protected reduced facts | No VM 100 or hardware mapping ownership |
| `debian_host` | Docker-host OS, devices, storage mounts, services and health | No Compose model or Restic repository ownership |
| `tailscale_access` | Enrollment preferences, tags, MagicDNS checks and Tailscale-only steady-state assertion | Tailnet ACL resource remains OpenTofu |
| `ssh_access` | Host-key metadata, OpenSSH validation, conventional-key absence, root/pubkey disablement | Does not weaken strict host-key checking or replace physical console recovery |
| `package_lifecycle` | Installed/candidate manifests, repository identity, holds, security classification and apply evidence | No reboot and no unreviewed dependency solution |
| `reboot_lifecycle` | Preflight, ordered shutdown/start expectations, reboot, reconnect, post-audit | No package installation or firmware change |
| `storage_lifecycle` | Adopt/assert existing ZFS, ext4 and NFS identities and activation token | Never formats/imports/destroys an unqualified device |
| `compose_*` | Existing deterministic stage/deploy/rollback behavior | No host package/network/storage ownership |
| `restic_*` | Existing snapshot, replication, retention and staging recovery behavior | No in-place production overwrite |
| `firewall_assets` | Install and byte-audit fixed transaction assets and systemd recovery units | PVE policy mutation remains the separate firewall transaction |
| `vfio_recovery` | Install/audit fixed helper and policy | Invocation remains manual with exact confirmation and Proxmox locks |

Prefer extending current shared roles (`apply_guard`, `apply_lock`, `human_access`, `tailscale`, `ssh`, `storage`, `maintenance`, `health`) over parallel implementations.

## Plan and apply protocol

1. Require clean committed Git state and the controller descriptor lock.
2. Load plan-only credentials; verify strict host keys independently.
3. Pull and lock OpenTofu state, create saved plans, and inspect every resource action.
4. Run lifecycle observation twice around deterministic Ansible check mode; normalize volatile fields and require equal output.
5. Build a manifest binding commit/tree, contract/schema, inventory, collections lock, role/helper/template hashes, OpenTofu plans, Compose artifact/image locks, live observation, action list, safety classes and expiry.
6. Apply verifies the saved manifest without replanning, asks for an exact operation/stage/plan confirmation, and only then loads apply credentials.
7. Acquire the host owner lock and reject conflicting controller, Nix-coexistence, firewall, VFIO, backup or recovery locks.
8. Re-observe protected preconditions; capture rollback state; execute only the selected tag/transition in fixed order.
9. Post-observe, run host and cross-system health checks, record terminal result, release locks, and require a new plan for any remaining work.

Check mode and audit remain mutation-free. A command task used for observation must declare `changed_when: false` and `check_mode: false` only when needed to obtain facts.

## Safety classes

| Class | Examples | Required controls |
|---|---|---|
| `guarded` | timezone, repository files, chrony | Saved plan, host lock, validation and rollback |
| `reboot-bound` | kernel, GRUB, module policy | Guarded controls plus expected reboot facts; no automatic reboot |
| `access-critical` | SSH, Tailscale, network, sudo/accounts | Console/LAN rollback, old and new live sessions, watchdog, strict host keys, remove old access last |
| `data-critical` | ZFS, exports, NFS/storage activation | Exact device/pool/dataset identity, recent backup, no format/import ambiguity, data canaries |
| `protected-session` | package set, VFIO recovery, protected token rotation | Exact operator gate, bounded candidate/action set, root-only journal, separately authorized session |
| `external-owner` | VM 100, tailnet policy, Authentik/Omada/AWS resources | OpenTofu only; Ansible blocks or audits |

## Minimal cloud-init and first contact

Cloud-init should be reduced to immutable first-contact facts: hostname/instance metadata, network required to reach the host, QEMU guest agent, SSH host-key generation, a locked temporary bootstrap identity, and the inert lifecycle marker. It must not create the durable `docker` workload account, install Docker/Tailscale/Restic/SOPS, activate data mounts, embed a reusable long-lived key, or grant open-ended steady-state sudo.

The bootstrap transition must:

1. verify console and independently recorded host keys;
2. create inert `ansible-plan` and `ansible-deploy` accounts with `nologin`, no keys, and no sudo; enable their separate fixed transports only after saved-plan fixtures pass;
3. enroll Tailscale with SSH disabled;
4. apply and verify the saved tailnet policy;
5. enable Tailscale SSH and prove plan/apply/human access from independent sessions;
6. remove temporary conventional authorization and set OpenSSH pubkey/root login off; and
7. only then authorize storage adoption and production convergence.

## Package automation

- **Debian:** produce candidate and exact-lock reports only. Every package mutation, including a Debian Security update, requires a separately reviewed exact package transaction. Unattended package mutation is forbidden and automatic reboot remains disabled.
- **Proxmox:** automate inventory, metadata refresh and proposal creation only. Package apply remains a protected attended session because PVE, kernel, ZFS and firmware must move as a compatible reviewed set. Preserve the exact-manifest model rather than `latest`.
- **Compose images:** automation may propose digest updates and regenerate the reviewed lock/model diff. The host never performs an unplanned build or pull during steady apply.
- **Release/EOL scheduler:** the credential-free weekly workflow has read-only repository permission, runs hostile fixtures, fetches only the fixed endoflife.date API endpoints, and publishes a non-authorizing report artifact. It cannot invoke Ansible, OpenTofu apply, or host credentials.
- **Package scheduler:** add a candidate-only workflow or controller timer with plan credentials only after the canonical package-lock generator is complete. No schedule or merge is package authorization.

## Reboot workflow

A reboot plan is valid only when it names one host, expected current and target kernel, boot identity, timeout, workload order and postchecks. Preconditions include recent Restic success, no active deploy/backup/firewall/VFIO/Nix lock, healthy storage, console or equivalent break glass, and tested Tailscale reconnect. Debian drains/stops Compose through the existing controlled path. Proxmox shuts down or migrates guests according to the saved plan and verifies ZFS, PVE, firewall recovery and VM 100 afterward. Reboot never occurs as a package-role handler.

## Recovery workflow

Recovery preserves the existing separation:

- OpenTofu may create only reviewed disposable/replacement infrastructure.
- SOPS/age identities remain out-of-band and independently recoverable.
- Restic restores an exact snapshot to a fresh private staging root and runs native verification.
- Compose recovery binds backup identity, artifact hash, image lock and environment metadata into a saved activation plan.
- Production storage activation is an explicit lifecycle transition; the currently unmanaged `/etc/home-lab/allow-storage-activation` token must become a contract-governed, audited object.
- Recovery has its own exact confirmation and owner journal but uses the same top-level controller and host mutual-exclusion protocol.

## Implementation acceptance sequence

1. Pin required Ansible collections and add syntax/argument/behavior tests.
2. Implement lifecycle observation and state assertions only; compare to Phase 0 evidence.
3. Implement low-risk Proxmox parity and one domain handoff fixture.
4. Implement package-plan and reboot-plan fixtures without live apply.
5. Implement access cutover fixtures and disposable host rehearsals.
6. Rehearse complete inert-to-production and recovery-to-production paths on disposable VMs.
7. Review saved plans and ADR gates before the first production ownership handoff.
