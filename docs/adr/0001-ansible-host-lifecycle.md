# ADR 0001: Consolidate host lifecycle management under Ansible

- Status: Accepted
- Date: 2026-08-28
- Decision owners: home-lab operators
- Review prerequisite: `docs/host-lifecycle-phase-0.md`
- Accepted by: operator instruction to continue after Phase 0 review

## Context

Proxmox host configuration is currently owned by a custom protocol-v4 Nix bundle with projection, observer, planner, protected preparer, activator, rollback journals and controller integration. Debian host configuration is owned by Ansible, while cloud-init, OpenTofu, Compose, SOPS/age, Restic and the PVE firewall transaction have separate boundaries. This division has strong safeguards but duplicates host lifecycle concepts and leaves no single inert/bootstrap/production/recovery state model.

Phase 0 verified the live protected Proxmox baseline, VM 100, remote OpenTofu state, tailnet policy, Debian host, Compose artifact/image identities, Restic recovery chain, host keys and locks. It also found conventional authorized-key files still present, an out-of-band storage activation token, package/reboot work, stale state-move residue and retained Nix rollback sessions.

The latest Git commit added a Nix timezone domain that is not installed on Proxmox. The operator explicitly waived that mismatch because timezone will be transferred to Ansible. This is a scoped migration decision, not a general permission to ignore drift.

## Decision

### 1. Source of truth

`infrastructure/contract/home-lab.yml` remains the shared declarative authority and is consumed directly by OpenTofu, Ansible, controller validation and supporting tools. We will not create a generated Nix-like policy projection as the new Ansible authority.

Schemas and semantic tests remain required. Runtime protected values are referenced by name and verified on the host; they are never rendered into Git, plans, logs or build stores.

### 2. Ownership

The final ownership model is:

- **Ansible:** Proxmox and Debian host OS lifecycle, packages, reboot planning, accounts, OpenSSH, Tailscale host configuration, host networking, host storage configuration, systemd services, health and fixed helper installation.
- **OpenTofu:** VM 100, PVE hardware mappings, AWS, Omada, Authentik and tailnet policy resources through saved plans and remote state locks.
- **Compose:** workload graph and deterministic runtime model.
- **SOPS/age:** encrypted configuration and out-of-band recovery identities.
- **Restic:** backup, replication, retention and staging-only restore.
- **PVE firewall transaction:** firewall policy mutation, console preauthorization, CAS state, canaries and automatic rollback. Ansible may install/audit its fixed assets but does not absorb it into ordinary convergence.
- **Controller:** cross-owner ordering, saved-plan manifest, plan/apply credentials, exact confirmations and mutual exclusion.
- **Physical console:** bootstrap, break glass, access-critical rollback and separately reviewed Proxmox reboot/recovery.

Nix remains Proxmox host mutation authority during migration. Authority transfers one domain at a time only when the Ansible replacement passes the parity gates in `docs/proxmox-nix-to-ansible-migration.md`. A domain never has two enabled writers.

### 3. Lifecycle states

Hosts use explicit `inert`, `bootstrap`, `production`, `maintenance`, `recovery` and `retired` states. State is contract-declared and live-invariant-verified; a marker file alone is insufficient.

- Cloud-init creates only bounded inert/first-contact prerequisites.
- Bootstrap is console-led, establishes independently verified host keys and separate plan/apply identities, enrolls Tailscale with SSH initially disabled, proves tailnet policy, then removes temporary ingress.
- Production requires Tailscale SSH only, absence of every conventional authorized-key file, exact host/storage/service health, and clear locks.
- Maintenance is a time-bounded saved transaction for packages, reboot, access, network or storage.
- Recovery restores exact Restic snapshots into fresh staging and requires a new activation plan before production use.

The unmanaged `/etc/home-lab/allow-storage-activation` seam becomes a contract-governed lifecycle transition artifact with audit, rollback and recovery rules.

### 4. Access

Steady-state SSH authentication uses Tailscale policy only.

- All `authorized_keys` and `authorized_keys2` files are absent on both hosts.
- OpenSSH `PubkeyAuthentication` is disabled and `PermitRootLogin` is `no`.
- Strict host-key checking remains mandatory; Debian keys are independently verified through QGA and keyscan, and Proxmox keys through console/host evidence and LAN/tailnet keyscan.
- Human and automation identities are distinct. `ansible-plan` has read-only/narrow sudo; `ansible-deploy` is loaded only for approved mutation; `firewall-apply` remains a fixed isolated transport; root is denied by tailnet policy.
- Existing `tofu-plan` and `tofu-apply` Unix accounts are transitional and retire with Nix.
- Physical console recovery remains available. Network root SSH is not the break-glass design.

Conventional keys are removed last, after new tailnet rules, MagicDNS transports, positive/negative tests, independent sessions and rollback proofs pass. Controller private keys are deleted outside Git only after their host files and every repository/live caller are retired.

### 5. Plans, transactions and locks

We retain the existing safety properties:

- a clean committed revision;
- plan-only credentials before review and separate apply credentials after confirmation;
- saved OpenTofu and Ansible plans bound into one manifest;
- no apply-time replan;
- deterministic normalized Ansible check output;
- exactly one approved Ansible tag or lifecycle transition per apply;
- exact operation/stage/plan confirmations;
- controller descriptor lock plus host owner journal;
- rejection of conflicting Nix, firewall, VFIO, backup, recovery and deployment locks;
- capture-before-mutate, ordered checkpoints, rollback, ambiguous-transport recovery and post-observation; and
- a new plan after any prerequisite or partial operation.

Nix rollback trees remain until every session is terminal, the affected domains have Ansible rollback parity, and the reviewed retention window closes. The firewall committed journal and watchdog recovery assets are retained independently.

### 6. Packages, images and reboots

- Debian may automatically apply security-origin package updates under an Ansible-managed unattended-upgrades policy with result evidence. It never automatically reboots.
- Proxmox automation may refresh metadata and propose an exact compatible PVE/kernel/ZFS/firmware package manifest. Installation remains a protected reviewed session.
- Generic `state: latest` is not an accepted package lifecycle design.
- Compose image automation proposes digest/lock changes; the production host does not perform unplanned steady-state pulls or builds.
- Reboot is a separate one-host saved plan with expected kernels, recent backup, workload ordering, console/access proof, storage/lock checks and post-boot audit. A package handler never reboots.

### 7. VM disks

OpenTofu continues to own VM 100, but the existing Debian root disk `scsi3` remains contract/audit-protected outside the resource's `disk` list. Provider `0.111.1` uses a TypeList and current state omits the live fourth disk. Adoption requires the disposable qualification in `docs/opentofu-disk-adoption-feasibility.md`; this ADR does not authorize a production disk change.

### 8. Recovery boundaries

SOPS/age and Restic recovery are preserved, not rewritten as ordinary host convergence. Recovery requires exact repository, snapshot, policy, Compose artifact, image and environment identities; a fresh private target; native verification; and no restore over live production. The controller coordinates ownership and locks but does not gain access to plaintext secrets beyond the existing bounded host paths.

## Rejected alternatives

### Keep permanent split ownership between Nix and Ansible

Rejected because lifecycle, access, package and reboot policy would remain duplicated and there would still be no unified host state model. Nix may remain only as a gated migration authority and rollback source.

### Replace the contract with generated Ansible or Nix projections

Rejected because parallel generated authorities obscure field ownership and can drift. Derived artifacts may exist for execution, but they are content-bound outputs, not policy sources.

### Use conventional SSH keys as permanent automation fallback

Rejected because the required steady state is Tailscale-policy-only. Physical console and tested lifecycle recovery replace network key fallback.

### Let Ansible own VM 100 or the PVE firewall as ordinary tasks

Rejected because it would cross existing external-owner and rollback/CAS boundaries. VM resources stay OpenTofu-owned; firewall mutation stays in its dedicated transaction.

### Automatically reboot after updates

Rejected because both hosts carry production storage/workloads and require ordered, independently recoverable maintenance.

## Consequences

### Positive

- One host lifecycle model and shared role patterns across Proxmox and Debian.
- Explicit first-contact, production, maintenance and recovery boundaries.
- Fewer permanent SSH credentials and clearer least-privilege identities.
- Package and reboot behavior becomes visible, reviewable and testable.
- Existing OpenTofu, Compose, firewall, Restic and SOPS/age safeguards remain intact.

### Costs and risks

- Ansible must reproduce substantial Nix planner/preparer/activator behavior, including adversarial failure handling, before retirement.
- Access migration is high risk and requires tailnet policy changes, controller refactors and console-backed rehearsals.
- Existing terminal rollback evidence and migration tools increase temporary operational surface.
- No committed CI scheduler currently exists; automation integration must be added and reviewed.
- Proxmox package updates remain intentionally less automatic than Debian security updates.

## Implementation authorization

Acceptance confirms the Phase 0 baseline, ownership and migration matrices, authorized-key and tailnet transition order, lifecycle/package/reboot/recovery design, script ledger, and disposable-only disk plan.

Acceptance authorizes implementation and disposable rehearsals. It does **not** authorize a production ownership handoff, conventional-key removal, package apply, reboot, firewall change, recovery activation, or disk change. Each remains a separately reviewed saved transaction.
