# Disposable official-PVE qualification

Gate 3 requires an independently identified official Proxmox VE target. Repository fixtures, the production node, a Debian guest, and the prior VM 9900 recovery guest cannot substitute for an isolated PVE installation.

## Target admission

Before any connection or plan, record and independently verify:

- endpoint and inventory alias;
- official PVE release and package origin;
- out-of-band console path;
- dedicated plan and apply identities with no production credentials;
- a dedicated mode-`0600`, single-link known-hosts file and exact host-key fingerprint;
- synthetic local storage and disks containing no production serial, UUID, pool GUID, datastore path, or state;
- network controls proving the target cannot reach production VM 100, production PVE storage, controller state, Restic credentials, or production service state;
- absence of production OpenTofu backend configuration and production API tokens; and
- absence of active target/controller transaction locks.

The target must not share the production PVE root filesystem, `/etc/pve`, ZFS pool, LVM-thin pool, NFS export, cloud-init snippets, VMIDs, or provider state.

Record these facts as canonical JSON conforming to `infrastructure/evidence/disposable-pve-target-admission.schema.json`. Keep both the admission document and dedicated known-hosts file as mode-`0600`, current-controller-owned, single-link regular files. `scripts/controller/validate-disposable-pve-target.js --evidence ABSOLUTE_PATH --known-hosts ABSOLUTE_PATH` rejects stale evidence, production identities/endpoints, credential reuse, shared storage, unsafe files, and host-key drift; its admission SHA-256 is the exact OpenTofu input.

## Required proof

1. Record a clean direct observation and synthetic expected contract.
2. Bootstrap through the bounded first-contact path while retaining console recovery.
3. Converge each approved Ansible tag separately.
4. Run a second convergence and complete audit with `changed=0`.
5. Prove all package, repository, timezone, access, PVE ACL, storage, networking, hardware, Tailscale, firewall, service, and health domains.
6. Produce a canonical `apt full-upgrade` proposal; apply only a separately reviewed synthetic package transaction and prove no automatic reboot.
7. Exercise stale evidence, host-key mismatch, active lock, unauthorized tag, transport widening, dropped connection, firewall interruption, and rollback/refusal paths.
8. Prove conventional key absence, disabled conventional authentication, exact tailnet grants/denials, and denied root.
9. Prove the production VM 100 normalized configuration and production OpenTofu state were never reachable or changed.
10. Destroy or retire every disposable identity, token, plan, state, disk, VM, and network rule with exact absence evidence.

## Disposable Debian guest boundary

`infrastructure/tofu/debian-lifecycle-qualification` may target only an admitted PVE node from this document. Enabled planning requires an exact isolation-attestation SHA-256 plus explicit node, image datastore, disk datastore, bridge, and pre-staged cloud-init snippet identities. The node name and endpoint must not match the production contract. The provider downloads the exact contract-pinned Debian image and verifies its SHA-512 before importing it; it may not reuse the production image-import path. Because provider-managed snippet uploads do not expose strict host-key verification, OpenTofu performs no SSH operation: a separately authorized fixed OpenSSH transaction must install the exact snippet using the admitted single-key known-hosts boundary.

The earlier VM 9900 plan `fe1423e38110f41dabd5600ba0d2ce0bc3471fc1d861b6747fcc1b66b2ebd645` was a read-only provider feasibility preview against the production PVE endpoint. It was never actionable or applied and is not qualification evidence because that host can reach production VM 100 and shared production storage. VM-level firewall rules cannot establish hypervisor/storage isolation.

## Current blocker

The operator selected an existing lab node, but no endpoint, inventory alias, host-key fingerprint, console method, synthetic-storage identity, or network-isolation evidence has been supplied. The controller's read-only tailnet peer list currently exposes only the production Proxmox and Debian hosts; neither is admissible. No PVE qualification connection or mutation is authorized until all target-admission fields above are available.
