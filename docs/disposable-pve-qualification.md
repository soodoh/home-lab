# Disposable official-PVE qualification

Gate 3 requires an independently identified official Proxmox VE target. Repository fixtures, the production node, a Debian guest, and the prior VM 9900 recovery guest cannot substitute for an isolated PVE installation.

## Target admission

Before any connection or plan, record and independently verify:

- endpoint and inventory alias;
- official PVE release and package origin;
- out-of-band console path;
- dedicated plan and apply identities with no production credentials;
- an independently verified PVE API CA bundle and exact SHA-256;
- dedicated mode-`0600`, single-link known-hosts and PVE public-key files with exact host-key and SSH-agent fingerprints;
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

### Guarded snippet prerequisite

After target admission and separate capability installation, `scripts/controller/debian-qualification-snippet.py plan` validates the admission and dedicated known-hosts artifacts, requires exactly one admitted PVE SSH-agent key, binds a distinct protected guest public key, renders the shared template, observes the fixed `local:snippets/home-lab-debian-lifecycle-qualification.yaml` target, and writes an expiring mode-`0600` saved plan. The plan is non-authorizing and cannot be applied automatically.

A separately approved apply must provide the plan SHA twice plus `DEBIAN_QUALIFICATION_SNIPPET_CONFIRMED`. The fixed forced transport and host transaction sources are under `infrastructure/qualification/host/`; they accept only `observe` or the exact approved plan, acquire a target lock, reject precondition drift or existing different bytes, use an atomic fsynced create, and return a canonical receipt. The guarded OpenTofu controller must consume that receipt and independently recheck the server-side SHA-256 before VM planning. These host assets are repository-only and are not installed on any target.

### Guarded stopped-foundation plan

`scripts/controller/debian-lifecycle-qualification.py plan` consumes only fresh admission output and a freshly revalidated snippet receipt. It requires canonical protected `qualification-plan-credentials.json` with exactly `version`, `format`, `purpose`, `principal`, `endpoint`, `api_token`, and `ca_pem`; the principal, endpoint, and CA SHA-256 must match admission. It uses a dedicated mode-private state root and `TF_DATA_DIR`, a sanitized provider environment, controller and target locks, and permits exactly four create actions: pinned image download, stopped VM 9900, firewall options, and firewall rules. The saved binary and rendered JSON are hash-bound; the manifest is actionable only as a proposal and remains `authorized: false` with no automatic apply.

A foundation apply requires a distinct canonical `qualification-apply-credentials.json`, the saved plan SHA and manifest authorization SHA each repeated exactly, and `CREATE_ISOLATED_DEBIAN_QUALIFICATION_9900`. It revalidates admission, the server-side snippet bytes, Git revision, provider identities, state hash, target lock, and exact plan JSON, then applies the saved binary without replanning. Failure after mutation is `tofu-apply-no-retry`; no automatic retry or start follows. A successful receipt still records `vm_started: false`.

`scripts/controller/debian-lifecycle-qualification-transitions.py` implements separately planned start and destroy operations. Start accepts only a stopped-foundation receipt, permits one in-place VM 9900 update from `started: false` to `true`, keeps `on_boot: false`, and requires `START_ISOLATED_DEBIAN_QUALIFICATION_9900`. Destroy accepts only a successful start receipt, permits deletion of exactly the four qualification resources, and requires `DESTROY_ISOLATED_DEBIAN_QUALIFICATION_9900`. Both bind an exact prior receipt, state, admission, snippet, API identities, saved plan, authorization manifest, and target lock; neither replans during apply or retries a failed mutation.

## Current blocker

The operator selected an existing lab node, but no endpoint, inventory alias, host-key fingerprint, console method, synthetic-storage identity, or network-isolation evidence has been supplied. The controller's read-only tailnet peer list currently exposes only the production Proxmox and Debian hosts; neither is admissible. No PVE qualification connection or mutation is authorized until all target-admission fields above are available.
