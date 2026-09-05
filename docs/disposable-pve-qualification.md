# Disposable official-PVE qualification

Gate 3 now follows the accepted `production-pve-disposable-vm` route in `infrastructure/contract/home-lab.yml` and the ADR amendment. Proxmox parity is qualified against the production PVE host; Debian first contact is qualified in disposable VM 9900 on that host. The operator accepts shared-hypervisor and host-outage risk, but VM 100, production disks, production state, and production guest credentials remain prohibited inputs.

## Target admission

Before any connection or plan, record and independently verify:

- the exact contract PVE API endpoint, node name, release, package origin, API CA, SSH host key, and attended physical-console path;
- the existing `root@pam!tofu-plan` and `root@pam!tofu-apply` API identities, used only through the VM9900 action inspectors and sanitized controller environment;
- a new dedicated `qualification-apply` fixed SSH identity and a distinct temporary guest first-contact key;
- `local` snippets/import storage and a single new `local-lvm` 32 GiB VM9900 disk with no production serial, UUID, attachment, passthrough, backup, or state identity;
- VM firewall defaults of DROP, bounded controller SSH, RFC1918 and CGNAT/Tailnet egress denial before public egress, and independent post-start proof that the guest cannot reach VM 100 or production services;
- an empty private OpenTofu state root dedicated to this qualification, never the production backend; and
- absence of active PVE/controller, package, reboot, firewall, backup, VFIO, or recovery locks.

The production root filesystem, `/etc/pve`, and storage pools are shared by explicit risk acceptance; they are not described as isolated. Every plan must contain only VM9900 qualification resources, and direct before/after observations must prove VM 100 unchanged.

Record these facts as canonical JSON conforming to `infrastructure/evidence/disposable-pve-target-admission.schema.json`. Keep admission and known-hosts artifacts as mode-`0600`, current-controller-owned, single-link regular files. `scripts/controller/validate-disposable-pve-target.js` accepts only the contract-selected production route, exact production plan/apply principals, the temporary `qualification-apply` Tailscale SSH user, fresh evidence, expected shared-storage declaration, and exact host trust.

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

`infrastructure/tofu/debian-lifecycle-qualification` accepts only the contract-selected production PVE node and API endpoint. Enabled planning requires an exact admission SHA-256 plus explicit local image/disk/bridge and pre-staged cloud-init snippet identities. The provider downloads the exact contract-pinned Debian image and verifies its SHA-512 before importing it. Because provider-managed snippet uploads do not expose strict host-key verification, OpenTofu performs no SSH operation: a separately gated fixed OpenSSH transaction installs and verifies the exact snippet.

The earlier VM 9900 plan `fe1423e38110f41dabd5600ba0d2ce0bc3471fc1d861b6747fcc1b66b2ebd645` remains historical and unusable: it predates the accepted-route contract, API CA/principal binding, temporary Tailscale-only PVE capability, dedicated guest key, server-side snippet receipt, lifecycle-wide locks, and exact create/start/destroy inspectors. A fresh plan is mandatory.

### Guarded snippet prerequisite

After target admission and separate capability installation, `scripts/controller/debian-qualification-snippet.py plan` validates the admission and dedicated known-hosts artifacts, requires exactly one admitted PVE SSH-agent key, binds a distinct protected guest public key, renders the shared template, observes the fixed `local:snippets/home-lab-debian-lifecycle-qualification.yaml` target, and writes an expiring mode-`0600` saved plan. The plan is non-authorizing and cannot be applied automatically.

A separately approved apply must provide the plan SHA twice plus `PRODUCTION_PVE_VM9900_SNIPPET_CONFIRMED`. The fixed forced transport and host transaction sources under `infrastructure/qualification/host/` accept only `observe`, `hold-lock`, or the exact approved plan. They reject precondition drift; create only into an absent target; and permit replacement only when the protected before-observation matches exact safe existing bytes. Replacement is an fsynced atomic CAS with verified rollback to the descriptor-read original bytes on postcondition failure. Every success returns a canonical receipt, and the guarded OpenTofu controller independently rechecks the server-side SHA-256.

The capability installer is `ansible/playbooks/install-qualification-snippet-capability.yml` with `ansible/inventory/proxmox-qualification-bootstrap.yml`. It is excluded from ordinary convergence and accepts only the contract-selected production PVE maintenance route and existing `proxmox` Tailscale bootstrap account. It pins UID/GID 1900, two reviewed executables, the fixed sudo command family, additive `local` snippets content, and explicit absence of conventional authorized-key files. After the saved Tailscale policy grants `qualification-apply`, rerun check mode immediately before one gated apply with `qualification_capability_confirmation=install-production-pve-vm9900-qualification-capability`.

### Guarded stopped-foundation plan

`scripts/controller/debian-lifecycle-qualification.py plan` consumes fresh admission and a freshly revalidated snippet receipt. It reads the existing protected `plan-credentials.json` but exports only the exact PVE plan token, endpoint, and CA; their principal and hashes must match admission. It uses a dedicated private state root and `TF_DATA_DIR`, lifecycle-wide controller/target locks, and permits exactly four create actions: pinned image download, stopped VM 9900, firewall options, and firewall rules. The binary, JSON, and authorization manifest are hash-bound; `authorized` and `automatic_apply` remain false.

A foundation apply uses the existing production `apply-credentials.json` but exports only the exact apply token, endpoint, and CA into a sanitized environment. It requires the saved plan SHA and manifest authorization SHA each repeated exactly plus `CREATE_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. It revalidates admission, server-side snippet bytes, Git revision, provider identities, state, locks, and plan JSON, then applies the saved binary without replanning. Failure after mutation is never retried automatically; success leaves `vm_started: false`.

`scripts/controller/debian-lifecycle-qualification-transitions.py` separately plans start, bounded network repair, stop, restart, and destroy. Start accepts only a stopped-foundation receipt, permits only `started: false` to `true`, keeps `on_boot: false`, and requires `START_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. Stop accepts an exact successful start receipt directly for failed-first-boot offline inspection, or the legacy bounded-repair receipt, and requires `STOP_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_FOR_OFFLINE_INSPECTION`; only `started: true` to `false` is permitted. Destroy accepts only the established successful restart chain, permits only the four qualification resources, and requires `DESTROY_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. None replans or retries.

### Clean first-boot proof

After a destroy/recreate/start cycle using the corrected snippet, `scripts/controller/debian-qualification-first-boot.py` uses only the dedicated strict Tailscale forced-command route. It holds the lifecycle controller lock while validating exact canonical foundation/start receipts, excludes intervening transaction receipts, and the fixed root helper acquires the metadata-validated shared target lock throughout observation. The helper requires an exact firewall-enabled `net0`, live PVE firewall options and all nine ordered rules, QGA ping, a guest/PVE-QEMU uptime delta of at most 30 seconds plus the sole recorded guest boot identity, completed error-free cloud-init, the installed and active QGA package, public DNS/HTTPS, and supplemental blocked private/CGNAT probes. The canonical receipt binds the clean pushed observer revision and exact helper, transport, template, historical admission, foundation, start, and observation bytes.

## Current gate

The first capability apply enabled `local` snippets and installed the fixed account/assets but exposed that Tailscale policy did not yet authorize `qualification-apply`; conventional OpenSSH was correctly disabled. The production owner lock was released. Next apply the saved Tailscale-only grant, rerun the capability transaction to remove the now-inert authorized-key file, prove the fixed connection, and capture a new admission with `snippet_content_enabled: true`. Packages, reboot, root-disk changes, resource destruction, authority cutover, and credential removal still stop for fresh exact approval.
