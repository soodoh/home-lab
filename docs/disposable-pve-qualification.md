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
 A fresh admission may rebind unchanged server-side snippet authority without mutation through `observe-receipt`; that receipt is source-bound, canonical, and valid only while its exact current observation, ownership, mode, link count, rendered bytes, guest key, known-hosts, target, and admission still match.

The capability installer is `ansible/playbooks/install-qualification-snippet-capability.yml` with `ansible/inventory/proxmox-qualification-bootstrap.yml`. It is excluded from ordinary convergence and accepts only the contract-selected production PVE maintenance route and existing `proxmox` Tailscale bootstrap account. It pins UID/GID 1900, two reviewed executables, the fixed sudo command family, additive `local` snippets content, and explicit absence of conventional authorized-key files. After the saved Tailscale policy grants `qualification-apply`, rerun check mode immediately before one gated apply with `qualification_capability_confirmation=install-production-pve-vm9900-qualification-capability`.

### Guarded stopped-foundation plan

`scripts/controller/debian-lifecycle-qualification.py plan` consumes fresh admission and a freshly revalidated snippet receipt. It reads the existing protected `plan-credentials.json` but exports only the exact PVE plan token, endpoint, and CA; their principal and hashes must match admission. It uses a dedicated private state root and `TF_DATA_DIR`, lifecycle-wide controller/target locks, and permits exactly four create actions: pinned image download, stopped VM 9900, firewall options, and firewall rules. The binary, JSON, and authorization manifest are hash-bound; `authorized` and `automatic_apply` remain false.

A foundation apply uses the existing production `apply-credentials.json` but exports only the exact apply token, endpoint, and CA into a sanitized environment. It requires the saved plan SHA and manifest authorization SHA each repeated exactly plus `CREATE_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. It revalidates admission, server-side snippet bytes, Git revision, provider identities, state, locks, and plan JSON, then applies the saved binary without replanning. Failure after mutation is never retried automatically; success leaves `vm_started: false`.

`scripts/controller/debian-lifecycle-qualification-transitions.py` separately plans start, bounded network repair, stop, restart, and destroy. Start accepts only a stopped-foundation receipt, permits only `started: false` to `true`, keeps `on_boot: false`, and requires `START_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. Stop accepts an exact successful start or restart receipt for offline inspection, or the legacy bounded-repair receipt, and requires `STOP_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_FOR_OFFLINE_INSPECTION`; only `started: true` to `false` is permitted. Fresh admission is the default; bounded expired admission is available only through the explicit stop-only `--allow-expired-admission` flag. When used, the contract-backed validator's four-hour `expired-safe-stop` mode and exact current server-side mutation or observation snippet receipt remain mandatory. Destroy accepts only the established successful restart chain, permits only the four qualification resources, and requires `DESTROY_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900`. None replans or retries.
 A restart may consume the exact stopped receipt from the prior admission only when a fresh admission independently re-establishes the same contract target; the new restart plan and receipt bind the fresh admission while preserving the stopped-receipt and host-key chain.

### Clean first-boot proof

After a separately approved destroy/recreate/start cycle using the corrected snippet, `scripts/controller/debian-qualification-first-boot.py` uses only the dedicated strict Tailscale forced-command route. It holds the lifecycle controller lock while validating exact canonical foundation/start receipts and excludes intervening transaction receipts. The fixed root helper holds both the shared host operation descriptor lock and metadata-validated qualification target lock throughout observation, refuses an active capability installation, and rechecks producer/snippet identities before returning. The helper checks firewall-enabled `net0`, live PVE firewall options and all nine ordered rules, QGA ping, the sole recorded guest boot identity, completed error-free cloud-init, the installed and active QGA package, public DNS/HTTPS, and supplemental blocked private/CGNAT probes. The inclusive PVE-minus-guest uptime bound remains **-2 through 120 seconds**; synthetic producer/controller tests cover both endpoints and immediately outside them.

The controller now requires `--snippet-receipt` (the exact apply or observation receipt referenced by foundation/start) and `--guest-public-key` (the admitted dedicated temporary **public** key, never its private key). It independently renders the current qualification template using the contract and that key, checks the snippet receipt's canonical bytes, filename, identity, size and digest, and requires equality with the start receipt's snippet digest. A fresh random challenge and admission/foundation/start/snippet receipt hashes travel over stdin to the existing `first-boot` command; no additional sudo or SSH command authority is introduced.

The returned envelope must echo that exact request and independently observed installed helper, transport and sudoers hashes. Installed hashes bind Ansible's file-lookup/copy bytes (trailing whitespace stripped); separate source hashes describe repository bytes, not an installation assertion. Under the locks, the helper verifies the exact VM9900 `cicustom` file ID and cloud-init disk, hashes the protected server snippet, and hashes the guest's root-owned cloud-init instance `user-data.txt` through QGA. The booted cache digest, installed snippet digest, start digest and independently rendered expected digest must all agree. Guest instance-directory traversal and the bounded cache read reject symlinks outside cloud-init's expected instance link, unsafe metadata and observed replacement/content races. Missing envelopes, stale producers, replayed challenges, template drift, malformed evidence or publication failures cannot produce readiness and do not trigger a retry.

The clean receipt is now `home-lab-debian-qualification-clean-first-boot-receipt-v2`, with the validated envelope in `provenance` and the exact `snippet_receipt_sha256`. `commit` identifies the observer revision; `booted_template_commit` and `template_sha256` identify the **current source whose rendered bytes were proved equal to the booted cache**, not a claim that a historical start used the current observer. Foundation/start hashes preserve that separate historical lineage. Historical v1 local-hash-only receipts must not be upgraded or accepted as v2 proof.

**Integration/deployment gate:** the host-key consumer now requires the exact v2 envelope/source/stopped-chain bindings and a content-addressed receipt filename; it rejects v1 evidence. Producer-to-consumer, provenance and cache-reader suites are registered in authoritative validation. Cache-reader filesystem tests run only inside disposable root-confined Linux fixtures (and explicitly skip on unsupported controllers); they include FIFO/short-read/replacement/mode-change refusal. Reinstall/check the changed helper through the separately approved capability playbook, retain its exact installed identity evidence, and obtain a fresh foundation/start/first-boot chain before using the new receipt. No changed helper bytes are installed by a repository edit.

A failed first boot may be diagnosed only after the exact guarded stop receipt. The authoritative contract permits a four-hour expired-admission grace exclusively for `read_only` offline diagnosis of `local-lvm:vm-9900-disk-0`. `scripts/controller/debian-qualification-first-boot-diagnostic.py` requires a canonical four-hour plan, exact approval, unchanged stopped receipt/state/revision, and the dedicated strict forced-command route. The shared target and VM backup locks guard a read-only NBD attachment and `ro,noload,nodev,nosuid,noexec` mount; bounded descriptor-safe reads publish only file hashes, package state, structured cloud-init result, fixed diagnostic signals, and redacted error excerpts before verified cleanup.

## Current gate — reviewed 2026-09-05

The initial capability/Tailscale-grant gate below the original route has been superseded by the recorded [warm repair](../infrastructure/evidence/debian-minimal-cloud-init-qualification-2026-09-04.json) and [inert canary/lock recovery](../infrastructure/evidence/debian-lifecycle-transaction-qualification-2026-09-05.json). Neither proves clean first boot or complete cold recovery.

The latest inspected private invocation-failure record, at 2026-09-05T19:34:17Z, identifies restart plan `09f7429ea9d5a0bf9d059470c8eb16fe10faf56b81e87fcfbaa942081f9c2976`, failure `incorrect-snippet-receipt-path`, and a post-failure VM9900 state of `stopped`. This is historical local evidence, not a fresh live observation. Automatic retry is explicitly forbidden. Preserve the receipts and state; re-establish current host trust, VM100 invariants, VM9900 state and locks, then obtain fresh admission and a separately reviewed new plan. Do not resume an expired plan or delete persistent mutex files.

Clean first boot must ultimately use a new foundation/start chain without restart/repair receipts. Packages, reboot, root-disk changes, resource destruction, authority cutover, and credential removal still require fresh exact approval. See [the completion review](host-lifecycle-completion-review-2026-09-05.md) before scheduling further qualification.
