# Host lifecycle Phase 1: observation and maintenance-plan fixtures

## Scope and boundaries

Phase 1 adds contract-backed, read-only Ansible observation for lifecycle state, package proposals, and reboot evidence. It does not authorize or implement lifecycle transitions, APT metadata refresh, package installation, reboot, access cutover, firewall mutation, recovery activation, Nix ownership handoff, or disk adoption.

Both maintenance playbooks run against one host at a time (`serial: 1`), use the production Tailscale MagicDNS inventory with strict host-key verification, and remain observable under Ansible check mode. Every emitted package proposal sets `apply_authorized: false`; every reboot observation sets `reboot_authorized: false`.

## Package proposal fixture

`ansible/playbooks/packages-plan.yml` hashes the sorted installed package inventory, records held packages and existing APT metadata age, and invokes only `apt-get --simulate` with APT locking disabled. It records exact candidate versions, origins, security classification, removals, downgrades, and a deterministic proposal digest. Metadata refresh is a separately reviewed operation and was not performed.

Read-only evidence observed at 2026-08-28T08:26Z:

| Host | Installed records | Candidate actions | Security-classified | Holds/removals/downgrades | Proposal SHA-256 |
|---|---:|---|---:|---|---|
| Debian | 373 | 0 install, 0 upgrade | 0 | none | `ca9eff3d46bd179bc93153992ba21509f18b10c39eab40398886d1df29121af1` |
| Proxmox | 1388 | 2 install, 94 upgrade | 33 | none | `08f20f0d96369fcc3912ad76f32c24512d2bbdff6332cf6f37a81ae7aaa42734` |

The Debian proposal is empty using metadata approximately 6.3 hours old. The Proxmox proposal uses metadata approximately 22.9 hours old and remains proposal-only: the PVE, kernel, ZFS, firmware, security-library, and Tailscale set requires a separately saved, reviewed protected-session plan. Neither proposal may be replayed as an apply artifact yet because controller-side artifact persistence and exact apply verification are not implemented.

## Reboot proposal fixture

`ansible/playbooks/reboot-plan.yml` records current and highest installed kernels, boot ID, reboot-required markers, lifecycle locks, workload/storage health, and bounded backup evidence. A valid transaction must subsequently bind exact expected current kernel, target kernel, and pre-reboot boot ID into a saved reviewed plan. Proxmox additionally requires a console attestation; neither host may reboot automatically.

Read-only evidence observed at 2026-08-28T08:27Z:

| Host | Current kernel | Highest installed kernel | Reboot indicated | Health | Backup proof | Authorization |
|---|---|---|---|---|---|---|
| Debian | `6.12.101+deb13-amd64` | `6.12.105+deb13-amd64` | Yes; `/var/run/reboot-required` names `linux-image-6.12.105+deb13-amd64` | Compose active; state, games, and NFS mounts present | Durable Restic chain clear, zero pending records, five Proton mappings, both daily stages successful, evidence age 5,624 seconds | Refused: lifecycle access gaps and saved expected kernel/boot inputs remain |
| Proxmox | `7.0.14-8-pve` | `7.0.14-8-pve` | No | ZFS `storage` healthy; VM 100 running | Not asserted from the host | Refused: saved expected kernel/boot inputs, recent-backup attestation, console attestation, and separate authorization remain |

## Proxmox timezone parity and handoff fixture

`ansible/playbooks/proxmox-timezone-handoff-plan.yml` proves the prospective Ansible timezone state without changing it and reduces the installed Nix observer output instead of exposing its full package inventory. Live evidence confirms both `timedatectl` and `/etc/localtime` resolve to `America/Los_Angeles`; the parity evidence SHA-256 is `2559627c498b4639dfaf9555ce94a8fb04cdfbde80e771dfd653f925a0bf6662`.

The ownership transfer remains refused. The installed Nix observer is still the pre-timezone build (`observer_sha256=b07874efcf4ccf79eacbbabb74eb721cf437e4fa6ceee6041fb1e2de570446d1`, observation SHA-256 `af96e7a16955a41446440e4efb9a4a7158310763a24af3facc852f96dc552792`) and has no timezone domain, while the current repository planning policy and Nix planner/activator sources still declare timezone mutation. The contract therefore retains `current_owner: nix`, `state: pending`, and `target_owner: ansible`; `handoff_ready` and `handoff_authorized` are both false.

The controller fixture proves readiness only when Ansible and Nix parity are both supplied, the handoff is explicitly moved to `ready`, the Nix planning domain is absent, and all Nix timezone mutation sources are absent. Even then it emits only readiness: a saved reviewed handoff plan and separate production authorization remain mandatory.

## Proxmox access cutover fixture

`ansible/playbooks/proxmox-access-cutover-plan.yml` records only reduced account, password-lock, group, shell, sudoers metadata, transport hashes, conventional-key metadata, and effective SSH policy. Live evidence SHA-256 `b541ea5a2c10d2598eaaca5ba5f09211aa865bb1ede36cb69f3efe259a51b48e` confirms that `ansible-plan` and `ansible-deploy` are absent, while `proxmox`, `firewall-apply`, `tofu-plan`, and `tofu-apply` remain. The fixed firewall transport is installed with SHA-256 `0aea8fe5a1328c3d927ab8649707beabb70fe5d3812f789c88255c825085e3ea`.

The controller fixture also proves the repository is not ready for cutover: the tailnet policy has no Proxmox grants/tests for `ansible-plan`, `ansible-deploy`, or `firewall-apply`; production inventory still uses the transitional human account; the firewall controller still targets `firewall-apply@192.168.0.123`; and the fixed firewall login shell requires the conventional forced-command `-c` shape plus `SSH_ORIGINAL_COMMAND`, so it is not yet a proven Tailscale SSH transport.

The plan remains refused while four conventional authorized-key paths exist, OpenSSH pubkey authentication and key-only root login remain enabled, the two tofu identities remain, and the six root PVE keys are not fully attributed. Root is also an explicit member of the otherwise unreferenced `apex` group (GID 1000); a bounded scan found no `apex`-owned paths under `/etc`, `/usr/local`, `/var/lib/home-lab`, or `/home`, but the stale membership still requires attribution or removal during access review. Account creation, tailnet policy changes, transport refactoring, inventory cutover, key removal, OpenSSH tightening, session termination, and tofu-account retirement remain separate ordered transactions. The target privilege model uses a fixed reduced observer for `ansible-plan`, a saved-plan-bound apply path for `ansible-deploy`, and the isolated fixed transaction transport for `firewall-apply`; it does not grant a generic root Python sudo path to the plan identity.

## Saved-plan and transition fixtures

`scripts/controller/save-host-maintenance-plan.js` extracts the reduced package or reboot observation from a check-mode log and can write one root-private, exclusive-create controller artifact under `.local/host-maintenance-plans`. The artifact binds the clean Git commit, contract hash, production inventory hash, independently supplied SSH host-key fingerprint, exact reduced evidence, and the 30-minute observation window. It preserves every exact package candidate and never sets `authorized: true`. The live worktree is intentionally dirty during implementation, and the CLI correctly refuses to save a production plan until these changes are reviewed and committed.

`ansible/playbooks/lifecycle-transition-plan.yml` was exercised read-only for `production -> maintenance` on both hosts. Both plans remain unauthorized because the canonical lifecycle markers have not been adopted and recent-backup attestations were not supplied; Debian additionally remains lifecycle-noncompliant, and Proxmox requires physical-console attestation. No transition task can create or rewrite a marker.

`infrastructure/debian/cloud-init/user-data.inert.fixture` is an unreferenced disposable first-contact candidate. It creates no user or SSH key, performs no package metadata refresh or upgrade, installs only QEMU Guest Agent, and contains no storage UUID, mount, NFS, Tailscale, unattended-upgrade, or production activation data. OpenTofu and the contract continue to reference the current production cloud-init source, so adopting the reduced candidate remains a separately reviewed OpenTofu/cloud-init transaction.
## Gates before implementation can progress

1. Persist normalized proposals as controller-side immutable artifacts bound to commit, contract hash, inventory, host keys, observation age, and exact candidate records.
2. Add an explicit bounded APT metadata-refresh transaction; do not hide refresh inside a supposedly read-only plan.
3. Implement apply-time exact-set verification with no dependency re-solve and reject origin drift, removals, downgrades, holds, conffile prompts, or unexpected service actions.
4. Resolve Debian lifecycle access noncompliance before any reboot transaction.
5. Add reviewed workload drain/start and post-boot audit fixtures; Proxmox must also prove console access and guest/ZFS/firewall recovery checks.
6. Keep automatic reboot disabled and require separate reviewed authorization for every production package apply or reboot.
