# Host lifecycle Phase 0 baseline

This document records the discovery baseline for consolidating Proxmox and Debian host lifecycle management under Ansible. It is evidence and design input, not mutation authority.

## Evidence boundary

- Repository: clean `main` at `38c01635b8f71afdbe69670e4cf4a7cdb6c53f2e`.
- Collection: 2026-08-27 PDT / 2026-08-28 UTC.
- Protected values remain in ignored mode-0600 files under `.local/lifecycle-discovery/`; this document records only reduced facts.
- The Proxmox observer installed before `38c0163` lacks the newly added `timezone` domain. The operator explicitly waived that mismatch for Phase 0 because timezone will move to Ansible. The waiver is not a zero-drift assertion and the Nix timezone action must not be applied.
- One separately authorized production action occurred: a guarded Restic catch-up after the daily timer correctly failed with `reason=concurrent_deploy`. The deploy lock, backup lock, and interruption journal were absent before the run. Local/NFS snapshot `a67ed70a…` and Proton replication completed successfully; the follow-up audit was `ok=54 changed=0 failed=0`.

## Verified live baseline

| Boundary | Verified state | Evidence/result |
|---|---|---|
| Proxmox identity | Debian amd64, `pve-manager/9.2.3`, kernel `7.0.14-8-pve` | Forced read-only observer and independent Tailscale SSH inspection |
| Proxmox convergence | All pre-timezone observer domains complete; protected access `6/6`, protected hardware `3/3`, PVE access `3/3`, firewall `7/7`, storage `6/6`, health `2/2` | Observation SHA-256 `af96e7a16955a41446440e4efb9a4a7158310763a24af3facc852f96dc552792` |
| Proxmox storage | ZFS pool `storage` ONLINE; live NFS/storage/VFIO summaries match the installed policy | Observer plus `zpool list/status` |
| VM 100 | Running, protected, on-boot, 24 cores, 65536 MiB, q35; boot `scsi3;net0`; no pending VM configuration | `qm config`, `qm pending`, OpenTofu plan |
| VM 100 disks | `scsi0` absent; `scsi1` protected raw games disk; `scsi2` `vm-100-disk-1` 128 GiB; `scsi3` `vm-100-disk-2` 64 GiB; cloud-init on `ide2` | Matches contract; `scsi3` remains omitted from the resource's `disk` blocks |
| OpenTofu | Zero-change current plans for AWS foundation, Proxmox, Omada, Tailscale, and Authentik | Live remote state; Proxmox state contains `proxmox_virtual_environment_vm.debian` and five hardware mappings |
| Tailnet policy | Live policy equals desired policy byte-for-byte after canonicalization | SHA-256 `983273a2f37c6b01b5b9c7c3d6f19537b687f7376c9011ecb644d274b4a7374e`; 5 grants, 5 SSH rules, 2 network tests, 3 SSH tests |
| Debian identity | Debian 13 trixie, kernel `6.12.101+deb13-amd64`, timezone `America/Los_Angeles` | Ansible facts and read-only commands |
| Debian storage | `/dev/sdc1` root, games UUID-backed ext4 at `/mnt/games`, state ext4 at `/srv/home-lab-state`, NFSv4 `192.168.0.123:/storage/docker` at `/mnt/storage` | Audit and `findmnt` |
| Compose | Artifact `31a2fe455d849ab38d373709ee39cd6378406708c1de29e43b6e410eb21ca213`; 38 declared and 38 running services | Live artifact recomputation and exact CLI identity |
| Compose images | All 37 committed service image IDs match live; `nextcloud-cron` is the 38th runtime record and shares the `nextcloud` image ID | 34 live unique image IDs versus 33 committed references because the runtime lock records IDs rather than source references |
| Restic | Daily local/NFS and Proton stages last completed 2026-08-27 23:38/23:55 PDT; timers enabled; no guard residue | Catch-up journals and clean audit |
| SSH host keys | Debian QGA key equals tailnet keyscan and committed evidence; Proxmox host key equals LAN and tailnet keyscan | Debian fingerprint `SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ`; Proxmox fingerprint `SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ` |
| Locks | Controller lock file has a dead recorded PID and no flock; Debian deploy/backup locks absent; Proxmox operation lock has no holder; firewall journal is terminal `committed` | Five retained Nix rollback sessions are all `released-committed` with no pending transition |

## Ownership matrix

| Domain | Current authority | Final authority | Boundary that must remain |
|---|---|---|---|
| Shared facts and safety policy | `infrastructure/contract/home-lab.yml` | Same file, consumed directly | No generated parallel contract; schema and semantic validation remain mandatory |
| AWS, Omada, Authentik, tailnet policy | OpenTofu through saved controller plans | OpenTofu | Saved plan only, remote state lock, policy inspection, no apply-time replan |
| VM 100 and PVE hardware mappings | OpenTofu | OpenTofu | `prevent_destroy`, exact resource address, protected disk/device identities, one reviewed plan |
| VM 100 root disk `scsi3` | Contract/audit protection only | OpenTofu only after disposable qualification | No production declaration until TypeList/adoption behavior proves update-only |
| Proxmox host OS | Nix protocol-v4 bundle/controller | Ansible | Domain-by-domain adoption; never simultaneous mutation ownership |
| Proxmox PVE firewall | Separate console-authorized API transaction installed by Nix bootstrap | Separate transaction, with Ansible only installing/auditing fixed assets | Preserve local-console authorization, rollback timer, canaries, CAS digest, and cross-authority lock |
| Debian host OS | Ansible | Ansible with explicit lifecycle states | Check mode, exactly one approved tag, apply confirmation, host owner lock |
| Workload graph | Compose source plus deterministic artifact | Same | Exact project/directory/env/file identity; no steady-state build or pull |
| Images | Committed source-reference lock plus runtime ID locks | Same, updated by reviewed automation | Digest pins, current/previous locks, rollback window, no mutable-tag apply |
| Secrets | SOPS/age and protected controller/host files | Same | No secret in Git, plan, logs, Nix store, or generated contract projection |
| Backups and restore | Restic runner, three repositories, staging-only recovery | Same | RPO/RTO, mutexes, exact snapshot/artifact identity, native verify, no in-place overwrite |
| Ordering and authorization | `scripts/local-controller` and `scripts/reconcile-infrastructure` | Controller invoking OpenTofu and lifecycle-aware Ansible | Clean commit, saved plans, exact confirmations, descriptor/host locks, no replan on apply |
| Bootstrap and break glass | Physical console, bounded cloud-init, protected tools | Physical console plus minimal first-contact Ansible | No network-only recovery assumption; reboots and destructive recovery remain separately reviewed |

## Conventional authorized-key retirement matrix

The target is Tailscale SSH only in steady state. Every conventional `authorized_keys` and `authorized_keys2` file must be absent, `PubkeyAuthentication` must be disabled for OpenSSH, and `PermitRootLogin` must be `no`. Host-key verification remains strict.

| Host/path or source | Live state | Current consumer | Required replacement and retirement gate |
|---|---|---|---|
| Debian `/root/.ssh/authorized_keys` | Empty mode-0600 file | None | Remove file; keep console recovery and `PermitRootLogin no` |
| Debian `/home/ansible-deploy/.ssh/authorized_keys` | One key, fingerprint `SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w` | Legacy controller key | Tailscale SSH already works for `ansible-deploy`; remove only after independent plan/apply canaries and host-key proof |
| Debian cloud-init embedded `docker` key | Source still embeds the same key; live `/home/docker/.ssh/authorized_keys*` is absent | First contact only | Replace with bounded, expiring first-contact authorization; cloud-init must not create durable workload/admin access |
| Proxmox `/home/tofu-plan/.ssh/authorized_keys` | Forced observer key, fingerprint `SHA256:u5YBkCDR2y9yRC1hvpd7zHUqOZOYKzU1ojBPPDNx0Bs` | Nix planner over LAN | Move observation to Ansible `ansible-plan` over MagicDNS/Tailscale SSH; preserve strict host keys and reduced evidence before removal |
| Proxmox `/home/tofu-apply/.ssh/authorized_keys` | Forced transport key, fingerprint `SHA256:aa8zg7MLx6q//zTZfvHpJx136UVLgOl5aULaxDV2n8g` | Nix prepare/apply | Retire only after all retained Nix sessions are terminal, Ansible rollback parity is proven, and rollback window closes |
| Proxmox `/home/firewall-apply/.ssh/authorized_keys` | Forced firewall key, fingerprint `SHA256:YUQQfpL0WvPdLoxVuQ1ZGDG7aM7941CpKd7RGeCeiQQ` | Firewall controller | Add and test a dedicated tailnet SSH rule for `firewall-apply`, refactor transport to MagicDNS, and prove LAN/tailnet/TLS/NFS canaries before removal |
| Proxmox human `proxmox` | Its home has no conventional key files; Tailscale SSH works | Human administration | Retain Tailscale-only path; keep physical console as break glass |
| Proxmox `/root/.ssh/authorized_keys` | Symlink to `/etc/pve/priv/authorized_keys`; target is root:www-data mode 0600 with six keys (three RSA, three ED25519), including legacy fingerprint `SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w` | Recovery/provider helper assumptions plus five keys requiring owner attribution | Inventory every consumer, move VM9900 snippet/import and remaining recovery paths away from unrestricted root SSH, remove the key set and symlink, then set `PermitRootLogin no` |
| Controller private keys `home-lab-arch-ansible`, `home-lab-proxmox-{plan,apply,firewall,lan-canary,tailnet-canary}` | Present outside Git | Matching rows above; VM9900 and firewall canaries also consume the legacy key | Delete only after repository caller scan is empty, host files are absent, recovery replacement is proven, and a rollback window has expired |

Current documentation that says Debian has no conventional authorized keys is inaccurate until the two live files above are removed.

## Tailnet access matrix

| Source | Destination/user | Live | Final decision |
|---|---|---:|---|
| owner | Docker `docker` | yes | Retain for human workload administration |
| owner/admin | Docker `ansible-deploy` | yes | Retain for mutation only |
| owner/admin | Docker `ansible-plan` | no | Add and make plan/check inventory use it; keep its narrow sudo surface |
| owner | Proxmox `proxmox` | yes | Retain for human administration |
| owner/admin | Proxmox `tofu-plan`, `tofu-apply` | yes | Transitional only; remove with Nix identities |
| owner/admin | Proxmox `ansible-plan`, `ansible-deploy` | no | Add before Proxmox Ansible adoption, with distinct plan/apply sudo policies |
| owner/admin | Proxmox `firewall-apply` | no | Add before conventional firewall-key retirement; keep fixed transport command |
| any tailnet principal | root on either host | denied by tests | Keep denied |
| Docker tag | Proxmox API `tcp:8006` | yes | Retain for bounded host/API dependency |
| Docker tag | Proxmox SSH `tcp:22` | denied by test | Keep denied; Ansible originates from the protected controller, not Docker |

Policy updates must retain positive and negative network/SSH tests, canonical live-policy identity, ETag compare-and-swap, and a saved OpenTofu plan.

## Package and reboot matrix

| Host/domain | Live state | Automatic safe action | Separately reviewed action |
|---|---|---|---|
| Debian security packages | Security-only unattended upgrades active; no package upgrade currently pending | Continue security-origin downloads/applies with Ansible-managed policy and evidence | Distribution/package-set changes and failures |
| Debian kernel | `6.12.105` installed while `6.12.101` runs; `/var/run/reboot-required` names the new kernel | Detect and report only | Guarded reboot after Compose/Restic health, recent backup, console/Tailscale proof, and post-boot audit |
| Proxmox packages | Exact installed manifest matches observer; updates are available, including PVE UI, kernel `7.0.14-14`, ZFS `2.4.4`, firmware, security libraries, and Tailscale | Refresh metadata and produce a bounded reviewed candidate manifest only | Package apply under protected session after ZFS/PVE/VM/backup checks |
| Proxmox reboot | Running kernel matches committed package baseline; no reboot currently required | Detect and report only | Console-confirmed reboot with VM shutdown/start ordering, ZFS health, firewall recovery, and post-boot audit |
| Compose images | Live IDs match committed lock for all 37 governed services; steady runtime has 38 records including duplicate-image `nextcloud-cron` | Open reviewed update proposals with digest and model diffs | Deploy only the saved artifact/image plan; no automatic pull on host |
| Tailscale binaries | Update checks enabled; automatic apply disabled | Detect candidate version | Apply through host package workflow, preserving SSH access canaries |
| Firmware/hardware | Stable protected identities | Inventory only | Maintenance window with rollback/console plan |

There is no committed CI workflow and `package.json` has no scripts entry. Any future scheduler must therefore be explicitly added, least-privileged, plan-only by default, and unable to bypass the local controller.

## Implementation blockers and required gates

1. Add lifecycle-aware Proxmox Ansible roles with parity for every Nix domain before retiring any Nix helper.
2. Introduce explicit `inert`, `bootstrap`, `production`, and `recovery` assertions; adopt the currently out-of-band storage activation token.
3. Add separate Ansible plan/apply identities and tailnet rules, then prove both before key removal.
4. Preserve all five terminal Nix rollback sessions and the committed firewall journal until a reviewed migration/retention decision.
5. Reconcile `candidate-state-move.tf`: live state and the zero-change plan prove `.debian` is the only VM resource, while the file still names obsolete `.debian_readopted` and `.arch` addresses.
6. Qualify `scsi3` adoption only on disposable infrastructure as specified in `docs/opentofu-disk-adoption-feasibility.md`.
7. Keep recovery, SOPS/age, Restic, Compose, OpenTofu saved-plan, firewall rollback, and controller-lock boundaries intact throughout migration.
