# Debian lifecycle profiles

`ansible/playbooks/site.yml` requires one inventory-selected profile and never defaults to production.

## Profiles

- `inert`: only the guarded base role is reachable. Protected mounts must be absent or unmounted empty directories. Docker, Compose, Restic, and Tailscale units must be absent or disabled and inactive. Tailscale state and the production age identity must be absent.
- `recovery`: only the guarded base role is reachable. It has the same mount and service stop gates as `inert`. A separately recovered age identity may already exist only as a single-link root-owned `0600` regular file; ordinary convergence does not create it. Tailscale state remains forbidden until its separate enrollment transaction.
- `production`: the lifecycle marker and production invariants must pass before any production-only role is reachable. Storage, Docker, Tailscale, SOPS/age, Restic, Compose, hardware, SSH, host files, and health remain production-gated.

The guard runs before the apply guard and before the host lock. It only observes and refuses; it does not mount, enroll, restore, start, enable, or create protected state. The inactive unit set includes Docker socket activation and every declared Restic timer, target, worker, and recovery service.

### Inactive protected-path observation

The role executes its separately tested [`debian-inactive-path.py`](../ansible/roles/debian_lifecycle_guard/files/debian-inactive-path.py) source through the read-only Python command task, including in check mode; it does not install a helper or create protected directories.

- Only canonical absolute non-root paths are accepted. Starting at a pinned `/` descriptor, `openat2` opens one directory component at a time with `O_PATH`, `O_DIRECTORY`, `O_NOFOLLOW`, `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_XDEV`. Neither ancestor symlinks (including dangling/magic links) nor mount crossings are followed. Same-filesystem bind mounts are crossings too; `st_dev` equality is not sufficient.
- `statx(AT_EMPTY_PATH)` supplies mount ID and inode/metadata identity for every descriptor. Every existing directory, including `/` and ancestors, must be root:root, not group/other-writable, and remain on the root mount. A separate filesystem or bind mount at `/srv` or `/mnt` therefore refuses admission as well as one at the protected leaf. The contract declares `/srv/home-lab-state`, `/mnt/games`, and `/mnt/storage`, but no separate ancestor filesystems; an unexpected ancestor mount requires review, not a fallback or silent exception.
- Enumeration uses only a separately identity-checked readable descriptor opened relative to the pinned target; it inspects at most one entry and never opens/stats child entries. **Every entry is refused**, including hidden files, symlinks and root-owned readiness tokens. The separate `/etc/home-lab/allow-storage-activation` gates are unchanged; there is no token exemption under inactive protected paths.
- Retained descriptor metadata and reopened namespace edges are compared before and after enumeration. Missing components must still be absent on recheck with stable parent metadata. Permission errors, syscall errors (including race-related `EAGAIN`), incomplete metadata, identity drift, non-directories and unsupported observations fail closed without retries or success JSON.

This requires Linux x86_64, the libc `statx` wrapper, `openat2` (Linux 5.6+) and `STATX_MNT_ID` (Linux 5.8+). The contracted Debian kernel is `6.12.107+deb13-amd64`, so its upstream ABI includes these features; syscall filtering, filesystem support and actual image availability still need disposable qualification. Other platforms/architectures and blocked or unavailable syscalls are refused, not emulated in production.

The threat model includes hostile path contents, symlinked/renamed ancestors, bind/overmount substitution and inspection/open races. Trusted root-owned, non-writable ancestors prevent unprivileged replacement; no-follow/no-crossing opens prevent accidentally reading redirected or mounted contents. Descriptor and namespace rechecks reject observed races. This is **not** an atomic filesystem snapshot, a lock, protection against a malicious kernel/root actor able to change and restore namespace state between observations, or authorization for subsequent writes. Cooperating privileged writers must still honor the existing controller/host locks and transaction rechecks; the guard itself runs before the host lock and cannot promise future inactivity.

Run `python3 scripts/controller/test-debian-inactive-path.py` for synthetic hostile filesystem, mount, race, syscall-ABI and failure fixtures. These tests do not perform actual mounts or claim Linux/live qualification. Real bind-mount/namespace and two-run convergence proof remains restricted to a separately approved disposable Linux target; VM100 and production filesystems/credentials are not inputs.

## Base ownership

The contract owns locale `C.UTF-8`, matching the adopted Debian host. The base role owns `/etc/locale.conf` as `root:root 0644` and `/etc/default/locale` as the compatibility symlink `../locale.conf`. The production check is zero-change.

Package installation is no longer implicit. `apt_packages` can report missing packages in check mode, but any installation requires a separately supplied exact `name=version` set matching every missing package and an explicit reviewed authorization. It never refreshes APT metadata.

## Entry points

- `ansible/inventory/debian-inert.yml`: strict-host-key disposable inert target.
- `ansible/inventory/production.yml`: adopted production target with `lifecycle_profile: production`.
- `ansible/playbooks/debian-lifecycle-audit.yml`: lifecycle-only read-only audit.
- `ansible/playbooks/site.yml`: one-tag guarded convergence.
- `ansible/playbooks/audit.yml`: lifecycle guard plus complete production audit.

At the repository milestone that introduced these guards, the production lifecycle audit completed with `changed=0`, and the complete production audit completed with `changed=0`. The base-tag check also completed with `changed=0` after preserving the adopted locale symlink topology.

## Remaining proof boundary

Repository validation and current-production checks do not substitute for disposable proof. Gate 5 remains incomplete until an independently identified disposable Debian guest proves inert convergence, second-run zero change, inactive protected services/timers, no Tailscale enrollment, no age identity creation, and safe empty inactive mountpoints. No production mutation is authorized by this document.

The later [warm-repair evidence](../infrastructure/evidence/debian-minimal-cloud-init-qualification-2026-09-04.json) and [canary/lock-recovery evidence](../infrastructure/evidence/debian-lifecycle-transaction-qualification-2026-09-05.json) are bounded positive milestones, not a clean first boot or full two-run base/recovery proof. The following 2026-09-03 plan is historical and has been superseded by the [shared-hypervisor VM9900 route](disposable-pve-qualification.md); it must not be resumed.

A read-only provider `0.111.1` refresh on 2026-09-03 produced exactly one VM 9900 create action from an empty private state. The protected saved plan SHA-256 is `b2c18f9c3fb46ca7cf39f946e98b9439c7ec6ead394eef61e6aad476f7042ba6`; its JSON SHA-256 is `b79e6f5a4616aca3c5b456203548d94a16c38b8984ad7e01f7ab2d6f6c4b489b`. It was not applied. `infrastructure/evidence/debian-lifecycle-vm9900-plan.json` intentionally marks it non-actionable because the recovery cloud-init snippet was not staged and the existing `vmbr0` topology does not independently prove network isolation from production state. A fresh isolated topology and exact authorization remain mandatory.
