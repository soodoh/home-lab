# Debian lifecycle profiles

`ansible/playbooks/site.yml` requires one inventory-selected profile and never defaults to production.

## Profiles

- `inert`: only the guarded base role is reachable. Protected mounts must be absent or unmounted empty directories. Docker, Compose, Restic, and Tailscale units must be absent or disabled and inactive. Tailscale state and the production age identity must be absent.
- `recovery`: only the guarded base role is reachable. It has the same mount and service stop gates as `inert`. A separately recovered age identity may already exist only as a single-link root-owned `0600` regular file; ordinary convergence does not create it. Tailscale state remains forbidden until its separate enrollment transaction.
- `production`: the lifecycle marker and production invariants must pass before any production-only role is reachable. Storage, Docker, Tailscale, SOPS/age, Restic, Compose, hardware, SSH, host files, and health remain production-gated.

The guard runs before the apply guard and before the host lock. It only observes and refuses; it does not mount, enroll, restore, start, enable, or create protected state. The inactive-path observer uses `lstat`, refuses symlinks and mounted paths, and counts entries only after proving the path is an unmounted directory.

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
