# Host lifecycle Phase 2: additive access capability

Phase 2 remains additive. No conventional key, legacy tofu identity, token escrow, OpenSSH setting, or console recovery path has been retired.

## Completed

- Created locked `ansible-plan` and `ansible-deploy` accounts with private primary groups and no conventional keys.
- Kept `ansible-deploy` on `/usr/sbin/nologin` with no sudo policy.
- Installed a fixed `ansible-plan` Tailscale SSH transport accepting only `observe` and delegating only to `proxmox-observer observe`.
- Installed a dual-mode fixed firewall transport that preserves the existing forced-command grammar and accepts only the same five commands under Tailscale SSH.
- Applied the saved tailnet policy adding `proxmox`, `ansible-plan`, `ansible-deploy`, and `firewall-apply` grants while retaining transitional tofu grants.
- Proved positive MagicDNS sessions for `firewall-apply inspect` and `ansible-plan observe`.
- Proved command-injection, arbitrary-shell, and mixed-transport attempts fail with status 64.
- Proved `ansible-deploy` remains inaccessible.

## Key attribution

The root PVE authorized-key file contains six non-empty keys. Three ED25519 comments attribute them to `personal-laptop`, `iphone-termius`, and `work-laptop`. One RSA fingerprint, `SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw`, matches the current `/root/.ssh/id_rsa.pub`. Two RSA keys with comments `root@proxmox` remain unattributed:

- `SHA256:/qSECkXxkpCIjTkBwa8XZZdRW2/seScon5uAKGlLC80`
- `SHA256:SNH3GBfBBvbkycl78DbrIjbaC0rJxkvue+KF9qhpXrs`

Root remains the sole member of stale group `apex` (GID 1000). No `apex` account or GID-1000-owned path was found under `/etc`, `/usr/local`, `/var/lib/home-lab`, or `/home`. Attribution or a separate removal transaction remains required.

## Remaining gate

`ansible-deploy` cannot be enabled as an ordinary Ansible SSH identity without violating the saved-plan-bound privilege contract. Standard Ansible requires arbitrary remote shell/Python execution, while the target identity must expose only a fixed activator consuming an immutable action artifact. The repository's current `ansible_checked_apply` flow performs check-mode planning immediately before apply and is not acceptable for this identity. A fixed saved-action activator or an explicit policy decision is required before deploy capability, inventory cutover, tofu retirement, key removal, or OpenSSH tightening.
