# Host lifecycle Phase 2: additive access capability

Phase 2 remains additive. No conventional key, legacy tofu identity, token escrow, OpenSSH setting, or console recovery path has been retired.

## Completed

- Created locked `ansible-plan` and `ansible-deploy` accounts with private primary groups and no conventional keys.
- Enabled `ansible-deploy` only through a fixed transport that stages, inspects, and applies immutable lifecycle-marker plans through one exact no-argument sudo activator.
- Installed a fixed `ansible-plan` Tailscale SSH transport accepting only `observe` and delegating only to `proxmox-observer observe`.
- Installed a dual-mode fixed firewall transport that preserves the existing forced-command grammar and accepts only the same five commands under Tailscale SSH.
- Applied the saved tailnet policy adding `proxmox`, `ansible-plan`, `ansible-deploy`, and `firewall-apply` grants while retaining transitional tofu grants.
- Proved positive MagicDNS sessions for `firewall-apply inspect` and `ansible-plan observe`.
- Proved command-injection, arbitrary-shell, and mixed-transport attempts fail with status 64.
- Proved malformed deploy plans fail closed with status 65 and command injection fails with status 64; no generic shell, conventional key, or broad sudo capability exists.

## Key attribution

The root PVE authorized-key file contains six non-empty keys. Three ED25519 comments attribute them to `personal-laptop`, `iphone-termius`, and `work-laptop`. One RSA fingerprint, `SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw`, matches the current `/root/.ssh/id_rsa.pub`. Two RSA keys with comments `root@proxmox` remain unattributed:

- `SHA256:/qSECkXxkpCIjTkBwa8XZZdRW2/seScon5uAKGlLC80`
- `SHA256:SNH3GBfBBvbkycl78DbrIjbaC0rJxkvue+KF9qhpXrs`

Root remains the sole member of stale group `apex` (GID 1000). No `apex` account or GID-1000-owned path was found under `/etc`, `/usr/local`, `/var/lib/home-lab`, or `/home`. Attribution or a separate removal transaction remains required.

## Timezone and lifecycle markers

Saved handoff plan `f529536ffaccca6216b0f98e74b79af6c841db8e9772c33a88631c03bd453935` transferred timezone ownership to Ansible without changing `America/Los_Angeles`. Nix retains read-only audit but has no timezone projection, planner, catalog, activator, or rollback mutation path. Post-handoff Ansible parity reported zero blockers and `changed=0`.

Proxmox marker plan `ffafc5f3523375957609f3bdd7e7c5da8e0924edde1e2a0f04123b01d9f1cae2` and corrected Debian marker plan `a61cd61ae5f0a43767d47206392972afbbdaf5be869df02b5f11d09a37f9b5f3` created only root-owned mode-0600 production lifecycle markers. Debian then retired its empty legacy marker under plan `4803d787fe890183bd3df3f35ccbb0f90965a545651ef5d5abb7fa6b3a4bbf03`, removed its personal-laptop deploy key and empty root key file under plan `2cb63cbe15a52849a97afa5a66cff9c8d18d552601c9649cd97403d2f8b18c58`, and disabled conventional public-key authentication under watchdog-backed plan `fd59fc1b7f586cea87f4af66e524817dc370d86f4695c6770c5455f680c33733`. Independent deploy and human Tailscale sessions passed; root-only key and SSH rollback material remains retained on-host. A final read-only audit reported Debian current and target lifecycle compliance with `changed=0`.

## Remaining gate

The saved-plan deploy identity currently accepts lifecycle-marker plans only; adding another action type requires its own reviewed schema and fixed activator support. Tofu retirement, conventional-key removal, OpenSSH tightening, the two unattributed historical RSA keys, and stale `apex` membership remain blocked on separate access-cutover review and authorization.
