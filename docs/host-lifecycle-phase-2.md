# Host lifecycle Phase 2: additive access capability

Phase 2 remains additive. No conventional key, legacy tofu identity, token escrow, OpenSSH setting, or console recovery path has been retired.

## Completed

- Created locked `ansible-plan` and `ansible-deploy` accounts with private primary groups and no conventional keys.
- Enabled `ansible-deploy` only through a fixed transport that stages, inspects, prepares, applies, and recovers explicitly supported immutable lifecycle-marker or package plans through one exact no-argument sudo activator.
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

## Exact package activation

Package activation `e08202fbf348eaedc13513a2032256f8d59d1c1233f6fdbd9117e9e0be1b06a2` bound commit `aa36a313a805efe1028d1d6881f86c1086f05da0`, current access/console evidence, unchanged APT metadata, the pre-apply package inventory, and solver stdout SHA-256 `083d842e7bda76e8415500c345f11d9cdc69caef6d10456a74281bcd1d232c19`. Preparation downloaded packages without refreshing metadata or installing packages. The separately authorized apply used `--no-download`, `--no-remove`, retained existing configuration files, and never rebooted.

The first parser surfaced 2 installs and 94 upgrades but silently skipped solver transition lines it did not recognize. The exact saved solver subsequently performed 2 installs and 152 upgrades. Tailscale was one of those upgrades and interrupted the SSH response after APT had completed successfully, leaving the durable journal in `applying`. Independent evidence showed no active APT/dpkg process, all surfaced candidate versions installed, a clean `dpkg --audit`, an empty post-apply solver, healthy services, and intact plan/observer sessions. Recovery support now refuses unrecognized `Inst` or `Remv` lines and can only promote an existing `applying` journal after read-only package-version, dpkg-audit, and empty-solver postconditions; it never invokes APT.

PVE 9.2.10/9.2.11 also has upstream bug 7942: `pvesh get /cluster/firewall/options` fails schema compilation while firewall enforcement and the other endpoints remain active. The fixed observer and firewall transaction now use the normal `pvesh` endpoint first and permit one exact, read-only `PVE::Firewall::load_clusterfw_conf` fallback only for that exact status-255 stderr. The fallback uses Proxmox's own `copy_opject_with_digest` function, so CAS digests and option normalization remain unchanged; unrelated failures still stop.

The root-owned package journal ultimately reached `committed` with `automatic_reboot: false`. Final verification reported a clean `dpkg --audit`, an empty package solver, no reboot-required marker, all expected services active, all observer domains complete, lifecycle check mode `changed=0`, zero pending package actions, Nix host plan `f79739b209e066c3dcaf91cc01df73f3bee2061f31931f7edbf5783d410b63d8` with zero actions/blockers/findings, and five immutable OpenTofu plans with no changes under controller manifest `075430c1dec2d7f509e65767df272babffc9fea55ddb150fa98f860c60f36201`.

## Guarded Proxmox reboot

The separately authorized follow-up package activation `ec9ab09686bde657351be3c2a644bcd63c1cbcc5e6395c710489c2e5b3a3a91a` upgraded only `libpve-apiclient-perl` 3.4.2→3.4.3 and `libpve-storage-perl` 9.1.9→9.1.10 after reboot preparation refused a non-empty solver. Exact reboot activation `3206b97611891d41b22b975d753e2aa379af471dc1a16656085954937ef554e3` then bound fresh access/console evidence, the accepted Debian local+Proton Restic chain, source state, boot ID `b2ab9646-6a22-4252-be34-cc875c92d9f9`, current kernel `7.0.14-8-pve`, target kernel `7.0.14-14-pve`, VM 100 running, healthy ZFS, clean dpkg, and an empty solver. Preparation and reboot were separately authorized. The root-owned journal reached `committed` with new boot ID `ee9e3e0b-6cac-44ef-9f94-b5d116fe1b36`; the host, VM, ZFS pool, firewall, Tailscale, SSH, NFS, chrony, ZFS ZED, PVE services, and all fixed observer domains passed after boot.

## Remaining gate

The saved-plan deploy identity accepts lifecycle-marker plans plus fixed package and reboot schemas only; any additional action type requires its own reviewed schema and activator support. Tofu retirement, conventional-key removal, OpenSSH tightening, the two unattributed historical RSA keys, and stale `apex` membership remain blocked on separate access-cutover review and authorization.
