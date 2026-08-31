# Proxmox access and OpenSSH handoff

This handoff is access-critical and remains separate from network-interface, local Tailscale-node, PVE firewall, VM, package, and controller ownership. `infrastructure/contract/home-lab.yml` is the lifecycle authority; OpenTofu remains the tailnet-policy writer, and the guarded host transaction must not mutate tailnet policy.

## Ownership boundary

The eventual Ansible access owner may manage only the contracted local accounts and groups, their contracted sudo policy and fixed transports, the contracted conventional authorized-key paths, `/etc/ssh/sshd_config.d/60-home-lab.conf`, and `ssh.service` enabled/active state. It must not replace SSH host keys, export protected key bytes, mutate `/var/lib/tailscale`, change tailnet policy, change the PVE firewall, modify PVE API tokens, alter VM 100, or absorb package lifecycle.

The target steady transport is Tailscale SSH. Physical console is the break-glass path. Healthy SSH and Tailscale services are not restarted merely to record ownership.

## Required transaction order

1. Maintain read-only reduced parity and verify fixed `ansible-plan`, `ansible-deploy`, `firewall-apply`, and human Tailscale sessions.
2. Attribute every currently retained root authorized key without exporting key bytes.
3. Remove transitional `tofu-plan` and `tofu-apply` **tailnet SSH grants** through a separately reviewed exact OpenTofu plan while their conventional LAN recovery paths remain intact.
4. Transfer packages/controller observation away from the legacy tofu SSH identities before deleting those identities, keys, sudo rules, or helpers.
5. Freeze Nix access mutation and install an exact, fixed access capability before source transfer.
6. Retire local tofu identities and stale root `apex` membership in separately authorized account/group transactions.
7. Remove conventional keys last under durable capture, controller/host locks, physical-console attestation, independent live-session canaries, and watchdog rollback.
8. Tighten OpenSSH only after key absence is proven. Stage exact bytes, run `sshd -t`, activate through reload rather than an unconditional restart, prove independent human and automation Tailscale sessions, and retain root-only rollback until commit.
9. Record access ownership only after final check mode reports `changed=0` and every recovery/postcondition gate passes.

A source change, readiness report, or check-mode result is not authorization for a host or tailnet mutation. Apply-time replanning is forbidden.

## Root key attribution

The six retained root authorized-key fingerprints are now contract-attributed. Three belong to named client devices, one to the current Proxmox root identity, and the two historical `root@proxmox` RSA keys were operator-attributed as obsolete Proxmox root identities. Attribution permits exact retirement planning; it does not itself authorize deletion.

The stale `apex` supplementary group remains an explicit retirement target. Its removal must be independently planned and authorized.

## Current status

The replacement plan, deploy, firewall, and human identities are present and their fixed transports match installed bytes. Read-only access planning reports `changed=0`. Conventional root/tofu/firewall keys, legacy tofu accounts, current OpenSSH public-key/root-login policy, and root `apex` membership remain unchanged.

The next separately authorized action is the OpenTofu tailnet-policy transition that removes only `tofu-plan` and `tofu-apply` Tailscale SSH grants and adds corresponding negative policy tests. It does not remove local accounts, conventional keys, sudo rules, helpers, PVE tokens, or LAN recovery access. Full local access cutover remains blocked until package/controller dependence on the legacy tofu identities is retired.
