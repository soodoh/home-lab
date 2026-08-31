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

## Guarded-controller scope correction

The first authorized tailnet transition was stopped before the Tailscale plan applied because the broad steady controller evaluated unrelated Debian tags at apply time. It exposed volatile `/dev/sdX` mount assertions and changed the Debian managed SSH drop-in from `PermitRootLogin no` to the role default `prohibit-password`, then reloaded SSH. Effective root login remained `no` because the earlier authoritative directive was unchanged, and both independent Tailscale sessions remained healthy. Exact Debian cleanup plan `359678a759789658c888678b2029944c03ec479cb1403a212ea29d313b4ad772` restored the drop-in under the retained watchdog/rollback transaction.

Mount checks now bind the contracted filesystem UUIDs rather than volatile device names. Debian kernel and metapackage evidence were refreshed to the already-running unattended-upgrade result `6.12.107+deb13-amd64` / `6.12.107-1`. The new `apply-tailnet` controller path accepts only a manifest with exactly one saved Tailscale change, zero Nix host actions, unrelated OpenTofu no-op preconditions, Ansible no-op preconditions, CAS-bound policy state, and post-verification. It cannot invoke broad Debian or Compose convergence.

## Current status

The replacement plan, deploy, firewall, and human identities are present and their fixed transports match installed bytes. Read-only access planning reports `changed=0`. Conventional root/tofu/firewall keys, legacy tofu accounts, current OpenSSH public-key/root-login policy, and root `apex` membership remain unchanged.

Guarded manifest `0d6e56438445350ae4addeb29c8b7c717aea78de0abd5ed9e888410cfc880f38` completed the exact OpenTofu tailnet-policy transition: `tofu-plan` and `tofu-apply` Tailscale SSH grants are absent, their negative policy tests are active, both live negative canaries fail, and the required plan/deploy/firewall/human Tailscale sessions pass. All OpenTofu and Nix plans are now no-op. Local tofu accounts, conventional keys, sudo rules, helpers, PVE tokens, and LAN recovery access remain unchanged. Full local access cutover remains blocked until package/controller dependence on the legacy tofu identities is retired; a later fresh physical-console attestation is also required before any access mutation.

Proxmox package ownership is now transferred to Ansible under no-mutation receipt `6b0f77137db3d19c84c16e5d38ca468723a85393c4f6209b46a190a026003055`. The retained Nix planner's live observation path has also moved from conventional `tofu-plan` LAN SSH to the fixed `ansible-plan` Tailscale observer and produced a clean guarded plan. The remaining controller dependency is the historical Nix apply/protected-bootstrap path using `tofu-apply`; local tofu identities and their recovery assets remain unchanged until that dependency and Nix access mutation are separately retired.
