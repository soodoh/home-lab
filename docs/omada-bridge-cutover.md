# Omada bridge and public-route retirement

The bridge-mode, DHCP option 138, Caddy route, and Authentik resource changes were
applied and verified on 2026-09-27. A fresh Authentik plan was no-op, host/Compose/backup
observations passed, and Omada's tailnet Serve endpoint returned HTTP 200. The
obsolete public DNS record for `omada.diloreto.com` remains pending identification
and removal by its actual DNS owner; do not infer DNS ownership from the public
nameservers alone. The steps below record the separately gated cutover procedure,
not permission to replay it. See [operations](operations.md) for production locks,
observations, plans and backup requirements; retain independent Docker-host and
gateway console access for any future changes.

## Preconditions — observe live, do not infer from Git

1. Observe hosts, Compose, backups, Omada and Authentik afresh. Verify the Docker
   host's LAN address is `192.168.0.100`, the Omada gateway is reachable without
   depending on the controller, and no retained apply/backup owner or journal
   blocks convergence. Have an independent recovery path if device management or
   DHCP fails. Confirm the controller's **live** listener ports and device types.
2. Observe the complete **live DHCP options** for the managed `Default` LAN. This
   reviewed source specifies only option 138 (`192.168.0.100`); do not apply if it
   would replace other options. Review a fresh Omada plan and retain any existing
   options in Git before proceeding. Verify option 138 is supported by the actual
   device firmware and the correct DHCP server/relay on every relevant device VLAN.
   Observe each adopted gateway/switch/AP's current inform/controller address and
   confirm the host LAN IP is reachable from all device VLANs; DHCP option 138
   alone may not overwrite an existing explicit inform URL. Arrange to correct
   those devices using the controller/device UI or Discovery Utility if needed.
3. Check for port conflicts on the host and LAN reachability/firewall policy for
   TCP 8043, 8044, 8088, 8843, 29811–29817 and UDP 19810, 27001, 29810.
   Host-IP port publishing does **not** transport L2 broadcasts into the bridge;
   option 138 is the chosen adoption path. Guest portal and OLT support require
   verifying their specific clients and traffic before calling the cutover done.
   Recheck that Omada's WAN forwards expose **only** the reviewed Caddy 80/443
   ingress, never the Omada device or admin ports. The intended Omada port
   bindings are LAN-only, except 127.0.0.1:8043 for Tailscale Serve.
4. Confirm a fresh complete backup chain and an independently tested path to
   restore the **same** Omada data and previous host-mode Compose configuration.
   A Git revert plus site convergence restores configuration; it cannot by itself
   restore a changed device inform address or DHCP option. Agree on the operator
   who will watch adoption and execute rollback before switching modes.

## Ordered rollout (separate reviewed actions)

1. First, while host-mode Omada still runs, plan and apply only the option-138
   Omada network change using fresh export, the usual policy gate and the saved
   reviewed plan. If the provider proposes unrelated changes, refuses the plan,
   or loses other DHCP options, stop. Renew device DHCP leases as appropriate;
   verify their controller/inform destination and that *all* managed devices stay
   connected. Have a way to reach the host and gateway if the controller drops.
2. Only then converge the reviewed Compose/Caddy change with `site.yml`, after
   fresh observation/check mode. This recreates Omada with bridge networking,
   keeps the tailnet Serve backend on host loopback HTTPS port 8043, and removes
   the public Caddy route and internal `:18043` hop. Verify strict-TLS Serve `:8443/api/info`,
   authenticated API calls via the existing provider identity, all managed devices,
   firmware/portal features used here, and negative access to the old public host.
   Do not treat a successful controller login as proof of device adoption.
3. The Authentik application `omada`, proxy provider `23`, and group policy binding
   `1574fabc-e9fb-4ab7-a345-9ccec64157d7` are omitted from post-cutover desired
   state. The embedded outpost's provider list and the allowlist are updated. **They
   were deleted live after separate exact-plan approval.** The plan inspector denies deletes by default;
   `prevent_destroy` would not protect a removed `for_each` instance anyway.
   After verifying Serve and device health, separately inspect a fresh saved
   Authentik plan and issue an exact-plan, exact-action private deletion approval
   using [operations](operations.md#approved-destructive-plans). Require exactly
   the three observed live identities (binding, application and provider), the
   expected embedded-outpost update, no unrelated change, a protected state
   before-image, and post-apply provider/state reconciliation with a fresh no-op
   plan. Do not merely remove objects from state while they still exist in
   Authentik; do not approve their deletion before the public path is retired.
4. Remove the obsolete **public DNS record** for `omada.diloreto.com` from its
   actual DNS owner after observing that owner and verifying no other use; Caddy
   route removal alone does not remove DNS or any previously issued certificate.
   Do not delete DNS resources managed outside this repository by guessing their
   owner. Verify external requests cannot reach Omada and the Serve path still
   works. Require a new complete backup chain for the changed Compose artifact.

## Rollback

If any managed device disconnects, portal/upgrade fails, or Serve loses Omada,
stop the cutover. Restore the reviewed old host-mode Compose and Caddy route through
normal host ownership/convergence, while keeping option 138 pointing at the same
host LAN IP (it is compatible with host mode). Reobserve all managed devices and
both Serve endpoints. Revert option 138 only after verifying how devices will find
host-mode Omada without it. Do not retire Authentik objects or public DNS until
this observation succeeds. Revert Git and converge to complete configuration
rollback; preserve any nonterminal host owner or journal for live resolution.

References: [container bridge/adoption guidance](https://github.com/mbentley/docker-omada-controller/blob/master/DEVICE_ADOPTION.md), [Omada controller port reference](https://support.omadanetworks.com/en/document/13090/).
