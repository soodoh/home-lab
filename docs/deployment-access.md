# Deployment access

## Current controller path

Local deployment uses native OpenSSH over the LAN. The inventory targets the two
fixed Omada DHCP reservations and pins each machine through its existing
`HostKeyAlias` entry. Both hosts expose the `ansible-deploy` account through
public-key authentication only, with noninteractive root escalation. Password,
keyboard-interactive and root login remain disabled.

The only authorized key is the public half of the existing Bitwarden SSH-agent
identity in [`ansible/inventory/keys/bitwarden-controller.pub`](../ansible/inventory/keys/bitwarden-controller.pub).
OpenSSH selects that public identity from `${SSH_AUTH_SOCK}` with
`IdentitiesOnly=yes`; the private key is not stored in this repository or on the
controller filesystem. Local operators must keep `SSH_AUTH_SOCK` pointed at
`~/.bitwarden-ssh-agent.sock`. Do not generate a replacement controller key as
part of deployment.

Tailscale remains installed for personal access. Its policy may permit personal
SSH and web access, but no repository deployment command, inventory endpoint or
provider preparation step relies on Tailscale.

## Staged WireGuard server

The Omada gateway has an enabled client-to-site WireGuard server with this
operator-created configuration:

| Setting | Value |
| --- | --- |
| Name | `home_lab_deploy` |
| Endpoint for future peers | `home.diloreto.com:51820` |
| Tunnel pool | `10.88.0.1/24` |
| Clients | none |

A fresh read-only API observation proved that the pinned Omada provider's
`/setting/vpns` endpoint does not expose client-to-site WireGuard servers. The
server therefore cannot be imported or managed by `omada_vpn`, even for name or
enabled state. It is an explicit, operator-approved UI-owned exception until the
provider gains a dedicated client-to-site WireGuard resource. OpenTofu must not
claim partial ownership through the unrelated VPN endpoint.

Do not add a client until its routes and gateway ACLs are reviewed together. A
future deployment peer needs only:

- Docker host: TCP 22 and TCP 8043;
- Proxmox host: TCP 22 and TCP 8006.

The current provider cannot express the required port-level VPN ACL. Install and
validate that ACL in the same future change that creates the first peer, or first
extend the provider so Git can own both.

## Future GitHub-hosted runners

Do not copy the local Bitwarden private key or a long-lived WireGuard profile into
GitHub secrets. The intended design requires an identity broker and host SSH CA:

1. A protected GitHub environment grants `id-token: write` only to the deploy
   job. The broker validates token issuer, audience, repository, workflow, ref,
   environment and run identifiers.
2. The runner generates ephemeral WireGuard and SSH key pairs. This does not
   create or replace a key on the local operator machine.
3. The broker installs the WireGuard public key as a bounded Omada peer and
   returns only the server public data, assigned client address, endpoint and
   narrow routes. The peer must have a short expiry and fail-closed cleanup.
4. The broker signs the ephemeral SSH public key with a short-lived certificate
   whose only principal is `ansible-deploy`. The hosts must trust a dedicated CA
   before this path is enabled.
5. The runner verifies pinned SSH host keys, performs the reviewed deployment,
   tears down the tunnel and destroys private keys. The broker removes the peer
   even when the job is cancelled.

Omada currently has neither provider-managed client peers nor native OIDC
exchange, so this is a future control-plane project, not an active deployment
path. Until the broker, SSH CA, gateway ACL and cancellation cleanup are built
and tested, GitHub-hosted runners are not authorized to deploy.
