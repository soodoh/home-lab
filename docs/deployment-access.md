# Deployment access

## Current controller path

Deployment reaches both managed hosts through Tailscale SSH. The production
inventory uses their MagicDNS names, pins the existing host-key aliases and sends no
OpenSSH identity. Tailscale policy maps authorized owner and administrator devices to
the local `ansible-deploy` account; the account has noninteractive root escalation for
Ansible.

The hosts do not accept a deployment public key through native OpenSSH. The
`tailscale_deploy_access` role preserves the local account and sudo policy while
removing the retired native authorized key and its user-specific sshd exception.
Password, keyboard-interactive and root login remain disabled. Keep independent
console access available before changing Tailscale, networking or host SSH policy.

The deployment network policy is limited to:

| Source | Destination | Ports |
| --- | --- | --- |
| Owner and administrator devices | Docker host | TCP 22 and direct Omada TLS on TCP 8043 |
| Owner and administrator devices | Proxmox host | TCP 22 and TCP 8006 |
| Ephemeral CI deployment nodes | Docker host | TCP 22 and Tailscale Serve HTTPS on TCP 8443 |
| Ephemeral CI deployment nodes | Proxmox host | TCP 22 and TCP 8006 |

CI is explicitly denied Omada's direct TLS port 8043 and loopback HTTP port 8088.
Tailscale SSH separately permits only `ansible-deploy` for deployment identities.
Personal account mappings remain distinct. The tracked Omada interface uses the same
system-trusted Serve endpoint from local controllers and future CI runners.

## GitHub-hosted runners

The Tailscale root declares a federated identity for the exact GitHub OIDC subject:

```text
Issuer:  https://token.actions.githubusercontent.com
Subject: repo:soodoh/home-lab:environment:infrastructure-deploy
Claims:  repository_id=751127419, repository_owner_id=18269267, ref=refs/heads/main
Scope:   auth_keys
Tag:     tag:ci-deploy
```

The numeric claims bind trust to the current GitHub owner and repository identities,
not only their mutable names. The identity's client ID and audience are non-secret
OpenTofu outputs. No auth key, OAuth client secret or host private key is stored in
GitHub. A future protected job
can request `id-token: write`, pass the client ID, audience and `tag:ci-deploy` to the
pinned `tailscale/github-action`, and receive a new ephemeral node for that job. The
action logs the node out when the job completes and Tailscale removes it from the
tailnet.

The tag receives only the destination ports above and Tailscale SSH access as
`ansible-deploy`. The runner must still verify the pinned host keys before Ansible
runs. Configure the GitHub environment and workflow only in the same reviewed change;
do not broaden the federated subject or use a long-lived fallback credential.

This repository currently stages the network and identity boundary only. It does not
yet authorize an automated deployment workflow.
