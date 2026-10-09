# Deployment access

## Current controller path

Deployment reaches both managed hosts through Tailscale SSH. The production
inventory uses their MagicDNS names, pins the existing host-key aliases and sends no
OpenSSH identity. Tailscale policy maps authorized owner and administrator devices to
the local `ansible-deploy` account; the account has noninteractive root escalation for
Ansible.

The hosts do not accept a deployment public key through native OpenSSH. The
`tailscale_deploy_access` role preserves the local account and sudo policy and
ensures native deployment keys are not active.
Password, keyboard-interactive and root login remain disabled. Keep independent
console access available before changing Tailscale, networking or host SSH policy.

The deployment network policy is limited to:

| Source | Destination | Ports |
| --- | --- | --- |
| Owner and administrator devices | Docker host | TCP 22, private ingress 443, and direct Omada TLS 8043 |
| Owner and administrator devices | Proxmox host | TCP 22 and TCP 8006 |
| Ephemeral CI deployment nodes | Docker host | TCP 22 and private ingress 443 |
| Ephemeral CI deployment nodes | Proxmox host | TCP 22 and TCP 8006 |

These grants permit the listed private routes at the network layer, subject to
separate application credentials. Actual ephemeral CI access and its
application credentials remain unverified. Recheck live host and provider
state, including unauthorized and WAN paths, before relying on these boundaries.
The work Mac's system PAC is off; reported client access does not qualify
browser routing or the isolated remote GOST denial boundary.

CI is explicitly denied Omada's direct TLS port 8043, retired Serve ports
8443/8444, and loopback HTTP port 8088.
Tailscale SSH separately permits only `ansible-deploy` for deployment identities.
Personal account mappings remain distinct. The tracked Omada interface uses the system-trusted private Traefik hostname
from local controllers. Adding a new ingress requires fresh backup/ownership
checks and separate host and policy approval.
Future CI runners must use the new hostname and application credentials, but
their actual path has been explicitly deferred rather than verified.

## Native tailnet ownership

The [`tailscale` root](../infrastructure/tofu/tailscale/tailnet.tf) declares native
provider ownership of the complete DNS configuration, reviewed tailnet settings
and permanent server tag assignments, in addition to the access policy and CI
federated identity. [`tailnet.auto.tfvars.json`](../infrastructure/tofu/tailscale/tailnet.auto.tfvars.json)
pins server names and stable node IDs; a same-name replacement is refused until
its identity is independently reviewed. Personal and ephemeral CI nodes are not
managed by the permanent-server resources.

MagicDNS stays enabled without global nameservers, extra search domains, split
DNS or overriding clients' local DNS. Do not add the individual DNS resources
alongside `tailscale_dns_configuration`: they would introduce competing writers.
The pinned provider labels this unified DNS resource alpha; review its readback
and plans carefully. Public `*.ts.diloreto.com` records remain AWS-owned.

Tailnet settings retain device approval off, user approval on, 180-day key duration,
admin-only external-tailnet joining and the existing tailnet auto-update default
on. Ansible still owns the two servers' local auto-update opt-out, installation,
SSH preferences and deployment accounts. Regional routing and posture identity
collection stay off. HTTPS and flow-logging settings are not declared until their
API reads and scopes are independently qualified. The desired ACL-management
flag prevents console policy edits and links to the Git policy source.

Before initial adoption, observe current identities, DNS and settings and review
an **import-only**, no-change saved plan against the remote backend. Keep any
bootstrap variable overrides and exact import approvals in the private controller
session, not Git. Adopt existing settings before separately planning the desired
external-policy flag and Git link; the plan inspector refuses imports combined
with updates. A declaration or import block is not permission to apply. Preserve
independent console access and require fresh observation, separate apply approval
and a no-op plan afterward, as described in [operations](operations.md#plan-and-apply-opentofu-resources).
Do not revoke old API clients until their consumers are independently reviewed.

The plan client needs `dns:read`, `feature_settings:read` and `devices:core:read`,
in addition to existing policy and federated-identity read scopes. The separate
apply client needs `dns`, `feature_settings` and `devices:core` with authority for
the permanent server tags, retaining existing policy, CI tag and federated-identity
permissions. Credentials and their scope grants remain independently owned.

CI validates the complete root, including `imports.tf`. Native mock tests use a
private copy of the unchanged production definitions and desired inputs, omitting
only `imports.tf` because OpenTofu mock providers cannot execute imports. They
cover DNS behavior, settings, tag assignments, identity replacement refusal and
the management gate. Actual import behavior requires a live remote-backed plan.

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
OpenTofu outputs; verify the corresponding live federated identity before setup.
No auth key, OAuth client secret or host private key is stored in GitHub. The
[Compose deployment job](../.github/workflows/deploy-compose.yml) requests
`id-token: write`, passes the client ID, audience and `tag:ci-deploy` to the
commit-pinned `tailscale/github-action`, and receives a new ephemeral node for that job. The
action logs the node out when the job completes and Tailscale removes it from the
tailnet.

The tag receives only the destination ports above and Tailscale SSH access as
`ansible-deploy`. The runner must still verify the pinned host keys before Ansible
runs. Configure the GitHub environment and workflow only in the same reviewed change;
do not broaden the federated subject or use a long-lived fallback credential.

The approved [routine upgrade policy](operations.md#automatic-compose-updates)
authorizes this narrowly scoped automatic deployment. Actual ephemeral CI SSH and
application access still require a successful live qualification; source validation
and an observed federation configuration are not proof of that path.

### Environment and merge protection

Use the native GitHub API/CLI with the reviewed JSON declarations in `controller/`:

- `github-compose-ruleset.json` preserves default-branch deletion protection and
  requires a PR, an up-to-date successful Actions `validate` check, resolved review
  threads and no force pushes. Zero mandatory human approvals permits routine
  automerge; major/data changes still require operator review and explicit deploy.
- `github-compose-environment.json` restricts `infrastructure-deploy` to custom
  branch policies. Add exactly one **branch** policy named `main` (not a tag rule).
  It has no wait timer or mandatory reviewer, so approved routine updates are unattended.
- Set environment variables `TS_OAUTH_CLIENT_ID` and `TS_AUDIENCE` from the exact
  live deployment federation—not an older apply/plan identity.
- Set environment variable `DOCKER_HOST_KNOWN_HOSTS` to the independently verified
  `docker-host` host-key alias entry. Never learn/accept a new key from an
  unauthenticated runtime scan. The inventory continues to require strict checking.
- Put the approved age identity in environment secret `SOPS_AGE_KEY`. This explicitly
  grants trusted main deployment jobs decryption authority for all ciphertext covered
  by that identity. It is not a Tailscale or native SSH credential.
- Set repository variable `COMPOSE_AUTO_APPLY_ENABLED=true` only when these inputs
  are ready; `false` disables push, scheduled and dispatched deployment jobs.
  Keep repository squash merge and auto-merge enabled.

The reusable CI workflow receives no deployment secrets or OIDC permission. Only
main's protected deployment job obtains them, after validating its exact selected
revision. The job creates one mode-0700 workspace outside Git, writes credentials
with mode 0600, uses Ansible `no_log` and quiet SOPS/Compose validation, then removes
controller secrets and scratch on every exit. Do not upload controller archives,
resolved Compose output, decrypted source or state as Actions artifacts. Production
ownership and before-images are never removed by controller cleanup.

Renovate's repository settings and required checks can be configured before merging
these workflow changes, but the new deployment workflow and scheduled retries do
not exist on GitHub until their reviewed commit reaches main. The first deployment
must start from an admitted existing source/backup state; the automatic lane does
not bootstrap hosts, restore data or admit outstanding configuration migrations.
