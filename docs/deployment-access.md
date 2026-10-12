# Deployment access

## Manual controller path

Manual deployment reaches both managed hosts through Tailscale SSH. The production
inventory uses their MagicDNS names, pins the existing host-key aliases and sends no
OpenSSH identity. Tailscale policy maps authorized owner and administrator devices to
the local `ansible-deploy` account; the account has noninteractive root escalation for
Ansible.

The hosts do not accept a deployment public key through native OpenSSH. The
`tailscale_deploy_access` role preserves the local account and sudo policy and
ensures native deployment keys are not active. Password, keyboard-interactive and
root login remain disabled. Keep independent console access available before
changing Tailscale, networking or host SSH policy.

The desired deployment network policy is limited to:

| Source | Destination | Ports |
| --- | --- | --- |
| Owner and administrator devices | Docker host | TCP 22, private ingress 443, and direct Omada TLS 8043 |
| Owner and administrator devices | Proxmox host | TCP 22 and TCP 8006 |

Application credentials remain separate from network admission. The tracked Omada
interface uses the system-trusted private Traefik hostname from local controllers.
Adding an ingress requires fresh backup/ownership checks and separate host/policy
approval. The work Mac's system PAC is off; reported client access does not qualify
browser routing or isolated remote GOST denial behavior.

## Host-local scheduled deployment

The Docker host is both the scheduled executor and deployment destination. It does
not use Tailscale SSH to itself, join an ephemeral CI identity, or receive provider
plan/apply credentials. Systemd runs the pinned controller locally as root and
reuses the existing Compose observation, ownership, backup admission, classification
and convergence interface. See [automatic updates](operations.md#automatic-compose-updates).

The existing 05:00 daily backup timer uses the shared full timer renderer to select
`home-lab-morning.target`. Backup reconfiguration preserves its installed target;
only an explicitly approved scheduling change replaces the trigger dependency.
That target composes the existing local/NFS and Proton
backup units, then routine deployment. The backup-only daily target and manual
backup commands are unchanged. A terminal Proton failure still reaches existing
routine admission; local failures, active writers and journals remain blockers.
There is no deployment clock cutoff, independent polling timer or missed-run alert.

`configure-compose-schedule.yml` is an approval-gated installation interface. From
clean reviewed committed source it installs:

- native Git/Python prerequisites and the pinned controller commit at
  `/opt/home-lab/compose-controller`;
- pinned Ansible in `/opt/home-lab/compose-venv`, collections in
  `/opt/home-lab/collections`, and checksum-verified SOPS in `/opt/home-lab/bin`;
- the separately approved protected age identity at
  `/etc/home-lab/compose-deploy/age-key`, supplied from independent controller custody
  through `SOPS_AGE_KEY_FILE`, never Git or a command-line value;
- native morning target, routine oneshot and the shared backup timer definition, without
  starting a backup or deployment during installation.

This installed controller is manually managed software. Fetching current main for
application updates never changes its playbooks, scripts, inventory or toolchain.
Each daily invocation uses one new private controller workspace. Systemd
`LoadCredential` supplies the age identity and removes its per-service copy and
runtime scratch on exit. Nonterminal production locks and before-images remain
untouched. See the [decryption grant](security.md#automatic-compose-deployment-credentials).

`soodoh/home-lab` is public. The controller uses anonymous HTTPS Git and GitHub API
reads: no GitHub token, deploy key or dispatch permission is needed. The native Git
module freezes fetched main; the newest CI run must be a successful completed push
on main for that exact SHA, workflow ID and repository ID. Reviewed numeric owner,
repository and workflow identities are in `controller/compose-updates.json`.
A transfer, workflow replacement, visibility change, rate limit, API outage or
incomplete/failed CI refuses deployment instead of adopting new identities or
bypassing validation.

## Native tailnet ownership

The [`tailscale` root](../infrastructure/tofu/tailscale/tailnet.tf) declares native
provider ownership of the complete DNS configuration, reviewed tailnet settings
and permanent server tag assignments, in addition to the access policy.
[`tailnet.auto.tfvars.json`](../infrastructure/tofu/tailscale/tailnet.auto.tfvars.json)
pins server names and stable node IDs; a same-name replacement is refused until
its identity is independently reviewed. Personal nodes are not managed by the
permanent-server resources.

MagicDNS stays enabled without global nameservers, extra search domains, split
DNS or overriding clients' local DNS. Do not add individual DNS resources alongside
`tailscale_dns_configuration`: they would introduce competing writers. The pinned
provider labels this unified DNS resource alpha; review its readback and plans
carefully. Public `*.ts.diloreto.com` records remain AWS-owned.

Tailnet settings retain device approval off, user approval on, 180-day key duration,
admin-only external-tailnet joining and the existing tailnet auto-update default
on. Ansible owns the two servers' local auto-update opt-out, installation, SSH
preferences and deployment accounts. Regional routing and posture identity
collection stay off. HTTPS and flow-logging settings are not declared until their
API reads and scopes are independently qualified. The desired ACL-management flag
prevents console policy edits and links to the Git policy source.

Before adoption, observe current identities, DNS and settings and review an
import-only saved plan against the remote backend. Keep bootstrap inputs and exact
import approvals in the private controller session, not Git. Adopt existing
settings before separately planning desired changes; the inspector refuses imports
combined with updates. Preserve independent console access and require fresh
observation, separate apply approval and a no-op plan afterward, as described in
[operations](operations.md#plan-and-apply-opentofu-resources).

The plan client needs `dns:read`, `feature_settings:read`, `devices:core:read` and
policy read scope. The separate apply client needs `dns`, `feature_settings`,
`devices:core` and policy authority for the permanent servers. Credentials and
scope grants remain independently owned; never revoke or alter them based merely
on removal of an unrelated deployment identity.

Removing a provider declaration must produce a reviewed destroy plan, not a
manual state deletion. Exact-plan deletion approval and independent consumer
review remain required. See [deletion review](operations.md#deletion-and-replacement).

CI validates the complete root, including `imports.tf`. Native mock tests use a
private copy of unchanged production definitions and desired inputs, omitting only
`imports.tf` because mock providers cannot execute imports. They cover DNS,
settings, permanent tags, identity replacement refusal and the management gate.
Actual import behavior requires a live remote-backed plan.

## GitHub merge protection

`controller/github-compose-ruleset.json` preserves default-branch deletion
protection and requires a PR, an up-to-date successful Actions `validate` check,
resolved review threads and no force pushes. Zero mandatory human approvals permits
routine Compose and development/CI tooling automerge; major/data changes still
require operator review and explicit deployment. Keep repository squash merge and
auto-merge enabled.

GitHub Actions validates source only. It requires no deployment environment,
SOPS secret, OIDC deployment grant or Tailscale federation. Changes to host-local
controller code and dependencies remain manually installed after their own review,
even if a tooling PR is merged into main.
