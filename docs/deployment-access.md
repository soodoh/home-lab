# Deployment access

## Manual controller path

Manual deployment reaches both managed hosts through Tailscale SSH. The production
inventory uses their MagicDNS names, pins the existing host-key aliases and sends no
OpenSSH identity. Tailscale policy maps authorized owner and administrator devices to
the local `ansible-deploy` account; the account has noninteractive root escalation for
Ansible.

The hosts do not accept a deployment public key through native OpenSSH. The
`tailscale_deploy_access` role preserves the local account and sudo policy and
verifies that native public-key, password, keyboard-interactive and root login
remain disabled, including in check mode. It does not manage authorized keys or
SSH daemon configuration. Keep independent console access available before
changing Tailscale, networking or host SSH policy. The read-only integration test
`ansible/tests/tailscale-deploy-access.yml` checks both hosts' effective native SSH
policy through the same verifier.

The desired deployment network policy is limited to:

| Source | Destination | Ports |
| --- | --- | --- |
| Owner and administrator devices | Docker host | TCP 22, private ingress 443, and direct Omada TLS 8043 |
| Owner and administrator devices | Proxmox host | TCP 22 and TCP 8006 |
| Docker host | Proxmox host | TCP 8006, plus separately activated snapshot-only TCP 2444; SSH remains denied |

Snapshot control is a systemd socket-activated bounded JSON worker, not a login
or general network proxy. The listener pins the Proxmox Tailscale IPv4 and binds
to `tailscale0`; tailnet policy admits only the Docker-host tag. The client uses
the pinned peer IP over WireGuard directly. No SSH account, key, password, SFTP,
forwarding or sudo authority is delegated. A restricted login shell would not by
itself constrain every SSH channel. Qualify the actual interface/peer denial and
worker/NFS lifecycle before relying on it; mocked manager/policy tests do not
establish live enforcement. Socket installation, scoped tailnet apply and
backup-runtime installation are separate approved steps.
See [snapshot lifecycle](operations.md#zfs-snapshot-authority-and-expiry).

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
That target waits for complete local capture, then routine deployment. NFS and
Proton reconcile independently at boot/hourly and after local success, never as a
deployment dependency. Manual backups never trigger deployment. Routine admission
requires local freshness, initial replica coverage and at most 48 hours of
capture-time lag to either destination. Copy progress/failure alone does not
block it; local failures, unresolved staging and journals do.
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
routine Compose, admitted tooling and non-major provider source automerge;
major/data changes and qBittorrent minor upgrades still require operator review.
The unchanged `validate` check name aggregates candidate-source and host-Python
compatibility lanes and refuses failed, cancelled or skipped lanes. See the
[dependency policy](operations.md#controller-dependency-updates).
Provider applies and controller installation remain independently approved.
Keep repository squash merge and auto-merge enabled.

GitHub Actions validates source only. It requires no deployment environment,
SOPS secret, OIDC deployment grant or Tailscale federation. Changes to host-local
controller code and dependencies remain manually installed after their own review,
even if their source pins automerge into main. The daily job still executes only
the installed implementation; no CI job refreshes it or applies provider changes.
