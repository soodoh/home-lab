# Operations

Git defines desired state; hosts and provider APIs define current state; remote
OpenTofu state defines provider ownership. Start each decision from a reviewed
checkout and **fresh** observation. Prior runs, migration notes and plan digests
are not admission evidence. This runbook is for current operation, not a ledger
of completed cutovers. See [architecture](architecture.md),
[security](security.md), [recovery](../recovery/README.md) and
[outstanding work](migrations.md).

## Prepare a disposable controller

Use a clean checkout with OpenTofu, Ansible, Docker Compose, Python, SOPS and the
pinned JavaScript tooling. Establish authenticated Tailscale access and separate
plan/apply credentials from protected storage. A local mode-0600 gitignored
`.env` based on [`.env.example`](../.env.example) is an option, but it holds
persistent plaintext credentials: protect it independently and never commit it.
Only source a trusted local file, if needed:

```sh
set -a
. ./.env
set +a
git status --short
tailscale status
python3 scripts/check-source-boundaries.py
python3 scripts/check-compose-image-pins.py
```

A dirty checkout, failed boundary check or unreviewed lockfile change is a
refusal. Neither Ansible nor OpenTofu loads `.env` automatically. Provide
`SOPS_AGE_KEY_FILE` from protected storage; validate Compose without printing
resolved values:

```sh
python3 scripts/check-compose-with-sops.py
```

For non-AWS providers, create a **new private session directory** and destroy it
at the end of this run. `scripts/configure-local-provider-credentials` refuses
reused or durable targets. Do not carry its credential files between sessions:

```sh
provider_session=$(mktemp -d)
chmod 0700 "$provider_session"
trap 'rm -rf "$provider_session"' EXIT
export HOME_LAB_PROVIDER_SESSION_DIR=$provider_session
scripts/configure-local-provider-credentials
unset AUTHENTIK_PLAN_TOKEN AUTHENTIK_APPLY_TOKEN \
  TAILSCALE_PLAN_ID TAILSCALE_PLAN_SECRET TAILSCALE_APPLY_ID TAILSCALE_APPLY_SECRET \
  OMADA_PLAN_USERNAME OMADA_PLAN_PASSWORD OMADA_APPLY_USERNAME OMADA_APPLY_PASSWORD
```

Protect the session directory and its saved plans, exports and approvals; never
print decrypted SOPS, resolved Compose, provider state or plan JSON. Run the
native validators applicable to changed files (see [README](../README.md) and
CI). Focused backup/recovery checks are `scripts/test-recovery-tools`,
`python3 scripts/test-restic-runtime.py`, and
`python3 scripts/test-restic-observer.py`.

## Observe before deciding

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/observe-hosts.yml
ansible-playbook ansible/playbooks/observe-compose.yml
ansible-playbook ansible/playbooks/observe-backups.yml
ansible-playbook ansible/playbooks/observe-proxmox.yml
ansible-playbook ansible/playbooks/observe-proxmox-packages.yml
```

Run the relevant observer afresh before **each** plan or host apply. The backup
observer checks live owners, policy and Compose artifact, repository identities,
timer cadence and the newest complete games → NFS → Proton chain within 48 hours;
it does not create a backup. A fresh admission can cover several related
reversible changes while the policy and artifact are unchanged, but is never a
standing approval for another run. Changing the artifact or policy requires a
new complete chain before declaring the changed state backed up or beginning a
subsequent change that requires current-state backup admission. Do not bypass
identity, ancestry or freshness checks. Before a destructive/data/storage change,
verify the acceptable data-loss window and recovery path for affected data,
including external storage; obtain a new chain or protected before-image when
necessary. Git revert restores configuration, **not data**.

Unknown locks, interruption journals, mounts, keys, owners, service counts or
repository identities are refusals. Inspect them on the authoritative host.
Keep nonterminal locks, journals and before-images until live inspection resolves
them. Observation output is current-run input, not a Git artifact.

## Plan and apply OpenTofu resources

Active remote-backed roots under `infrastructure/tofu/` are `authentik`,
`aws-foundation`, `omada`, `proxmox`, `proxmox-firewall`, `servarr` and `tailscale`.
Initialize against the **remote S3 backend**, refresh against the provider,
review the whole saved plan and apply only that plan with the separate apply
identity. A new plan after apply must have zero proposed changes. Never target
around a policy refusal or drop a tracked resource from state merely to avoid a
destroy.

```sh
root=infrastructure/tofu/proxmox # choose the reviewed root
work=$(mktemp -d "$provider_session/plan.XXXXXX")
chmod 0700 "$work"
: "${TF_BACKEND_BUCKET:?load the current plan credential environment first}"
tofu -chdir="$root" init -backend-config="bucket=$TF_BACKEND_BUCKET"
tofu -chdir="$root" plan -out="$work/plan"
policy_args=()
allow_file="infrastructure/policy/allow/$(basename "$root").txt"
[[ ! -f $allow_file ]] || policy_args+=(--allow-change-file="$allow_file")
TOFU_PLAN_CHDIR="$root" scripts/inspect-tofu-plan "$work/plan" "${policy_args[@]}"
```

Use only a currently reviewed allowlist, never a standing migration waiver.
An ordinary allowlist does **not** authorize deletion. For Omada, compare a
fresh private export made with `scripts/prepare-omada-plan-input` against every
identity in the reviewed `desired.json`. Supply `TF_VAR_omada_export_path` as an
unused path in the private session directory. The export validates ownership of the LAN, reservations, port forwards, SSIDs/WLAN
groups and gateway; its settings are not desired state. See the
[selective ownership boundary](../infrastructure/tofu/omada/EXPORT_SCHEMA.md),
including write-only Wi-Fi credentials and notification-selector import limits. Drift against Git is a refusal to investigate,
not a reason to copy live settings into Git. For Proxmox, the host observer must
compare live disk/USB topology, sealed host expectations and
[`expected-hardware.json`](../infrastructure/tofu/proxmox/expected-hardware.json)
before plan/apply; reobserve after topology changes. Never update expected
hardware automatically from an unexplained observation. The Proxmox cluster
firewall has its own root and ordered policy; the host observer separately
checks the provider's non-round-tripping default forward policy. Preserve
independent console access for network, boot and storage changes.

### Deletion and replacement

Removing a declaration should produce an explicit destroy plan. The inspector
denies deletions/replacements by default, not forever: after live ownership,
consumers, recovery and protected state before-image have been checked, the
owner privately reviews the **entire** saved plan, including unrelated changes,
then creates a mode-0600 approval **outside Git**, bound to the exact plan digest:

```json
{
  "saved_plan_sha256": "<digest printed by inspect-tofu-plan>",
  "deletions": [
    { "address": "<exact resource address>", "type": "<resource type>", "actions": ["delete"] }
  ]
}
```

Enumerate **every** destructive action and its exact sequence; replacement may
be `["delete", "create"]` or `["create", "delete"]`. Run the default inspector
first, then rerun it on the **same saved plan** with
`--approve-deletion-file="$work/delete-approval.json"` and the same policy
arguments. Approval does not bypass IAM identity/ownership, incomplete plans,
drift or VM-start prerequisites and does not itself authorize an apply. Obtain a
separate human confirmation before applying the inspected plan. A new plan needs
a new approval. Afterward verify provider reality and a fresh no-op plan.

### Authentik OAuth client-secret rotation

Before planning the managed Authentik root, obtain independent
approval for the plan identity's provider-change grant: a view-only identity does
not receive OAuth secrets from the API, so a secret plan would otherwise propose
false updates even if the encrypted value is already live. Protect the plan token
as a mutating credential. `scripts/prepare-authentik-plan-input` checks all four
OAuth secret reads and every owned signing-certificate private-key read without
printing their values; it refuses a masked or inaccessible identity. It also
checks live login-stage binding values that the pinned provider cannot read back.
Run it in a
private provider session, with unused output paths supplied as
`TF_VAR_authentik_client_secrets_path` and `TF_VAR_authentik_signing_keys_path`.
It prepares both encrypted authorities; use the same SOPS revision for the saved
plan and any consumer update. [Authentik ownership](authentik-ownership.md) defines
membership, shared stages, system defaults and the certificate-discovery boundary. The apply token remains separate. Vaultwarden's
protected client-secret file and Home Assistant's existing `!secret` entry derive
from the same Authentik SOPS client secrets during site convergence; CWA's
generic OAuth setting remains a manually verified admin UI step because its
only observed HTTP writer is a bulk, CSRF-protected settings form. Do not assume an
Authentik plan or apply makes a consumer switch atomic; verify a fresh OIDC login
and a no-op plan before declaring rotation complete. Do not count the CWA step
as complete until its admin setting and fresh login have been checked.

### Omada SMTP and recipients

[Omada mail](omada-mail.md) uses a separate SOPS authority and native Ansible
API SMTP convergence, not Compose interpolation or an invented password-file
reader. Recipients are derived from independently owned administrator account email
addresses and alert subscriptions; notification PATCH does not configure them.
Review account changes separately and require the observed destination set to match
SOPS before SMTP convergence. Use `observe-omada-mail.yml` with a fresh private plan credential session;
`converge-omada-mail.yml --check` also validates host, Compose and backup admission.
A separately approved apply uses the apply identity under the production host
lock. SMTP is controller-wide; the recipient prerequisite is observed in the
reviewed site. Notification toggles remain provider-owned and must be preserved.
The mail role never writes notification or account documents. Serialize SMTP
convergence against account changes, manual edits and OpenTofu notification applies;
rereading cannot eliminate a concurrent-edit race.

The API masks the SMTP token. Public-settings convergence cannot prove secret
synchronization; an approved token-only rotation needs its explicit flag. Opt-in
tests use the reread controller settings, not a transient desired token, and
successful submission does not prove mailbox delivery. Keep the old token valid
until receipt is independently verified. Failed convergence retains the host
lock; inspect live state and preserve private evidence rather than automatically
rolling back or clearing ownership. SMTP native writes and test behavior still
require live qualification on the first separately approved activation.

### Download-client credential rotation and Arr provider ownership

For the Servarr root, use the [documented one-key Arr provider exception](security.md#opentofu-state-and-plans): there is no separate read-only Arr API key. In a fresh private provider session, run
`python3 scripts/prepare-servarr-variables.py` after supplying a protected
`SOPS_AGE_KEY_FILE`, then pass `-var-file="$HOME_LAB_PROVIDER_SESSION_DIR/servarr.auto.tfvars.json"`
to a saved Servarr plan. Protect the generated mode-0600 file, saved plan and
remote state; never print their contents. Do not initialize a new state key
until its AWS state-key/IAM grants have independent owner approval. Reobserve
hosts, Compose, backups and provider APIs, privately inspect the **whole**
saved plan, and reject unreviewed imports, replacements or deletion.

On an explicitly approved credential change, plan the Arr resources **before**
rotating qBittorrent/SABnzbd. Then run
`ansible-playbook ansible/playbooks/converge-download-clients.yml -e download_client_apply_confirmed=true`
under the observed host/backup admission: it takes the production host lock,
changes only credentials that differ, and verifies persistence/authentication.
Immediately apply the reviewed saved Arr plan using the separate apply
confirmation, then test every Sonarr, Radarr, Radarr-4k and Prowlarr download
client and require a fresh no-op plan. These cross-application changes are **not
atomic**: do not call a partial rotation complete or automatically restore an
old credential when an apply fails. Preserve the lock and private evidence
until live ownership and connectivity are resolved. An Arr application's
**own** API key has a different order: `production.sops.yaml` is its single
desired source for Compose and provider inputs. On an approved key rotation,
converge Compose first so the application accepts the new key, then prepare a
**new** private provider session and saved plan using that same SOPS revision;
a saved plan made with the old provider key is not reusable. Prowlarr's
application integration may briefly have the old key until its OpenTofu update.
Verify all other consumers and do not claim a partial rotation complete.
The Prowlarr indexers remain the sole writer of downstream synchronized
indexers; Recyclarr remains the sole writer of its profiles and custom formats. Media catalogs are not
OpenTofu-owned. Arr host settings are not provider-owned: Compose owns runtime
ports/API-key injection, while native login settings remain in backed-up app
databases; the provider host resource overlaps those owners and cannot read
back the existing password. Radarr-4k's existing Radarr import list is
OpenTofu-owned. Its top-level `rootFolderPath` is already `/data/movies/4k`;
the separate `fields.rootFolderPaths` list is empty. The reviewed import plan
must preserve the top-level root and must not treat the empty field list as
permission to change it. Disabled metadata providers remain application
defaults, not managed resources.

### Independently owned AWS identities

The normal inspector refuses managed IAM/Roles Anywhere changes and drift. A
narrow create-only ACME user/policy/attachment exception requires independent
owner review of the **entire** policy, external permissions boundaries and exact
saved plan, plus a private mode-0600 `--approve-identity-file` bound to its
SHA-256. It does not authorize an access key in state, IAM deletion, OIDC or an
unrelated identity. A controller apply role cannot update its own IAM policy.
Any externally owner-updated IAM document needs a separately reviewed **state-
only** reconciliation: preserve the remote state-object version, save and
privately inspect a `tofu plan -refresh-only`, approve only the exact state
delta, apply that saved refresh-only plan with locking, reobserve live identity,
and require a fresh normal no-op plan. Do not use a targeted normal plan to hide
identity drift. A failed Route 53 create may leave a live record tainted; after
independent live/state review and owner approval, native `tofu untaint` with
locking can reconcile that marker before a fresh zero-change plan. Do not apply
an unintended record replacement. Verify the Docker-host Tailscale IPv4 against
the committed ingress record and the public hosted-zone ID and externally owned
ACME-user boundary against AWS on every relevant change. Runtime ACME keys belong
in SOPS, not OpenTofu state. The DDNS credential may have other live consumers;
never revoke it based on removal of an old ingress route.

## Converge managed hosts

[`site.yml`](../ansible/playbooks/site.yml) owns the complete Docker-host
convergence: it observes active Compose, acquires the production host lock,
checks Tailscale identity and GOST DNS, converges SSH access, backup tools and
units, Docker maintenance and the complete committed Compose project, then
observes the result. Source changes or changed credential files recreate the
complete project: atomic replacement otherwise leaves file bind mounts reading
old inodes. This includes Openfit startup, but does not change its configuration
or bootstrap credential. Check mode validates
active state; do not apply after a refused observation or check. Do not claim a
changed artifact is backed up until a fresh complete chain is admitted.

```sh
ansible-playbook ansible/playbooks/site.yml --check
# Review the current output and obtain host approval before applying.
ansible-playbook ansible/playbooks/site.yml
```

`configure-backups.yml` is a narrower existing-host interface: it validates
adopted files and journal under production/backup ownership, then converges
reviewed policy and runners without bootstrapping repositories or running a
backup. [`policy.json`](../services/data/restic/policy.json), native Restic
files-from/excludes and systemd units define recurring behavior; the runner is
only the writer-consistency adapter. `deploy-compose.yml` is a narrower
Compose-only interface requiring `compose_native_apply_confirmed=true`; prefer
`site.yml`. An interrupted source swap preserves host-local
`/srv/docker-compose/previous`: inspect the lock, journal and before-image
before retrying. Do not delete host-local artifacts merely because a controller
session ended. [Recovery](../recovery/README.md) currently supports private
staging, not production activation.

### Backup runtime and downtime

The daily runner reports bounded `stop`, `scan`, `restart`, `nfs_copy` and
`proton_copy` durations without paths or credentials. Sum the first three for
an upper bound on the writer-stop window; the copy phases occur after restart.
Compare several cycles before changing scope. The runner asks native Compose
to stop the selected applications as one dependency-aware group, then stops the
selected databases as a separate group; it restarts only the previously running
services. Gluetun and Recyclarr are paused because their writable mounts include
backed-up data. FlareSolverr is paused with Gluetun because it shares Gluetun's
network namespace. The recorded reverse start order brings Gluetun up before
qBittorrent (needed by Gluetun's port-forward hook) and the other namespace
dependents, and Recyclarr after the Arr services. It waits for Gluetun health
before starting those dependents; a failed health gate retains the interruption
journal. The systemd recovery unit needs access to both repositories and the
local Restic cache to complete its native preflight after restoring services.
If shutdown dominates, inspect slow graceful-stop behavior rather than
shortening the timeout or adding a filesystem snapshot layer by default. A
source-level audit of the stop list found no *proven* safe removals: it covers
databases, embedded application state, configuration writers and game profiles.
Do not leave a writer running merely because it is not a database; require
fresh mount/writer evidence and a private restore before narrowing the list. Keep the full daily chain and batch
related reversible changes under the existing admission rule.

If the scan itself becomes the downtime bottleneck, snapshot-backed scanning
is a separate, approval-gated storage design, **not** a change to this runner.
The observed `/srv/home-lab-state` and `/mnt/games` are separate ext4
filesystems on direct partitions, without a native mounted
snapshot source. First restore a complete admitted chain and establish protected
before-images, rollback access and capacity. Then evaluate a snapshot-capable
storage layer for both included filesystems: under the backup lock, quiesce
writers, snapshot, restart, and scan immutable snapshots with native Restic.
Preserve original recovery paths, policy/artifact tags, three-copy ancestry,
interruption recovery and private restore validation. Handle external Nextcloud
data independently. Any storage migration needs its own live observation, plan,
destructive-data review and explicit approval; online database export is an
alternative only with a qualified application-file restore.

Docker must publish private Traefik TCP 443 only on the currently reviewed
Docker-host Tailscale IPv4; the bridged container listens on TCP 443. Public
Traefik must own only the listed public routes and the reviewed TCP 18080 / TCP+UDP 18443 host ports forwarded by Omada from WAN
80/443. Its HTTP-01 resolver needs public TCP 80. Verify exact live forwarding,
port ownership, strict TLS, listed/unlisted hosts, HSTS, HTTP redirects,
WebSockets, and public UDP/HTTP3 from appropriate clients before an ingress
change. Proxmox's private route uses its fixed LAN address on TCP 8006 with a
backend-only certificate verification exception for its untrusted native
certificate. Omada's private backend now uses a dedicated Docker bridge with
its observed self-signed certificate pinned as a trust input; compare the live
certificate fingerprint and SAN before changing the host and after a rotation.
Z-Wave's private route reaches Authentik on the proxy bridge without publishing
its UI port 8091 or Authentik port 9000. Check Proxmox's native login and
Z-Wave's Authentik group gate (including denial) and WebSocket flows before
removing Proxmox's obsolete Authentik resources with a reviewed destroy plan.
The public names must no longer reach either UI.
[Ingress headers](ingress-headers.md) records the current HSTS policy.
Keep private and public ACME stores protected; neither is in the Restic
files-from set and reissuance is subject to CA limits. GOST is an authenticated
transport, **not** authorization for private backends: test its allowlist with an
isolated authenticated client without a local bypass as well as testing real
client credentials. Actual ephemeral CI access, isolated GOST denials and
UDP/HTTP3 private-route negatives must not be called verified until exercised
in the current environment. Before revoking any credential, inspect independent
consumers rather than relying on age or past migrations.

## Maintain Proxmox

```sh
ansible-playbook ansible/playbooks/observe-proxmox.yml
ansible-playbook ansible/playbooks/observe-proxmox-packages.yml
ansible-playbook ansible/playbooks/configure-proxmox-maintenance.yml --check
ansible-playbook ansible/playbooks/maintain-proxmox-packages.yml --check
```

Reboots require explicit playbook inputs and fresh observation. Networking,
firewall, storage and boot changes require independent console access. The
cluster firewall is OpenTofu-owned, **not** a second Ansible writer; its native
host observer checks rule order and both backends. New state-key or IAM grants
need independent AWS owner approval. For any import, confirm remote state and
live ownership before admitting a no-op import; neither a committed import block
nor an old adoption report is permission to repeat an import.

## Operation ownership and cleanup

`/var/lib/iac-ansible-production.lock` serializes production host mutation;
backup writers use `/run/lock/home-lab-backup.lock`. Never delete an owner just
because its controller has gone: inspect its process and journal first.
[`clear-failed-apply-lock.yml`](../ansible/playbooks/clear-failed-apply-lock.yml)
removes only one separately inspected terminal owner.

Controller caches and `.local/` / `.reconcile/` are scratch, not evidence. Before
removing ignored state, confirm no live owner/journal remains, every active
OpenTofu root refreshes from its remote backend, no resource is owned only by
local state, and independent custody exists for required credentials and
recovery payloads. Then remove private per-run work rather than archiving it.

Package, Tailscale, image and provider updates are reviewed changes, not
automatic installs; image tags do not override tracked digest pins. Sonarr,
Radarr and Radarr-4k's `downloadPropersAndRepacks: doNotPrefer` lives in their
backed-up application databases, not Compose. Verify it in each application
after restore; do not start a real download merely to test that setting.
