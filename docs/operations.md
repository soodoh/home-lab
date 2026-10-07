# Operations

Git defines desired state; hosts and provider APIs define current state; remote
OpenTofu state defines provider ownership. Start each decision from a reviewed
checkout and **fresh** observation. Prior runs, migration notes and plan digests
are not admission evidence. This runbook is for current operation, not a ledger
of completed cutovers. See [architecture](architecture.md),
[security](security.md), [recovery](../recovery/README.md) and
[outstanding work](migrations.md).

## Prepare a disposable controller

Follow the [workspace lifecycle](../AGENTS.md) for disposable controller artifacts
and retained recovery material.

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
umask 077
provider_session=$(mktemp -d "${TMPDIR:-/tmp}/home-lab-provider.XXXXXXXX")
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

Run the relevant observer afresh before **each** plan or host apply. Backup
observation never creates a backup. Select admission according to reviewed risk:

- **Routine reversible upgrades:** after checking release notes and startup
  behavior for persistent-data compatibility, a daily local snapshot less than
  48 hours old must cover the current files-from scope under the current backup
  policy. Its `artifact=` tag may identify an earlier deployment. NFS/Proton lag,
  unavailability or a terminal failed Proton copy is a warning, not a reason to
  stop an otherwise covered upgrade. A failed **local** unit remains a blocker:
  it combines scan and NFS copy, so failure alone cannot distinguish NFS lag from
  a partial local snapshot. Inspect it rather than accepting possibly incomplete
  data. Accessible repositories must still have the expected
  identities and copied ancestry must be unambiguous. Independently committed
  upgrades do not require a new backup for every deployment hash.
- **Data/storage/schema changes, deletion or incompatible upgrades:** verify the
  acceptable data-loss window, affected-data recovery path and external storage.
  Obtain a fresh affected-data backup or protected before-image when needed and
  explicitly review recovery before applying. The default `strict` observation
  still requires a complete games → NFS → Proton chain less than 48 hours old
  matching current policy and deployment; it is not by itself approval for a
  destructive change or proof that an image won't migrate data at startup.

For routine observation use
`ansible-playbook ansible/playbooks/observe-backups.yml -e restic_backup_admission=routine`.
Writer exclusion, interruption journals, unknown ownership, tool identities,
policy/scope and freshness checks remain blockers in both modes. Convergence
revalidates admission under the exact acquired production owner; that exception
never admits another owner's lock. A fresh observation is current-run input,
not standing approval. Only a matching complete chain proves the **changed
artifact** has three-copy backup coverage. Git revert restores configuration,
**not data**.

Unknown locks, interruption journals, mounts, keys, owners, service counts or
repository identities are refusals. Inspect them on the authoritative host.
Keep nonterminal locks, journals and before-images until live inspection resolves
them. Observation output is current-run input, not a Git artifact.

## Plan and apply OpenTofu resources

Active remote-backed roots under `infrastructure/tofu/` are `authentik`,
`aws-foundation`, `omada`, `proxmox`, `proxmox-firewall`, `servarr` and `tailscale`.
The declared `proxmox-access` root is owner-only and requires independent backend
and provider admission; never initialize it with ordinary controller credentials.
[Proxmox ownership](proxmox-ownership.md) describes new adoption, native snippet
replacement/readback and the host boundaries that remain outside the provider.
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
before plan/apply; reobserve after topology changes. For ordinary snippet plans
and after any snippet apply, also run
`ansible-playbook ansible/playbooks/observe-proxmox-cloud-init.yml`: native file
resources do not compare remote content. An intentional Git snippet change needs
private before-image inspection and explicit replacement review, not an ignored
hash mismatch. Never update expected hardware automatically from an unexplained
observation. The Proxmox cluster
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
as a mutating credential. `scripts/prepare-authentik-plan-input` checks all existing managed
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
from the same Authentik SOPS client secrets during site convergence. Do not
assume an Authentik plan or apply makes a consumer switch atomic; verify a fresh
OIDC login and a no-op plan before declaring rotation complete.
Grimmory consumes that same encrypted authority through its approval-gated native
settings API role; see
[native authentication convergence](#grimmory-native-authentication-and-library-ownership).
A new provider has no imported ID: the preflight discovers it by client ID after
creation and
requires its secret read, rather than continuing to skip a create-only declaration.
The dedicated Grimmory signing certificate follows the same create-only boundary:
rediscover it by exact name and independently admit its private-key read before
subsequent plans. Do not grant provider identities their own permissions.

### Grimmory native authentication and library ownership

[`converge-grimmory.yml`](../ansible/playbooks/converge-grimmory.yml) converges only
managed authentication settings through the native API over verified HTTPS. Check
mode authenticates the existing recovery administrator but does not write settings:

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/converge-grimmory.yml --check
# Separate approval after fresh host/Compose/strict-backup observation:
ansible-playbook ansible/playbooks/converge-grimmory.yml -e grimmory_apply_confirmed=true
```

OIDC-only mode retains the protected `grimmory-admin` local recovery exception.
Initialize only an explicitly approved empty instance with
`grimmory_initialize_confirmed=true`; never expose uninitialized setup, reset
accounts or promote users during convergence. Native settings writes are sequential,
not atomic: concurrent-edit guards and exact readback are required, and failures
retain production ownership for inspection.

Grimmory is the sole catalog/file writer. Use native uploads or BookDrop and
`BOOK_PER_FOLDER` to group formats as one book. Keep library roots separate:
`/books/paul` for Paul and `/books/sarabeth` for Paul and Sarabeth. Library
assignment defines web access; Kobo shelves define device selection only.
Preserve book/file identities and history when moving books between library roots;
qualify native moves and rescans before bulk changes. Keep original formats,
including KEPUB derivatives excluded by the generic scanner. Writable storage does
not approve metadata write-back, organization or automatic device selections.
After data/path/schema changes, verify a fresh private restored `books` scope with
current paths, IDs, covers, library grants, shelves and progress, not just empty
directories or an older restore. Regular backups preserve native state, not
discarded legacy records; never fabricate completion dates or catalog entries.
See [device qualification](migrations.md#physical-kobo-continuity).

### Shelfmark acquisition and seeding

Shelfmark at `shelfmark.diloreto.com` uses Authentik's operator-only embedded
proxy and trusted username/group headers; `App Operators` maps to Shelfmark admin.
It shares Gluetun's VPN namespace and publishes no host port. Ansible merges
Prowlarr's key and Hardcover's `HARDCOVER_API_KEY` from `production.sops.yaml`
and qBittorrent's login/SABnzbd's key from `download-clients.sops.yaml` into
native protected JSON settings. Store the raw Hardcover token from
`https://hardcover.app/account/api`, without `Bearer ` or whitespace; edit it
with `sops edit secrets/production.sops.yaml` for subsequent rotations. No new
credential authority or OpenTofu resource is introduced. Compose/site deployment
and native download-client credential convergence run the same consumer role.
A narrow resync is available after fresh host/Compose/strict-backup admission:

```sh
ansible-playbook ansible/playbooks/converge-shelfmark.yml --check
# Review the check and obtain separate approval:
ansible-playbook ansible/playbooks/converge-shelfmark.yml -e shelfmark_apply_confirmed=true
```

Only the managed connection fields and client selectors are owned; indexers,
source enablement (including `HARDCOVER_ENABLED`), Hardcover sort/list settings,
categories and import/seeding settings are preserved. Clear
Shelfmark's qBittorrent API-key field so it cannot override the managed login.
Check mode compares native files and tests desired credentials using isolated
private copies, without writing live settings or restarting. Apply stops only Shelfmark when credentials or file permissions differ, guards against
concurrent edits, atomically merges files as UID/GID 1000 mode 0600, starts it
and verifies effective values with the pinned native connection tests, including
Hardcover's read-only `me` query. Its connection test updates user metadata only
in the isolated verification copy, never live settings. No downloads are
submitted. Failure retains production ownership for inspection; do not
blindly restart or reset settings. Settings remain in the backed-up `/config`
directory, not Compose environment or OpenTofu state. Treat edits to managed
fields in the UI as drift; other fields remain application-owned.
Use qBittorrent categories `shelfmark` and `shelfmark-audiobooks`, without changing
other applications' categories or existing torrents.

Completed ebooks are copied into Grimmory BookDrop, never written directly into
the library. Shelfmark sees qBittorrent's `/data/downloads` read-only, keeps
torrents after import and disables ebook/audiobook hardlinks: ingest or metadata
edits cannot alter seeded originals. Audiobooks stay separate under Shelfmark's
configuration directory. BookDrop discovery is not proof of automatic library
import: review its native import settings and destination library before enabling
unattended imports. Qualify the copy/import/seeding flow with an approved test
book; do not launch an arbitrary download merely to verify deployment.

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
changes only credentials that differ, verifies persistence/authentication and
syncs Shelfmark from those same authorities before releasing ownership.
Immediately apply the reviewed saved Arr plan using the separate apply
confirmation, then test every Sonarr, Radarr, Radarr-4k and Prowlarr download
client and require a fresh no-op plan. These cross-application changes are **not
atomic**: do not call a partial rotation complete or automatically restore an
old credential when an apply fails. Preserve the lock and private evidence
until live ownership and connectivity are resolved. An Arr application's
**own** API key has a different order: `production.sops.yaml` is its single
desired source for Compose and provider inputs. On an approved key rotation,
converge Compose first so the application accepts the new key and Shelfmark
consumes it, then prepare a
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

### MAM session bootstrap and rotation

`secrets/servarr.sops.yaml` owns the initial MAM session ID at
`indexers["8"].mamId` for both consumers. Create a replacement session under
MAM Preferences → Security for the current VPN exit IP/ASN, permitting dynamic
seedbox IP updates, then edit only this field with SOPS. Store the raw ID, not
`mam_id=...`. Never put it in shell history or print decrypted content.

After reviewed committed source and fresh host/Compose/backup admission, prepare
a private Servarr saved plan using this SOPS revision. Review the complete plan,
including the enabled MAM indexer. Separately approve Compose convergence to
install Gluetun's protected bootstrap file, and separately approve the reviewed
Servarr apply to update Prowlarr. These are sequential, not atomic. Verify the MAM
hook succeeds without printing cookies, run Prowlarr's native indexer test, and
require a fresh no-op Servarr plan before declaring rotation complete.

Gluetun bootstraps a missing jar or changed initial ID on its next port-forward
hook, atomically publishing only a successful response with a session cookie.
Unchanged initial IDs preserve refreshed cookies across restarts. An explicit
session rejection permits one retry with the initial ID; network errors and
cooldowns do not. Persistent rejection requires replacing the SOPS ID, not
clearing the jar or retrying an expired credential indefinitely. Prowlarr retains
its native cookie refresh behavior; no runtime cookie synchronization or SOPS
write-back is performed. Bootstrap delivery is not proof of live MAM validity.

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
observes the result. Site convergence uses strict backup admission before host
changes. Source publication uses native rsync with checksums, delayed atomic
file replacement and deletion, preserving unchanged file/directory inodes.
Publication is **not** atomic across the whole tree. A complete source
before-image and the production lock remain until convergence succeeds.
A small read-only mount observer compares inode/metadata identities for managed
source and credential mounts, never secret contents or digests. Only declared
consumers of changed mounts are explicitly recreated; native Compose's
`recreate: auto` handles model/image/environment changes and removes orphans.
Mutable application-state mounts are excluded, not a restart signal. Unchanged
services are not restarted just because another image changed. Check mode
validates active state; do not apply after a refused observation or check.
Do not claim a changed artifact is backed up until strict admission succeeds.

```sh
ansible-playbook ansible/playbooks/site.yml --check
# Review the current output and obtain host approval before applying.
ansible-playbook ansible/playbooks/site.yml -e wolf_security_console_confirmed=true
```

Site convergence includes the scoped Wolf firewall and app-image pins. Confirm
independent Proxmox console access before supplying the console flag. For a
narrow security change, first review and apply the Tailscale root's owner-only
Wolf grant, then observe hosts, Compose and strict backups afresh:

```sh
ansible-playbook ansible/playbooks/converge-wolf-security.yml --check
# After review, with verified console access and no active Wolf sessions or lobbies:
ansible-playbook ansible/playbooks/converge-wolf-security.yml \
  -e wolf_security_apply_confirmed=true -e wolf_security_console_confirmed=true
```

The narrow interface does not publish a Compose source artifact. It changes only
native firewall configuration and backed-up Wolf image assignments, briefly
stopping Wolf when a pin changes. Verify native packet allow/deny behavior,
owner-tailnet access and other service health; qualify a real Moonlight session
before declaring streaming behavior verified. The namespace behavior test is
`ansible/tests/wolf-firewall.yml`; assignment tests use synthetic data in
`ansible/tests/wolf-image-pins.yml`; writer-exclusion response tests are in
`ansible/tests/wolf-admission.yml`. These are not production migration receipts.
On failure, inspect the retained production lock and root-only
`/var/lib/home-lab-wolf-security.*` before-image; do not clear them or infer safe
rollback from a Git revert. A fresh backup is needed before claiming the changed
application settings are backed up.

`configure-backups.yml` is a narrower existing-host interface: it validates
adopted files and journal under production/backup ownership, then converges
reviewed policy and runners without bootstrapping repositories or running a
backup. [`policy.json`](../services/data/restic/policy.json), native Restic
files-from/excludes and systemd units define recurring behavior; the runner is
only the writer-consistency adapter. `deploy-compose.yml` is a narrower
Compose-only interface requiring `compose_native_apply_confirmed=true`. Prefer
it for an independently reviewed service upgrade; use `site.yml` for full host
convergence. The default change class is `data` (strict admission). Selecting
`compose_native_change_class=routine` attests the persistent-data compatibility
review above; image-only does not automatically mean low risk:

```sh
ansible-playbook ansible/playbooks/deploy-compose.yml --check
# From reviewed committed source, after release/data compatibility review:
ansible-playbook ansible/playbooks/deploy-compose.yml \
  -e compose_native_apply_confirmed=true -e compose_native_change_class=routine
```

The host must have native rsync installed. An interrupted publication preserves host-local
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
fresh mount/writer evidence and a private restore before narrowing the list.
Keep the full daily chain; routine admission changes upgrade gating, not backup
scope, frequency, writer quiescence or replication.

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

The desired Proxmox apply grant scopes `Sys.Modify` to `/nodes/proxmox`.
Global cluster options are owner-only in `proxmox-access`; cluster-firewall writes
in `proxmox-firewall` also need separately approved independent owner Proxmox
apply credentials. Its normal audited plan token remains
usable. Do not restore global `Sys.Modify` to ordinary automation to get an apply
past a permission failure.

For normal Proxmox provider plans, supply `PROXMOX_VE_API_TOKEN` from the protected
`PROXMOX_PLAN_TOKEN`, switching to `PROXMOX_APPLY_TOKEN` only for a separately
approved saved-plan apply. Native snippet uploads additionally require the
[credential-free SSH and verified FQDN pin](proxmox-ownership.md#snippet-lifecycle-and-ssh).
Boot-disk/storage/node/snippet declarations are not permission to mutate or import
production resources; review their complete remote-backed plan first. The deployment
preserves the bridge's implicit MTU through its committed null variable; an explicit
MTU configuration and network reload need separate review.

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
