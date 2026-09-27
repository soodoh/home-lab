# Operations

This is the current operator path. Every admission decision uses source from the
reviewed checkout and observations made during the current run.

## 1. Prepare a disposable controller

Use a clean checkout with `tofu`, Ansible, Docker Compose, Python and the pinned
JavaScript package manager available. Establish provider credentials and authenticated
Tailscale access without committing credentials. For a local
controller, copy [`.env.example`](../.env.example) to gitignored `.env`, fill
in the protected age-identity path and separate plan/apply provider credentials,
and keep the file private (`chmod 0600 .env`). These are persistent plaintext
controller credentials: protect and rotate them as such; Gitignore is not access
control or a backup. Never put decrypted SOPS values or live observations in it.
Neither Ansible nor OpenTofu automatically loads this file; from the repo root,
load the trusted local file into the current shell before running the commands
below:

```sh
set -a
. ./.env
set +a
```

Do not source an untrusted `.env` or commit it. A fresh controller can instead
export the same values from protected storage. The helper consumes these exported
provider identities without prompting and creates only current-run credential
files. Proxmox hardware identity checks are separate from provider credentials.

```sh
git status --short
tailscale status
python3 scripts/check-source-boundaries.py
python3 scripts/check-compose-image-pins.py
```

Provide the controller age identity and validate interpolation through SOPS without
persisting plaintext or exposing resolved values:

```sh
# If you did not load .env, export SOPS_AGE_KEY_FILE from protected storage.
sops exec-file --no-fifo --input-type yaml --output-type dotenv \
  secrets/production.sops.yaml 'docker compose --env-file {} config --quiet'
```

Treat a dirty checkout, failed boundary check or unreviewed lock-file change as a
refusal.

When establishing non-AWS provider credentials, create a new private session directory
and remove it on exit. The credential helper refuses durable or reused targets:

```sh
provider_session=$(mktemp -d)
chmod 0700 "$provider_session"
trap 'rm -rf "$provider_session"' EXIT
export HOME_LAB_PROVIDER_SESSION_DIR=$provider_session
# Export the provider variables from .env or protected storage before this step.
scripts/configure-local-provider-credentials
# The per-run files now hold the credentials; do not pass both identities to later tools.
unset AUTHENTIK_PLAN_TOKEN AUTHENTIK_APPLY_TOKEN \
  TAILSCALE_PLAN_ID TAILSCALE_PLAN_SECRET TAILSCALE_APPLY_ID TAILSCALE_APPLY_SECRET \
  OMADA_PLAN_USERNAME OMADA_PLAN_PASSWORD OMADA_APPLY_USERNAME OMADA_APPLY_PASSWORD
```

The generated `plan-credentials.json` and `apply-credentials.json` are inputs for this
controller run only. Do not copy them into `$HOME`, another checkout or a later session.

Focused behavior and native validation:

```sh
python3 scripts/check-compose-image-pins.py
python3 scripts/test-restic-runtime.py
python3 scripts/test-restic-observer.py
scripts/test-recovery-tools
infrastructure/policy/test-policy.sh
```

## 2. Observe live state

Run broad host observation first, then the domain being changed:

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/observe-hosts.yml
ansible-playbook ansible/playbooks/observe-compose.yml
ansible-playbook ansible/playbooks/observe-backups.yml
ansible-playbook ansible/playbooks/observe-proxmox.yml
ansible-playbook ansible/playbooks/observe-proxmox-packages.yml
```

The backup observer holds the backup lock nonblockingly across the complete
observation, refuses retained operation owners and drifted runtime bytes, validates
all three repository identities and timer cadence, and selects the newest complete
current-policy and current-Compose-artifact games → NFS → Proton chain less than
48 hours old. It observes a backup; it does not create one. Its output is for the
current review only; do not save it in Git or feed it to a later session.

### Backup admission for change batches

A fresh observation is required for each admission decision, not a new snapshot
before every apply. When the live policy and Compose artifact are unchanged, a
complete chain admitted by the current observation can protect several related,
reversible changes within its 48-hour freshness window. Reobserve the affected
host/provider state and rerun the applicable check-mode or saved-plan gates for
each apply; never reuse an earlier observation as permission for a later apply.
Group related Compose source changes into one reviewed site convergence where
possible: changing the Compose artifact or backup policy invalidates the old
chain for *current-state* admission. Obtain and observe a new complete chain before
treating the changed state as backed up or starting another ordinary change that
requires current-state backup admission. Do not bypass the observer's artifact,
policy, repository, ancestry or freshness checks to keep a batch moving.

Before a destructive operation, data/schema migration, storage change or other
change that could compromise production data, decide whether the last complete
chain meets the acceptable data-loss window and whether a verified recovery path
exists for the affected data (including external storage). If not, obtain a new
complete chain and/or protected before-image before proceeding; a daily schedule
alone is not evidence of a completed backup. Keep operation-specific approvals,
console access and rollback gates. A Git revert restores configuration, not data;
[recovery](../recovery/README.md) currently qualifies private staging, not
production data activation. Extra Restic snapshots reuse unchanged chunks but
still cost changed-data storage, transfer and a writer-stop consistency window;
do not take them merely because several low-risk applies are consecutive.

An unknown owner, interruption journal, repository identity, mount, service count or
host key is a refusal. Inspect it on the authoritative host instead of updating source
to match an unexplained observation.

## 3. Plan provider changes

Roots are `authentik`, `aws-foundation`, `omada`, `proxmox`,
`proxmox-firewall` (the sole cluster firewall owner), and `tailscale` under
`infrastructure/tofu/`. Each declares an S3 backend.

For the selected root, run fresh host observation first. In particular,
`observe-proxmox.yml` compares the live disk and USB devices, the host's sealed
hardware expectations and the reviewed
[`expected-hardware.json`](../infrastructure/tofu/proxmox/expected-hardware.json).
It refuses disagreement; never update Git automatically from a live observation.
Only the Proxmox root uses these identities. Reobserve immediately before its
plan/apply if the host or USB topology may have changed.

For the selected root:

```sh
root=infrastructure/tofu/proxmox
work=$(mktemp -d "$provider_session/plan.XXXXXX")
chmod 0700 "$work"
# The section 1 EXIT trap removes this work directory with the provider session.

: "${TF_BACKEND_BUCKET:?load the current plan credential environment first}"
tofu -chdir="$root" init -backend-config="bucket=$TF_BACKEND_BUCKET"
tofu -chdir="$root" plan -out="$work/plan"
policy_args=()
allow_file="infrastructure/policy/allow/$(basename "$root").txt"
[[ ! -f $allow_file ]] || policy_args+=(--allow-change-file="$allow_file")
TOFU_PLAN_CHDIR="$root" scripts/inspect-tofu-plan "$work/plan" "${policy_args[@]}"
```

Use root-specific protected-input helpers where required. Pass an allowlist only when
that root has a reviewed file under `infrastructure/policy/allow/`; omit the argument
otherwise. A normal allowlist **never** approves deletion. For Omada, review `infrastructure/tofu/omada/desired.json` as the intended LAN,
DHCP-reservation and port-forward settings. Set `TF_VAR_omada_export_path` to a
nonexistent path in the private temporary directory, then run
`scripts/prepare-omada-plan-input`; it obtains a fresh live export through the Docker
host's tailnet-only Tailscale Serve endpoint on TCP 8443 using the system trust store
and read-only provider identity, including all port-forwarding rules in the selected
site. The export must match every reviewed resource identity, but its settings are
not desired state. A changed live setting must appear as drift against Git; do not
copy it into `desired.json` to make a plan pass. Do not print
`tofu show -json`, state, private exports or saved plans. Apply only the saved plan
inspected in the same session. After apply, run a new plan; zero proposed changes is
the completion criterion.

### Scoped ACME IAM identity exception (exact-plan owner review required)

The plan inspector's default still refuses **all** managed IAM/Roles Anywhere
mutations. A narrow exception exists only for the reviewed `aws-foundation`
ACME DNS-01 user, policy and user-policy attachment **creations**. Controller
plan/apply policy updates remain owner-only. It requires a current-run
mode-0600 file **outside Git**, bound to the exact saved-plan SHA-256 and listing every changed IAM identity resource
by address, type and actions. This is not an allowlist or a general IAM
bootstrap mechanism. Managed OIDC providers, access keys, imports, tracking
moves, drift, deferred or incomplete plans, deletion/replacement and unrelated
IAM identities remain forbidden. [OpenTofu 1.12's plan JSON](https://opentofu.org/docs/v1.12/internals/json-format/#plan-representation)
omits a `complete` field; the pinned 1.12.6 binary does so as well. For
identity approval the inspector recognizes only that exact producer version and JSON format 1.2 when the field is absent, planning
succeeded, and no deferrals exist. An explicit incomplete result or another
producer/format version still requires a separate gate review. For the two
ACME identity creations, the provider marks a policy `name_prefix` and empty
tag unknown masks as computed even when the explicit name and both planned tag
maps are known. The gate admits only those exact metadata shapes and the
reviewed `System`/`ManagedBy` tags; unknown tag values or unrelated computed
identity fields remain forbidden.

The identity-creation exception was used only after the independent AWS owner
reviewed the [migration](ts-ingress-migration.md), IAM policy and external
plan/apply permissions boundaries. The apply role still cannot update its own
IAM policy. Any future owner policy change requires independent bootstrap and
separately reviewed state-only reconciliation; a normal plan cannot disguise
that drift. Do not target around this refusal.
The exact wildcard A record and dedicated ACME IAM user, policy and attachment
are now live; a reviewed state-only recovery and native untaint followed the
first DNS create, and a fresh `aws-foundation` plan passed with zero changes.
One scoped ACME access key has since been issued into
`secrets/production.sops.yaml`, outside OpenTofu state; private Traefik is
**not deployed**, and Serve remains active. The key and staged Compose source
do **not** authorize host convergence. For future planning, the independent owner must supply
the public hosted-zone ID as `TF_VAR_tail_ingress_zone_id` and the independently owned ACME-user boundary
ARN as `TF_VAR_tail_ingress_user_boundary_arn`. Verify the reviewed IPv4 in
`infrastructure/tofu/aws-foundation/tail-ingress.auto.tfvars.json` against a
fresh Docker-host Tailscale observation. Neither Git nor a controller lookup
proves that the zone, record, role permissions or boundary remain live. No
plan-bound IAM approval can be reused for a later plan.

For any separately reviewed identity-creation saved plan, create a private
approval file with this exact structure; include only the actual changed
subset of the named resources, not a blanket list. The original approval is
spent and cannot authorize another plan:

```json
{
  "root": "aws-foundation",
  "saved_plan_sha256": "<digest printed by inspect-tofu-plan>",
  "identity_mutations": [
    { "address": "aws_iam_user.tail_ingress_acme", "type": "aws_iam_user", "actions": ["create"] },
    { "address": "aws_iam_policy.tail_ingress_acme", "type": "aws_iam_policy", "actions": ["create"] },
    { "address": "aws_iam_user_policy_attachment.tail_ingress_acme", "type": "aws_iam_user_policy_attachment", "actions": ["create"] }
  ]
}
```

The file grants approval only after the owner privately verifies the *entire*
plan, exact IAM policy JSON, scoped TXT-record permissions, external boundary,
identity and unrelated changes. Run the normal inspector first, then rerun on
**the same saved plan** with `--approve-identity-file="$work/identity-approval.json"`.
A passing inspector does not itself authorize apply. Any new plan needs a new
approval. Do not generate an IAM access key through OpenTofu: its secret would
enter state. Keep this approval out of Git and remove it with the private
session.

### Approved destructive plans

OpenTofu `prevent_destroy` was removed from all roots: it cannot stop a destroy
when its resource declaration is removed, and it prevents intentional in-place
replacements. The separate plan inspector still **denies all delete/replacement
operations by default**. It permits them only with a current-run, mode-0600 approval
file **outside Git** bound to the exact SHA-256 of the saved plan, listing every
resource address, type, and exact `actions` sequence involving `delete`. This is
not the root's normal update/import allowlist; it does not override unconditional
IAM identity/ownership, incomplete/deferred-plan, drift, or VM-start-prerequisite
denials. Other protection/identity rules still apply. It does not authorize an
unreviewed change to the provider's own deletion behavior or server-side safety
settings.

After observing live state and saving a new plan as in section 3, run the normal
inspector first; it prints only a bounded saved-plan digest and a deletion refusal.
An owner must privately inspect the saved plan (including exact before identity,
changes besides deletion, replacement consequences and dependency order), verify
recovery/console access and a protected state before-image, then create a private
approval file for **this plan only**:

```json
{
  "saved_plan_sha256": "<64-character digest printed by inspect-tofu-plan>",
  "deletions": [
    { "address": "<exact resource address>", "type": "<resource type>", "actions": ["delete"] }
  ]
}
```

A replacement uses its exact order, for example `["delete", "create"]`. Include
**all** destructive actions; do not approve other or missing actions. The owner
creates this file with `umask 077` in the existing private current-run directory,
sets mode 0600, and never puts plan JSON, secrets, or approval receipts in Git.
Rerun `TOFU_PLAN_CHDIR="$root" scripts/inspect-tofu-plan "$work/plan" \
--approve-deletion-file="$work/delete-approval.json" "${policy_args[@]}"` and
apply **only the same saved plan**, after a separate human confirmation of its
exact changes. Any new plan needs a new approval; neither a passing policy check
nor an approval file is an automatic apply. Remove the file with the private
session and verify fresh live state and a no-op plan. A destructive AWS identity
change or other owner-only boundary still requires its separately documented
independent owner procedure; do not use this gate to bypass it.

## 4. Converge managed hosts

Tailscale SSH account, sudo policy and native-key retirement for both hosts are owned
by [`configure-tailscale-ssh.yml`](../ansible/playbooks/configure-tailscale-ssh.yml).
The Docker host's complete node-level Serve configuration is owned by
[`configure-tailscale-serve.yml`](../ansible/playbooks/configure-tailscale-serve.yml).
It requires tailnet HTTPS certificates to be enabled, exact host identity and an empty
or matching ownership boundary; convergence replaces any extra node-level Serve route.
Its only TLS-verification exception is the encrypted loopback hop to Omada on 8043;
controllers and runners strictly verify the Serve certificate with system trust.
Apply the Tailscale policy first, verify both MagicDNS endpoints through Tailscale, then
run the focused plays in check mode before apply. The staged
[Omada bridge cutover](omada-bridge-cutover.md) requires separate DHCP/adoption and
Authentik-retirement gates; do not deploy that source as an ordinary site apply.

```sh
ansible-playbook ansible/playbooks/configure-tailscale-ssh.yml --check
ansible-playbook ansible/playbooks/configure-tailscale-ssh.yml
ansible-playbook ansible/playbooks/configure-tailscale-serve.yml --check
ansible-playbook ansible/playbooks/configure-tailscale-serve.yml
ansible-playbook ansible/playbooks/observe-hosts.yml
```

### Private tailnet ingress: staging deployment pending

The separate `traefik-tailnet` service is staged in Compose with host networking
but binds HTTPS only to the reviewed Docker-host Tailscale IPv4. It has explicit
Omada and LLM routes, loopback-only upstreams, a separately protected staging
ACME store, and a Route 53 DNS-01 resolver. The public Traefik service and
Omada WAN forwards are unchanged. The dedicated ACME key is age-encrypted in
`secrets/production.sops.yaml`, rendered through the existing root-only
`/etc/docker-compose/production.env` only at deployment, and passed only to
the private container. It must not enter OpenTofu state, shell history, Docker
logs or resolved Compose output. The staging CA certificate will **not** pass
normal client TLS verification; do not migrate Omada/LLM clients or remove
Serve until a separately approved production-CA promotion and strict-TLS test.

Before any host deployment, reobserve host identity/IP, TCP 443 ownership,
Compose, backups, source artifact and Route 53 record/credential scope. Run
source validation and the site/check-mode gates, review the complete project
change from 41 to 42 services, and obtain separate operator approval. Ensure
protected `/srv/home-lab-state/traefik-tailnet-data/acme-staging.json` and its
parent are owned by root with modes 0600/0700. Keep the staging and later
production ACME stores separate and excluded from Restic intentionally;
recovering a lost store requires reissuance subject to CA limits. On a failed
staging deployment, retain Serve and the prior Compose source for rollback;
inspect the host lock, journal and before-images before retrying. Never use
an untrusted staging certificate as evidence that client migration is ready.

### Public ingress: Caddy to Traefik

The Caddy-to-Traefik cutover was applied and verified on 2026-09-27. The saved
Omada plan changed only the two intended forwarding targets, and a fresh
remote-backed plan was no-op. All 25 named HTTPS hosts served valid public
certificates; HTTP redirects, HSTS, negative routes, and an HTTP/3 request through
the gateway passed. The operator verified the work-Mac GOST/CLIProxyAPI relay.
A new complete games → NFS → Proton backup chain passed after Compose convergence.
The old Caddy container, live data and temporary before-image were retired after
explicit operator approval; Route 53 credentials were removed from SOPS/Compose.
A fresh AWS owner lookup and protected host comparison found that the same IAM
access key is still configured in the live `ddns-updater` data. **Do not revoke
`route53-user` or its key as Caddy cleanup**: DDNS still depends on them, even
if IAM last-used data appears old (its age alone does not prove inactivity).
Rotate or retire that identity only after a separately reviewed DDNS credential
migration and live update/backup verification.
The file provider owns only the listed HTTPS hosts; no Docker socket, dashboard,
DNS challenge, or wildcard certificate is needed. Omada continues to accept public
80/443 and must forward TCP 80 to Docker-host TCP 18080, and TCP/UDP 443 to
TCP/UDP 18443. Traefik listens on container 80/443. Its HTTP-01 challenge needs
public TCP 80 even though the host publishes 18080. Traefik persists its private
ACME account and certificates at `/srv/home-lab-state/traefik-data/acme.json`.
Like Caddy's previous certificate store, this is not in the Restic files-from set;
recovery from a lost host requires new ACME issuance (subject to CA rate limits).
The application configuration lives in Git. The proxy remains at `172.23.0.250`,
Home Assistant's trusted address.

For a future replay or rollback, obtain fresh host/Compose/backup and Omada
observations as in sections 1–3. Confirm 18080/TCP and 18443/TCP+UDP are free on the host,
that the gateway can map external 80/443 to those exact host ports (including UDP),
and that external DNS reaches the gateway. Do not use the reviewed desired settings
as proof of live forwarding. Confirm independent gateway and host access, a complete
backup chain, the exact saved Omada plan and policy approval, and a protected Caddy
certificate-store before-image outside Git. Plan for a short public ingress
interruption: switching either the gateway forward or Compose first will interrupt
the old endpoint until both layers have converged. Keep the old gateway mapping
available for rollback. Never apply a plan proposing unrelated Omada changes.

During the approved window, apply only the reviewed Omada forwarding plan and
converge committed Compose through `site.yml` (with the usual check/observe/lock
gates). Verify from outside the LAN that the currently listed hosts receive
valid public certificates and correct upstream responses, HTTP redirects to HTTPS
without `:18443` in the Location, HSTS on every listed HTTPS host, Books' HTTPS
redirects and generated links without `X-Scheme`, Home Assistant, WebSockets
(notably the authenticated GOST relay), and HTTP/3 over UDP 443. The shared
header policy and its upstream rationale are recorded in
[ingress headers](ingress-headers.md).
Verify that unlisted hosts, including `omada.diloreto.com`, have no application
route. Check Traefik's ACME state for successful issuance without printing it,
and obtain a complete new backup chain for the changed Compose artifact. The
ACME store is not in that chain; preserve it independently if immediate certificate
recovery rather than reissuance is required. If any gate fails, restore the former gateway forwards and the
reviewed Caddy Compose source under normal host ownership; do not delete the old
certificate data during rollback. After the rollback window closes and a fresh
live observation confirms the new ingress and backups, separately retire the
old host `/srv/home-lab-state/caddy-data` after confirming its ownership.
Before revoking any credential, inspect independent consumers: the historical
Caddy Route 53 key is **not unused**, because live DDNS shares it. Git removal
is not permission to erase an unexplained live path or credential. Since the approved
cleanup removed both Caddy stores, a future Caddy rollback cannot reuse its old
certificates; it must reissue them and honor CA limits. The steps above record the
cutover gates, not permission to replay a plan or delete additional resources.

### GOST relay hostname and account cutover (historical procedure)

The relay has three independently recoverable layers: the Authentik identity
objects, the private GOST/public ingress service, and the work-Mac client. This cutover
intentionally removes `ts-control.diloreto.com` and renames the existing
Authentik user to `gost-proxy-user` without a parallel old route. Expect a
brief loss of work-Mac Tailscale coordination until the new app password and
client are active. Keep independent console access to the Docker host and do
not restart the Mac's active Tailscale daemon until the first two layers pass.

1. Verify public DNS for `gost.diloreto.com` points to the current public ingress.
   Observe the live Authentik user and provider, and confirm remote state tracks
   the user and binding at their `gost-proxy-user` addresses before planning the
   `authentik` root using section 3. The existing user and binding IDs must be
   preserved; the provider's external host and the user's username must update
   **in place**. Any replacement, unexpected deletion, or plan refusal is a
   stop: do not issue a destructive-plan approval to complete this rename.
   Apply only the reviewed plan, then verify the old route/username no longer authenticate.
2. Converge Compose and confirm `https://gost.diloreto.com` presents the
   public certificate and an Authentik authentication response. Confirm the old
   hostname has no application route. The private GOST container must publish no
   host port. A change to the bind-mounted ingress configuration requires explicit
   recreation (the site play recreates the complete project on source changes).
3. In the Authentik Admin interface, open **Directory → Tokens and App passwords**,
   select **Create**, use identifier `gost-proxy`, select user `gost-proxy-user`,
   choose intent **App password**, disable expiry, and copy the value once into
   the protected work-Mac session. Do not put it in this repository, shell
   history or an OpenTofu input.
4. The work-Mac dotfiles checkout already holds the age-encrypted new username
   and the new endpoint, but **still holds the old encrypted app password**.
   Replace that value securely and validate before launching the updated client:

   ```sh
   mise set --file mise.work-macos.toml --age-encrypt --prompt GOST_AUTH_PASSWORD
   mise --env work-macos run validate:fast
   ```

5. After reviewing and committing the new ciphertext, apply only the work
   profile's package, privileged-file and LaunchAgent resources from the work Mac:

   ```sh
   MISE_ENV=work-macos mise bootstrap \
     --only packages,files,macos-launchd-agents
   ```

6. Before restarting Tailscale, check control-plane transport:

   ```sh
   curl --proxy http://127.0.0.1:1055 \
     https://controlplane.tailscale.com/
   ```

   Any normal Tailscale HTTP response proves transport; an Authentik login page,
   `401`, `403`, Zscaler block page or TLS error is a refusal. The work-Mac
   client's first-hop bypass now dials nonmatching destinations locally, so a
   negative `example.com` request through that client does **not** test the
   remote GOST allowlist. Test that boundary separately with an isolated,
   authenticated client that has no first-hop bypass.
7. Restart the Homebrew Tailscale daemon, then verify control and peer state:

   ```sh
   sudo brew services restart tailscale
   tailscale status
   tailscale netcheck
   ```

Soak beyond the previous failure interval with Zscaler enabled. Direct UDP peer
traffic should remain direct; the local HTTP proxy is for Tailscale coordination
and HTTPS relay fallback only. After successful new-token verification, revoke
`tailscale-control-proxy` in Authentik: renaming the user does **not** revoke its
old app password. Terminate any old WebSocket and confirm old credentials are
refused. The exact CLIProxyAPI CONNECT test follows below.

For immediate client rollback, remove the managed proxy environment before
restarting Tailscale, and stop the LaunchAgent. Revert Git and reconverge both
repositories before treating rollback as complete. If the old app password was
revoked, reverting source cannot restore it: issue a fresh password for the
restored identity before reconnecting the client.

```sh
launchctl bootout "gui/$UID" \
  "$HOME/Library/LaunchAgents/dev.mise.tailscale-control-proxy.plist" || true
sudo rm -f /etc/tailscale/tailscaled-env.txt
sudo brew services restart tailscale
```

### CLIProxyAPI through the authenticated WebSocket proxy

The `gost.diloreto.com` Authentik/GOST relay permits `tailscale.com` on TCP
80/443 and all subdomains of `mora-rattlesnake.ts.net` on **any TCP port**.
This owner-approved expansion uses the same service-account app password as
Tailscale coordination, not the CLIProxyAPI API or management key. A holder of
that password can attempt to reach other tailnet services with the Docker host's
network identity, including admin ports; Tailscale's grants for that identity
and each service's authentication still apply. GOST continues to refuse other
Internet destinations. It is not a path-filtered API-only ingress. The service
still publishes no public HTTP port, and the OAuth callback port must stay
private. Confirm work-device policy permits this use before rollout.
Docker's default DNS cannot resolve MagicDNS peers. Only the GOST container uses
the Tailscale resolver `100.100.100.100` and the host-observed public resolver
`1.1.1.1`, instead of a single static host alias. The `tailscale_serve` role
checks that DNS pair and the observed host resolver. Use the site play for this
change, not the narrower Compose-only deployment. The HTTPS client still
verifies the renamed Serve hostname; the site play replaces both old Serve
routes together and tests Omada and CLIProxyAPI afterward.

After a reviewed Compose deployment and fresh host observation, verify from the
work Mac with Zscaler enabled and the existing local GOST client running. Force
`curl` through the proxy even if `NO_PROXY` names the tailnet host; keep responses
and credentials out of logs:

```sh
curl --proxy http://127.0.0.1:1055 --noproxy '' \
  --silent --show-error --connect-timeout 10 --max-time 30 \
  --output /dev/null \
  --write-out 'connect=%{http_connect} http=%{http_code} tls=%{ssl_verify_result}\n' \
  https://docker-host.mora-rattlesnake.ts.net:8444/v1/models
```

This request should show CONNECT `200`, TLS verification `0`, and an API
authentication refusal (normally HTTP `401`, without an API key); a connection
failure, proxy denial, Authentik redirect, Zscaler block or TLS error is not
success. The local client's first-hop whitelist dials nonmatching sites directly;
a successful negative `example.com` request through it does not prove the
remote relay refuses non-tailnet destinations. If the first request fails,
observe GOST-container DNS for both MagicDNS peers and public control names,
Serve TLS, and the host's Tailscale policy; do not publish the backend. Then
verify an API-key-authenticated request from the actual Pi client configured to
use this proxy, without printing the key. A working `curl` CONNECT alone does
not establish that Pi supports the WebSocket-backed local proxy. Keep the
separate management key private; the relay does not filter management paths.

### CLIProxyAPI first rollout

The committed Compose project adds CLIProxyAPI alongside LiteLLM. Its API and
management UI share `https://docker-host.mora-rattlesnake.ts.net:8444`; Tailscale Serve
owns this route and Omada's separate `:8443` route as one exact node-level
configuration. Compose publishes the backend on host loopback only. A changed
Serve route resets and republishes both routes: check the Omada path before
and after convergence. Apply the reviewed `tailscale` OpenTofu policy change
first: only owner/admin devices may reach port 8444, not CI nodes. Do not
publish port 8317 or the OAuth callback port to
LAN or the public Internet.

`secrets/cli-proxy-api.sops.yaml` holds two independent keys: `API_KEY` for
clients and `MANAGEMENT_KEY` for the UI. The controller needs its protected age
identity for deployment; Ansible renders a root-owned mode-0600 runtime config
at `/etc/docker-compose/credentials/cli-proxy-api-config.yaml`, mounted read-only
in the container. Never print either key, the rendered file, a decrypted secret,
or resolved Compose output. The management key grants **full** configuration and
auth-file access: use the UI only for OAuth/account operations, keep Git/SOPS as
the config source, and treat any UI edit to settings or keys as drift requiring
review and reconvergence. The UI's Codex login callback-forwarding flow must be
verified over tailnet HTTPS with the dedicated, permitted account; do not open
port 1455 on the host.

After a reviewed source commit and fresh host/backup observation, run
`ansible/playbooks/site.yml --check`, then apply the site play as described
below. The post-convergence play verifies the UI through strict TLS. Confirm
without logging credentials that an unauthenticated API request is rejected,
an API-key-authenticated Codex request works from a temporary Pi client setup,
and management requires its distinct key. Authenticate via the tailnet UI and
verify the auth directory is populated before depending on the service. The
OAuth directory `/srv/home-lab-state/cli-proxy-api/auths` is included in the
existing encrypted Restic chain, including off-site copies; observe a complete
new backup chain before counting it as recoverable. Recovery staging is not
production activation (see [recovery](../recovery/README.md)). Do not put the
API key in Pi's permanent configuration as part of this change.

Keep LiteLLM and its secrets, config, backup path and recovery mapping intact
for now. After successful real Pi sessions and an operator decision, remove
those resources in a separate reviewed change; no fixed soak threshold or
restore test was selected. Revocation of the dedicated provider account and
rotation of both gateway keys remain manual incident-response actions.

The complete Docker-host interface is [`ansible/playbooks/site.yml`](../ansible/playbooks/site.yml).
It observes before taking ownership, converges deployment access, Tailscale Serve,
adopted backup files and units, Docker maintenance and the complete committed Compose
project, then observes the result.
Compose apply decrypts `secrets/production.sops.yaml` on the controller through
`community.sops`; `SOPS_AGE_KEY_FILE` must reference the protected age identity.

```sh
ansible-playbook ansible/playbooks/site.yml --check
# Check mode validates active state; apply archives committed Git source and converges it.
ansible-playbook ansible/playbooks/site.yml
```

A Git revert followed by this convergence is configuration rollback. Data rollback
uses [recovery](../recovery/README.md).

[`configure-backups.yml`](../ansible/playbooks/configure-backups.yml) is a narrower
existing-host interface. [`services/data/restic/policy.json`](../services/data/restic/policy.json)
defines repository, retention and runtime policy; `files-from` and `excludes` are the
native Restic path inputs. The role requires the installed policy
to match it exactly. The play observes first, acquires production ownership while
checking the backup mutex, and revalidates adopted files after ownership is published.
It converges reviewed policy and runner changes while that ownership is held, preserves
unit activation, and does not bootstrap repositories or run a backup.
The runner is only the consistency adapter around native Restic commands: daily work
creates one local snapshot and copies it to NFS and Proton; monthly maintenance owns
forget, prune and randomized 10% repository data checks. The percentage check avoids
an external subset cursor, trading guaranteed ten-run coverage for native stateless
selection. There is no separate replication queue.

[`deploy-compose.yml`](../ansible/playbooks/deploy-compose.yml) is the narrower
Compose-only interface. It requires `compose_native_apply_confirmed=true`, replaces
changed committed source as one project, and uses native Compose convergence with
orphan removal. A source change recreates the complete project. An interrupted source
swap preserves `/srv/docker-compose/previous`; inspect and resolve it before retrying.
The first migration publishes a new Compose artifact digest, so complete a fresh
backup cycle before treating recovery observations as current. Prefer the complete
site play.

## 5. Maintain Proxmox

Observe before using any mutating play:

```sh
ansible-playbook ansible/playbooks/observe-proxmox.yml
ansible-playbook ansible/playbooks/observe-proxmox-packages.yml
ansible-playbook ansible/playbooks/configure-proxmox-maintenance.yml --check
ansible-playbook ansible/playbooks/maintain-proxmox-packages.yml --check
```

A reboot requires its playbook's explicit inputs and a current package/host
observation. Networking, firewall, storage and boot changes also require an
independent access path.

### AWS foundation owner-only state reconciliation

An externally updated IAM policy can match Git and still appear as `resource_drift`
in an `aws-foundation` plan. The normal plan inspector correctly **refuses** this;
never add an IAM allowlist or describe that plan as admitted. This requires a
separate, bounded owner intervention, not an ordinary controller apply:

1. Require a clean reviewed checkout, fresh provider observations and protected
   foundation inputs cross-checked against both remote state and live AWS. Confirm
   that the independent owner retains the remote S3 state-object version as a
   private before-image. Keep the version identity and any saved plan outside Git
   and logs; check for concurrent state changes before applying.
2. With only the controller **plan** identity, save a `tofu plan -refresh-only` in a
   private current-run directory. Inspect its JSON privately. It must be complete
   and state-only, with exactly the externally owner-approved IAM policy-document
   refreshes and any separately explained provider-computed bucket fields. For
   `aws_s3_bucket.state.lifecycle_rule`, compare against the separately owned
   lifecycle resource and live S3 rules. No import, tracking move, unknown identity
   result, unrelated drift or cloud-resource mutation is acceptable. Have the
   independent owner explicitly approve those exact before/after state changes;
   an inspector refusal is not an approval.
3. Only after that review, use the controller **apply** identity to apply the
   **same saved refresh-only plan** while the S3 backend holds its lock. The
   controller apply identity still has no IAM writer privilege. Verify a new state
   version, reobserve live IAM/bucket identities and require a fresh ordinary plan
   with **no identity drift**. A proposed S3 lifecycle change is a separate normal
   reviewed plan/apply, never smuggled into the state-only intervention. Stop on
   any failed predicate and preserve the before-image for independent recovery.

A failed multi-step Route 53 create can leave a live `INSYNC` record **and** a
tainted resource in state. A refresh-only reconciliation updates computed
fields but does not remove the taint. Never apply the resulting record
replacement as a shortcut. First inspect the exact live record, authoritative
answer, remote state version and backend lock; after separate owner approval,
use native `tofu untaint <exact address>` under the apply identity with locking.
Keep the pre-untaint S3 version and require a new drift-free, zero-change plan.
For the tail-ingress record, the owner-controlled apply role also needs a
scoped `route53:GetChange` grant before any future DNS mutation; see the
[owner correction](aws-ts-ingress-owner-review.md#post-creation-controller-getchange-correction).

### Proxmox cluster firewall ownership

`infrastructure/tofu/proxmox-firewall/` isolates cluster options and complete ordered
rules from VM/hardware provider-planned updates. The root reads the same
`infrastructure/policy/proxmox-firewall.json` that the independent host observer
checks **in order**. The variable defaults **off**; the committed auto tfvars
enables management for the imported policy, but does **not** authorize an
unreviewed apply. The live default forward policy
is omitted by PVE's API; without the narrow ignore rule the pinned provider
would propose `ACCEPT` on import. OpenTofu ignores only that non-round-tripping
attribute while the observer checks that it is absent (the native default) or
explicitly `ACCEPT`. Never treat that
exception as permission to stop observing the forward policy.

The AWS foundation manifest declares a new state key. Verify live that the plan
and apply policies **and** their owner-controlled boundaries authorize only the
reviewed key and lock actions. The plan inspector unconditionally forbids managed
IAM policy mutation, and the controller apply role lacks IAM write privileges. An
independent AWS owner must review any IAM changes and reconcile identity drift
through a separate owner-reviewed state procedure before requiring a no-op
`aws-foundation` plan. The identity gate may refuse an ordinary plan when it sees
externally changed IAM policy. Do not bypass that refusal, initialize the firewall
root against local state or reuse the VM root's state key. The separate
[legacy AWS recovery-stack retirement](migrations.md#legacy-aws-recovery-stack-retirement)
may remain pending only with explicit owner approval to **retain unchanged** legacy
AWS ownership while firewall adoption proceeds. Compare protected inputs to the
tracked resources and live provider privately; retention is not approval of a new
S3 Restic writer, changed grants, or deletion. The preexisting `proxmox` root
independently proposes provider updates to two USB mappings and the VM even though
firewall ownership is isolated here; do not target around or apply those changes as part
of firewall adoption.

The initial two-resource adoption completed with a production-backed no-op
import, a fresh native observation, and a driftless remote-backed plan. If the
state key ever appears missing, inspect its versioned history before considering
re-import; never treat this checkout as automatic recovery permission. Any
future adoption/recovery import requires separate approval for a fresh saved
plan after confirming all of the following:

1. Fresh native host and provider observations show the **exact order** of the
   reviewed rules, the reviewed options, both active backends and no retained
   mutation owner. Confirm independent console access and a tested way to restore
   the native policy if network access is lost.
2. Have the independent AWS owner authorize only
   `home-lab/proxmox-firewall/tofu.tfstate` and its `.tflock` object in the
   existing controller plan/apply policies, and verify the owner-controlled
   permissions boundaries still apply. Obtain protected AWS foundation inputs
   from their independent owner, resolve any identity-drift refusal through a
   separate owner-reviewed reconciliation, and require a fresh **no-op**
   foundation plan. The ordinary controller cannot perform this IAM change.
   Reobserve before the firewall plan.
3. Supply only the selected Proxmox plan identity as `PROXMOX_VE_API_TOKEN`
   from protected storage (`PROXMOX_PLAN_TOKEN` is not wired by the current
   non-AWS credential helper); remove the apply identity from the plan session.
   Preview the two declarative imports against the new remote backend. Both the
   options and **all six ordered
   rules** must import with `no-op` actions and no other mutations. Any replacement,
   reorder, unexpected attribute change or access refusal stops adoption. The
   reviewed [`import:`-only allowlist](../infrastructure/policy/allow/proxmox-firewall.txt)
   permits only those two no-op imports, never later firewall mutations.
4. If management enablement needs changing, commit it separately from the
   import-only allowlist after that proof. Apply only the inspected saved plan from
   the same session with console recovery ready, then reobserve both backends and
   require a fresh no-op plan. Subsequent firewall changes need their own reviewed allowlist and
   independent console/rollback preparation. Ansible must never also write the
   cluster firewall.

## Operation ownership

`/var/lib/iac-ansible-production.lock` serializes production host mutation. Backup
writers use `/run/lock/home-lab-backup.lock`. Recovery and reconciliation interfaces
may have additional host-local owners.

Never delete an owner because the controller that created it is gone. Observe its
contents and associated process/journal first. The bounded
[`clear-failed-apply-lock.yml`](../ansible/playbooks/clear-failed-apply-lock.yml)
removes only one separately inspected terminal owner.

## Manual update policy

Package, Tailscale, image and provider updates are reviewed changes. Automatic
installation remains disabled; update checks may remain enabled. Image tags do not
override the tracked digest pins.

## Controller cleanup

`.local/`, `.reconcile/`, provider caches, saved plans and browser captures are
scratch space. They are not validation inputs and may be removed after confirming:

1. no host reports a live operation owner or interruption journal;
2. every active OpenTofu root initializes from its remote backend and refreshes
   against the provider;
3. no live resource is owned only by local state;
4. required credentials or recovery payloads exist in independent protected storage.

Do not archive scratch space as evidence. The reviewed controller scratch was removed
only after these checks completed; apply the same checks to any future ignored state.
