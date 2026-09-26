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
current-policy games → NFS → Proton chain. Its output is for the current review only;
do not save it in Git or feed it to a later session.

An unknown owner, interruption journal, repository identity, mount, service count or
host key is a refusal. Inspect it on the authoritative host instead of updating source
to match an unexplained observation.

## 3. Plan provider changes

Roots are `authentik`, `aws-foundation`, `omada`, `proxmox`, `proxmox-firewall`
(staged; do not apply without a reviewed import-only plan and separate approval), and `tailscale`
under `infrastructure/tofu/`. Each declares an S3 backend.

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
otherwise. For Omada, review `infrastructure/tofu/omada/desired.json` as the intended LAN,
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
run the focused plays in check mode before apply.

```sh
ansible-playbook ansible/playbooks/configure-tailscale-ssh.yml --check
ansible-playbook ansible/playbooks/configure-tailscale-ssh.yml
ansible-playbook ansible/playbooks/configure-tailscale-serve.yml --check
ansible-playbook ansible/playbooks/configure-tailscale-serve.yml
ansible-playbook ansible/playbooks/observe-hosts.yml
```

### GOST relay hostname and account cutover

The relay has three independently recoverable layers: the Authentik identity
objects, the private GOST/Caddy service, and the work-Mac client. This cutover
intentionally removes `ts-control.diloreto.com` and renames the existing
Authentik user to `gost-proxy-user` without a parallel old route. Expect a
brief loss of work-Mac Tailscale coordination until the new app password and
client are active. Keep independent console access to the Docker host and do
not restart the Mac's active Tailscale daemon until the first two layers pass.

1. Verify public DNS for `gost.diloreto.com` points to the current Caddy ingress.
   Observe the live Authentik user and provider, and confirm remote state tracks
   the user and binding at their `gost-proxy-user` addresses before planning the
   `authentik` root using section 3. The existing user and binding IDs must be
   preserved; the provider's external host and the user's username must update
   **in place**. Any replacement, unexpected deletion, or plan refusal is a
   stop: never bypass `prevent_destroy` to complete this rename. Apply only the
   reviewed plan, then verify the old route/username no longer authenticate.
2. Converge Compose and confirm `https://gost.diloreto.com` presents Caddy's
   public certificate and an Authentik authentication response. Confirm the old
   hostname is not served by Caddy. The private GOST container must publish no
   host port. Caddy's bind-mounted configuration requires explicit recreation.
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
never add an IAM allowlist or describe that plan as admitted. This is a separate,
one-time owner intervention, not an ordinary controller apply:

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

### Staged Proxmox cluster firewall ownership

`infrastructure/tofu/proxmox-firewall/` isolates cluster options and complete ordered
rules from VM/hardware provider-planned updates. The root reads the same
`infrastructure/policy/proxmox-firewall.json` that the independent host observer
checks **in order**. The variable defaults **off**; the committed auto tfvars
stages management enablement after a production-backed no-op import preview, but
does **not** authorize an apply. The live default forward policy
is omitted by PVE's API; without the narrow ignore rule the pinned provider
would propose `ACCEPT` on import. OpenTofu ignores only that non-round-tripping
attribute while the observer checks
that it is absent (the native default) or explicitly `ACCEPT`. Never treat that
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

No firewall import **apply** or mutation is authorized merely by this checkout.
The auto tfvars stages the reviewed adoption input; a separate approval for the
fresh saved plan is required after confirming all of the following:

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
4. Stage management enablement in a separate reviewed commit after that proof.
   Apply only the inspected saved plan from the same session
   with console recovery ready, then reobserve both backends and require a fresh
   no-op plan. Subsequent firewall changes need their own reviewed allowlist and
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
