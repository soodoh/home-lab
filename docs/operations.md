# Operations

This is the current operator path. Every admission decision uses source from the
reviewed checkout and observations made during the current run.

## 1. Prepare a disposable controller

Use a clean checkout with `tofu`, Ansible, Docker Compose, Python and the pinned
JavaScript package manager available. Establish provider credentials and authenticated
Tailscale access without writing credentials into the repository.

```sh
git status --short
tailscale status
python3 scripts/check-source-boundaries.py
python3 scripts/check-compose-image-pins.py
```

Provide the controller age identity and validate interpolation through SOPS without
persisting plaintext or exposing resolved values:

```sh
export SOPS_AGE_KEY_FILE=/protected/path/to/age-identity
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
# Supply the current protected hardware observation and provider identities, then run:
scripts/configure-local-provider-credentials
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

Active roots are `authentik`, `aws-foundation`, `omada`, `proxmox` and `tailscale`
under `infrastructure/tofu/`. Each has an S3 backend.

For the selected root:

```sh
root=infrastructure/tofu/proxmox
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT

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
otherwise. For Omada, set `TF_VAR_omada_export_path` to a nonexistent path in the
private temporary directory, then run `scripts/prepare-omada-plan-input`; it obtains a
fresh live export through the Docker host's tailnet-only Tailscale Serve endpoint on
TCP 8443 using the system trust store and read-only provider identity, including all
port-forwarding rules in the selected site. Do not print
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

### Tailscale coordination proxy rollout

The coordination proxy has three independently recoverable layers: the Authentik
identity objects, the private GOST/Caddy service, and the work-Mac client. Keep
independent console access to the Docker host and do not alter the Mac's active
Tailscale daemon until the first two layers pass their checks.

1. Plan and apply the `authentik` OpenTofu root using the fresh-plan procedure in
   section 3. The plan must add only the `tailscale-control` provider/application,
   the `tailscale-control-proxy` service account, and its exact application binding.
2. Converge Compose and confirm `https://ts-control.diloreto.com` presents Caddy's
   public certificate and an Authentik authentication response. The private GOST
   container must publish no host port.
3. In the Authentik Admin interface, open **Directory → Tokens and App passwords**,
   select **Create**, use identifier `tailscale-control-proxy`, select user
   `tailscale-control-proxy`, choose intent **App password**, disable expiry, and
   copy the value once into the protected work-Mac session. Do not put it in this
   repository, shell history or an OpenTofu input.
4. In the clean `~/Projects/dotfiles` checkout, age-encrypt the fixed username and
   prompt securely for the app password:

   ```sh
   mise set --file mise.work-macos.toml --age-encrypt \
     GOST_AUTH_USERNAME=tailscale-control-proxy
   mise set --file mise.work-macos.toml --age-encrypt --prompt GOST_AUTH_PASSWORD
   mise --env work-macos run validate:fast
   ```

5. After reviewing and committing that ciphertext, apply only the work profile's
   package, privileged-file and LaunchAgent resources from the work Mac:

   ```sh
   MISE_ENV=work-macos mise bootstrap \
     --only packages,files,macos-launchd-agents
   ```

6. Before restarting Tailscale, require the positive and negative proxy checks:

   ```sh
   curl --proxy http://127.0.0.1:1055 \
     https://controlplane.tailscale.com/
   ! curl --fail-with-body --proxy http://127.0.0.1:1055 \
     https://example.com/
   ```

   Any normal Tailscale HTTP response proves transport; an Authentik login page,
   `401`, `403`, Zscaler block page or TLS error is a refusal. The negative request
   must be denied by GOST.
7. Restart the Homebrew Tailscale daemon, then verify control and peer state:

   ```sh
   sudo brew services restart tailscale
   tailscale status
   tailscale netcheck
   ```

Soak beyond the previous failure interval with Zscaler enabled. Direct UDP peer
traffic should remain direct; the local HTTP proxy is for Tailscale coordination
and HTTPS relay fallback only.

For immediate client rollback, remove the managed proxy environment before
restarting Tailscale, and stop the LaunchAgent. Revert Git and reconverge both
repositories before treating rollback as complete:

```sh
launchctl bootout "gui/$UID" \
  "$HOME/Library/LaunchAgents/dev.mise.tailscale-control-proxy.plist" || true
sudo rm -f /etc/tailscale/tailscaled-env.txt
sudo brew services restart tailscale
```

### CLIProxyAPI first rollout

The committed Compose project adds CLIProxyAPI alongside LiteLLM. Its API and
management UI share `https://docker-host.tailea1a78.ts.net:8444`; Tailscale Serve
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
