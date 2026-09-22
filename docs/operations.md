# Operations

This is the current operator path. Every admission decision uses source from the
reviewed checkout and observations made during the current run.

## 1. Prepare a disposable controller

Use a clean checkout with `tofu`, Ansible, Docker Compose, Python and the pinned
JavaScript package manager available. Connect to the home LAN and expose the existing
Bitwarden SSH agent without writing credentials into the repository. Tailscale is an
independent personal recovery path, not a deployment prerequisite.

```sh
git status --short
test "$SSH_AUTH_SOCK" = "$HOME/.bitwarden-ssh-agent.sock"
test "$(ssh-add -L | wc -l | tr -d ' ')" = 1
ssh-add -L | ssh-keygen -lf - -E sha256 | grep --fixed-strings \
  'SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA' >/dev/null
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
# Supply the current protected hardware observation and Omada CA, then run:
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
fresh live export over the LAN using the read-only provider identity. The imported VPN
ownership is intentionally limited to name and enabled state; see
[deployment access](deployment-access.md). Do not print `tofu show -json`, state,
private exports or saved plans. Apply only the saved plan inspected in the same
session. After apply, run a new plan; zero proposed changes is the completion
criterion.

## 4. Converge managed hosts

Native SSH identity, sshd and sudo policy for both hosts is owned by
[`configure-native-ssh.yml`](../ansible/playbooks/configure-native-ssh.yml). Run its
check mode before apply. During the one-time Tailscale-to-LAN migration, use a private
temporary inventory that preserves the reviewed old Tailscale endpoints only for this
bootstrap; do not commit or reuse that inventory. Validate the normal inventory over
LAN immediately afterward.

```sh
ansible-playbook ansible/playbooks/configure-native-ssh.yml --check
ansible-playbook ansible/playbooks/configure-native-ssh.yml
ansible-playbook ansible/playbooks/observe-hosts.yml
```

The complete Docker-host interface is [`ansible/playbooks/site.yml`](../ansible/playbooks/site.yml).
It observes before taking ownership, converges adopted backup files and units, Docker
maintenance and the complete committed Compose project, then observes the result.
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
