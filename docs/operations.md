# Operations

This is the current operator path. Every admission decision uses source from the
reviewed checkout and observations made during the current run.

## 1. Prepare a disposable controller

Use a clean checkout with `tofu`, Ansible, Docker Compose, Python and the pinned
JavaScript package manager available. Establish provider credentials and authenticated
Tailscale access without writing credentials into the repository.

```sh
git status --short
python3 scripts/check-source-boundaries.py
python3 scripts/check-compose-image-pins.py
scripts/test-compose-secret-files
```

After decrypting the current environment into a mode-0600 file in this run's private
temporary directory, validate interpolation without exposing resolved values:

```sh
docker compose --env-file "$runtime_env" config --quiet
```

Treat a dirty checkout, failed boundary check or unreviewed lock-file change as a
refusal.

Focused source tests:

```sh
python3 scripts/test-compose-native.py
python3 scripts/test-restic-runtime.py
python3 scripts/test-restic-systemd.py
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

The backup observer takes the backup lock nonblockingly, refuses retained operation
owners, opens all three live repositories and reports their current identities and
latest snapshots. Its output is for the current review only; do not save it in Git or
feed it to a later session.

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
TOFU_PLAN_CHDIR="$root" scripts/inspect-tofu-plan "$work/plan"
```

Use root-specific protected-input helpers where required. For Omada, set
`TF_VAR_omada_export_path` to a nonexistent path in the private temporary directory,
then run `scripts/prepare-omada-plan-input`; it obtains a fresh live export using the
read-only provider identity. Do not print `tofu show -json`, state, private exports or
saved plans. Apply only the saved plan inspected in the same session. After apply, run
a new plan; zero proposed changes is the completion criterion.

## 4. Converge the Docker host

The complete host interface is [`ansible/playbooks/site.yml`](../ansible/playbooks/site.yml).
It observes before taking ownership, converges adopted backup files and units, Docker
maintenance and the complete Compose generation, then observes the result.

```sh
ansible-playbook ansible/playbooks/site.yml --check
# Review all current observations and proposed changes.
ansible-playbook ansible/playbooks/site.yml
```

A Git revert followed by this convergence is configuration rollback. Data rollback
uses [recovery](../recovery/README.md).

[`configure-backups.yml`](../ansible/playbooks/configure-backups.yml) is a narrower
existing-host interface. [`services/data/restic/policy.json`](../services/data/restic/policy.json)
defines active desired policy; the role compares that projection to the installed
policy while tolerating only installed historical fields pending the documented
normalization migration. It preserves unit activation and does not bootstrap
repositories or run a backup.

[`deploy-compose.yml`](../ansible/playbooks/deploy-compose.yml) is an exceptional
bounded Compose interface. Prefer the complete site play so partial ownership does
not become normal operation.

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

Do not archive scratch space as evidence. This repository change intentionally does
not delete existing ignored directories because their ownership has not been checked
against the live systems in this run.
