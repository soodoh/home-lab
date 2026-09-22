# Home lab

OpenTofu owns provider resources, Ansible owns the two hosts, and Docker Compose
owns applications. Controllers are disposable: every run starts from reviewed Git
source and observes the live systems again.

## Authority

- Git defines desired configuration, pins, recovery groups and safety policy.
- Proxmox, the Docker host and provider APIs define current state.
- OpenTofu remote backends define provider-resource ownership.
- A managed host may retain an active operation lock, interruption journal or
  before-image until that operation is resolved.
- Git history supplies historical context. Historical outcomes are not operational
  inputs.

See [architecture](docs/architecture.md) for the complete boundary.

## Start here

- [Operations](docs/operations.md): source checks, live observation and mutation.
- [Recovery](recovery/README.md): fresh snapshot discovery and private staging.
- [Migrations](docs/migrations.md): unresolved live conditions only.
- [Security](docs/security.md): secrets, state and protected output.
- [Deployment access](docs/deployment-access.md): native LAN SSH, WireGuard staging and future CI.

Applications are in [`docker-compose.yml`](docker-compose.yml) and
[`services/`](services/). OpenTofu roots are under [`infrastructure/tofu/`](infrastructure/tofu/).
Host inventory and playbooks are under [`ansible/`](ansible/).

## Normal host workflow

```sh
python3 scripts/check-source-boundaries.py
python3 scripts/check-compose-image-pins.py
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-lint ansible/playbooks ansible/roles
yamllint . --no-warnings
shellcheck $(find . -type f \( -name '*.sh' -o -name '*.bash' \) -not -path './.git/*' -print)
docker compose config --no-env-resolution --no-interpolate --quiet
tofu fmt -check -recursive
export SOPS_AGE_KEY_FILE=/protected/path/to/age-identity
sops exec-file --no-fifo --input-type yaml --output-type dotenv \
  secrets/production.sops.yaml 'docker compose --env-file {} config --quiet'

ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-hosts.yml
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-compose.yml
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-backups.yml
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-proxmox.yml

ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/site.yml --check
# Review current output, then repeat without --check.
```

A Git revert followed by authoritative site convergence is configuration rollback;
data recovery remains a separate operation.

Do not print resolved Compose configuration, decrypted SOPS data, OpenTofu state or
saved plans. Merge approval is not deployment approval.
