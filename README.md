# Home lab

OpenTofu for infrastructure, Ansible for hosts, Docker Compose for applications.
The direction is **adopt the existing server first**, using standard SSH and
Ansible become—not rebuild the installation around a custom controller.

The Docker host has one authoritative native Ansible convergence interface:
[`ansible/playbooks/site.yml`](ansible/playbooks/site.yml). It derives the clean
tracked source, complete Compose service set, artifact changes and bind-file owners;
converges adopted backup definitions, Docker image maintenance and Compose; retires
superseded host state; and performs final observation. Tracked repository digests are
the sole image authority. No image lock, override, previous-artifact rollback or
service-specific recovery interface participates.

Normal usage is one source-bound check followed by the same site play without
`--check`; no service/path/hash argument set is required. The lower-level bounded
Compose play remains for exceptional reviewed subsets. Historical interrupted/refused
attempts and their consumed authorities remain documented in
[operations](docs/operations.md).

Ordinary rollback is a Git revert followed by authoritative site convergence from the
latest reviewed automation. Missing old images are pulled again by exact digest.
Disaster recovery uses one generic Restic flow with declarative recovery groups for
all or partial private-staging restores. Production restore activation remains
honestly unqualified; there are no Nextcloud-specific or archive-specific alternatives.

- [Operations](docs/operations.md): local checks, intended native workflow and retained implementation.
- [Recovery](recovery/README.md): snapshot staging, independent credentials and rollback boundaries.
- [Migrations](docs/migrations.md): unresolved database, storage, access and provider adoption.
- [Decisions](docs/decisions.md): ownership, safeguards and deliberate legacy dependencies.

Applications remain in [`docker-compose.yml`](docker-compose.yml) and
[`services/`](services/). Infrastructure roots are under
[`infrastructure/tofu/`](infrastructure/tofu/); host definitions under
[`ansible/`](ansible/). Service images, persistent paths, resource identities and
backup/firewall policy remain explicit source-owned state.

For native Docker-host convergence:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/site.yml --check
# Review, then repeat without --check.
```

For a local Compose configuration check only:

```sh
docker compose config --quiet
```

Do not print the rendered configuration: it can contain secrets. Merge approval
is not deployment approval. Authentik was observed already running PostgreSQL 18;
retain the old cluster until the [remaining migration/rollback checks](docs/migrations.md)
are resolved rather than rerunning the migration. A fresh rebuild and production
restore activation remain unproved.
