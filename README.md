# Home lab

OpenTofu for infrastructure, Ansible for hosts, Docker Compose for applications.
The direction is **adopt the existing server first**, using standard SSH and
Ansible become—not rebuild the installation around a custom controller.

This checkout is in an **incremental native-tool transition**. The universal
controller, abandoned Compose admission implementation, reporting platform and
completed one-shot entrypoints have been removed. There is no supported general
application deployment entrypoint: the legacy general Compose lane now refuses
execution, while its exact migration/recovery consumers remain preserved.

Supported native scope includes read-only host and Compose observation, manual-update
policy and existing-host backup configuration. The native Compose canary passed a
live observation and source-bound check-mode qualification; no container mutation
was run. One gated `flaresolverr` canary attempt is now authorized after a fresh
observation and preview bound to the same clean committed checkout. See
[operations](docs/operations.md) for its scope and safety limits.

- [Operations](docs/operations.md): local checks, intended native workflow and retained implementation.
- [Recovery](recovery/README.md): snapshot staging, independent credentials and rollback boundaries.
- [Migrations](docs/migrations.md): unresolved database, storage, access and provider adoption.
- [Decisions](docs/decisions.md): ownership, safeguards and deliberate legacy dependencies.

Applications remain in [`docker-compose.yml`](docker-compose.yml) and
[`services/`](services/). Infrastructure roots are under
[`infrastructure/tofu/`](infrastructure/tofu/); host definitions under
[`ansible/`](ansible/). Service images, persistent paths, resource identities and
backup/firewall policy are unchanged by this simplification.

For a local configuration check only:

```sh
docker compose config --quiet
```

Do not print the rendered configuration: it can contain secrets. Merge approval
is not deployment approval. Authentik was observed already running PostgreSQL 18;
retain the old cluster until the [remaining migration/rollback checks](docs/migrations.md)
are resolved rather than rerunning the migration. A fresh rebuild and production
restore activation remain unproved.
