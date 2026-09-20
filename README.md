# Home lab

OpenTofu for infrastructure, Ansible for hosts, Docker Compose for applications.
The direction is **adopt the existing server first**, using standard SSH and
Ansible become—not rebuild the installation around a custom controller.

This checkout is in an **incremental native-tool transition**. The universal
controller, abandoned Compose admission implementation, reporting platform and
completed one-shot entrypoints have been removed. The legacy general Compose lane
refuses execution while its exact migration/recovery consumers remain preserved. A
manual native Compose entrypoint accepts explicit subsets of the existing service set;
each production invocation still requires reviewed paths, exact source and separate
authorization. Tracked repository digests are the sole ordinary image authority;
native deployment and observation do not consult image-lock or override files.

Supported native scope includes read-only host and Compose observation, manual-update
policy and existing-host backup configuration. Native Compose completed its canary
qualification and the attended all-service transfer from the former host image
override to tracked digest references. Immediate post-cutover observation was
zero-change. The ordinary bounded path then qualified stateless/dependent recreation,
tracked bind-file publication and a reviewed digest-pinned image update, each with
zero-change post-observation. Every future production run still requires exact scope
review and separate authorization; this is not unrestricted live use. Historical
interrupted/refused attempts and their consumed authorities remain documented in
[operations](docs/operations.md).

Ordinary rollback is a Git revert followed by the same bounded
[`deploy-compose.yml`](ansible/playbooks/deploy-compose.yml) forward deployment from
the latest reviewed automation. Missing old images are pulled again by exact digest.
The generic previous-artifact rollback entrypoint is retired; operation-specific
Nextcloud, database, storage and archive recovery paths remain separate.

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
