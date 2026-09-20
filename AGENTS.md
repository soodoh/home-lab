# Repository work

## Start here

- For host, provider, deployment or validation work, read [operations](docs/operations.md).
- For backup, secrets, rollback or storage changes, read [recovery](recovery/README.md).
- For database, access or resource adoption, read [migrations](docs/migrations.md).
- Before retiring helpers or changing ownership, read [decisions](docs/decisions.md) and trace callers, installers and recovery consumers together.

## Current boundary

- This OpenTofu/Ansible/Compose repository uses native tools. Read[operations](docs/operations.md) before host, provider, deployment or recovery work.
- Never print decrypted SOPS data, resolved Compose config, state or saved plans.

## Layout and editing

- `docker-compose.yml` includes domain-grouped `services/*.yml`; runtime hooks and app config live in `services/data/`.
- `infrastructure/tofu/` contains separate provider roots and locks.
- `ansible/` contains inventories, variables, roles and retained migration/recovery plays.
- `infrastructure/contract/` still feeds legacy consumers; change those dependencies together rather than rewriting hashes to admit a change.
- `scripts/` contains local tests and surviving runtime/recovery helpers. Tests are not all read-only: inspect their subprocesses and fixtures first.
