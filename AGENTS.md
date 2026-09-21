# Repository work

## Start here

- For host, provider, deployment or validation work, read
  [operations](docs/operations.md).
- For backup, secrets, rollback or storage work, read
  [recovery](recovery/README.md) and [security](docs/security.md).
- For database, access or resource adoption, read
  [migrations](docs/migrations.md).
- For authority and ownership questions, read
  [architecture](docs/architecture.md).

## Authority

Use Git for desired state and fresh host/provider observations for current state.
Treat controller files and observation output as disposable. Preserve a managed
host's nonterminal owner, journal or before-image until live inspection resolves it.
Use Git history for completed actions.

Run `python3 scripts/check-source-boundaries.py` after changing operational sources.

## Safety

- Never print decrypted SOPS data, resolved Compose configuration, OpenTofu state or
  saved plans.
- Refresh live state in the current run. A prior result, receipt or plan is not
  admission evidence.
- Revalidate after acquiring the mutation lock.
- Keep saved plans and protected output in private temporary directories and remove
  them when the run ends.
- Migrate or retire local-state ownership before deleting ignored controller files.

## Layout

- `docker-compose.yml` includes domain-grouped `services/*.yml`; application config
  lives under `services/data/`.
- `infrastructure/tofu/` contains independent remote-backed provider roots.
- `ansible/inventory/hosts.yml` and `ansible/playbooks/` are the host interfaces.
- `recovery/groups.json` is the declarative recovery scope.
- `scripts/` contains source checks and reusable operational helpers. Inspect a test's
  subprocesses and fixtures before running it.
