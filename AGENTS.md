# Repository work

## Start here

- For host, provider, deployment or validation work, read [operations](docs/operations.md).
- For backup, secrets, rollback or storage changes, read [recovery](recovery/README.md).
- For database, access or resource adoption, read [migrations](docs/migrations.md).
- Before retiring helpers or changing ownership, read [decisions](docs/decisions.md) and trace callers, installers and recovery consumers together.

## Current boundary

This is an OpenTofu/Ansible/Compose repository in an incremental native-tool transition.
Read [operations](docs/operations.md) for supported observation, manual-update and
backup-configuration scope and dated outcomes before invoking any playbook.
Backup adoption requires existing identities, tool-policy equality and same-content
runtime files; it leaves enabled/active states untouched. Broader adoption is
pending; there is no general deploy command.
Surviving legacy playbooks may mutate hosts even under check mode; inspect them
before invocation. Source deletion does not retire installed helpers or timers.

Preserve service images, project/volume names, storage identities, HCL addresses,
imports, firewall behavior and backup scope unless that change is explicitly approved.
Keep `.local`, `.reconcile`, `.terraform`, state, credentials, journals, locks and
recovery bundles intact. Never clear locks or disable watchdogs to pass a check.

## Layout and editing

- `docker-compose.yml` includes domain-grouped `services/*.yml`; runtime hooks and app config live in `services/data/`.
- `infrastructure/tofu/` contains separate provider roots and locks.
- `ansible/` contains inventories, variables, roles and retained migration/recovery plays.
- `infrastructure/contract/` still feeds legacy consumers; change those dependencies together rather than rewriting hashes to admit a change.
- `scripts/` contains local tests and surviving runtime/recovery helpers. Tests are not all read-only: inspect their subprocesses and fixtures first.

Use two-space YAML indentation and existing domain groupings. Keep executable helper
modes. Prefer native tool definitions and narrow runtime helpers over new launchers,
transaction manifests or receipt frameworks. CLAUDE.md remains an alias here.

## Verify and report

Run safe focused local tests for changed helpers, parse changed YAML, check local
Markdown links, and run `docker compose config --quiet` without rendering secrets.
Use `tofu fmt -check` for HCL edits. The documented native observation playbook is
read-only; provider init/plan, other live Ansible plays, Docker up/pull and restore
require separate operational authority. Installing missing
tools is not implicit validation permission. Report missing tools and failed checks.

Never print decrypted SOPS data, resolved Compose config, state or saved plans.
Report changed/deleted files, tests/commands and outcomes, retained dependencies and
operational blockers. Follow Conventional Commits when a commit is requested;
staging, committing and pushing require authorization.
