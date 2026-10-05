# Repository guidance

Prefer declarative OpenTofu, Ansible, Docker Compose, systemd and Restic
functionality over custom scripts. Add custom code only for a demonstrated tool gap;
keep adapters small and test behavior rather than source text.

For infrastructure work, read [operations](docs/operations.md) and follow its links
for recovery, secrets, migrations or ownership.

Git defines desired state. Base operational decisions on fresh host or provider
observations. For migrations, commit only reusable configuration and behavior
tests. After verification, remove transition-only allowlists, rollback
implementations, absence assertions and completed runbooks;
Git history preserves the explanation. Removing a resource declaration should
produce a reviewed destroy plan, not an orphaned state entry or a tombstone.

Use one private `mktemp -d` workspace under `${TMPDIR:-/tmp}` per task, outside
Git, for disposable one-off scripts, exports, logs and plans (`0700`, `umask 077`).
Execute and verify there; reuse it across phases. Remove it after verified
completion; report retained paths with their purpose and cleanup condition.
Check filesystem capacity before large exports or restores; temporary storage
may be RAM-backed.

Keep decrypted secrets, resolved Compose output, OpenTofu state, saved plans and plan
JSON out of logs and Git. Keep required backups in protected durable storage.
Preserve nonterminal host locks, journals and before-images there until live
inspection resolves them. Obtain approval before retaining other per-run artifacts
persistently.

Run the native validators relevant to the files changed.
