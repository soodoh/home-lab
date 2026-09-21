# Repository guidance

Prefer declarative OpenTofu, Ansible, Docker Compose, systemd and Restic
functionality over custom scripts. Add custom code only for a demonstrated tool gap;
keep adapters small and test behavior rather than source text.

For infrastructure work, read [operations](docs/operations.md) and follow its links
for recovery, secrets, migrations or ownership.

Git defines desired state. Base operational decisions on fresh host or provider
observations.

Keep decrypted secrets, resolved Compose output, OpenTofu state, saved plans and plan
JSON out of logs and Git. Preserve nonterminal host locks, journals and before-images
until live inspection resolves them.

Run the native validators relevant to the files changed.
