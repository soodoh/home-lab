# Proton incident source retirement

## Scope and result

This is a source-only audit against baseline `c4e7371`, not a new deployment or
host observation. The completed TOTP cutover lane and superseded v2 migration
writer are removed. Password-reset diagnostics and staged qualification recovery
are conservatively retained: their transaction-specific closure is not established
by the repository's account-wide incident resolution.

No credentials, repositories, evidence records, bundles, locks, journals or
operational directories are retired. Installed copies and temporary staged files
have not been inspected or removed. Historical source remains in Git at the
baseline. Reintroducing an old writer requires a separately reviewed recovery
decision, not simply checking it out and replaying it.

## Removed source and evidence

| Removed files | Evidence and dependency boundary |
| --- | --- |
| `scripts/migrate-proton-restic-v2` | Hard-bound to predecessor `d1faa9cd…`, the old first-run snapshot and `Backups/home-lab-restic-v2`; it initializes/copies/checks that destination, not the promoted canonical repository. Its only tracked caller was `scripts/test-restic-tools.py`. The [promotion](../infrastructure/evidence/proton-qualified-promotion.json) and [incident resolution](../infrastructure/evidence/proton-incident-resolution.json) identify the damaged v2 repository `98d792c0…` and its subsequent retirement. This is supersession, **not proof that `migration-v2.json` reached `verified`**. Preserve that host journal and any installed helper; do not resume copying into the retired destination. |
| `ansible/playbooks/prepare-proton-totp-transition.yml`, `transition-proton-totp.yml`, `finalize-proton-totp-transition.yml` | The [cutover](../infrastructure/evidence/proton-totp-cutover.json) records the production lock absent, both timers active/enabled, no interruption and zero pending replicas. Its exact hashes link [qualification](../infrastructure/evidence/proton-totp-qualification.json), the local transition evidence and [independent bundles](../infrastructure/evidence/proton-totp-recovery-bundles.json). Qualification identifies transaction `fde2f5f4a1ed940bb4ec9f298eca195df3493b50b6b9fa5132909aa954087da1`. This closes that cutover, not unrelated transactions. |
| `scripts/transition-proton-totp-config`, `scripts/test-proton-totp-transition.py` | The transition playbook was the sole runtime source consumer; the dedicated test was the other caller. It staged a hash-checked helper and ciphertext under `/run/`, wrote transaction-bound evidence and retained the production lock until finalization. No backup role, bundle builder/consumer or VM recovery source set imports it. |

The migration-only block in `scripts/test-restic-tools.py` was replaced with
source-retirement and immutable evidence-chain checks. Active TOTP handling in
credential bootstrap, backup and bundle recovery remains unchanged; removing a
cutover writer does not remove
support for the resulting authentication mode.

## Retained dependencies and blockers

### Password reset and diagnostics

`scripts/diagnose-proton-auth` is not merely a read-only diagnostic. Its six
direct playbook consumers are:

- `diagnose-proton-auth.yml`, `diagnose-proton-beta.yml`,
  `diagnose-proton-post-reset.yml`;
- `rotate-proton-login-credential.yml`, `transition-proton-password-only.yml`,
  `reconcile-proton-account-reset.yml`.

The adjacent `deploy-proton-password-only-artifacts.yml` uses
`bootstrap-restic-credentials` and `qualify-proton-backup`, not this helper.
The six direct consumers bind helper SHA-256
`42f9dcbf90839c77f2ff381102a3c71244b0f7dd310604fdbf2a48953568e6e2`.
They stage/execute it transiently, validate the retained `proton-qualification`
owner, and preserve that lock. The helper supports resumable `started` claims
for password-only transition and account-reset reconciliation; the deployment
playbook separately supports interrupted artifact installation.

`recover-proton-qualification.yml` consumes immutable transaction-specific
transition, deployment and account-reset records, including their referenced
authentication, credential-rotation and beta evidence. It does **not** execute
`diagnose-proton-auth` to consume already-published evidence. Those data references
alone do not require keeping their writers. The unresolved question is whether
any retained qualification transaction still needs an incomplete prerequisite
completed. The tracked successful qualification record lacks a transaction ID;
later incident closure cannot answer that question for every earlier owner.
Therefore this pass keeps the whole reset lane and its tests byte-for-byte,
without regenerating pinned hashes or treating the historical plays as currently
runnable. Their old inert/Offen/policy guards remain in force.

`diagnose-proton-quota` has no tracked runtime caller/installer, but creates a
transaction-bound `started`/`observed` diagnostic record. It is retained pending
the same per-transaction review, not offered as routine quota maintenance.

### Staged qualification recovery

`supervise-staged-proton-recovery` and `finalize-staged-proton-recovery` have no
tracked playbook installer/caller; `scripts/test-restic-tools.py` tests them.
Absence of a source caller is not evidence that a manually staged recovery is
terminal:

- The supervisor verifies its own hash, the exact owner/config and the staged
  `/run/qualify-proton-backup-recovery-<transaction>` hash, then runs that helper's
  `recover-installed` action under the backup mutex as UID/GID 60000. It validates
  a recovered result and removes only the validated transient executable.
- The finalizer verifies its own/result/policy/config hashes, publishes the exact
  result to `/var/lib/home-lab-restic/proton-qualification-recovery-<transaction>.json`,
  tolerates an already-published identical result, then removes the transient result
  and releases only the matching owner-bearing lock. Publication-before-release
  and interruption handling remain recovery dependencies.
- Keep `qualify-proton-backup`, its role installer, `recover-proton-qualification.yml`,
  `resume-proton-qualification.yml` and `finalize-proton-empty-recovery`. The empty
  finalizer has a separate exact script pin and post-reset observation pin in the
  recovery playbook. No guard or receipt was changed.

Retirement needs separately authorized inspection of exact owners, staged files,
result/evidence pairs and incomplete claims. No generic lock clearing or replay is
an acceptable substitute. No live inspection was performed in this pass.

### VM recovery and immutable nonterminal history

A local, read-only inventory of 39 `.reconcile/restic-recovery-vm/*/journal.json`
files found these state labels:

| State | Count |
| --- | ---: |
| `destroy-applied` | 7 |
| `new` | 5 |
| `create-planned` | 4 |
| `create-replanning` | 4 |
| `create-applying` | 2 |
| `create-applied` | 4 |
| `run-pretransfer-observed` | 3 |
| `run-disk-prepared` | 10 |

These are local historical labels, not 32 proven live failures or independent VMs.
For example, `1371b101…` retains `run-disk-prepared` and `4b81eaa1…` retains
`create-applying`. Later successful restores/destroys do not rewrite their lineage.
Plaintext cleanup is required before `prove-restic-recovery-vm` records
`run-complete`; these labels alone do not prove cleanup. Preserve every directory.

Keep `prove-restic-recovery-vm`, its validator, Tofu root/locks, transport/capability,
`run-restic-recovery-bundle`, `test-restic-activation-fixture` and
`activate-restic-staging-fixture`. VM plans bind their source files (and bundle
inputs for create); none of the six removed files is in that source set. A local
scan of the `bindings` objects in 37 retained top-level create/destroy manifests
also found no removed-source path or exact baseline-file hash. No surviving tracked
source/evidence file references those removed-file hashes. These checks do not
validate saved plans or establish that retained source versions still match every
old manifest. Bundle builder/consumer and `restore-critical-backup` also remain.
No provider plan, restore, VM inspection or cleanup was run.

The incident receipt itself retains `canonical_creation=copied` and
`trash=cleanup-started` with their original hashes. The canonical creation failure
also records `receipt_committed=false`. These are immutable history, not permission
to finish obsolete destructive operations. Keep all evidence/schema files and
local plans/receipts, regardless of the source deletion.

Current backup scope, runner bytes, tool pins, repository identities, systemd
units, schedule activation receipts and native configuration are unchanged. See
[operations](operations.md) and [recovery](../recovery/README.md) for their existing
limits; source tests cannot establish backup integrity or live recovery readiness.

## Local validation

The following are parent-observed command outcomes from this source-edit session,
not immutable operational receipts or independent restore proof. Inspected tests
were run with synthetic inputs and temporary files only:

- `python3 -B scripts/test-proton-totp-transition.py` passed before removal.
- `python3 -B scripts/test-restic-tools.py` passed, including retained staged
  supervision/finalization, reset interruption and hash-binding fixtures. Real
  subprocesses are local Node YAML loading, disposable timeout/stdin processes
  and a failing synthetic shell command, not host or provider operations.
- `python3 -B scripts/test-proton-password-only-transition.py`,
  `python3 -B scripts/test-proton-transaction-boundaries.py` and
  `python3 -B scripts/test-restic-proton-sandbox.py` passed.
- `PYTHONDONTWRITEBYTECODE=1 bash scripts/test-restic-recovery-bundle` passed with
  fake tools/credentials/restore and disposable password-only, TOTP and interruption
  fixtures; no actual bundle or repository was opened.
- Python AST parsing, changed Markdown local paths/anchors, `git diff --check`,
  and parsing all ten surviving Proton playbooks with existing `js-yaml` passed.
  Python's PyYAML was unavailable; no dependency was installed. Only deleted YAML
  changed; no Ansible playbook was invoked.
- `docker compose config --quiet` failed for missing interpolation inputs
  `INTERNAL_HOST_IP`, `LITELLM_MASTER_KEY` and `OPENROUTER_API_KEY`. No secrets were
  decrypted and no resolved Compose configuration was printed.

## Independent review

A fresh, read-only `openai-codex/gpt-5.5` reviewer completed the dependency/recovery
review with **no issues found; OK with notes**. It independently checked source
callers, TOTP bundle support, VM recovery source bindings, evidence-chain semantics,
retained auth-helper pins and local journal labels. It did not execute tests or
inspect hosts. Its note about the pre-removal TOTP test is addressed above by
explicitly distinguishing parent-observed validation from immutable evidence.

The review artifact is `/tmp/home-lab-proton-retirement-review-gpt55.md`, run
`cd02ae72-69b9-4d74-bc2e-5d4481afbb9a`. Earlier reviewer attempts failed with
`fetch failed`, an unsupported Codex model and a Vertex model-not-found error;
they provided no review evidence. The operator approved alternate-model retries
through the same subagent mechanism; no external execution fallback was used.
Live transaction closure remains a blocker to broader retirement regardless of
this source review result.
