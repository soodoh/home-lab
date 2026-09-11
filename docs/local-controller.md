# Local controller

`scripts/local-controller` is a **deferred source candidate**, not a supported current maintenance default. The attended controller/helpers are local, undeployed and unqualified; the older v6 candidate is also deferred. Bounded existing-host Nix-runtime retirement completed 2026-09-11 with no removals or configuration changes; see the [completion checklist](host-lifecycle-completion-plan.md). This does not certify new-source convergence or a clean rebuild.

The complete accepted source snapshot is preserved on local, unpublished branch `wip/deferred-attended-controller-3491395-01`, including independent improvements as well as the attended controller. Local `main` contains the non-controller integration and retains its older v6 implementation, still deferred; clean committed source establishes neither installation nor operational readiness. [ADR 0005](adr/0005-attended-operational-admission.md) remains binding whenever this controller is invoked. Admission currently rejects the legitimate persistent firewall-recovery `operation.lock` pathname; the compatibility fix is **not implemented**. Retain locks, journals and watchdogs. Unknown pending operations and uncertain independent recovery access bar relevant writes. Do not substitute ordinary `observe`, execute legacy private-preparer `summary`, downgrade to v6, or bypass via raw OpenTofu or direct ungated Ansible.

## Candidate source reference — not execution instructions

The examples, v7 protocols, contract additions and attended test paths below describe only `wip/deferred-attended-controller-3491395-01`, not the implementation on `main`. They are a deferred design/source reference, not installation or operation approval. Candidate-only paths can be read locally with `git show wip/deferred-attended-controller-3491395-01:<repository-relative-path>`; no checkout or helper execution is needed.

```text
scripts/local-controller plan steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
scripts/local-controller apply steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
```

Future separately approved validation requires the exact Ansible collection set; no installation is authorized here:

```text
ansible-galaxy collection install --requirements-file ansible/collections/requirements.yml
```

Validation refuses a missing or differently versioned pinned collection.

The controller accepts only clean, committed revisions. Plan loads read-only credentials, validates the complete repository, creates commit-bound saved plans, runs policy checks, and displays the plans. Apply verifies those exact plans, requires the exact interactive confirmation, and loads separate mutation credentials only after confirmation.

The `.reconcile/controller-apply.lock` file is a persistent descriptor mutex. Its existence and last-owner metadata do **not** establish an active transaction: `scripts/controller/controller_lock.py` releases the lock by closing descriptors and intentionally leaves the inode and metadata in place. Inspect contention without changing the file; never unlink it as stale-lock cleanup. The runner loads reviewed Python source directly, not ignored bytecode caches. Host owner journals and failed-operation receipts have separate recovery rules.

Proxmox mutation authority has transferred to Ansible. [ADR 0005](adr/0005-attended-operational-admission.md) selects manifest v7 and `attended-operational-v1` for steady planning, verification and provider admission. On that candidate branch, the `proxmox-audit.yml` / `proxmox_complete_audit` role calls fixed `observe-admission`, independently verifies seventeen domains, and records the bounded sample. This source route does not call `observe-controller` or the v6 installer, but its rejection of the existing recovery `operation.lock` remains an unresolved compatibility blocker. This is **not installed qualification**: the selected neutral collector was absent and observer/VFIO/protected dependencies still need exact native qualification under separate future approval, not as reopened retirement gates. See the [completion checklist](host-lifecycle-completion-plan.md). The [v6 capability candidate](proxmox-controller-capability-candidate.md) and its qualification consumers remain deferred and cannot consume attended evidence. Retained `nix/` data and the selected pre-v6 VFIO implementation do not execute Nix and must not be deleted while needed.

## Required non-secret controller boundary manifest

Every ordinary `local-controller` action and direct `reconcile-infrastructure` action
(including `validate`, `verify`, and `apply-tailnet`) requires an explicit absolute
`--boundary-manifest` path. There is no default file, ARN pair, environment substitute,
or override switch. This is separate from `--config-dir` and the capability-specific
credential JSON. `configure-local-controller-aws` remains a credential/certificate setup
helper; it neither provisions this manifest nor selects boundaries.

**Provisioning is a separate, approved operator step, not an owner bootstrap executor.**
After independent review, place one non-secret JSON document at the explicitly selected
path, owned by the controller user, as a regular non-symlink file with no group/world
write permission (0600 recommended). Do not create it from the inert proposal JSON or
assume the policies already exist. The schema is exactly:

```json
{
  "version": 1,
  "account_id": "658271954302",
  "partition": "aws",
  "plan_policy_arn": "REQUIRED_REVIEWED_EXTERNAL_PLAN_POLICY_ARN",
  "apply_policy_arn": "REQUIRED_REVIEWED_EXTERNAL_APPLY_POLICY_ARN",
  "provenance": {
    "review_reference": "REQUIRED_INDEPENDENT_REVIEW_REFERENCE",
    "plan_policy_sha256": "REQUIRED_64_LOWERCASE_HEX_SHA256",
    "apply_policy_sha256": "REQUIRED_64_LOWERCASE_HEX_SHA256"
  }
}
```

These placeholders deliberately fail validation. Both distinct ARNs must be managed
policies in account `658271954302`, partition `aws`, not either controller-owned
`home-lab-opentofu-state-{plan,apply}` policy. Only alphanumeric and `+=,.@_-` policy
name/path components are admitted; `.`/`..` components, empty components, wildcard ARNs,
and trailing slashes are rejected. Names are at most 128 characters and paths at most
512 characters. JSON is UTF-8 without BOM, at most 16 KiB; duplicate/unknown/missing keys,
wrong types, and unsupported versions are rejected at every schema level. The review
reference is 1–256 printable ASCII characters without surrounding whitespace. Policy
hashes are SHA-256 of the exact independently reviewed policy-document bytes, not
claims of current AWS default-version identity. Keep those reviewed bytes, version
metadata and approval evidence independently; this loader does not fetch or evaluate IAM.

A later authorized operator can validate the provisioned **non-secret file only**, without
credentials, AWS, tofu, or providers:

```bash
python3 -B -E -s -S scripts/controller/controller-boundary-manifest.py load --manifest /absolute/path/to/reviewed-controller-boundaries.json
```

The output contains both ARNs and their accepted binding. Matching inherited/configured
`TF_VAR_controller_{plan,apply}_permissions_boundary_arn` values are tolerated; empty or
conflicting values fail before provider preparation. Nonempty `TF_CLI_ARGS` and all
`TF_CLI_ARGS_*` are refused rather than parsed. Foundation plans and every verification/
tailnet preflight receive the accepted pair as fixed `-var` arguments (higher precedence
than auto tfvars). Saved binary plans are still applied without replacement variables.
The current manifest is rechecked after credential loading and before backend operations.
Apply ordering remains validation → interactive confirmation → mutation-config loading:
manifest/inherited conflicts and saved-binding drift fail before validation. A conflict
first encountered in mutation-config JSON fails immediately after that existing load,
before TLS/provider preparation or any use of the loaded capability. This does **not**
claim such a conflict prevents the earlier validation, which uses only the already-admitted
manifest; mutation configuration is never read early to make that claim.

Saved plans bind the resolved absolute manifest path, exact raw-byte SHA-256, and complete
document including declared provenance. Changing bytes (even formatting), provenance,
path, or either ARN requires a new reviewed generation; all legacy v6 saved manifests and
manifests without this binding are refused. Nothing here establishes live existence, policy content,
external ownership, effective authorization, session containment, or deployment approval.
The separate owner/bootstrap, live readback, source review/immutable publication and custody,
provisioning, recovery protection, and writer stop/drain gates remain required. Do not clean,
stage, or commit an unapproved dirty checkout merely to bypass ordinary source admission.

## Saved plan boundary

Plans are stored under `.reconcile/plans/<commit>/steady/<generation>/`. Every invocation requires an explicit lowercase alphanumeric/hyphen generation (1–64 characters). A failed or expired attempt is retained; choose a new generation at the same commit instead of deleting or overwriting its evidence. Apply must select the exact reviewed generation. The manifest binds:

- the commit and backend identity;
- the required controller boundary manifest path, exact bytes hash, and declared provenance;
- every enabled OpenTofu plan file and SHA-256 value;
- `assurance_model: attended-operational-v1`, the complete Proxmox audit, source/dependency hashes, independently pinned host trust, exact role scope and controller observation interval;
- the Compose artifact hash;
- protected input hashes when present; and
- Tailscale policy hashes and live ETag.

Apply never substitutes a new consumable plan. Read-only unrelated-root drift checks and final no-op verification plans remain safety checks, never replacement mutation plans. Legacy external-owner and VM-start prerequisite stages are explicitly rejected. The controller descriptor spans plan, apply and verify. The fixed `observe-admission` verb samples existing lock/owner state before and after its reads and returns a required admission envelope. Shared `observe` still returns the unchanged protocol4 payload for transaction-internal snapshots while their own locks are held; ordinary observations are rejected by attended audit/evidence validation. Existing host transactions keep their locks and journals.

### Attended window and producer prerequisite

Before each collection, type `attended-operational-v1` at the interactive prompt. Keep other controllers, privileged/API writers, backups, recovery, packages, VFIO work and queued reboots excluded through final verification. Resolve unknown jobs and retained ownership first. Coordinate timers separately; the command does not stop them. Keep the independent console/access route and operation-specific backup/recovery readiness available. Apply confirmation is `apply-attended-steady-converge` (or `apply-attended-tailnet-steady-converge`). An elapsed/abandoned window, drift, failed collection or ambiguous mutation requires intervention and a fresh reviewed generation—not a retry, automatic cleanup or receipt restamp.

Set `RECONCILE_PROXMOX_KNOWN_HOSTS` to a dedicated controller-owned mode0600 absolute file containing only the independently verified `proxmox ssh-ed25519 …` entry, and `RECONCILE_PROXMOX_HOST_KEY_SHA256` to its independently established fingerprint. Collection passes that exact file to the role with global known-hosts disabled. Evidence expires five minutes after collection starts, not after a slow audit finishes; collection itself is bounded to four minutes. Plan generation must finish and be reviewed within that bound or be replaced.

For source review, render with `node scripts/controller/build-proxmox-ansible-observer.js --output-dir /absolute/new/private/artifact --assurance-model attended-operational-v1`. This does not install anything. The default builder output remains the separate gated v6 candidate; never deploy it as an attended artifact. Attended artifacts contain the neutral observer and summary-only protected collector, no controller-observer. The coherent installation set is **observer, neutral collector, updated fixed plan transport, and exact ansible-plan sudo rule**. The new transport literal dispatches only `proxmox-observer observe-admission`; the contract permits exactly that additional read-only invocation. The artifact binds the transport hash, contract-derived sudo content and admission schema. Pair-only installation cannot supply the new route. Qualify/install all four with current contract/specification and strict interpreter/protected dependencies through separate approval; preserve ordinary `observe` for all existing callers. Missing or mismatched bytes fail. Do **not** use retained private-preparer `summary`: it creates the permanent operation lock and can break the installed historical reboot contract. No installation method or rollback is authorized here. The future plan must preserve/restore the exact prior observer, transport and sudo bytes and handle absent-collector creation/rollback without deleting foreign bytes; do not reuse the gated v6 installer.

Candidate-only source regression `scripts/controller/test-proxmox-observer-caller-compatibility.py` (absent from `main`) traces the actual installed-compatible network/Tailscale lock → validation → snapshot → shared-observer chain. Its `--native-installed-read-only` mode is **not run or authorized**: it requires a new exact host/lock/inspection grant, Linux root, the clean reviewed `/root/home-lab` checkout used by the historical activator with the named Git object and existing Node dependencies, exact helper/transport/sudo identities and safe preexisting lock files. It exercises read-only installed `inspect-network-lifecycle` / `inspect-tailscale-lifecycle` under their existing locks and checks that admission refuses the same lock, without repeating ownership transfers. It neither installs tools nor creates locks, stages work, writes host receipts or repairs missing prerequisites. Native transport/login, role, protected-dependency and real provider checks remain separate qualification requirements.

`node scripts/controller/proxmox-check-evidence.js verify-evidence /absolute/receipt` performs offline source/freshness validation only; it neither collects facts nor authorizes apply. Collection still uses the real role, while both manifest readers and apply's immediate before-state recheck require the selected model. Samples are not atomic snapshots, leases, challenge-bound host freshness or queued-reboot custody.

## Production authority

VM 100 accepts only Debian deployment authority. The controller no longer exposes Arch, Flatcar, qualification, cutover, state-move, or infrastructure-recovery modes. Production Ansible convergence is restricted to one reviewed tag per run and the `ansible-deploy` identity, authenticated by the tailnet policy through Tailscale SSH.

## Verification

Success requires:

- every enabled OpenTofu root at no-op;
- a fresh attended, complete, zero-change Proxmox audit (not an executed host convergence);
- live Tailscale policy/state equality;
- a zero-change Debian production audit; and
- an exact Compose create simulation with builds and pulls disabled.

Application-data recovery and Compose rollback remain separate guarded procedures; see [`../recovery/README.md`](../recovery/README.md) and [`compose-deployment.md`](compose-deployment.md).
