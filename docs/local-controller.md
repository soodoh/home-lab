# Local controller

`scripts/local-controller` is the public entry point for steady infrastructure reconciliation.

```bash
scripts/local-controller plan steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
scripts/local-controller apply steady --generation baseline-1 --boundary-manifest /absolute/path/to/reviewed-controller-boundaries.json
```

Install the exact Ansible collection set before validation:

```bash
ansible-galaxy collection install --requirements-file ansible/collections/requirements.yml
```

Validation refuses a missing or differently versioned pinned collection.

The controller accepts only clean, committed revisions. Plan loads read-only credentials, validates the complete repository, creates commit-bound saved plans, runs policy checks, and displays the plans. Apply verifies those exact plans, requires the exact interactive confirmation, and loads separate mutation credentials only after confirmation.

The `.reconcile/controller-apply.lock` file is a persistent descriptor mutex. Its existence and last-owner metadata do **not** establish an active transaction: `scripts/controller/controller_lock.py` releases the lock by closing descriptors and intentionally leaves the inode and metadata in place. Inspect contention without changing the file; never unlink it as stale-lock cleanup. The runner loads reviewed Python source directly, not ignored bytecode caches. Host owner journals and failed-operation receipts have separate recovery rules.

Proxmox mutation authority has transferred to Ansible. The active controller now uses neutral v6 manifests and a fixed, nonce-bound, audit-only Proxmox capability instead of a Nix runtime. Repository validation passes without Nix, but installation/policy/host-lock migration and revision-bound live qualification are still required before this path is accepted. Historical Nix sources remain rollback evidence, not an alternate enabled writer; see [the completion review](host-lifecycle-completion-review-2026-09-05.md).

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
path, or either ARN requires a new reviewed generation; legacy v6 saved manifests without
this binding are refused. Nothing here establishes live existence, policy content,
external ownership, effective authorization, session containment, or deployment approval.
The separate owner/bootstrap, live readback, source review/immutable publication and custody,
provisioning, recovery protection, and writer stop/drain gates remain required. Do not clean,
stage, or commit an unapproved dirty checkout merely to bypass ordinary source admission.

## Saved plan boundary

Plans are stored under `.reconcile/plans/<commit>/steady/<generation>/`. Every invocation requires an explicit lowercase alphanumeric/hyphen generation (1–64 characters). A failed or expired attempt is retained; choose a new generation at the same commit instead of deleting or overwriting its evidence. Apply must select the exact reviewed generation. The manifest binds:

- the commit and backend identity;
- the required controller boundary manifest path, exact bytes hash, and declared provenance;
- every enabled OpenTofu plan file and SHA-256 value;
- the complete neutral Proxmox audit, source/dependency hashes, host trust, scope, nonce and freshness;
- the Compose artifact hash;
- protected input hashes when present; and
- Tailscale policy hashes and live ETag.

Apply never substitutes a new consumable plan. Read-only unrelated-root drift checks and final no-op verification plans remain safety checks, never replacement mutation plans. Legacy external-owner and VM-start prerequisite stages are explicitly rejected. The controller descriptor spans apply; the host descriptor locks cover only the immediate audit snapshot, not subsequent external-owner transactions. Those retain their own existing locks and exact transactions.

## Production authority

VM 100 accepts only Debian deployment authority. The controller no longer exposes Arch, Flatcar, qualification, cutover, state-move, or infrastructure-recovery modes. Production Ansible convergence is restricted to one reviewed tag per run and the `ansible-deploy` identity, authenticated by the tailnet policy through Tailscale SSH.

## Verification

Success requires:

- every enabled OpenTofu root at no-op;
- a fresh locked, complete, zero-change Proxmox audit;
- live Tailscale policy/state equality;
- a zero-change Debian production audit; and
- an exact Compose create simulation with builds and pulls disabled.

Application-data recovery and Compose rollback remain separate guarded procedures; see [`../recovery/README.md`](../recovery/README.md) and [`compose-deployment.md`](compose-deployment.md).
