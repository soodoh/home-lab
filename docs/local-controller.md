# Local controller

`scripts/local-controller` is the public entry point for steady infrastructure reconciliation.

```bash
scripts/local-controller plan steady --generation baseline-1
scripts/local-controller apply steady --generation baseline-1
```

Install the exact Ansible collection set before validation:

```bash
ansible-galaxy collection install --requirements-file ansible/collections/requirements.yml
```

Validation refuses a missing or differently versioned pinned collection.

The controller accepts only clean, committed revisions. Plan loads read-only credentials, validates the complete repository, creates commit-bound saved plans, runs policy checks, and displays the plans. Apply verifies those exact plans, requires the exact interactive confirmation, and loads separate mutation credentials only after confirmation.

The `.reconcile/controller-apply.lock` file is a persistent descriptor mutex. Its existence and last-owner metadata do **not** establish an active transaction: `scripts/controller/controller_lock.py` releases the lock by closing descriptors and intentionally leaves the inode and metadata in place. Inspect contention without changing the file; never unlink it as stale-lock cleanup. The runner loads reviewed Python source directly, not ignored bytecode caches. Host owner journals and failed-operation receipts have separate recovery rules.

Proxmox mutation authority has transferred to Ansible. The active controller now uses neutral v6 manifests and a fixed, nonce-bound, audit-only Proxmox capability instead of a Nix runtime. Repository validation passes without Nix, but installation/policy/host-lock migration and revision-bound live qualification are still required before this path is accepted. Historical Nix sources remain rollback evidence, not an alternate enabled writer; see [the completion review](host-lifecycle-completion-review-2026-09-05.md).

## Saved plan boundary

Plans are stored under `.reconcile/plans/<commit>/steady/<generation>/`. Every invocation requires an explicit lowercase alphanumeric/hyphen generation (1–64 characters). A failed or expired attempt is retained; choose a new generation at the same commit instead of deleting or overwriting its evidence. Apply must select the exact reviewed generation. The manifest binds:

- the commit and backend identity;
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
