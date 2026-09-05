# Local controller

`scripts/local-controller` is the public entry point for steady infrastructure reconciliation.

```bash
scripts/local-controller plan steady
scripts/local-controller apply steady
```

Install the exact Ansible collection set before validation:

```bash
ansible-galaxy collection install --requirements-file ansible/collections/requirements.yml
```

Validation refuses a missing or differently versioned pinned collection.

The controller accepts only clean, committed revisions. Plan loads read-only credentials, validates the complete repository, creates commit-bound saved plans, runs policy checks, and displays the plans. Apply verifies those exact plans, requires the exact interactive confirmation, and loads separate mutation credentials only after confirmation.

The `.reconcile/controller-apply.lock` file is a persistent descriptor mutex. Its existence and last-owner metadata do **not** establish an active transaction: `nix/proxmox/controller_lock.py` releases the lock by closing descriptors and intentionally leaves the inode and metadata in place. Inspect descriptor-lock contention without changing the file; never unlink it as stale-lock cleanup. Host owner journals and failed-operation receipts have separate recovery rules.

Proxmox mutation authority has transferred to Ansible, but this entrypoint still depends on the read-only Nix compatibility stage described below. Nix-free controller acceptance is not complete; see [the completion review](host-lifecycle-completion-review-2026-09-05.md).

## Saved plan boundary

Plans are stored under `.reconcile/plans/<commit>/steady/`. The manifest binds:

- the commit and backend identity;
- every enabled OpenTofu plan file and SHA-256 value;
- the canonical Proxmox Nix host plan and internal digest;
- the Compose artifact hash;
- protected input hashes when present; and
- Tailscale policy hashes and live ETag.

Apply never substitutes a new plan. A VM-start prerequisite plan exits after the exact prerequisite action and requires a new reviewed plan before any later work.

## Production authority

VM 100 accepts only Debian deployment authority. The controller no longer exposes Arch, Flatcar, qualification, cutover, state-move, or infrastructure-recovery modes. Production Ansible convergence is restricted to one reviewed tag per run and the `ansible-deploy` identity, authenticated by the tailnet policy through Tailscale SSH.

## Verification

Success requires:

- every enabled OpenTofu root at no-op;
- a fresh zero-action Proxmox host plan;
- live Tailscale policy/state equality;
- a zero-change Debian production audit; and
- an exact Compose create simulation with builds and pulls disabled.

Application-data recovery and Compose rollback remain separate guarded procedures; see [`../recovery/README.md`](../recovery/README.md) and [`compose-deployment.md`](compose-deployment.md).
