# Proxmox LXC provider qualification

The disposable LXC qualification is isolated from both production Proxmox roots in `infrastructure/tofu/proxmox-lxc-qualification`. Its encrypted backend key and retained empty state are dedicated tombstones. Never import an existing container, reuse the `proxmox` or `proxmox-legacy` state, or move qualification state between roots.

Each qualification operation runs manually from any clean committed revision on the trusted controller. Planning loads the separate read-only Proxmox identity; apply loads the mutation identity and consumes the exact local saved plan. The native OpenTofu S3 lock serializes operations. The manifest binds operation, commit, fixed public marker, plan hash, backend identity hash, endpoint hash, provider lockfile hash, and CA hash; apply recomputes each identity before backend access or mutation.

**AWS foundation ordering:** merge and apply (or conclusively prove a no-op for) the `aws-foundation` policy change that adds `home-lab/proxmox-lxc-qualification/tofu.tfstate` to the exact allowed state keys before dispatching any qualification operation. The restricted plan/apply roles cannot access this root until that prerequisite is live.

## Protected prerequisites

Store these values only in the mode-`0600` local controller credential files; do not put them in repository variables, filenames, output, or summaries:

- `PROXMOX_LXC_QUALIFICATION_VMID`: an unused disposable VMID other than 100 or 101.
- `PROXMOX_LXC_QUALIFICATION_TEMPLATE_FILE_ID`: the exact verified `local:vztmpl/...tar.{gz,xz,zst}` file ID already present on `local`.
- existing strict-TLS endpoint and CA bundle values;
- separate Proxmox plan/apply tokens, Roles Anywhere AWS profiles, backend bucket/region, and the controller's strict TLS CA.

Before create, the plan preflight requires the protected VMID to be absent and the exact template to exist once; the apply preflight additionally uses the mutation identity for a read-only exact local-LVM residual-volume check before the saved plan may apply. Every later phase requires the canonical fixed marker (the provider/API's single trailing newline is accepted and removed only for comparison), stopped status, disabled console, no network, no mount points or additional disks, no passthrough, mappings, hooks, tags, startup behavior, or non-default features, the minimal local-LVM root disk, exact protection state, and agreement between protected inputs, API, and isolated state. Apply postconditions use the mutation identity only for read-only exact volume proofs, then return to the plan identity for the fresh no-op. The helper rejects any extra capability exposed in the pinned provider plan/state or Proxmox configuration. It never broadens ACLs and never discovers or chooses an identifier.

## Required live sequence

Run one exact local plan/apply operation at a time in this order:

1. `create` — create only the marked, protected, stopped, off-at-boot, unprivileged, no-network LXC and prove a fresh no-op.
2. `probe-protected-delete` — plan exact deletion, require apply to fail with a recognized protection-specific provider/API rejection, then prove through read-only API and state evidence that the exact LXC remains protected.
3. `verify-protected` — independently require the protected declaration to be a no-op before any unprotection.
4. `unprotect` — change only `protection = true` to `false`, then prove exact unprotected identity and a fresh no-op.
5. `delete` — delete only that already-unprotected LXC, then prove API absence, local-LVM volume absence, empty isolated state, absent backend lock, and a fresh `verify-empty` no-op.
6. `verify-empty` — independently repeat the absent API/volume, empty-state, no-lock, and no-op proof. Retain the empty backend state.

`reprotect` is emergency-only after `unprotect` and before `delete`; it permits only `false -> true` and requires the protected identity/no-op proof. After reprotection, repeat `verify-protected`, then explicitly dispatch `unprotect` again before deletion.

The protected-delete apply log is a mode-`0600` temporary file and is always destroyed without raw emission. Only a recognized Proxmox protection rejection passes. Authentication, authorization, TLS, provider startup, DNS, connection, transport, timeout, generic apply, and incomplete post-proof errors are inconclusive and fail closed. A failed operation never imports, removes state, retries, or mutates automatically; inspect the exact native backend lock and state before any reviewed follow-up.

## Read-only recovery inspection

Run `scripts/qualify-proxmox-lxc inspect-recovery` from any clean committed revision after an ambiguous failure. It uses only plan identities, performs no plan or apply, and emits only the documented sanitized classification.

A split, mismatched, or locked result is evidence only. It requires a separate reviewed recovery plan. Do not automatically import, run `state rm`, unlock, retry, unprotect, delete, or otherwise mutate from the inspection result.

## CT 101 gate

`proxmox.legacy_container.lxc_provider_qualified` is `true` only because the complete disposable live sequence passed and the schema-valid, secret-free evidence is committed at `infrastructure/evidence/proxmox-lxc-qualification.json`. The evidence binds the exact qualification tooling commit, pinned provider lock, six distinct local operation IDs in order, and the final empty-state/API/volume/lock plus no-op proof.

This gate does not authorize a CT 101 mutation. Unprotection and deletion remain separate exact-plan operations with separate explicit approvals, and the evidence change must never be combined with either CT stage transition.
