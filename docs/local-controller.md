# Trusted local controller

Paul's MacBook is the interactive infrastructure controller. GitHub is only the Git remote; branches, pull requests, `main`, and remote refs are not authorization boundaries. Any clean committed revision may be planned and applied.

## Supported operations

The public controller exposes exactly two commands for both `steady` reconciliation and guarded `recovery`:

```sh
scripts/local-controller plan steady
scripts/local-controller apply steady
```

For recovery, replace `steady` with `recovery`. Recovery also requires the ignored mode-`0600` Ansible extra-vars file described in [`../recovery/README.md`](../recovery/README.md).

Both commands run the complete static validation suite. Plan is read-only: it creates policy-inspected OpenTofu plans and an exact Proxmox Nix host plan. A ready host plan produces the normal `converge` stage. Recovery can produce `external-owner-prerequisite`. Steady can produce `vm-start-prerequisite` only when the host blockers are exactly VM 100 OpenTofu ownership plus its derived health blocker and the saved Proxmox plan passes the dedicated VM-start policy: one update-in-place of historical address `proxmox_virtual_environment_vm.arch`, VMID 100 and protection retained, `started` changing only from false to true, and no other change except provider-computed network outputs. Every plan and hash is bound into one version-5 manifest and displayed for review.

Apply verifies the same commit-bound saved plans, prints their manifest identity and stage, and requires the operator to type the exact stage-bound confirmation. `apply-reviewed-steady-vm-start-prerequisite` applies only the exact AWS no-op, legacy Proxmox no-op, and policy-proven Proxmox VM-start plan, then exits with `requires_new_reviewed_plan=true` before guarded Nix, Arch, Omada, Tailscale, or Compose. Recovery prerequisite behavior is analogous. Mutation credentials are loaded only after confirmation, and apply never replans. The operator must run a second independent plan/review; only its ready `converge` stage can continue guest and application convergence. Explicit no-concurrent-mutation confirmation is required only when guarded host apply is reached; console, LAN rollback, and backup confirmations are required only for watchdog-required host actions.

## Protected controller configuration

Create `~/.config/home-lab/controller` with mode `0700`. It contains:

- mode-`0600` `plan-credentials.json` and `apply-credentials.json`;
- separate IAM Roles Anywhere plan/apply certificates and private keys;
- the local Roles Anywhere CA material; and
- `bin/aws_signing_helper`.

Credential JSON is an object of environment-variable names and string values. It holds backend coordinates, provider endpoints and CA PEMs, hardware identities, and capability-specific provider credentials. Never commit, print, pass in command arguments, or copy these values into logs.

Plan and apply capabilities stay separate:

- AWS uses independent Roles Anywhere certificates, roles, and policies.
- Proxmox uses read-only planning and mutation-capable apply API tokens.
- Tailscale uses separate OAuth clients; the apply client intentionally lacks device-deletion authority.
- Omada uses a viewer for planning and a distinct administrator for apply.

Run `scripts/configure-local-controller-aws` to create the separate `credential_process` profiles and verify both assumed-role identities without printing their ARNs. Run `scripts/configure-local-provider-credentials` locally to enter provider credentials through hidden prompts. These commands write only to existing protected controller files. The AWS foundation deliberately has no hosted OIDC provider or DynamoDB mutation lease; Roles Anywhere and native S3 lockfiles are the current boundaries.

## Saved-plan and confirmation boundary

Every public controller command requires a clean working tree, including no untracked files. Plans are stored under:

```text
.reconcile/plans/<commit>/<operation>/
```

The version-5 manifest binds:

- the exact 40-character commit and phase;
- the backend bucket;
- the exact enabled root set and each saved-plan filename and SHA-256;
- the exact Compose artifact SHA-256;
- the complete protected Ansible extra-vars file SHA-256 when present;
- the recovery backup identity and exact contract/runtime expectations projection when applicable; and
- Tailscale's canonical before/after policy SHA-256 values and live plan-time ETag; and
- the exact ready Proxmox Nix host plan path, file SHA-256, internal plan SHA-256, and action count.

Apply checks the manifest and plan hashes, reinitializes each provider backend, reinspects every saved plan under the current `normal` or `recovery` policy, and never generates a replacement apply plan. Post-apply plans are mandatory no-op verification only. The interactive confirmation names the reviewed operation and occurs before mutation credentials are loaded.

The reconciler itself exclusively acquires and owns one nonblocking descriptor `flock` on the persistent user-owned mode-`0600` regular file `.reconcile/controller-apply.lock`. A fixed supervisor writes canonical ownership metadata, re-executes the reconciler with an inherited descriptor and ephemeral token, and nested host/firewall paths validate and borrow that ownership without reacquiring or unlinking it. The lock serializes the complete apply and becomes inert when the owner exits. Per-root OpenTofu operations also use native S3 lockfiles with a five-minute lock timeout. Tailscale policy mutation verifies the live canonical SHA and ETag immediately before an `If-Match` update and proves the resulting live policy equals OpenTofu state.

## Omada input and strict TLS

Omada management remains strict-TLS-only at `https://Omada:8043`. The protected credentials provide the exact export JSON and controller CA PEM. Steady plan and apply write them only to ignored mode-`0600` files under `.local/omada`, verify the CA, and verify the local hostname alias without mutating `/etc/hosts`.

Configure the alias explicitly once, or rerun it after the Docker host's Tailscale identity changes:

```sh
scripts/prepare-omada-plan-input configure-alias
scripts/prepare-omada-plan-input verify-alias
```

`configure-alias` resolves `docker-host` through MagicDNS, requires a Tailscale CGNAT IPv4 address, and uses explicit local sudo to atomically manage only:

```text
<tailscale-ip> Omada # home-lab-omada
```

Remove only that marked line with:

```sh
scripts/prepare-omada-plan-input remove-alias
```

To refresh intentional Omada LAN or reservation desired state, load `OMADA_URL`, the read-only viewer credentials, and optional `OMADA_SITE` only through protected local environment handling, then run:

```sh
scripts/export-omada-state.py \
  --connect-host docker-host \
  --ca-file .local/omada/controller-ca.pem \
  --gateway-subnet 192.168.0.1/24 \
  --output .local/omada/export.json
```

Review the ignored mode-`0600` JSON and put its exact contents in the capability-appropriate protected `OMADA_EXPORT_JSON` values. This is a read-only desired-state refresh, not an import or qualification operation. Never place Omada credentials in command arguments, replace strict CA verification with `--insecure`, use an IP-based Omada URL, or add a second unmanaged alias.

## Apply and convergence

Steady applies the exact enabled plans for AWS foundation, the empty `proxmox-legacy` tombstone, Proxmox, Omada, and Tailscale. It then runs reproducible Ansible check plans, converges only approved host tags, stages and deploys the exact Compose artifact, and performs maintenance.

Recovery uses AWS foundation, Proxmox, Omada, and Tailscale; it deliberately excludes the legacy tombstone. It verifies Proxmox access, creates/reconciles VM 100 with hardware mappings exactly bound to the recovery expectations hash, bootstraps Arch, restores only the reviewed backup into inventoried fresh targets, activates the hash-bound Compose artifact, and completes maintenance checks. The adopted environment keeps contract mode `managed` in both recovery and steady operation. Protected mappings and normal policy reject reversing that mode.

Success always requires a fresh zero-action Proxmox Nix host plan, a fresh no-op OpenTofu plan for every enabled root, live Tailscale policy/state equality, and a zero-change Arch audit. Recovery also requires a no-op Arch bootstrap check. Compose deployment keeps the current and previous exact artifacts and environments for separately reviewed rollback; see [`compose-deployment.md`](compose-deployment.md).

## Repository and artifact rules

Repository rules remain source-review controls, not runtime authorization. No hosted workflow, environment, OIDC identity, or deployment state is part of the controller boundary.

All Compose images retain a readable upstream tag and immutable digest. Renovate updates the matching pair, and local validation rejects incomplete pins.
