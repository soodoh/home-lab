# Infrastructure reconciliation

The desired-state boundary is `infrastructure/contract/home-lab.yml`. OpenTofu roots under `infrastructure/tofu/` own separate failure domains; Ansible owns host configuration; Compose owns application convergence.

Use only the canonical entry point:

```sh
scripts/local-controller validate
scripts/local-controller plan steady
scripts/local-controller review steady
scripts/local-controller approve steady --confirmation apply-reviewed-steady
scripts/local-controller apply steady
```

`bootstrap` and `adopt` remain plan-only compatibility commands. The trusted local controller accepts any clean committed revision, stores commit-bound plans locally, loads separate plan/apply credentials, and consumes exact saved plans without replanning. Native OpenTofu S3 locks and host apply locks serialize mutation; post-apply no-op checks remain mandatory.

Plan credentials must be read-only. Apply credentials are loaded only after a manifest-bound local approval. Provider secrets remain in mode-`0600` controller JSON, never command arguments, plans, manifests, or logs. The protected CT confirmation is loaded only into the local process and is independently validated by OpenTofu; it never authorizes either CT stage without the separate exact operation approval.

Special modes (`recovery`, network migration, VM 100 root-disk growth, CT retirement, Tailscale controller retirement, gateway-policy lifecycle, and Omada qualification) have narrower policy allowlists and dedicated gates. They cannot be combined. Disk-growth mode permits only `scsi0` growth from 400 to 550 GiB, spans the Proxmox and guest operations with the host mutation lock, and requires exact disk, partition, filesystem, and no-op proofs. A successful static plan is not proof that a provider can perform a live operation.

## Tailscale gateway-policy lifecycle

The durable `tailscale.gateway_policy_stage` is `active`, `detached`, or `retired`. `active` enables only owner/admin recovery routing; `detached` removes route auto-approvers and the two routed LAN grants while retaining direct owner/admin access and the infra-router recovery node. No stage contains a hosted-controller tag. `retired` additionally removes the final infra-router owner and grant, and is allowed only after CT retirement and separate device-absence approval.

Contract comparison permits steady states, `active -> detached`, pre-CT-retirement rollback, and `detached -> retired` only with an already retired CT. It rejects skips, transitions out of retired, and simultaneous CT/gateway transitions.

Use the exact local-controller operation for a reviewed stage transition:

```sh
scripts/local-controller plan tailscale-detach
scripts/local-controller review tailscale-detach
```

The saved-plan manifest binds operation, stage, canonical before/after policy SHA-256 values, and the live plan-time ETag. Apply revalidates the exact plan and live ETag before an `If-Match` update, proves live policy equals state, and finishes with a no-op. Unrelated drift is never overwritten.

Retirement additionally fails closed unless `TAILSCALE_GATEWAY_DEVICE_ABSENCE_APPROVED` is exactly `true` in the protected local plan and apply credentials. Set it only after separate device-deletion approval and read-only absence verification; it does not authorize deletion.

## Proxmox LXC provider qualification gate

Before CT 101 unprotection, complete the isolated saved-plan lifecycle in [`proxmox-lxc-qualification.md`](./proxmox-lxc-qualification.md) from the trusted controller. The dedicated root has its own backend and may own only the fixed-marker disposable LXC.

The durable `proxmox.legacy_container.lxc_provider_qualified` gate remains `false` until a separate evidence-only PR records the completed create, rejected protected-delete probe, independent protected no-op, unprotect, delete, volume/API absence, empty state, no-lock, and verify-empty sequence. While false, the real evidence path stays absent and only `infrastructure/evidence/proxmox-lxc-qualification.example.json` is tracked. A `false -> true` PR must add the exact schema-valid `infrastructure/evidence/proxmox-lxc-qualification.json`; universal transition validation binds its six run IDs, tooling commit, provider lock, and final proof. CT `unprotect` and `delete` are rejected while the gate is false.

## CT 101 retirement lifecycle

The durable desired state is `proxmox.legacy_container.retirement_stage`:

- `protected`: the resource exists with protection enabled.
- `unprotected`: the resource exists with protection disabled.
- `retired`: resource count and import are disabled; the empty `proxmox-legacy` root and state remain as a tombstone.

Change the contract stage in a clean committed revision before planning an operation. Validation permits only `protected -> unprotected`, `unprotected -> retired`, and `unprotected -> protected`; skips and transitions out of `retired` are rejected. Unprotection and deletion additionally require `lxc_provider_qualified: true` from completed evidence.

Plan and review each operation locally, then stop for its separate explicit approval:

```sh
scripts/local-controller plan ct-unprotect
scripts/local-controller review ct-unprotect
# After explicit approval only:
scripts/local-controller approve ct-unprotect --confirmation unprotect-reviewed-ct-101
scripts/local-controller apply ct-unprotect

# Deletion is planned and approved separately after the unprotected no-op proof.
```

The operation selects only the gate and plan policy; it never controls resource count or protection. Saved-plan manifests bind the exact operation and contract stage alongside commit, Compose artifact identity, and plan hashes. A special operation requires every non-legacy OpenTofu root and all Ansible checks to be no-op. Immediately before applying the legacy root last, a read-only Ansible playbook recomputes the active artifact at `/srv/docker-compose/current` with its own `scripts/compose-artifact.py --no-git hash` and requires exact equality with the already repository-verified manifest hash. A missing, unreadable, or mismatched active artifact stops retirement; this prerequisite never stages or deploys Compose. Post-apply no-op verification remains mandatory. Repeating the special operation is rejected because its policy requires exactly one target action. Use normal operation `none` for subsequent reconciliation.
