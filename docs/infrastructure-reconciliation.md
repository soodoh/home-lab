# Infrastructure reconciliation

The desired-state boundary is [`../infrastructure/contract/home-lab.yml`](../infrastructure/contract/home-lab.yml). OpenTofu owns infrastructure, Ansible owns hosts, and Compose owns applications. Completed one-time transition operations are not supported controller modes.

Use only the trusted local controller:

```sh
scripts/local-controller plan steady
scripts/local-controller apply steady
```

Recovery uses the same commands with operation `recovery`. Both commands run validation internally, `plan` displays every validated saved plan, and `apply` requires an interactive operation-specific confirmation before loading mutation credentials. Direct `scripts/reconcile-infrastructure` use is an implementation and recovery-debugging interface.

## Failure domains and roots

Steady plans the following roots, subject to the Omada and Tailscale management enable flags:

1. `aws-foundation`
2. `proxmox-legacy`
3. `proxmox`
4. `omada`
5. `tailscale`

Recovery plans `aws-foundation`, `proxmox`, `omada`, and `tailscale`. It excludes `proxmox-legacy` because retired CT 101 is not a recovery resource.

Two empty roots remain deliberately:

- `proxmox-legacy` preserves the retired CT 101 backend/state boundary as a steady tombstone.
- `proxmox-lxc-qualification` preserves the completed disposable-LXC qualification backend and provider lock as an out-of-band tombstone; it is not a steady or recovery root. Its tracked evidence remains schema-validated.

Do not delete either backend or run `state rm`, import, or backend migration merely because its configuration is empty.

## State-address invariants

The simplification deliberately preserves active resource addresses:

- `proxmox_virtual_environment_vm.arch`
- `omada_network.lan[0]`
- `omada_dhcp_reservation.reservation[<mac>]`
- `terraform_data.tailscale_policy[0]`

VM 100, the Omada LAN, and the Tailscale policy anchor retain destruction protection. Address changes require an explicit state-migration design and a separately reviewed live plan; source refactoring alone must not rename, recount, forget, or recreate these resources.

## Plan policy

The inspector has two policy modes:

- `normal` for every steady root and non-Proxmox recovery root;
- `recovery` only for the Proxmox recovery plan.

`normal` rejects destructive, replacement, compute creation, protection-disabling, root-disk-size, and network/device changes unless an enduring root allowlist explicitly permits them. `recovery` compares every expected Proxmox resource and protected field with a mode-`0600` expectations projection generated from the validated contract and protected disk identity; it accepts only exact creates/no-ops and rejects unrelated changes or unknown protected values. The projection SHA-256 is manifest-bound. The unresolved disposable Proxmox VM qualification configuration remains isolated in the main Proxmox root and is not enabled by normal steady/recovery input.

The durable `proxmox.vm.hardware_attachment_mode` is `managed`. Zigbee and Z-Wave serial secrets are resolved on the Proxmox host to unique physical USB paths and passed as protected runtime OpenTofu inputs. The tracked contract declares explicit serial and port *reference names* but never the protected serial or port values. Reversing managed mode to raw would delete protected mapping resources and rewrite protected VM devices, so lifecycle and normal policy fail closed.

A plan pass proves only that the proposed action shape is authorized. It does not prove that a provider operation works live.

## Exact saved plans

Planning initializes each isolated S3 backend, uses native lockfiles and `-lock-timeout=5m`, creates one binary saved plan per enabled root, checks that provider credentials do not appear in it, and runs the policy inspector. The version-3 manifest binds the commit, phase, backend bucket, exact root set, plan paths and SHA-256 values, Compose artifact SHA-256, the complete protected Ansible extra-vars file when present, recovery backup identity and expectations projection, and Tailscale policy identities.

Apply requires the exact manifest commit and a clean checkout. It reinitializes each backend, verifies every saved-plan hash and policy result, and calls `tofu apply` with the saved binary file. It never generates a new plan as an apply source; mandatory post-apply `tofu plan` runs are convergence verification only.

Plan credentials are read-only. Apply verifies the saved-plan identity and requires interactive confirmation before mutation credentials are loaded. Provider credential values remain in mode-`0600` controller files or environment variables and never enter the manifest; the Tailscale OAuth client secret is URL-encoded through a protected temporary request file rather than a process argument.

## Locks and Tailscale concurrency

`reconcile-infrastructure apply` itself exclusively acquires and owns the controller-wide `.reconcile/controller-apply.lock`; callers cannot claim that the lock is already held. The lock spans OpenTofu, Ansible, Compose, and final verification. Every root also uses the native S3 state lock.

For the Tailscale root, planning records the canonical live policy SHA-256 and HTTP ETag as well as the planned before/after SHA-256 values. Apply refuses unrelated live drift, uses `If-Match`, verifies the resulting policy hash, and proves that live policy equals the state-held policy. The terminal policy retains direct owner/admin access required for Proxmox and Omada, including TCP 8043 to the Docker host.

## Host and Compose convergence

The Proxmox Ansible-to-Nix migration now includes its controller-side foundation. The authoritative contract is projected through an explicit allowlist into tracked canonical, schema-closed JSON under `nix/proxmox/`; repository validation proves exact regeneration and exclusion of protected values, reference names, paths, controller/API locations, hardware identities, and migration/cleanup gates. The dedicated sanitized flake root is `nix/`, pinned to `nixos-26.05`; use `nix flake check 'path:./nix'` and `nix build 'path:./nix#proxmox-host-bundle'`. The explicit `path:` prefix prevents nested-flake Git resolution from archiving the repository root. No repository-root flake exists. Validation archives and scans the exact sanitized flake source, direct derivation source inputs, output, and closure. The flake builds a canonical content-hashed bundle containing the projection, current exact 1,353-package manifest with its count derived from hash-bound provenance, rendered safe ordinary files and audit expectations, and bound protocol-v4 observer, activator, and private-preparer helpers. Nix remains controller-side; ordinary fixed helpers run on Proxmox only after the separately approved console bootstrap.

The local controller has a separate read-only shadow lane. Its tracked policy is currently `pre-bootstrap`, so normal plans emit a deterministic disabled result and perform no additional Proxmox transport. A later reviewed `shadow-required` policy change may capture sequential Ansible-check and Nix-plan summaries under `.reconcile/proxmox-nix-shadow/`; those canonical artifacts bind one way to the existing version-3 controller manifest and exact Git/bundle/plan identities. They are audit evidence only: blocked plans remain valid audit records, observations are explicitly non-atomic, and neither the controller manifest nor apply consumes the evidence. Temporary Ansible remains production authority. Apply-manifest binding, lock/freshness design, recovery sequencing, private approval, and authority cutover are deferred to the cutover milestone.

Ansible check plans are run twice and normalized; differing plans fail closed. The protected extra-vars file is SHA-256-bound to the manifest, and controller-fixed Compose artifact and recovery values are passed last so file values cannot override them. Steady converges Proxmox and bounded Arch tags, then stages the exact manifest-bound Compose artifact. Compose deployment reproduces a private action-plan hash immediately before activation, uses no builds or orphan removal, preserves current/previous artifact and environment generations, and requires an idempotent post-check. Failures retain the host production lock for inspected recovery.

Recovery first proves Proxmox connectivity, reconciles the host and VM 100, bootstraps Arch through the recovery inventory, restores only the exact reviewed backup into fresh targets, and activates Compose through the recovery-specific plan hash. Critical ZFS/storage restoration remains assertion-oriented and cannot format or overwrite existing storage.

## Required final verification

Every successful apply ends by replanning every enabled OpenTofu root and requiring exit code zero. It also requires:

- live Tailscale policy/state equality;
- a no-op Proxmox steady play;
- a zero-change Arch audit; and
- for recovery, a no-op Arch bootstrap check.

A changed or failed final check means reconciliation is incomplete even if earlier apply steps succeeded. See [`local-controller.md`](local-controller.md), [`compose-deployment.md`](compose-deployment.md), and [`../recovery/README.md`](../recovery/README.md).
