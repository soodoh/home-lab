# Recovery rehearsal

Run the non-mutating static rehearsal from a clean controller:

```sh
scripts/rehearse-recovery --static
```

It validates the contract and provider locks, exercises hostile archive and volume fixtures, and syntax-checks the retained recovery playbooks. A pass proves only static control flow; it performs no provider mutation, restore, or service activation.

## Current qualification boundary

Substantive cold recovery remains **incomplete**. [ADR 0001](adr/0001-ansible-host-lifecycle.md#amendment--shared-hypervisor-qualification-route) accepts production PVE plus disposable VM9900 instead of requiring an independent physical hypervisor. This accepts shared-host risk; a guest firewall is not hypervisor isolation. VM100, production disks, application state and guest credentials are never rehearsal inputs. The guarded qualification controllers do not yet provide an accepted end-to-end synthetic recovery route; redirecting a production recovery inventory is not a substitute.

Each operation still requires fresh target/trust, lock, backup and console prerequisites, its exact saved plan and applicable separate confirmation. The [failed first-boot invocation](host-lifecycle-completion-review-2026-09-05.md#interrupted-qualification-investigation) remains failed: no automatic retry, assumed current VM state or repaired guest relabeled as clean first boot. New failed-operation recovery requires separate approval.

The qualification must demonstrate:

- a new exact foundation, snippet, start, guest-key and booted-cache provenance chain;
- minimal-image prerequisites, native x86_64 inactive-path checks, inert convergence and a second zero-change run;
- durable package/tool, mount, Compose/guard and Restic unit ownership without starting inert workloads or replacing vendor Docker units;
- synthetic storage and recovery identities, exact Restic repository/snapshot/policy bindings, and native `restic restore --verify` into fresh private staging;
- separately admitted access, storage and production-profile transitions, preserving strict host trust and bootstrap-key retirement checks;
- exact Compose artifact, image and environment identities with no unplanned builds/pulls;
- service, storage and network health, with VM100 configuration and production hardware/disks unchanged;
- protected staging cleanup, interruption handling and separately authorized cold-boot/reboot proof; and
- final same-revision OpenTofu and Ansible no-op checks within the qualified scope.

The [historical disposable disk-append proof](opentofu-disk-adoption-feasibility.md#qualification-conclusion) remains completed at its recorded provider/target scope. It is neither production-root adoption authority nor complete cold-recovery acceptance.

## Historical route

Earlier guidance required an isolated PVE host, Nix bootstrap/check/install and archive-oriented recovery. That describes the prior design, not current execution instructions. Ansible already owns both hosts; retained Nix material is rollback evidence, not a bootstrap shortcut. Native Restic staging is the current recovery model. Retained hostile archive fixtures still test their bounded inputs; their success does not qualify Restic restoration or cold recovery.

Measure elapsed time from the agreed recovery start to verified service health. Save only secret-free commit, plan, artifact, backup, health, and duration hashes/outcomes. The current eight-hour recovery-time objective is not qualified until this timed exercise passes.

Never call an unrehearsed production restore a rehearsal. This repository intentionally has no command that silently escalates `--static` into a live restore, and successful steady reconciliation is not a substitute for a cold-boot recovery exercise.
