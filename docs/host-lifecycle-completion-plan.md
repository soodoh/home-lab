# Finish Nix runtime retirement

The owner's **2026-09-11** amendment to [ADR 0004](adr/0004-operational-nix-retirement.md) separates existing-host runtime retirement from new-controller adoption. Both hosts are already Ansible-owned; [aggregate Proxmox cutover](proxmox-aggregate-authority-cutover-2026-09-04.md) and [Docker qualification](docker-version-admission-qualification.md) are complete. Do not repeat them. **Nix runtime retirement is complete for the reviewed existing-host entrypoints as of 2026-09-11.** This checklist grants no reads, host operations or Git publication.

## Bounded evidence already available

- **2026-09-10 `runtime-read-01`:** selected Nix roots/profiles/commands were absent on both hosts; selected Nix packages/units were not found. Debian Docker/containerd and the daily Restic timer were active; Compose/guard were exited oneshots. This proves neither fresh startup/backup success nor absence of external callers.
- **2026-09-11 `simplified-finish-01/prerequisites-01`:** installed VFIO helper/policy matched retained Nix-free Python/data; the historical Ansible activator matched known source. Its `nix/proxmox/` projection/manifest references are data dependencies, not Nix execution. Preserve those files and full transaction source/plan identity guards.
- **2026-09-11 `simplified-finish-01/recovery-consumer-read-01`:** firewall transaction, boot wrapper and four watchdog/recovery units matched public source; watchdog enabled/active, boot recovery enabled/exited. These are non-Nix recovery consumers of persistent `operation.lock`; retain them. Unknown operations and uncertain console/recovery custody remain write blockers, not proof of Nix use.

Evidence names are relative to private `~/.local/state/home-lab-source-integration/operational-nix-retirement-3491395-01/`. Existing grants are consumed. The original `runtime-retirement-only-01/consumer-map.md` and `next-reads.md` preserve the initial gaps, not a current read programme. The following observations close the selected execution-binding questions; original evidence is unchanged.

## Completion evidence and limits

- **2026-09-11, 19:25Z:** both approved reads succeeded. Installed guard, Compose and five daily/maintenance/recovery backup commands matched public forms; backup timers selected their expected targets. Restic/rclone paths and pinned binary hashes matched. Backup Compose selection uses its retained fallback—not the new controller's image-override certification.
- The exact captured Proxmox observer and private preparer were traced **offline**: native Python/PVE/system utilities and data, no Nix execution in the observer→`summary` path. Neither helper was invoked. Remaining firewall failure-edge files matched; their native command bindings were observed, not executed.
- **19:45Z:** the separately approved unprivileged read identified Docker's effective executable as `/usr/sbin/dockerd`. The prior allowlist-redacted result remains unknown in its original packet; this new observation resolves the binding question.
- The owner reported **no known extra entrypoints**. This is knowledge-bounded. Vendor argv, unreported Exec fields, complete environment resolution and unknown additional unit edges are not certified. Missing literal mount-edge comparisons remain configuration-parity gaps, not demonstrated Nix execution. No universal transitive dependency, fresh boot, backup-success or maintenance-admission claim follows.

Exact receipts and output identities: private `runtime-retirement-only-01/read-01/`, `docker-exec-binding-01/` and `completion-01/`. All read grants are consumed. No host removal or configuration change was performed by this completion work.

## Finish only this boundary

- [x] **Close the selected runtime-consumer questions.** The observations and offline traces above establish native entrypoint/command selections for the reviewed boot, maintenance and backup paths; retained Python/data references are not Nix execution. Coverage exclusions remain explicit, not silently passed. No repository-wide cleanup inventory or new qualification programme.
- [x] **Accept retention and the exact removal list.** No obsolete runtime dependency has been identified for removal here: **approved removal list: empty**. Retain necessary helpers/data, current **and previous** Compose artifacts/images, protected storage/access, VM100 `scsi3`, boot `scsi3;net0`, absent `scsi0`, Restic/firewall recovery and inactive recovery media/records. Keep credentials, access/authorization snapshots, journals and locks. No journal/lock disposition is needed for retention. If a genuine obsolete dependency emerges, separately approve its exact removal and affected postchecks; consumer counts alone cannot authorize deletion. An evidence-supported empty list can finish retirement.

## Deferred, not passed

[ADR 0005](adr/0005-attended-operational-admission.md)'s coherent four-asset rollout, admission compatibility, native qualification, new-source normal convergence/no-change and source-aligned no-op-plan certification are outside this finish line. **Every future invocation of that controller still requires all its guards.** No ordinary-observation substitution, legacy `summary`, raw-Tofu/unguarded apply, manifest downgrade or gated-v6 fallback.

The journal-presence read was **never approved or run** and is now deferred. Preserve its unexecuted packet, original R1 failures, correction/reviews and review-disclosed filename-scope deviation; no retry, repair, rollback or cleanup. Preserve all unshipped source. Native tests are not run here; source acceptance is not installed qualification. Rebuild/fixture/toolchain, VM9901, predecessor Adapter, reporting and v6 work remain deferred; clean rebuild remains uncertified. Existing [approval/recovery rules](adr/0003-bounded-attended-migration.md), [managed-OIDC ownership](shared-oidc-ownership.md) and [retirement-matrix cautions](script-retirement-matrix.md) remain binding.
