# Compose operation classification

The machine-readable authority is `infrastructure/retirement/compose-operation-classification.json`. Classification does not authorize deletion. `infrastructure/contract/home-lab.yml`, the current Compose artifact, image locks, Restic policy, and recovery boundaries remain authoritative.

| Component | Class | Decision |
|---|---|---|
| Compose artifact stage/review/deploy | durable runtime | Keep the model, hash, action-plan, image-lock, secret materialization, staging, review, and deploy path. |
| Compose rollback and recovery | durable recovery | Keep preflight, empty staging, structural validation, activation, rollback, and exact artifact/image checks. |
| Nextcloud steady configuration | durable policy | Keep native configuration and validation independently of the path migration. |
| Nextcloud five-mount migration | pending migration | Keep until the migration succeeds, old copies pass the seven-day hold, and disposable cold recovery passes. Ordinary convergence must not invoke it. |
| Nextcloud migration rollback | conditional recovery | Keep while old Nextcloud application/config paths remain a valid rollback source. |
| Calibre local rollback lane | conditional recovery | Keep the exact interrupted-resume and NFS rollback lane while the retained NFS library remains available. Do not duplicate it outside `compose_deploy`. |
| Preserved Calibre/Caro forward migration | retire after proof | The forward copy is completed one-time code. Do not rerun it; delete only after cold-recovery and rollback evidence. |
| Steady Restic retry/recovery | durable recovery | Keep pending journals, backup mutexes, writer restart, repository copy, and systemd recovery behavior. |
| Restic restore boundary | durable recovery | Keep native `restic restore --verify`, recovery bundles, structural checks, and staged activation. |
| First Restic run | retire after proof | Terminal one-time transaction and resume/finalize lanes remain frozen until cold recovery proves no live journal/tool consumer. |
| Restic repository initialization | retire after proof | Initialization and adoption/resume code remains frozen until cold recovery proves existing-repository adoption and terminal evidence retention. |
| Compose health/artifact canaries | durable validation | Keep service-model, image-pin, health, and active-artifact checks. A successful historical canary does not replace recurring validation. |
| PVE firewall/NFS canary | conditional recovery | Keep until the final firewall transport proves equivalent VM 100 and NFS behavior without the transitional path. |

## Deletion rules

1. `durable-*` entries cannot be deleted without a tested replacement preserving the same locks, artifact identities, recovery semantics, and refusal paths.
2. `conditional-recovery` entries remain until their exact rollback inputs are approved absent.
3. `pending-migration` entries are callable only through their operation-specific gate, never ordinary convergence.
4. `retire-after-proof` entries are frozen: no new production invocation is allowed, but deletion waits for disposable cold recovery and caller/host-asset absence proof.
5. Historical evidence, terminal journals, plan/receipt hashes, and recovery bundles are not executable code and remain immutable.

`python3 scripts/controller/test-compose-operation-classification.py` validates schema closure, required coverage, path existence, duplicate components, and the prohibition on classifying core recovery/runtime components for retirement.
