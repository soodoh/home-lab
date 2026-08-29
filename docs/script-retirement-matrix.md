# Script retirement matrix

> Phase 0 classification began at commit `38c01635b8f71afdbe69670e4cf4a7cdb6c53f2e` and includes subsequent lifecycle-foundation tests. No script is authorized for deletion by this matrix. Static callers do not prove live use or absence of external use.

## Classes

| Class | Phase 0 decision |
|---|---|
| `retain-compose-runtime` | steady Compose artifact/model/deploy path |
| `retain-controller` | current controller/provider input path |
| `retain-firewall-boundary` | separate guarded PVE firewall transaction |
| `retain-incident` | diagnostic tool; archive only after incident/runbook closure |
| `retain-manual-bootstrap` | break-glass/bootstrap tool; replacement required first |
| `retain-operational` | active helper without retirement evidence |
| `retain-recovery` | active Restic/SOPS/recovery boundary |
| `retain-test` | test retained while subject exists |
| `retain-test-fixture` | fixture retained with its test |
| `retain-validation` | schema/policy/normalization guard |
| `retirement-candidate` | no deletion yet; prove no live/external caller and preserve evidence |
| `transition-with-nix` | retain through Nix-to-Ansible parity and rollback-window closure |

## Per-file ledger

| File | Class | Tracked caller count | Example tracked callers |
|---|---:|---:|---|
| `scripts/activate-recovered-data.py` | `retain-operational` | 1 | `ansible/roles/compose_recovery/tasks/main.yml` |
| `scripts/activate-restic-staging-fixture` | `retain-recovery` | 3 | `scripts/prove-restic-recovery-vm`, `scripts/reconcile-infrastructure`, `scripts/test-restic-activation-fixture` |
| `scripts/audit-opentofu-state-objects` | `retain-controller` | 2 | `docs/opentofu-state-cleanup.md`, `scripts/reconcile-infrastructure` |
| `scripts/bootstrap-proxmox-nix-access` | `transition-with-nix` | 3 | `docs/proxmox-bootstrap.md`, `docs/recovery-rehearsal.md`, `scripts/controller/test-proxmox-nix-bootstrap.py` |
| `scripts/bootstrap-proxmox-nix-host` | `transition-with-nix` | 7 | `docs/proxmox-bootstrap.md`, `docs/proxmox-firewall-cutover.md`, `scripts/bootstrap-proxmox-nix-access` (+4) |
| `scripts/bootstrap-restic-credentials` | `retain-recovery` | 4 | `ansible/playbooks/deploy-proton-password-only-artifacts.yml`, `ansible/roles/restic_backup/tasks/main.yml`, `docs/restic-backups.md` (+1) |
| `scripts/build-restic-recovery-bundle` | `retain-recovery` | 2 | `scripts/reconcile-infrastructure`, `scripts/test-restic-recovery-bundle` |
| `scripts/check-compose-image-pins.py` | `retain-validation` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/check-sops-env.py` | `retain-validation` | 2 | `scripts/compose-artifact.py`, `scripts/test-compose-secret-files` |
| `scripts/collect-proxmox-protected-inputs` | `transition-with-nix` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/compose-action-plan.py` | `retain-compose-runtime` | 5 | `ansible/roles/compose_deploy/tasks/main.yml`, `ansible/roles/compose_rollback/tasks/main.yml`, `scripts/reconcile-infrastructure` (+2) |
| `scripts/compose-artifact.py` | `retain-compose-runtime` | 12 | `ansible/playbooks/resume-first-restic-backup.yml`, `ansible/playbooks/run-first-restic-backup.yml`, `ansible/playbooks/verify-active-compose-artifact.yml` (+9) |
| `scripts/compose-deployment-diff.py` | `retain-compose-runtime` | 1 | `ansible/roles/compose_deploy/tasks/main.yml` |
| `scripts/compose-image-lock.py` | `retain-compose-runtime` | 5 | `ansible/roles/compose_deploy/tasks/main.yml`, `ansible/roles/compose_recovery/tasks/main.yml`, `ansible/roles/compose_rollback/tasks/main.yml` (+2) |
| `scripts/compose-model-inventory.py` | `retain-compose-runtime` | 4 | `ansible/roles/compose_stage/tasks/main.yml`, `docs/compose-deployment.md`, `scripts/compose-artifact.py` (+1) |
| `scripts/compose-recovery-plan.py` | `retain-compose-runtime` | 2 | `ansible/roles/compose_recovery_preflight/tasks/main.yml`, `scripts/test-recovery-tools` |
| `scripts/configure-local-controller-aws` | `retain-controller` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/configure-local-provider-credentials` | `retain-controller` | 2 | `scripts/controller/test-reconcile-security.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/attest-debian-qualification-plan.js` | `retain-validation` | 2 | `scripts/controller/test-attest-debian-qualification-plan.js`, `scripts/reconcile-infrastructure` |
| `scripts/controller/audit-root-local-paths.py` | `retain-validation` | 1 | `scripts/controller/test-root-local-audit.py` |
| `scripts/controller/authentik-bootstrap-service-account.py` | `retain-controller` | 1 | `scripts/controller/test-authentik-tofu-foundation.py` |
| `scripts/controller/authentik-normalize-inventory.mjs` | `retain-controller` | 3 | `docs/authentik-opentofu.md`, `scripts/controller/test-authentik-tofu-foundation.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/check-vm-100-authority.js` | `retain-controller` | 5 | `scripts/controller/test-reconcile-manifest.py`, `scripts/controller/test-reconcile-security.py`, `scripts/controller/test-vm-100-authority.js` (+2) |
| `scripts/controller/controller-apply-lock.py` | `retain-controller` | 3 | `scripts/controller/test-controller-apply-lock.py`, `scripts/controller/test-reconcile-security.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/fixtures/zpool-status-online.txt` | `retain-test-fixture` | 1 | `scripts/controller/test-zpool-status-parser.py` |
| `scripts/controller/fixtures/zpool-status-resilver-cache.txt` | `retain-test-fixture` | 1 | `scripts/controller/test-zpool-status-parser.py` |
| `scripts/controller/normalize-ansible-plan.py` | `retain-validation` | 3 | `infrastructure/policy/test-policy.sh`, `scripts/controller/test-normalize-ansible-plan.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/lifecycle-marker-transaction.py` | `retain-controller` | 1 | `scripts/controller/test-lifecycle-marker-transaction.py` |
| `scripts/controller/debian-access-cleanup.py` | `retain-controller` | 1 | `scripts/controller/test-debian-access-cleanup.py` |
| `scripts/controller/omada-host-alias.py` | `retain-controller` | 3 | `infrastructure/policy/test-policy.sh`, `scripts/controller/test-omada-host-alias.py`, `scripts/prepare-omada-plan-input` |
| `scripts/controller/parse-ansible-recap.py` | `retain-validation` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/parse-zpool-status.py` | `retain-validation` | 1 | `scripts/controller/test-zpool-status-parser.py` |
| `scripts/controller/protected_execution.py` | `retain-controller` | 2 | `scripts/controller/lifecycle-marker-transaction.py`, `scripts/controller/proxmox-package-activation.py` |
| `scripts/controller/proxmox-access-cutover.js` | `transition-with-nix` | 2 | `scripts/controller/proxmox-access-readiness.js`, `scripts/controller/test-proxmox-access-cutover.js` |
| `scripts/controller/proxmox-access-evidence.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-cutover.js` |
| `scripts/controller/proxmox-access-readiness.js` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-cutover.js` |
| `scripts/controller/proxmox-access-identity-stage.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-identity-stage.py` |
| `scripts/controller/proxmox-plan-capability.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-transports.py` |
| `scripts/controller/proxmox-deploy-capability.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-transports.py` |
| `scripts/controller/proxmox-firewall.py` | `retain-firewall-boundary` | 2 | `docs/proxmox-firewall-cutover.md`, `scripts/controller/test-proxmox-firewall-controller.py` |
| `scripts/controller/proxmox-nix-projection.js` | `transition-with-nix` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/proxmox-timezone-handoff.js` | `transition-with-nix` | 1 | `scripts/controller/test-proxmox-timezone-handoff.js` |
| `scripts/controller/proxmox-timezone-handoff-transaction.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-timezone-handoff.js` |
| `scripts/controller/proxmox-package-manifest.js` | `transition-with-nix` | 5 | `nix/proxmox/bundle.py`, `nix/proxmox/planner.py`, `scripts/bootstrap-proxmox-nix-host` (+2) |
| `scripts/controller/proxmox-package-activation.py` | `retain-controller` | 1 | `scripts/controller/test-proxmox-access-transports.py` |
| `scripts/controller/save-host-maintenance-plan.js` | `retain-controller` | 1 | `scripts/controller/test-save-host-maintenance-plan.js` |
| `scripts/controller/tailscale-policy.py` | `retain-controller` | 3 | `infrastructure/policy/test-policy.sh`, `scripts/controller/test-tailscale-policy.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/test-ansible-collections.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-attest-debian-qualification-plan.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-authentik-tofu-foundation.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-contract-schema.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-controller-apply-lock.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-debian-access-cleanup.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-lifecycle-state.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-lifecycle-marker-transaction.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-lifecycle-transition-plan.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-maintenance-planning.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-normalize-ansible-plan.py` | `retain-test` | 1 | `infrastructure/policy/test-policy.sh` |
| `scripts/controller/test-omada-host-alias.py` | `retain-test` | 1 | `infrastructure/policy/test-policy.sh` |
| `scripts/controller/test-protected-file.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-access-cutover.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-access-identity-stage.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-access-transports.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-ansible-deploy-activator.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-disk-adoption-plan.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-firewall-controller.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-firewall-nfs-canary.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-firewall-schemas.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-firewall-transaction.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-nix-apply.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-nix-bootstrap.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-nix-foundation.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-nix-plan.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-nix-projection.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-package-manifest.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-proxmox-timezone-handoff.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-reconcile-manifest.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-reconcile-security.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-restic-policy.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-root-local-audit.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-save-host-maintenance-plan.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-tailscale-policy.py` | `retain-test` | 1 | `infrastructure/policy/test-policy.sh` |
| `scripts/controller/test-vfio-recover.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-vm-100-authority.js` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/test-zpool-status-parser.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/controller/validate-offen-retirement-evidence.js` | `retain-validation` | 0 | none found in tracked files |
| `scripts/controller/validate-protected-file.py` | `retain-validation` | 2 | `scripts/controller/test-protected-file.py`, `scripts/reconcile-infrastructure` |
| `scripts/controller/validate-proxmox-host-policy.js` | `transition-with-nix` | 0 | none found in tracked files |
| `scripts/controller/validate-proxmox-package-policy.js` | `transition-with-nix` | 0 | none found in tracked files |
| `scripts/controller/validate-restic-policy.js` | `retain-recovery` | 0 | none found in tracked files |
| `scripts/controller/validate-vm-artifact-references.js` | `retain-validation` | 0 | none found in tracked files |
| `scripts/create-sops-age-identity.sh` | `retain-manual-bootstrap` | 4 | `infrastructure/evidence/offen-retirement.json`, `infrastructure/evidence/offen-retirement.schema.json`, `infrastructure/retirement/offen-retirement-manifest.json` (+1) |
| `scripts/diagnose-proton-auth` | `retain-incident` | 9 | `ansible/playbooks/diagnose-proton-auth.yml`, `ansible/playbooks/diagnose-proton-beta.yml`, `ansible/playbooks/diagnose-proton-post-reset.yml` (+6) |
| `scripts/diagnose-proton-quota` | `retain-incident` | 1 | `scripts/test-restic-tools.py` |
| `scripts/diagnose-sops-byte-mismatch.py` | `retirement-candidate` | 0 | none found in tracked files |
| `scripts/export-omada-state.py` | `retain-controller` | 0 | none found in tracked files |
| `scripts/extract-dotenv-keys.py` | `retain-validation` | 1 | `docs/sops-age.md` |
| `scripts/finalize-proton-empty-recovery` | `retain-recovery` | 2 | `ansible/playbooks/recover-proton-qualification.yml`, `scripts/test-restic-tools.py` |
| `scripts/finalize-staged-proton-recovery` | `retain-recovery` | 1 | `scripts/test-restic-tools.py` |
| `scripts/initialize-restic-repositories` | `retain-recovery` | 9 | `ansible/playbooks/finalize-restic-repository-initialization.yml`, `ansible/playbooks/initialize-restic-repositories.yml`, `ansible/playbooks/resume-restic-repository-initialization.yml` (+6) |
| `scripts/inspect-tofu-plan` | `retain-controller` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/install-sops-age.sh` | `retirement-candidate` | 1 | `docs/sops-age.md` |
| `scripts/inventory-proxmox-local-artifacts` | `retain-manual-bootstrap` | 0 | none found in tracked files |
| `scripts/local-controller` | `retain-controller` | 12 | `README.md`, `docs/authentik-opentofu.md`, `docs/compose-deployment.md` (+9) |
| `scripts/materialize-compose-secret-files.py` | `retain-compose-runtime` | 5 | `ansible/roles/compose_deploy/tasks/main.yml`, `ansible/roles/compose_recovery/tasks/main.yml`, `ansible/roles/compose_stage/tasks/main.yml` (+2) |
| `scripts/migrate-proxmox-zfs-stack` | `retirement-candidate` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/prepare-authentik-plan-input` | `retain-controller` | 4 | `scripts/controller/test-authentik-tofu-foundation.py`, `scripts/controller/test-reconcile-security.py`, `scripts/local-controller` (+1) |
| `scripts/prepare-omada-plan-input` | `retain-controller` | 2 | `scripts/local-controller`, `scripts/reconcile-infrastructure` |
| `scripts/prepare-provider-ca-bundle` | `retain-controller` | 2 | `scripts/controller/test-reconcile-security.py`, `scripts/local-controller` |
| `scripts/prepare-proxmox-nix-protected-inputs` | `transition-with-nix` | 3 | `docs/proxmox-bootstrap.md`, `scripts/controller/test-proxmox-firewall-schemas.py`, `scripts/controller/test-proxmox-nix-bootstrap.py` |
| `scripts/prepare-recovery-volumes.py` | `retain-recovery` | 1 | `ansible/roles/compose_recovery/tasks/main.yml` |
| `scripts/prove-aws-recovery-hold` | `retain-recovery` | 5 | `ansible/playbooks/finalize-first-restic-backup.yml`, `ansible/playbooks/resume-first-restic-backup.yml`, `ansible/playbooks/run-first-restic-backup.yml` (+2) |
| `scripts/prove-restic-recovery-vm` | `retain-recovery` | 2 | `docs/restic-backups.md`, `scripts/test-restic-recovery-vm` |
| `scripts/qualify-proton-backup` | `retain-recovery` | 15 | `ansible/playbooks/deploy-proton-password-only-artifacts.yml`, `ansible/playbooks/diagnose-proton-auth.yml`, `ansible/playbooks/qualify-proton-backup.yml` (+12) |
| `scripts/reconcile-infrastructure` | `retain-controller` | 8 | `docs/proxmox-appliance-maintenance.md`, `docs/restic-backups.md`, `docs/restic-live-migration-plan.md` (+5) |
| `scripts/refresh-proxmox-nix-protected-inputs` | `transition-with-nix` | 1 | `scripts/controller/test-proxmox-nix-bootstrap.py` |
| `scripts/rehearse-recovery` | `retain-recovery` | 2 | `docs/recovery-rehearsal.md`, `scripts/reconcile-infrastructure` |
| `scripts/render-proxmox-package-manifest` | `transition-with-nix` | 0 | none found in tracked files |
| `scripts/render-restic-policy.js` | `retain-recovery` | 1 | `docs/restic-backups.md` |
| `scripts/restic-backup` | `retain-recovery` | 14 | `ansible/playbooks/finalize-first-restic-backup.yml`, `ansible/playbooks/recover-post-nfs-first-run.yml`, `ansible/playbooks/resume-first-restic-backup.yml` (+11) |
| `scripts/restore-critical-backup` | `retain-recovery` | 9 | `docs/restic-backups.md`, `recovery/README.md`, `scripts/build-restic-recovery-bundle` (+6) |
| `scripts/restore-dotenv-layout.py` | `retain-recovery` | 3 | `ansible/roles/compose_stage/tasks/main.yml`, `docs/sops-age.md`, `scripts/compose-artifact.py` |
| `scripts/review-compose-stage.py` | `retain-compose-runtime` | 1 | `ansible/playbooks/review-compose-stage.yml` |
| `scripts/rotate-proxmox-nix-session-key` | `transition-with-nix` | 1 | `scripts/controller/test-proxmox-nix-bootstrap.py` |
| `scripts/rotate-proxmox-plan-api-token` | `retain-manual-bootstrap` | 0 | none found in tracked files |
| `scripts/run-first-restic-backup` | `retain-recovery` | 10 | `ansible/playbooks/finalize-first-restic-backup.yml`, `ansible/playbooks/recover-post-nfs-first-run.yml`, `ansible/playbooks/resume-first-restic-backup.yml` (+7) |
| `scripts/run-restic-recovery-bundle` | `retain-recovery` | 3 | `scripts/prove-restic-recovery-vm`, `scripts/reconcile-infrastructure`, `scripts/test-restic-recovery-bundle` |
| `scripts/supervise-staged-proton-recovery` | `retain-recovery` | 2 | `docs/restic-backups.md`, `scripts/test-restic-tools.py` |
| `scripts/test-compose-action-plan.py` | `retain-test` | 1 | `scripts/reconcile-infrastructure` |
| `scripts/test-compose-secret-files` | `retain-test` | 1 | `scripts/test-recovery-tools` |
| `scripts/test-nextcloud-config` | `retain-test` | 1 | `scripts/test-recovery-tools` |
| `scripts/test-proton-password-only-transition.py` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-proton-qualification.py` | `retain-test` | 1 | `docs/restic-backups.md` |
| `scripts/test-proton-totp-transition.py` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-proton-transaction-boundaries.py` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-recovery-tools` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-restic-activation-fixture` | `retain-test` | 4 | `scripts/prove-restic-recovery-vm`, `scripts/reconcile-infrastructure`, `scripts/test-recovery-tools` (+1) |
| `scripts/test-restic-first-run.py` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-restic-recovery-bundle` | `retain-test` | 5 | `docs/nextcloud-34-configuration.md`, `docs/restic-backups.md`, `scripts/reconcile-infrastructure` (+2) |
| `scripts/test-restic-recovery-vm` | `retain-test` | 2 | `scripts/rehearse-recovery`, `scripts/test-recovery-tools` |
| `scripts/test-restic-repository-initialization.py` | `retain-test` | 0 | none found in tracked files |
| `scripts/test-restic-restore-branch` | `retain-test` | 3 | `docs/nextcloud-34-configuration.md`, `scripts/reconcile-infrastructure`, `scripts/test-recovery-tools` |
| `scripts/test-restic-tools.py` | `retain-test` | 2 | `docs/restic-backups.md`, `scripts/reconcile-infrastructure` |
| `scripts/transition-proton-totp-config` | `retirement-candidate` | 2 | `ansible/playbooks/transition-proton-totp.yml`, `scripts/test-proton-totp-transition.py` |
| `scripts/validate-contract` | `retain-validation` | 3 | `docs/restic-backups.md`, `scripts/reconcile-infrastructure`, `scripts/rehearse-recovery` |
| `scripts/validate-provider-locks` | `retain-validation` | 2 | `scripts/reconcile-infrastructure`, `scripts/rehearse-recovery` |
| `scripts/validate-proxmox-bootstrap-keys` | `transition-with-nix` | 2 | `scripts/controller/test-proxmox-firewall-schemas.py`, `scripts/reconcile-infrastructure` |

## Executable support files outside `scripts/`

| File | Class | Decision |
|---|---|---|
| `ansible/roles/firewall_nfs_canary/files/proxmox-firewall-nfs-canary.py` | `retain-firewall-boundary` | Installed canary remains part of firewall rollback proof |
| `ansible/roles/plan_controller/files/iac-read-docker-version` | `retain-controller` | Narrow `ansible-plan` helper |
| `infrastructure/policy/inspect-plan.py` | `retain-validation` | OpenTofu plan policy |
| `infrastructure/policy/inspect-proxmox-disk-adoption-plan.py` | `retain-validation` | Offline policy for the isolated TypeList scsi3 qualification root |
| `infrastructure/policy/inspect-restic-recovery-vm-plan.py` | `retain-recovery` | Disposable recovery plan policy |
| `infrastructure/policy/test-policy.sh` | `retain-test` | Policy fixture runner |
| `infrastructure/proxmox-firewall/host/proxmox-apply-transport` | `retain-firewall-boundary` | Fixed transaction isolation helper |
| `infrastructure/proxmox-firewall/host/proxmox-firewall-boot-recovery` | `retain-firewall-boundary` | Boot rollback/recovery helper |
| `infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py` | `retain-firewall-boundary` | Firewall mutation authority |
| `infrastructure/proxmox-firewall/host/proxmox-firewall-transport` | `retain-firewall-boundary` | Fixed remote transaction transport |
| `infrastructure/proxmox-access/host/proxmox-ansible-plan-transport` | `retain-controller` | Fixed Tailscale SSH observer transport; never a normal Ansible shell |
| `nix/proxmox/activator-template.py` | `transition-with-nix` | Retain until Ansible transaction parity and rollback closure |
| `nix/proxmox/apply.py` | `transition-with-nix` | Retain until controller handoff |
| `nix/proxmox/bundle.py` | `transition-with-nix` | Retain until reproducible Ansible artifact replacement |
| `nix/proxmox/controller_lock.py` | `transition-with-nix` | Retain until lock protocol handoff |
| `nix/proxmox/observer-template.py` | `transition-with-nix` | Retain until read-only Ansible parity |
| `nix/proxmox/planner.py` | `transition-with-nix` | Retain until saved Ansible plan parity |
| `nix/proxmox/prepare.py` | `transition-with-nix` | Retain until protected preflight parity |
| `nix/proxmox/private-preparer-template.py` | `transition-with-nix` | Retain until protected preflight parity |
| `nix/proxmox/vfio-recover.py` | `transition-with-nix` | Port exact helper and tests before Nix removal |
| `services/data/gluetun/gluetun_up.sh` | `retain-operational` | Runtime-mounted VPN hook |
| `services/data/gluetun/mam_seedbox.sh` | `retirement-candidate` | Runtime-used today, but unpinned `apk update/add` must be replaced before retirement |
| `services/data/gluetun/qbittorrent_port.sh` | `retain-operational` | Runtime-mounted VPN port hook |
| `services/data/wolf/es-de/dolphin-config.sh` | `retain-operational` | Runtime-mounted Wolf helper |
| `services/data/wolf/waybar-disabled` | `retain-operational` | Intentional no-op process used by Wolf |

## Retirement gates

Every `retirement-candidate` requires all of the following before deletion: no tracked caller; no installed host copy, systemd unit, timer, operator alias, external CI/scheduler, or recovery runbook; a retained replacement or an explicit declaration that the capability is obsolete; recovery evidence remains reproducible; and the deletion passes the full controller validation suite. `transition-with-nix` additionally requires Ansible parity, terminal retained Nix sessions, a closed rollback window, and removal from the controller manifest in the same reviewed change.
