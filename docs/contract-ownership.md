# Contract ownership and retirement boundary

`infrastructure/contract/home-lab.yml` is now a compatibility input for retained
Ansible, lifecycle and recovery paths. It is not a provider-wide desired-state
interface. New consumers must use domain-owned native inputs rather than adding
another top-level contract field.

## Native owners

| Domain | Owned input | Consumers | Status |
| --- | --- | --- | --- |
| Compose source assets | `docker-compose.yml`, `services/*.yml` and the tracked files they reference | Compose artifact tooling and runtime-specific installers | Migrated. The unused `compose_deployment` inventory and schema were deleted rather than replaced; existing narrow installers and audit variables remain the owners of host-consumed files. |
| Production Proxmox VM | `infrastructure/tofu/proxmox/vm.auto.tfvars.json` plus the typed `proxmox_endpoint` and `proxmox_vm` variables | The Proxmox OpenTofu root | Migrated. The root owns its API endpoint. Resource addresses, disk indexes, VMID, MAC, hardware mappings and cloud-init references are unchanged. |
| Omada | `infrastructure/tofu/omada/domain.auto.tfvars.json` plus the typed `omada_domain` variable | The Omada OpenTofu root and `scripts/configure-local-provider-credentials` | Migrated. The obsolete global `omada` subtree and schema have been removed. The ignored export remains an explicit `omada_export_path` input. |
| Tailscale policy | `infrastructure/tofu/tailscale/policy.auto.tfvars.json` plus the typed `tailscale_policy_identity` variable | The Tailscale OpenTofu root | Migrated. The root owns the policy owner and tags. The global contract no longer carries the provider-only owner or an unused endpoint summary. |
| Proxmox firewall | `infrastructure/proxmox-firewall/host/proxmox-firewall-policy.json`; explicit play-local canary hostname | The fixed controller, installed autonomous transaction helper and NFS-canary installer | Migrated. The controller now hashes the same canonical policy file installed on the host, and the canary installer no longer loads unrelated global variables. The duplicate global subtree and schema were removed without changing rules or defaults. |
| AWS foundation | Root-local HCL and `state-objects.json` | The AWS foundation OpenTofu root | Previously migrated. The now-unconsumed legacy `aws` compatibility subtree and schema were removed here. |
| Native host observation/configuration | `ansible/inventory/host_vars/*.yml` and explicit legacy group variables | Native and retained Ansible plays | Existing native domains remain unchanged; the shared timezone now belongs to `ansible/group_vars/docker_host.yml` instead of the global contract. |

Unused global metadata (`system_name`), the unconsumed generic recovery objectives
and the obsolete Compose asset inventory were removed rather than assigned new
owners. Operation-specific backup-age and asset constraints remain beside their
actual lifecycle, Restic, Compose and recovery consumers. The former eight-hour RTO
is retained only as a recovery-assessment criterion, not as active contract input.

The Proxmox and Tailscale compatibility sections still repeat a few physical or
access identities used by retained host and recovery code. That is a real shared
invariant, not authority for an OpenTofu root to reload the compatibility document.
`scripts/controller/test-domain-input-ownership.js` tests each native interface
from its owning input and separately checks that the provider roots do not cross
back into the global contract.

## Remaining direct consumers

The following inventory describes current source consumers. Historical evidence,
ignored state, saved plans, recovery bundles and installed files are not rewritten
or inspected by this source change.

### Qualification-blocked

These paths consume Restic qualification state, Debian qualification facts or
retained lifecycle bindings. They cannot be detached by copying values without
reviewing the corresponding journals, provider/state lineage and recovery rules:

- `ansible/playbooks/qualify-proton-backup.yml`
- `ansible/playbooks/resume-proton-qualification.yml`
- `ansible/playbooks/recover-proton-qualification.yml`
- `ansible/playbooks/debian-lifecycle-audit.yml`
- `ansible/playbooks/lifecycle-assert.yml`
- `ansible/playbooks/lifecycle-observe.yml`
- `ansible/playbooks/lifecycle-transition-plan.yml`
- `ansible/playbooks/apply-debian-lifecycle-transaction.yml`
- `scripts/controller/debian-lifecycle-transactions.py`
- the `debian.qualification`, VM/storage identity and lifecycle portions consumed
  transitively by their roles and plan producers

VM9900 callable-source retirement is complete in tracked source. Its preserved
provider-state/evidence lineage remains a separate unresolved external workstream
for this migration: ignored state/evidence and old plans remain preserved, and this
pass does not make a new claim about their custody.

### Recovery-blocked

These paths use the contract as a durable compatibility input for backup scope,
repository identity, recovery evidence, retained Compose generations or migration
rollback:

- Restic initialization and first run:
  `initialize-restic-repositories.yml`,
  `resume-restic-repository-initialization.yml`,
  `finalize-restic-repository-initialization.yml`,
  `run-first-restic-backup.yml`, `resume-first-restic-backup.yml`,
  `finalize-first-restic-backup.yml`, `recover-post-nfs-first-run.yml`,
  `update-retained-first-run-tools.yml` and `clear-failed-apply-lock.yml`
- Restic policy/runtime:
  `ansible/roles/restic_backup/`, `ansible/group_vars/docker_host.yml`,
  `scripts/render-restic-policy.js`,
  `scripts/prepare-restic-recovery-bundle-metadata`,
  `scripts/test-restic-first-run.py`,
  `scripts/test-restic-repository-initialization.py`,
  `scripts/test-restic-tools.py` and `scripts/prove-aws-recovery-hold`
- Compose and migration recovery:
  `stage-compose.yml`, `review-compose-stage.yml`,
  `verify-active-compose-artifact.yml`, `plan-compose-recovery.yml`,
  `recover-compose.yml`, `rollback-compose.yml`,
  `deploy-nextcloud-migration.yml`, `rollback-nextcloud-migration.yml`,
  `migrate-preserved-backup-data.yml` and `scripts/test-nextcloud-config`

The semantic consumers behind those playbooks include `compose_stage`,
`compose_deploy`, `compose_recovery`, `compose_rollback`,
`nextcloud_path_migration`, `nextcloud_configuration`, `restic_backup` and the
shared Docker-host variables. Their backup scope, project/volume identity, storage
identity and rollback rules remain unchanged.

### Deliberately retained compatibility consumers

The remaining direct loaders support host lifecycle, access, audit, package,
reboot or firewall compatibility paths:

- `ansible/playbooks/adopt-lifecycle-marker.yml`
- `ansible/playbooks/apply-debian-access-cleanup.yml`
- `ansible/playbooks/audit.yml`
- `ansible/playbooks/bootstrap.yml`
- `ansible/playbooks/install-debian-lifecycle-capability.yml`
- `ansible/playbooks/packages-plan.yml`
- `ansible/playbooks/plan-controller-audit.yml`
- `ansible/playbooks/reboot-plan.yml`
- `ansible/playbooks/reconcile-tailscale-baseline.yml`
- `ansible/playbooks/site.yml`
- `scripts/controller/debian-access-cleanup.py`
- `scripts/controller/debian-package-activation.py`
- `scripts/controller/debian-reboot-activation.py`
- `scripts/controller/maintenance-capability-activation.py`
- `scripts/controller/save-host-maintenance-plan.js`
- `scripts/migrate-proxmox-zfs-stack`

Their semantic consumers include the lifecycle, access-cutover, package-lifecycle,
reboot-lifecycle, base, storage, SOPS/age, Tailscale, audit and firewall roles.
Several are retained recovery or migration internals rather than supported general
entrypoints; loading the contract does not expand their operational authority.

### Validators, generated inputs and whole-document bindings

- `scripts/validate-contract` and the `test-contract-*`, Debian lifecycle,
  Restic-policy, provisioning and maintenance tests validate the compatibility
  surface. They are test consumers, not additional owners.
- `ansible/roles/debian_lifecycle_transaction/tasks/inactive-unit-admission.yml`
  directly binds declaration constants from `infrastructure/contract/schema.json`;
  that role must migrate before the schema can be retired.
- `services/data/restic/files-from` and `services/data/restic/excludes` are generated
  from `backups.restic`; their exact bytes remain runtime and recovery inputs.
- `ansible/roles/debian_lifecycle_transaction/templates/production-dependencies.json.j2`
  renders a whole-contract SHA-256. The lifecycle task and host transaction verify
  the same binding.
- Debian access, lifecycle, package and maintenance plan producers bind the current
  contract SHA-256. A source change therefore makes an old saved plan stale by
  design. Old plans and evidence must remain immutable; never rewrite their hashes
  to admit this decomposition.
- `infrastructure/contract/schema.json` remains because the compatibility document
  is still active. Its removal must happen with all consumers above, not before.

## Final deletion gate

Delete the remaining contract and schema only after all of the following are true:

1. retained Ansible roles receive explicit domain variables without rebuilding a
   universal inventory object;
2. Restic policy, generated scope files, repository initialization/first-run and
   bundle recovery have one reviewed recovery-local owner;
3. Compose/Nextcloud rollback paths no longer need the compatibility values;
4. lifecycle and maintenance plan formats no longer bind the whole document, with
   existing saved plans and receipts preserved as historical provenance; and
5. qualification/provider-state lineage has an independently reviewed disposition.

Until then, the narrow compatibility document remains fail-closed. Do not weaken
checks, regenerate evidence or introduce a projection layer merely to delete it.
