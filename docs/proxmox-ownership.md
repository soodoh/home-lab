# Proxmox native-provider ownership

The pinned `bpg/proxmox` provider is the desired writer for PVE control-plane
resources. A declaration is not proof of adoption: remote state and fresh provider
reads establish ownership. See [operations](operations.md) for plan admission,
independent console access, backups and separate apply approval.

## Resource boundaries

The `proxmox` root declares:

- VM 100, including its existing `scsi3` boot volume, `scsi1` physical games
  attachment, `scsi2` state volume, cloud-init drive and hardware mappings;
- the `local`, `local-lvm` and `storage` PVE storage registrations;
- the `vmbr0` bridge, node DNS and timezone;
- three native snippet files referenced directly by VM initialization.

Hardware attachments use the owned native PCI/USB mappings directly. Preserve
resource addresses and require a fresh remote-backed no-op plan when refactoring
these declarations; offline mock tests do not establish live equivalence.

The disk list follows the native importer's ascending bus order: games (`scsi1`),
state (`scsi2`), then boot (`scsi3`). These provider positions are not changes to
PVE bus attachments. The retired disk declaration and whole-disk ignore are
removed. Adopting the boot volume is not disk creation, image import or permission
to change its identity. Review the complete disk/boot change in the saved plan;
never use state removal to conceal it. The physical device's omitted file format
is still ignored, not the disk attachment itself. An old partial disk state can
still produce protected changes: a normal allowlist cannot admit them. Arrange
independently approved, backed-up provider state repair/readback before deployment,
then require a remote-backed plan proving the existing attachments are preserved.
A successful import into a disposable read fixture is not remote-state repair.

Storage resources register **existing** pools and paths; they do not create the
underlying ZFS pool, datasets, LVM pool, partitions or filesystems. In particular,
`proxmox_node_disk_zfs` cannot reconstruct topology and creation properties on
import. It is not declared for the data-bearing pool. The pinned ZFS storage
resource also does not expose PVE's `mountpoint` field. Host observation and
recovery remain necessary; native storage registration is not complete filesystem
or ZFS drift management. Destruction of a registration still requires exact-plan
approval and consumer inspection.

`proxmox-access` additionally declares cluster keyboard/MAC-prefix settings,
which require global `Sys.Modify` and therefore an independent owner writer.
`proxmox-firewall` remains a separate state root. Its default forward-policy
readback exception and native host observer are unchanged. Cluster firewall writes
also require global `Sys.Modify`: after the scoped apply role is activated, use
separately approved independent owner Proxmox apply credentials for firewall plans
that mutate it, never restore global privilege to normal automation. The normal
plan token can still perform its audited reads. No Ansible task is a second
control-plane writer.

PVE reports an unconfigured bridge MTU as null even when the live kernel uses
1500. `proxmox_bridge_mtu` supports explicit MTU configuration (1500 by default);
this deployment records null in `vm.auto.tfvars.json` to preserve the implicit API
configuration. An explicit-MTU change and network reload require a separately
reviewed plan; do not mix the reload into an import-only approval.

## Snippet lifecycle and SSH

[`cloud-init/files.json`](../infrastructure/tofu/proxmox/cloud-init/files.json)
defines the existing file identities. Git contains their desired contents, without
legacy bootstrap SSH keys or the inert provisioning marker. The existing instance
ID is deliberately preserved: changing it can trigger first-boot execution.
Updating the files does not remove a key from the running guest or reinitialize
that guest. Cold guest provisioning and storage activation still require their
own qualification and access/recovery prerequisites.

The native file importer cannot reconstruct `source_raw`. Its initial plan
therefore proposes **delete then create**, even for unchanged contents. Do not
approve this as an import-only no-op. The inspector accepts this narrow case only
with both an explicitly reviewed mutation address and a private deletion approval
bound to the exact saved plan. It requires the same node, datastore and filename.
`import:` allowlist entries are insufficient. Do not use create-before-destroy on
the same path: the later deletion would remove the new upload. Do not reboot or
create another consumer during replacement; preserve protected before-images and
inspect a partial failure rather than automatically deleting or retrying files.
After verified adoption, remove temporary allowlists; the importer must not become
a standing mutation waiver.

The uploader uses the existing `ansible-deploy` account through the node's Tailscale
FQDN. Tailscale SSH authenticates SSH's initial `none` handshake; no deployment
key, password, agent or forwarding is introduced. Unset `PROXMOX_VE_SSH_PASSWORD`,
`PROXMOX_VE_SSH_PRIVATE_KEY` and `PROXMOX_VE_SSH_AUTH_SOCK`. The pinned provider does
not use OpenSSH configuration and accepts unknown host keys. Before native uploads,
require a previously verified FQDN pin in its `$HOME/.ssh/known_hosts`; an alias-only
`proxmox` pin is insufficient. Do not use `ssh-keyscan` output as independent trust.

If preparing a private provider HOME, copy the controller's protected known-hosts
file and add the FQDN using only the already verified `proxmox` entry. Keep both
names for Ansible, preserve explicit AWS configuration/credential paths and the
protected SOPS identity path, and remove the temporary HOME with the session. No
new credential or persistent controller artifact is required. Qualify the real
native uploader after the separately approved replacement plan; a mock test or
API-only import does not prove SSH upload behavior.

The provider checks file presence and its local source, not remote contents.
Use `ansible/playbooks/observe-proxmox-cloud-init.yml` to verify regular root-owned
mode-0644 files and exact SHA-256 readback independently. This playbook never
uploads or repairs. A mismatch is a refusal to investigate. For an intentional
Git content change, inspect the current protected before-image and explicitly
review that mismatch as part of the whole replacement plan; do not add a standing
observer bypass. Require matching observation after apply before completion.

## Independent access ownership

The separate `proxmox-access` root owns five `HomeLabTofu*` roles and seven
ACLs referencing the two independently owned automation token identities.
`Sys.Modify` is absent from the global apply role;
`HomeLabTofuApplyNodeModify` grants it only at `/nodes/proxmox`.
`HomeLabTofuPlanStorageInspect` has non-propagating plan-token ACLs at
`/storage/local`, `/storage/local-lvm` and `/storage/storage`. Existing roles are
discovered for import natively. Role adoption must be no-op before any separately
approved privilege change; never relax policy to accept an import-and-update plan.

It does not own `root@pam`, create a new privileged user, or grant normal
automation permission to change access. [`access.json`](../infrastructure/tofu/proxmox-access/access.json)
is the desired privilege/binding authority. Token records and secrets remain in
independent protected custody, not provider state: PVE token-metadata reads require
`User.Modify`, which also permits token changes. The owner auditor does not receive
that privilege solely for import. The existing host observer verifies the exact
sealed identities and privilege separation. A token replacement is an independently
approved credential rotation, not ordinary provider adoption.

**Storage-read exception:** PVE requires `Datastore.Allocate` for storage-definition
GETs and for snippet visibility. With only `Datastore.Audit`, the native file
importer can incorrectly report existing snippets absent. The inspection role is
limited to the three storage IDs, not a grant at `/`, and does not add permission
to change ACLs. It is nevertheless a **mutating credential**: this permission also
allows deleting volumes/snippets in those stores, not merely editing definitions.
Do not call it read-only or assume VM protection blocks the storage API. Changing
this exception requires explicit independent owner acceptance of that risk.
Independently align the sealed host access expectations and reviewed observation
bindings with approved changes; do not capture or rewrite them automatically from
newly observed permissions. Reviewed
`additionalAcls` must specify `propagate: false` for each scoped storage binding;
omitting it retains the existing propagating-ACL expectation. A more-specific PVE
token ACL replaces inherited role privileges: the scoped storage role must retain
`Datastore.Audit` alongside `Datastore.Allocate`, and the node-modification role
retains `Sys.Audit`. Otherwise the narrow grants silently remove needed read access.

**Node-modification boundary:** global `Sys.Modify` also authorizes role-definition
writes at `/access`. It is not a safe ordinary-apply grant even without
`Permissions.Modify`. Node networking/DNS/timezone writes instead use the scoped
node ACL; global cluster options remain owner-controlled. Changes to the scoped grants
require separate owner approval; declarations alone do not activate them. This narrows direct PVE API authority, not the
existing root authority available through approved Tailscale SSH/become.

Normal roots cannot own identity or global cluster-option resources, including via imports, nested
modules or retained state. The access root rejects its managed token identities
as provider credentials. The owner must independently supply distinct plan/apply
credentials and authorize any privilege changes; ordinary allowlists do not
supply that authority. The provider-token variable is sensitive and ephemeral:
it is not persisted in plans/state and can be supplied separately at plan/apply.

The `home-lab/proxmox-access/tofu.tfstate` key and its lock require independently
approved owner storage credentials. It is deliberately excluded from the normal
controller's AWS state-key grants. Do not reuse the ordinary `home-lab-plan` or
`home-lab-apply` identities for access-state mutation, add the key to their grant
manifest, or initialize a local-state deployment. Use a separately owner-controlled
protected bucket: ordinary controllers must have neither object writes nor
bucket-policy administration there. Merely adding another key to the normal state
bucket is not sufficient isolation when its apply identity administers that
bucket's policy. Supply the independently approved bucket through
`PROXMOX_ACCESS_BACKEND_BUCKET`, not `TF_BACKEND_BUCKET`. Owner state/permission
bootstrap is not activated by CI.

For an admitted owner plan, supply `TF_VAR_proxmox_access_api_token` from
`PROXMOX_ACCESS_PLAN_TOKEN`; supply the separately approved apply token only when
applying that inspected plan. Never echo either variable. No owner credential or
permission grant is provisioned by the normal root.

## Remaining host ownership

Ansible/systemd remain responsible for operating-system packages, complete APT
repository/key policy, chrony service configuration, Tailscale deployment access,
NFS exports, kernel/IOMMU/VFIO setup, maintenance and recovery. Provider timezone
management is not chrony/NTP-server management. Native APT activation resources
cannot replace the complete repository-file policy, so a competing APT writer is
not added.

## Validation

CI validates both full roots, including import blocks, with the native provider.
`scripts/test-proxmox-tofu` runs native mock-provider behavior tests against copies
of the unchanged declarations, omitting only `imports.tf` (including live import
discovery) because mock providers cannot execute imports. It covers disk
identities/indexes, storage references, management networking, snippet content/references, node-scoped privileges and
independent credential admission. `ansible/tests/proxmox-cloud-init.yml` tests native hash/metadata refusal;
policy tests cover identity-root isolation and exact snippet-replacement approval.
These tests do not establish live adoption or grant permission to apply.
