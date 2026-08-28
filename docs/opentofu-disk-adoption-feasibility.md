# OpenTofu VM disk-adoption feasibility plan

## Decision

Production `scsi3` adoption is **not yet feasible or authorized**. OpenTofu owns VM 100, but the Debian root disk remains contract/audit-protected outside the resource's `disk` list until provider behavior is proven on disposable infrastructure.

## Verified starting facts

- Provider: `bpg/proxmox` `0.111.1` against PVE 9.2.3.
- Remote state contains only `proxmox_virtual_environment_vm.debian`; the current live plan is zero-change.
- VM 100 is running/protected with `scsi0` absent, games `scsi1`, state `scsi2`, Debian root `scsi3`, boot `scsi3;net0`, and no pending PVE configuration.
- The provider schema models `disk` as `nesting_mode=list` with at most 31 items. Ordering and list indexes therefore matter.
- Current prior and planned state each contain exactly three disk entries: inert tombstone `disk[0]`, games `disk[1]/scsi1`, and state `disk[2]/scsi2`. Live `scsi3` is not represented in state.
- `disk.interface` is required. `file_id`, `datastore_id`, `serial`, `backup`, `discard`, `iothread`, and `ssd` are optional. `path_in_datastore` and `size` are optional/computed.
- Provider documentation shows existing/other-VM disk attachment through `datastore_id` plus `path_in_datastore`, and warns that host-path pass-through is experimental. `file_id`/`import_from` examples are image-import paths, not proof of safe adoption of an already attached LVM volume.
- `lifecycle.ignore_changes = [disk[0], disk[1].file_format]` protects the retired TypeList slot and physical games disk format. It does not prove how a new `disk[3]` will bind.
- `candidate-state-move.tf` names obsolete `.debian_readopted -> .arch` addresses. Contrary to an earlier static concern, current validation and the live plan succeed because neither address exists. The block is stale residue and provides no disk-adoption safety.

## Required disposable test root

Create a self-contained qualification root copied only from the minimal VM/provider schema. It must have:

- no production backend, state bucket key, VMID, datastore path, disk serial, UUID, MAC, NFS path, hardware mapping or cloud-init snippet;
- a dedicated API token and separately reviewed disposable VMID;
- `started = false`, `on_boot = false`, `protection = false`, `prevent_destroy` appropriate to the test stage, and `delete_unreferenced_disks_on_destroy = false` while adoption behavior is measured;
- 1–2 GiB disposable disks with unique `QUAL-DISK-*` serials and a nonsecret checksum fixture;
- saved plans, JSON inspection, exact confirmations and a private local qualification state directory; and
- before/after read-only hashes of VM 100's normalized configuration proving it never changes.

The existing VM9900 Restic recovery qualification must not be reused concurrently or have its recovery semantics weakened. Allocate a different reviewed VMID unless VM9900 is proven absent and the recovery owner explicitly releases it for this isolated test.

## Implementation status

The isolated root now exists at `infrastructure/tofu/proxmox-disk-adoption-qualification`. It has local-only state, provider `bpg/proxmox` `0.111.1`, defaults disabled, restricts VMIDs to 9901–9999, forbids VM 100 and VM 9900, requires a dedicated `qual-*` datastore when enabled, creates an offline/unprotected/non-booting VM with three 1 GiB `QUAL-DISK-BASE-*` slots, and leaves unreferenced disks undeleted. Disabled plans for this root and the separate VM9900 Restic recovery root are both zero-change.

`infrastructure/policy/inspect-proxmox-disk-adoption-plan.py` and its negative fixtures enforce an update-only fourth `scsi3` entry, unchanged indexes 0–2, known volume/datastore/size/serial, unchanged boot/start/protection/destruction policy, no copy/import, no unknowns, no extra resources, and no production identifiers. Provider schema inspection confirms `disk` remains `nesting_mode=list`, `max_items=31`.

Offline phase 1 and both reviewed live rehearsals are complete. VMID 9951 first exercised dedicated directory storage and then a dedicated loop-backed LVM-thin VG/thinpool matching production storage semantics. Each run created `scsi0`–`scsi2`, allocated an unattached datastore-native candidate, applied the inspected append-only `scsi3` plan, proved a subsequent no-op, and destroyed the VM and all four volumes. VM identity, indexes 0–2, boot order, stopped state, and VM 100 configuration remained byte-for-byte stable. All datastores, ACLs, identities, tokens, loop/LVM artifacts, local credentials, and directories were retired.

### Qualification conclusion

Provider `TypeList` append ordering, identity preservation, and existing-volume attachment are now qualified for both directory and isolated LVM-thin storage with provider `0.111.1`. The disposable qualification blocker is closed. Production `scsi3` declaration still requires a separately saved and inspected production plan that preserves disk indexes 0–2 and boot order, adds only the exact `local-lvm:vm-100-disk-2` entry, keeps the VM running, and first changes `reboot_after_update` to `false` so adoption cannot trigger an automatic reboot.
## Test phases

### 1. Offline schema and policy fixtures

1. Pin provider `0.111.1` and archive its schema evidence.
2. Build synthetic plan fixtures for a four-entry TypeList: tombstone, `scsi1`, `scsi2`, candidate `scsi3`.
3. Require the plan inspector to reject list reorder, index replacement, create/delete, interface reuse, boot-order change, protection change, unknown values, unexpected resources and production identifiers.
4. Add negative fixtures for `file_id`, `path_in_datastore`, `datastore_id`, size and serial ambiguity.
5. Prove the policy still rejects any production plan containing destructive disk actions even if another resource is otherwise allowed.

### 2. Establish an unmanaged attached disk

1. Create a disposable VM and baseline disks from a reviewed saved plan.
2. Write and hash a small fixture on the candidate disk.
3. Attach that disk to the disposable VM at `scsi3` through a separately reviewed disposable-only PVE API operation, intentionally leaving it absent from OpenTofu configuration/state.
4. Refresh and plan. Require zero destructive actions and record whether the provider continues to omit the extra live disk from state, matching production behavior.
5. Record exact PVE config, volume identity, state JSON, list indexes, boot order and fixture hash.

### 3. Compare adoption representations

Use a fresh clone of the disposable state for each variant; never test variants sequentially on one state.

| Variant | Configuration under test | Acceptance question |
|---|---|---|
| A | `interface = "scsi3"`, exact `datastore_id`, exact existing `path_in_datastore`, size/serial/options | Does the provider bind the attached volume without allocating, importing, moving or resizing it? |
| B | `interface = "scsi3"` with exact existing volume identifier in the provider-supported field discovered from state/source behavior | Does the plan remain update-only with the same volume identity? |
| C | Provider-documented import mechanism, only if source inspection proves it supports an already attached PVE volume rather than an image import | Is adoption semantically distinct from copy/import and demonstrably non-destructive? |

Reject a variant if any disk identity is unknown after plan, if the candidate maps to another index, or if the provider cannot express the existing attached volume unambiguously.

### 4. Saved-plan apply on disposable infrastructure

Only after a variant passes plan review:

1. Re-read PVE config and the fixture immediately before apply.
2. Apply only the exact saved plan under the disposable owner lock.
3. Require the PVE task log to show no volume allocation, import, move, resize, detach or delete.
4. Re-read provider state and require candidate `disk[3]` to be `scsi3` with the original volume identity.
5. Boot the disposable VM, verify filesystem/fixture checksum, shut down, and repeat plan; it must be zero-change.
6. Reboot once and repeat the checksum and zero-change plan.

### 5. Removal and destruction behavior

1. Test configuration removal with `delete_unreferenced_disks_on_destroy = false`; verify whether the disk stays attached, becomes unused, or is detached. Record this behavior rather than assuming it.
2. Re-adopt from a clean state clone and prove repeatability.
3. Destroy only the disposable VM/volumes under an exact destroy plan. Verify no leaked volume, task or state lock remains.
4. Re-read VM 100 and require its normalized configuration hash to equal the pre-test hash.

### 6. Production proposal, not apply

A production proposal may be prepared only when all disposable evidence passes. It must:

- add exactly one fourth block at `disk[3]`/`scsi3` without changing `disk[0..2]`;
- bind exact current `vm-100-disk-2`, datastore, 64 GiB size, serial `HOME-LAB-DEBIAN-64G`, backup/discard/iothread/SSD policy and boot order;
- produce one update-only VM resource action with no stop/reboot/replacement/storage task;
- preserve `prevent_destroy`, protection, cloud-init, PCI/USB mappings, network and VM generation identity;
- pass a purpose-built production plan policy and two independent live observations; and
- remain a saved plan for separate human review. This feasibility milestone does not authorize its apply.

## Stop conditions

Stop and keep `scsi3` audit-only on any:

- TypeList reorder or index shift;
- volume create, import/copy, move, resize, detach, delete or replacement;
- unknown `file_id`, `path_in_datastore`, datastore, size or serial;
- boot/protection/start-state change;
- provider/PVE version-specific inconsistency;
- failure to preserve and verify the disposable fixture;
- inability to cleanly destroy disposable resources; or
- any observed change to VM 100.

Provider upgrades require the complete qualification again. Do not combine removal of the stale moved block, provider upgrade and disk adoption in one review.
