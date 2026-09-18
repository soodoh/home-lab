# VM9900 qualification and recovery retirement assessment

## Status and authority

This is a read-only assessment and a proposed sequence, not retirement authority.
No VM, disk, image, snippet, ACL, account, helper, state, lock, journal, credential,
recovery bundle or policy was changed. Provider applies, state writes, host cleanup
and Tailscale policy changes each require separate explicit approval.

The observation was performed on September 18, 2026 at approximately 20:45 UTC
from clean repository commit `5c7b8e2d95431f006d57fdab5732da3329d52e68`.
The documented native Proxmox observation passed 20 tasks with `changed=0`,
`failed=0` and `unreachable=0`. A separate ephemeral read-only play used native
`qm`, `pvesh`, `pveum`, LVM/ZFS, account, file-metadata, lock, process and systemd
reads. It did not access, start or mount the guest. Its final four tasks passed with
`changed=0`, `failed=0` and `unreachable=0`.

These are dated observations, not exclusive ownership or permanent absence proofs.
Re-run them under the operation's coordination immediately before any approved
change.

The accompanying preparatory source makes no live change. The Debian transition
controller now admits the exact interrupted-stop receipt as a destroy predecessor
while retaining its fresh-admission, saved-plan, four-address and state-digest
guards. `scripts/controller/retire-restic-recovery-image.py` is a separate one-shot
image controller bound to the exact image-only state and journal. It refuses to plan
until VM9900 is absent, accepts only one image delete, requires a clean pushed commit
and exact approval hashes, and never uses `tofu state rm`. The post-provider host
play binds every removable file and the two account identities, removes only the
VM9900 ACL, preserves diagnostic/capability evidence, and retains its owner on
failure for the separate exact-owner recovery play. None of this preparatory source
has been planned or applied.

## Current ownership

### Debian lifecycle is the only live VM9900 generation

VM9900 is stopped, unlocked, unprotected and not configured for boot. Its current
identity is:

- name `home-lab-debian-lifecycle-qualification`;
- tags `debian-lifecycle`, `disposable`, `qualification`;
- `scsi0` `local-lvm:vm-9900-disk-0`, 32 GiB, serial
  `DEB-LIFE-ROOT-32G`;
- cloud-init volume `local-lvm:vm-9900-cloudinit` with
  `local:snippets/home-lab-debian-lifecycle-qualification.yaml`;
- MAC `BC:24:11:61:ED:75` on firewall-enabled `vmbr0`;
- no `scsi1`.

Only the two expected LVM volumes exist. Their UUIDs remain
`OKJ0NY-Uiqm-CkgE-jRbL-FqH2-GzoE-uExP6U` and
`teapke-MKJb-JJWB-fc48-LtE9-yc23-KugY3b`; no `vm-9900-*` ZFS object exists.
The VM firewall remains enabled with DROP input/output policies and nine rules.
The firewall file SHA-256 remains
`2ca450cc2b81a9b5108d68a6f6bee6c134fdae90ed6f91bb4423bc107c588644`.

The live identity matches the four resources in
`.local/qualification-route/clean-first-boot-foundation-final/state.tfstate`:
the Debian image, VM, firewall options and firewall rules. That protected state is
mode 0600, serial 5, SHA-256
`87ca813d8a68913208f2223ef9d6446fbd7751c939571e825c05ad1b1dea511b`.
Its backup is the same lineage at serial 4 and remains untouched.

The latest stopped receipt is
`cd6a77371f93fa19699af14e7f8c46454999167a118c8f77597f5850155927a8.receipt.json`.
It is an `interrupted-restart-stop` receipt, binds the current state hash and records
VM9900 stopped. The later invocation failure records
`incorrect-snippet-receipt-path`; it is not permission to retry or destroy.
The current generic transition controller accepts a normal stop or restart receipt
for destroy, but not this interrupted-stop format. Do not bypass that mismatch with
a raw old plan or by starting the guest merely to obtain a different receipt.

### Restic owns no live VM or disk

The Restic cloud-init snippet is absent. No Restic VM disk serial or LVM/ZFS volume
exists. The historical Restic state at
`.reconcile/restic-recovery-vm/09d091e5c9f44eafaf5a8b89576c9929e1fa5644/tofu.tfstate`
is mode 0600, serial 1, SHA-256
`6fa9556295404743504e60566cdb9dca7ddd7796ed415844ba1734eec40ea88d`.
It owns exactly one resource:
`proxmox_download_file.recovery_image`, whose live object is
`local:import/home-lab-restic-recovery-debian-20260810-2566.qcow2`.
The journal remains `create-replanning` with the
`legacy-local-state-adopted` checkpoint. Preserve it unchanged unless a separately
approved state-backed image destroy writes the next state generation.

The Restic and Debian qualification import images both still exist, are root-owned
single-link mode-0644 files, and are byte-identical: 436,404,224 bytes with SHA-256
`d4e6f5d1e9f571c198a65b45ab1adae6c5734607614e72f9661d84ce5881e5fc`.
They are downloadable Debian base images, not restored application data, recovery
bundles or proof of independent recovery custody.

The current Restic VM controller does not safely reconcile the retained image
lineage:

- its transaction state is commit-scoped, so a new run does not use the retained
  `09d091e5...` state;
- its prior-state adoption requires a state containing exactly the recovery VM,
  while `09d091e5...` contains only the image;
- its destroy path requires a same-transaction create manifest and cannot destroy
  this image-only state;
- its `status` command reports any VMID 9900 status without first requiring the
  Restic VM name, so it would describe the Debian VM as a stopped recovery VM.

Do not run this controller while the Debian generation owns VMID 9900. Separate
local backends are not hypervisor isolation.

### Installed capabilities remain live

The following Debian qualification capability remains installed:

- `qualification-apply` UID/GID 1900, no supplementary groups, fixed transport
  shell, and an empty `.ssh` directory;
- the qualification snippet, helper, forced transport and sudo rule;
- five entries in the root-only qualification diagnostic directory;
- the exact `/vms/9900` plan-token ACL for
  `root@pam!tofu-plan` / `HomeLabTofuPlanDiskInspect`.

The following Restic recovery capability remains installed:

- the exact source-owned Restic transport, SHA-256
  `186d6adf91649182d063165e50a4ab961968876c8a65254be53b6258bd2e95e1`;
- its restricted `ansible-deploy` transport and sudo rule;
- the committed capability record under
  `/var/lib/home-lab/restic-recovery-capability/240db6d859e21f633e3cbe9bed93414c8ebeda58a9717d70d02566744776d4b5`,
  whose state SHA-256 remains
  `708af9c013eea53a8158df668d75261037f05a5f95a3718811029494ace269dc`.

No listed qualification/recovery lock path existed, no matching lock was held, no
relevant process was found and systemd had no queued job. That does not reserve a
window or authorize cleanup. The capability record, diagnostic entries and retained
host before-images are evidence; do not delete or rewrite them when removing their
forward callers.

## Recovery boundary

The generic recovery capability does not depend on VM9900. Keep
`build-restic-recovery-bundle`, `run-restic-recovery-bundle`,
`restore-critical-backup`, both encrypted bundles, credentials, repository policy,
activation fixtures and all canonical evidence. Those support exact snapshot restore
to private staging under the limits in [recovery](../recovery/README.md).

The VM9900 controller is a historical isolated qualification harness. Its successful
runs proved staged restoration and structural validation without starting services.
They did not qualify fresh-server rebuild or production activation. Removing the
harness and its duplicate base image does not remove a Restic repository, snapshot,
bundle, production backup writer or recovery receipt. It does remove one reusable
way to repeat the old isolated exercise; rebuilding that capability later would need
a new, independently isolated design and qualification.

## Decision options

### 1. Full VM9900 retirement — recommended

Retire the stopped Debian VM, both qualification-only import images, the dedicated
ACL/snippet/accounts/transports and all callable VM9900 source. Preserve every
historical state generation, journal, receipt, key, diagnostic record, capability
record, recovery bundle and evidence file. Keep generic Restic staging and production
Debian lifecycle recovery source that does not require the disposable canary.

This is the smallest long-term ownership model: no shared VMID, no dormant account
or ACL, no controller that can mislabel another lane's VM, and no duplicate base
image presented as recovery readiness.

### 2. Retire Restic VM qualification only

Delete only the image owned by the Restic image-only state, remove the Restic VM
controller/transport route and keep the Debian lifecycle VM and its capability.
This removes the current cross-lineage collision but retains a stopped one-off canary
and its host access surface. Choose this only if a future Debian lifecycle canary is
still an explicit operational requirement.

### 3. Preserve an isolated recovery harness

Do not reuse VMID 9900 or the current image-only state. First design a new unique
VMID, stable state ownership, private-network boundary and end-to-end recovery
exercise. Retire the existing Debian and Restic VM9900 lineages only after that new
capability is independently qualified. Merely renaming a root or moving local state
is insufficient.

### 4. No change

Continue preserving both lineages and all installed capability. This is safe only as
a deliberate retention decision; stopped state is not cleanup, isolation or recovery
proof.

## Proposed full-retirement sequence

Every mutation phase below needs a fresh read, an exact saved plan or bounded Ansible
preview, explicit approval, and immediate postconditions. Do not combine phases into
one broad play.

1. **Prepare retirement source without deleting current callers.** Review the
   accompanying narrow Debian interrupted-stop admission, image-only Restic state
   controller, exact post-provider host/ACL retirement play and retained-owner
   recovery play. Push this preparatory commit before planning. The image controller
   must continue to accept exactly one delete action for
   `proxmox_download_file.recovery_image`.
2. **Destroy the Debian-owned live generation.** Produce and inspect a saved
   OpenTofu destroy plan containing exactly the four Debian state addresses. Re-read
   VM9900, VM100, locks and state immediately before apply. Apply only that saved
   plan. It may remove VM9900, its two LVs, VM firewall resources and the Debian
   qualification import image; it must not address VM100 or the Restic import image.
3. **Verify the hypervisor boundary.** Require VM9900 absent, no `vm-9900-*` LVM or
   ZFS objects, no VM9900 firewall file, VM100 unchanged, native protected hardware
   and access checks passing, and the Debian state empty. Preserve the resulting
   state, its backup and all receipts.
4. **Destroy the Restic image through its owning state.** Produce a separate saved
   plan against the exact `09d091e5...` state. It must contain one delete and no VM,
   disk, snippet, ACL or other image action. Apply only after separate approval, then
   require the exact import path absent and that state empty. Preserve both state
   generations and the journal; do not use `tofu state rm` as a substitute for live
   deletion.
5. **Retire host access after provider cleanup.** Remove the Debian snippet, disable
   the qualification account, remove its sudo/helper/transport, and remove only the
   `/vms/9900` ACL. Disable the Proxmox-side `ansible-deploy` forced route, remove its
   sudo rule and the two Restic transports only after their source callers are
   retired. Inventory UID-owned files before deleting either account or home.
   Preserve the diagnostic directory, committed capability directory and all
   before-images. Leave local snippet-storage support, the firewall watchdog,
   native `proxmox` access and VM100 ACLs unchanged.
6. **Narrow Tailscale policy separately.** Remove `qualification-apply` and the now
   unused Proxmox-side `ansible-deploy` SSH grants/tests while preserving Docker-host
   `ansible-deploy`, `proxmox` and `firewall-apply`. Follow the full-policy ETag/live
   comparison procedure and use a separately authorized saved plan.
7. **Retire source only after live closure.** Remove both VM9900 Tofu roots,
   controllers, plan inspectors, fixtures, install/retirement playbooks and dedicated
   tests. Remove the disposable `qualification-canary` execution route without
   disturbing production lifecycle recovery operations. Update the contract and
   native protected-access expectations together. Keep historical evidence schemas
   and every ignored `.local`, `.reconcile` and `.terraform` artifact.
8. **Final verification.** Re-run native Proxmox observation with the reviewed
   post-retirement access expectation, require fresh zero-change provider plans for
   retained roots, verify Tailscale live policy against source, run focused tests,
   parse changed YAML, check Markdown links, run `tofu fmt -check`, and run protected
   Compose validation without printing resolved configuration.

## Preparatory source validation

The source-only safety tests for the Debian transition, Restic image controller and
host-capability role passed, including hostile extra-resource/update plans, malformed
interrupted-stop receipts, changed image identities, evidence-preservation assertions
and exact retained-owner recovery wiring. Existing Debian qualification and Restic
VM safety tests also passed. Both new Ansible playbooks passed syntax checking;
`tofu fmt -check -recursive infrastructure/tofu`, local Markdown link checks,
`git diff --check` and SOPS-backed quiet Compose validation passed.

No provider plan was produced: the image controller deliberately refuses while
VM9900 remains present, and no Debian destroy planning or mutation is authorized by
these source checks.

## Explicit non-options

- Do not apply any historical Restic or Debian destroy plan.
- Do not start VM9900 to manufacture a receipt acceptable to the current destroy
  controller.
- Do not run the two VM9900 roots concurrently or let one import the other's VM.
- Do not remove state ownership before deleting its exact live object.
- Do not delete locks, journals, receipts, saved plans, keys, recovery bundles,
  diagnostic records or capability records to make source cleanup pass.
- Do not treat image equality as permission to delete both in one unreviewed action.
- Do not point the legacy Compose activator at Restic staging or claim production
  activation is qualified.
