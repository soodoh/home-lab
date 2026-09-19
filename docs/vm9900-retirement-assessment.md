# VM9900 qualification and recovery retirement assessment

## Status and authority

Full VM9900 retirement was selected and completed in separately reviewed phases on
September 18, 2026. Both provider-owned lineages are empty, the bounded host
capability is retired, the live Tailscale policy denies the retired Proxmox users,
and callable VM9900 source is removed. Historical state, journals, plans, receipts,
diagnostics, capability evidence and ignored provider caches remain preserved.

The initial observation at approximately 20:45 UTC used clean commit
`5c7b8e2d95431f006d57fdab5732da3329d52e68`. Native Proxmox observation passed 20
tasks with `changed=0`, `failed=0` and `unreachable=0`. A separate ephemeral
read-only play used native `qm`, `pvesh`, `pveum`, LVM/ZFS, account, file-metadata,
lock, process and systemd reads without accessing, starting or mounting the guest.

Preparatory commit `327f2d70e220847782273f97dfd2f638e0b7d40e` admitted the exact
interrupted-stop receipt while retaining fresh-admission, saved-plan, four-address
and state-digest guards. The reviewed Debian plan
`baa189d65415a521a1b2c392f48cd79c86577d50326c05bdaa6e97b34ca2dbe6`
deleted exactly the Debian image, stopped VM, firewall options and firewall rules.
The resulting Debian state is serial 6 with no resources and SHA-256
`b1a3df4bb05dfe6102c2d8bcc9b636deaaa5a011d6fb93255afd7bc3144b23f5`.
Its receipt SHA-256 is
`e599c8bf83ffcfb361dde17b5329fbbc77f9f2bec81d6885c2097174f4eb45ba`.

The image inspector safely refused its first unpublished plan because the retained
resource was indexed. Commit `bd53518d89fa3aab2c6ad8623c6e76f028cfe1d9` bound the
exact address `proxmox_download_file.recovery_image[0]`. The separately reviewed
plan `67d2647dcbeb23be77a128970e7301306d289f0800ca6c312a56adc7924e635f`
then deleted only that image. The Restic state is empty with SHA-256
`1e2e006a219250a3d0a13c5534cd52d0b51cd7291105f73fc178f96b716a19fb`;
the unchanged journal SHA-256 remains
`8b8130d85b1019bf13711c730ca1b696311ed24e88adbdf5c47a771ae52f0aeb`.
The protected before-state was preserved with its original SHA-256
`6fa9556295404743504e60566cdb9dca7ddd7796ed415844ba1734eec40ea88d`.

Post-apply reads require VM9900, its LVM/ZFS objects, firewall file and both import
images absent while VM100 remains running, named `docker-host` and protected. PVE
removed the now-invalid `/vms/9900` ACL when the VM was deleted, so current contract,
native-observer and host-retirement inputs must use the two-ACL plan-token baseline.
No host file, account, Tailscale policy, recovery bundle, credential, journal or
historical evidence was removed by either provider phase.

Post-provider source alignment commit
`375b3aed7c546e49877e1112dc68ac1e54d199c0` passed a 46-task check-mode preview.
The separately approved normal play then passed 59 tasks with two bounded changed
tasks: it retained and locked both dedicated accounts with `/usr/sbin/nologin`, and
removed exactly seven snippet/helper/transport/sudo files. It preserved both homes,
empty `.ssh` directories, five diagnostic entries, the exact capability record,
VM100 and both retained plan-token ACLs. The shared operation owner was released.
No Tailscale policy was changed by the host phase.

Source policy commit `f114010d` removed only the Proxmox-side `ansible-deploy` and
`qualification-apply` SSH users while retaining Docker-host `ansible-deploy`,
`proxmox` and `firewall-apply`. The separately authorized saved full-policy plan had
SHA-256 `01b8243709d10090e9374aa96aafbdf4257dc34c262e30b5ffa84c84450962e7`
and authorization SHA-256
`f9fc43bd3c7171681f18c51b27a259220505f771a2b2251d922ae4eecf515c47`.
Its sole action updated `tailscale_acl.policy[0]`; its four semantic differences were
the two Proxmox SSH user lists and matching accept/deny test lists. A protected read
immediately before apply matched both the planned-before policy and original ETag.
The post-apply policy matched planned-after SHA-256
`a2f51c28f1f59c4ac9339cdbf27ae7ab6c370afafb5bec13cd628d58a86eed6e`,
the ETag changed, remote state retained exactly the native ACL owner and a fresh
provider plan returned zero changes.

## Historical ownership and retained capability

The ownership details below record the exact pre-retirement boundary used to admit
the two provider plans. The live VM, disks and images described in the first two
subsections are now absent; their states, plans, receipts and journals remain.

### Debian lifecycle was the only live VM9900 generation

Before the reviewed destroy, VM9900 was stopped, unlocked, unprotected and not
configured for boot. Its identity was:

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

The live identity matched the four resources in
`.local/qualification-route/clean-first-boot-foundation-final/state.tfstate`:
the Debian image, VM, firewall options and firewall rules. Immediately before apply,
that protected state was mode 0600, serial 5, SHA-256
`87ca813d8a68913208f2223ef9d6446fbd7751c939571e825c05ad1b1dea511b`.
Its backup remains untouched; serial 6 now records the reviewed empty state.

The admitted stopped predecessor was
`cd6a77371f93fa19699af14e7f8c46454999167a118c8f77597f5850155927a8.receipt.json`,
an `interrupted-restart-stop` receipt bound to the serial-5 state. The preparatory
controller change admitted only that exact receipt shape under a fresh stable
admission; the guest was not restarted to manufacture replacement evidence.

### Restic owned no live VM or disk

The Restic cloud-init snippet is absent. No Restic VM disk serial or LVM/ZFS volume
exists. Before apply, the historical Restic state at
`.reconcile/restic-recovery-vm/09d091e5c9f44eafaf5a8b89576c9929e1fa5644/tofu.tfstate`
was mode 0600, serial 1, SHA-256
`6fa9556295404743504e60566cdb9dca7ddd7796ed415844ba1734eec40ea88d`.
It owned exactly one indexed resource,
`proxmox_download_file.recovery_image[0]`, whose live object was
`local:import/home-lab-restic-recovery-debian-20260810-2566.qcow2`. The next state
generation is empty. The journal remains unchanged at `create-replanning` with the
`legacy-local-state-adopted` checkpoint.

The Restic and Debian qualification import images were root-owned single-link
mode-0644 files and byte-identical: 436,404,224 bytes with SHA-256
`d4e6f5d1e9f571c198a65b45ab1adae6c5734607614e72f9661d84ce5881e5fc`.
Both are now absent. They were downloadable Debian base images, not restored
application data, recovery bundles or proof of independent recovery custody.

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

### Host forward capabilities are retired

The dedicated accounts remain as identity tombstones rather than being deleted:

- `qualification-apply` remains UID/GID 1900 with its home and empty `.ssh`
  directory, but is password-locked with `/usr/sbin/nologin`;
- Proxmox-side `ansible-deploy` remains UID 996/GID 994 with its home and empty
  `.ssh` directory, but is password-locked with `/usr/sbin/nologin`.

The Debian snippet, qualification helper/transport/sudo rule, Restic transport,
Proxmox `ansible-deploy` transport and sudo rule are absent. The `/vms/9900` ACL is
absent while root and `/vms/100` plan-token bindings remain exact.

Five diagnostic entries and the committed capability record under
`/var/lib/home-lab/restic-recovery-capability/240db6d859e21f633e3cbe9bed93414c8ebeda58a9717d70d02566744776d4b5`
remain. Its state SHA-256 is
`708af9c013eea53a8158df668d75261037f05a5f95a3718811029494ace269dc`.
The shared operation owner was released. Tailscale grants naming the two inert
accounts remain until the separate full-policy change; they no longer have a usable
host account route.

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

1. **Completed — prepare retirement source without deleting current callers.** The
   narrow Debian interrupted-stop admission, image-only Restic state controller,
   exact post-provider host retirement play and retained-owner recovery play were
   pushed before planning. The corrected image inspector accepts only the indexed
   recovery-image delete address.
2. **Completed — destroy the Debian-owned live generation.** The inspected saved
   OpenTofu plan contained exactly the four Debian state addresses. Fresh VM9900,
   VM100, lock and state checks preceded apply. The plan removed VM9900, its two LVs,
   VM firewall resources and the Debian qualification import image without addressing
   VM100 or the Restic import image.
3. **Completed — verify the hypervisor boundary.** VM9900, its `vm-9900-*` LVM/ZFS
   objects, firewall file and Debian image are absent; VM100 is unchanged and the
   Debian state is empty. PVE removed `/vms/9900` with the VM, so the old three-ACL
   plan-token expectation correctly failed closed until source was narrowed.
4. **Completed — destroy the Restic image through its owning state.** The separate
   saved plan against the exact `09d091e5...` state contained one indexed image
   delete and no VM, disk, snippet, ACL or other image action. After separate
   approval, apply removed the exact import path and emptied the state. The previous
   generation and unchanged journal remain preserved; `tofu state rm` was not used.
5. **Completed — retire host access after provider cleanup.** The Debian snippet,
   qualification sudo/helper/transport, Proxmox-side `ansible-deploy` route and sudo
   rule, and the Restic transport were removed. Both accounts remain locked and inert;
   their homes were preserved. `/vms/9900` was already absent while root and
   `/vms/100` plan-token access remained exact. Diagnostics, capability evidence,
   before-images, local snippet-storage support, the firewall watchdog, native
   `proxmox` access and VM100 remained unchanged.
6. **Completed — narrow Tailscale policy separately.** A fresh protected read and
   exact one-update saved plan removed `qualification-apply` and the Proxmox-side
   `ansible-deploy` from live SSH grants/tests while preserving Docker-host
   `ansible-deploy`, `proxmox` and `firewall-apply`. Planned-before and pre-apply live
   body/ETag matched; planned-after and post-apply live policy matched.
7. **Completed — retire source only after live closure.** Both VM9900 Tofu roots,
   controllers, plan inspectors, fixtures, installed-capability setup/retirement
   source and dedicated tests are removed in commit
   `5b0a1f040abf50e9c5b078e0d4cadb701c54804a`. The disposable `qualification-canary`
   route and its retained-lock recovery are removed without changing the production
   lifecycle operations. Contract and protected-access expectations now omit the
   retired Proxmox route. Historical evidence schemas and every ignored `.local`,
   `.reconcile` and `.terraform` artifact remain.
8. **Completed — final retained-root verification.** Native Proxmox observation
   passed after the policy update. Fresh provider-backed plans for Tailscale,
   retained Proxmox, AWS foundation, Omada and Authentik all returned zero changes
   from clean pushed source. Focused tests, contract/policy checks, source parsing,
   Markdown links, formatting, Ansible syntax checks, generic Restic fixtures and
   protected quiet Compose validation passed without printing resolved configuration.

## Validation and retained evidence

Source safety tests for the Debian transition, Restic image controller and
host-capability role passed, including hostile extra-resource/update plans, malformed
interrupted-stop receipts, changed image identities, the exact indexed Restic state
instance, evidence-preservation assertions and exact retained-owner recovery wiring.
Existing Debian qualification and Restic VM safety tests also passed.

Both applied saved plans were independently rendered and digest-compared to their
protected JSON before approval. Post-apply native reads confirmed VM9900, its disks,
firewall and both images absent; VM100 remained running and protected. The Debian and
Restic states contain no resources. The Restic journal, before-state, all plans,
receipts, diagnostics and capability evidence remain. The expected native observation
failure after Debian apply was limited to its stale three-ACL plan-token declaration;
PVE had removed `/vms/9900` with the VM. Current source narrows that declaration to
the exact two retained plan-token bindings before any host-capability mutation. The
post-provider host-retirement check-mode preview then passed 46 tasks with two
explicit preview-only changes, no failures and no live mutation. After separate
approval, the normal play passed 59 tasks with two bounded changed tasks. A final
read-only native observation passed 20 tasks with `changed=0`; a ten-task exact host
postcondition play confirmed both accounts locked/inert, seven files absent, homes
and evidence retained, and the operation owner released.

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
