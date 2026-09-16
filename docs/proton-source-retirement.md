# Proton incident source retirement

## Scope and result

The initial source-only pass in `fa7214f` used baseline `c4e7371`. This follow-up
starts from `fa7214f` and includes operator-authorized read-only local and live-host
inspection on **September 15, 2026**, beginning at **21:42 UTC**. It retires the
completed password-reset/authentication lane, quota diagnostic and one-off staged
qualification supervisors. The later read-only reconciliation below, against
`42611822`, leaves **16 attempts without an exact terminal/successor binding** and
identifies six additional resource-cohort bindings. Installed consumers remain.
Resource destruction/supersession is separate from proven plaintext cleanup.

Those source passes performed no live mutation, credential change, Proton request,
repository operation, recovery execution, provider initialization/plan,
installed-file/resource deletion, commit or push. A subsequent, separately approved
[host-artifact retirement](#approved-host-artifact-retirement) from repository
baseline `9c41fd4` removed exactly two obsolete files on September 15, 2026.
All evidence, local journals/manifests, locks, bundles, credentials and state remain
intact. Historical source is available in Git, not an instruction to replay old
writers. No new cleanup framework was introduced.

## Source retired in the initial pass

| Removed source | Evidence and boundary |
| --- | --- |
| `scripts/migrate-proton-restic-v2` | Hard-bound to predecessor `d1faa9cd…`, the old first-run snapshot and `Backups/home-lab-restic-v2`. [Promotion](../infrastructure/evidence/proton-qualified-promotion.json) and [incident resolution](../infrastructure/evidence/proton-incident-resolution.json) superseded and retired damaged v2 repository `98d792c0…`. The initial pass did not establish its host journal's terminal state; the new inspection below does. |
| `prepare-proton-totp-transition.yml`, `transition-proton-totp.yml`, `finalize-proton-totp-transition.yml` under `ansible/playbooks/`; `scripts/transition-proton-totp-config` and `scripts/test-proton-totp-transition.py` | [Cutover](../infrastructure/evidence/proton-totp-cutover.json) binds [qualification](../infrastructure/evidence/proton-totp-qualification.json), transition and [bundle](../infrastructure/evidence/proton-totp-recovery-bundles.json) hashes for transaction `fde2f5f4a1ed940bb4ec9f298eca195df3493b50b6b9fa5132909aa954087da1`. It records no production lock/interruption/pending replicas and both timers active/enabled. |

The live `/var/lib/restic-proton/migration-v2.json` now independently confirms
`status=verified`, `full_read_data_check=true`, repository
`98d792c009c01e06b8b39aab5112f0392050e9c533d1882e9c0d87727884ea25`
and snapshot `e0ac47b09716b3a1632a9fce21ada5f53b82980ecce6723fa7a682b9117fc139`.
Its SHA-256 is `3213ceff96d067da22c5b243a213f39a00e7f9cce74905fc53c5d5229ac1f4a5`.
This is **completed historical migration, subsequently superseded**, not current
repository health. At that source-pass inspection, the installed
`/var/lib/restic-proton/migrate-proton-restic-v2` remained UID/GID 60000, mode 0700,
SHA-256 `b0ea9aeb571c0f5f87df68f947ff3e692b290eaf5ded8737aef0c6d0053fbca9`.
It was not executed or deleted during that pass; its separately approved removal
is recorded below. The incident receipt's `canonical_creation=copied`,
`trash=cleanup-started`, and creation failure's `receipt_committed=false` remain
immutable; none is permission to resume obsolete destructive operations.

## New transaction-specific closure evidence

All paths in the following tables are under live Debian
`/var/lib/home-lab-restic/`. SSH used the native inventory's strict existing host-key
trust and ordinary sudo, not a legacy playbook. Only selected nonsecret JSON fields,
file metadata and hashes were returned; no credentials or decrypted content were
printed. These are dated observations, not newly manufactured operational receipts.

### Password reset/authentication — completed and recovered

Transaction **`ac9d9acbe5cd6142ca2802cf6be856ff2defa77c22f63c46e59f8043bdbcf730`**
is abbreviated `A` below; substitute its full value in filenames.

| File | Recorded state | Observed SHA-256 |
| --- | --- | --- |
| `proton-auth-diagnostic-A.json` | `observed` | `b87ea466ac0e7234824d5a4bf8c59095534bd26eb38c8baaf0cce2faaf27a5ed` |
| `proton-credential-rotation-A.json` | `rotated` | `8e8f2b932ab436e0fb67eeeecbfd97253cf1ff945d21acd1465119a0d5873249` |
| `proton-password-only-transition-A.json` | `password-only` | `1e503ba7af5d08b9ed0f7c42f10417a6f442ca851eb7ceff4fa0f772ad13784c` |
| `proton-password-only-deployment-A.json` | `deployed` | `c38e84773f07cb1c39ff1cd9e4a4f71efc9901b22ef42c29d76fe09102160230` |
| `proton-beta-diagnostic-A.json` | `observed` | `3329ac4cae644b4b9604ff69bce8a6122ce624eefddcb9c061aa5c78789c816b` |
| `proton-account-reset-reconciliation-A.json` | `reconciled` | `0af6c2583e352cc71e501a640ff20dc53a9634d3ebfe86f2f94608f76ad63609` |
| `proton-post-reset-diagnostic-A.json` | `observed` | `92b6f08b04653aba031cac7012dd121c4cc316221890e8612cfa76c4c0fac44e` |
| `proton-post-reset-diagnostic-v2-A.json` | `observed` | `c8c2055fe1547fdc8e3678fb580ba6d3e54eee85f3d54c264420fb35f8eaec78` |
| `proton-post-reset-diagnostic-v3-A.json` | `observed` | `fb511d7a9960217256108a7a5914a89bca8da04e2db7b97fae1c8b39665450bb` |
| `proton-post-reset-diagnostic-v4-A.json` | `observed` | `7164a86b3c7d4c61c64ec780c192e333e2ee26407a9f39dfa38f6a5fdff6405b` |
| `proton-qualification-recovery-A.json` | `recovered`, cleanup `pass`, no recovered files | `74b9273051e0bbcc4001f0c088caee464af74895784886fb363ae0e0dceeae02` |

Every present auth/rotation/transition/deployment/beta/account-reset reference hash
matched its actual same-transaction file. Each post-reset prior-diagnostic hash
matched a retained same-transaction record. Account identity bindings agreed.
The v4 observation records `category=reachable`, `rclone_rc=3`; earlier failures
remain failures, not successful authentication. The exact v4 hash is still pinned
by the retained empty-recovery play. Recovery was published at
**2026-08-25T21:40:48Z**. These transaction-bound facts, not a newer backup or the
account-wide incident receipt, close this reset lane.

### Quota and staged qualification recovery — completed and recovered

| Transaction | Exact retained evidence |
| --- | --- |
| `3135e755304a8ebc4145c6a3644bf45298dfb4ba227cbd96ec6adf3cc46068f7` | `proton-quota-diagnostic-<transaction>.json`: `observed`, SHA-256 `bbe00e1dc27839251fd0af467f580f6eace64ea7dc34f29d300cfb2447df4c9f`. `proton-qualification-recovery-<transaction>.json`: `recovered`, cleanup `pass`, no recovered files, **2026-08-26T00:19:26Z**, SHA-256 `12f051e4b5179823ef1471a52e964534618d3b3ace488f0bcbdfc57a614f731c`. |
| `7ebac2493453a51577b0966520c85c29f05bb62b4d330b7312e3f49de198497e` | `proton-qualification-recovery-<transaction>.json`: `recovered`, cleanup `pass`, recovered files exactly `["fixture.bin"]`, **2026-08-26T00:31:30Z**, SHA-256 `64909a0b052a3fd55ba252a2f901c805bcef85afe2b94d88a0e864a8c7fd05c7`. |

All three recovery records passed the seven-field result shape, exact filename /
transaction binding, timestamp, allowed recovered-file set and protected regular
single-link root:root 0600 metadata checks. No `started` claim was found among
Proton JSON evidence. The published records are historical remote-cleanup evidence;
no new remote listing or qualification was attempted. The generic successful
`proton-qualification.json` still lacks a transaction ID and was **not** used to
close earlier owners.

### Installed consumers, staging and lock observations

- The production apply directory `/var/lib/iac-ansible-production.lock` and owner
  were absent, including a repeat observation. The transient
  `/var/lib/restic-proton/proton-qualification-result.json` was absent.
- No Proton/qualification-named staged files were found in the depth-two inventory
  of `/run`, `/tmp` and `/var/tmp`. Known evidence/helper locations were also
  inventoried: `/var/lib/home-lab-restic`, `/var/lib/restic-proton` and
  `/usr/local/libexec/home-lab`. This is a bounded known-location scan, not proof
  that no arbitrarily renamed copy exists anywhere.
- A content scan of **320 regular files** under systemd, cron, sudoers,
  `/usr/local/libexec` and `/usr/local/bin` found no references to the removed auth,
  quota, staged-supervisor or v2-migration helper names, with no read errors.
  Symlinks were skipped. No matching qualification/auth helper process was found
  by a redacted `/proc/*/cmdline` search; no Restic/rclone process or systemd job
  appeared in the sample.
- `/run/lock/home-lab-backup.lock` remains root:60000 0660. No relevant held lock
  appeared in `lslocks`; no lock was acquired, cleared or removed. These sampled
  facts do not establish an exclusive maintenance window.
- Both Restic timers remained loaded, active and enabled.
  `/usr/local/libexec/home-lab/qualify-proton-backup` remains root:60000 0750,
  SHA-256 `081416b7d0b51aec8e906abf77767bfb1eed1e8040eb9c12730ac5128c35a9e7`.
  An old `cleanup-damaged-proton-restic-v1` bytecode cache also remained installed
  during that inspection; its presence was recorded, not treated as an active
  caller. Its separately approved removal is recorded below.

## Source retired in this follow-up

| Removed files | Consumer/closure boundary |
| --- | --- |
| `scripts/diagnose-proton-auth`; `ansible/playbooks/diagnose-proton-auth.yml`, `diagnose-proton-beta.yml`, `diagnose-proton-post-reset.yml`, `rotate-proton-login-credential.yml`, `transition-proton-password-only.yml`, `reconcile-proton-account-reset.yml` | Six direct transient-execution playbook consumers all removed with their helper. The reset transaction above is recovered, no incomplete claim/owner/staged input was observed. These were incident writers, not routine authentication maintenance. |
| `ansible/playbooks/deploy-proton-password-only-artifacts.yml` | The same transaction's artifact deployment reached `deployed`. Its bootstrap/qualification helpers remain independently consumed by the backup role and recovery; only this completed forward installer is removed. |
| `scripts/diagnose-proton-quota` | No tracked runtime installer/caller. Its exact observed transaction has a published recovery record. Active runner quota checks remain. |
| `scripts/supervise-staged-proton-recovery`, `scripts/finalize-staged-proton-recovery` | No tracked runtime installer/caller; the one-off staged recovery transactions have protected published results, with no retained owner/transient executable/result found. This does not remove generic qualification recovery. |
| `scripts/test-proton-password-only-transition.py`; dedicated blocks in `scripts/test-restic-tools.py` | Test only the retired writers. Shared runner, bootstrap, qualification, empty-finalizer, resume, systemd, restore and lock-safety coverage remains. The existing retired-source assertions were extended; they do not purport to prove live closure. |

Before deletion, tracked consumer tracing covered callers, installers, bundle
builder/consumer and VM source bindings together. A read-only scan of **142 JSON
records** under `.reconcile/restic-recovery-vm` and Proton-named `.local` directories
(excluding state and plan JSON) found no four-helper name or current exact script
hash reference. The 37 top-level VM create/destroy manifests bind a source set
that excludes these incident writers. This does not validate saved plans or make
old manifests runnable against current source. No pinned hash was regenerated.
After deletion, remaining tracked references to these writers are documentation
and retired-source assertions only. A final tracked-file scan found no reference
to any of the twelve deleted files' exact baseline hashes. Protected runtime,
role, contract, service, provider and evidence paths remain byte-identical to HEAD.

## Approved host-artifact retirement

On **September 15, 2026, 22:08–22:11 UTC**, operator-authorized read-only inspection
on Debian `docker-host` established the following exact candidates. The operator
then explicitly approved removal of **only these two files**, conditional on
unchanged identities/hashes and fresh dependency checks.

| Removed exact path | Pre-removal metadata | SHA-256 |
| --- | --- | --- |
| `/var/lib/restic-proton/migrate-proton-restic-v2` | Single-link regular file; `restic-proton:restic-proton` (60000:60000), 0700, 10,836 bytes; device 2049, inode 137415 | `b0ea9aeb571c0f5f87df68f947ff3e692b290eaf5ded8737aef0c6d0053fbca9` |
| `/usr/local/libexec/home-lab/__pycache__/cleanup-damaged-proton-restic-v1cpython-313.pyc` | Single-link regular file; root:root, 0640, 35,895 bytes; device 2049, inode 137630 | `52694eb34cba63c543f279103c0fac0bf7f5a0002a8052e3ed8540fa7c6c038e` |

The writer matched historical Git source at `fa7214f^:scripts/migrate-proton-restic-v2`.
The cache contained its expected retired source path; that executable was already
absent. Neither artifact was executed, imported or replayed. All ancestors were
non-symlink directories with the observed owners/modes. The writer's parent remains
60000:60000 0700; the shared cache directory remains root:root 0755.

### Fresh dependency checks and exact removal

- All **632 tracked files** were scanned for both helper names and candidate hashes.
  References were confined to this audit, retirement tests and the legacy role's
  existing removal task for the old cleanup executable. No tracked installer,
  active caller or recovery/bundle consumer requires either removed artifact.
  The role was not invoked or changed.
- Immediately before deletion, **581 regular host files**, with **152 symlink
  entries** inspected and regular targets deduplicated, had no caller references
  or aliases to either candidate. Scope was systemd configuration/generators,
  cron/spool entries, sudoers, `/usr/local/libexec`, `/usr/local/bin` and the known
  crontab/anacrontab/rc.local files. No read errors occurred. One unrelated dangling
  generated `systemd-networkd.service` link remained untouched. The initial size
  exclusions for rclone and SOPS were subsequently scanned; the final scan had no
  size exclusions. **45 loaded service definitions** also had no matching execution
  or source-path references.
- The final `/proc` sample inspected **735 processes**: no helper-name matches,
  Restic/rclone/qualification or UID 60000 processes, candidate open descriptors,
  mapped inodes or executable/cwd inode users were found. No systemd job or relevant
  held lock was observed; production apply lock and transient qualification result
  were absent. These bounded checks are not an exclusive maintenance window or
  proof against arbitrary renamed copies or concurrent privileged writers.
- At **22:14:48 UTC**, after rechecking hashes, device/inode, owner/group, mode,
  link count, size and modification/change timestamps, a one-off Python stdin
  command unlinked only the two approved basenames through open non-symlink parent
  directory descriptors. Both candidates were validated before the first unlink;
  each binding was rechecked immediately before its unlink. No recursive removal,
  directory cleanup, new helper installation, lock acquisition or service action
  occurred. The command used native strict-trust SSH/sudo, not an Ansible playbook.

### Verified preservation and remaining boundaries

Immediate verification passed, followed by a separate SSH check at **22:15:16 UTC**:

- Both exact paths are absent. Parent directory identities/ownership/modes remain;
  their entry sets differ by only the approved basename in each. The neighboring
  `restic-backupcpython-313.pyc` and `retire-offen-localcpython-313.pyc` remain.
- **21 retained files** kept identical metadata and hashes across removal: the five
  installed active Restic helpers, both neighboring caches, `migration-v2.json`,
  backup lock, runtime policy, two input files and all nine unit definitions.
- **20 top-level JSON records** under `/var/lib/home-lab-restic` and
  `/var/lib/restic-proton` retained their path/owner/group/mode/link-count/size/hash
  inventory digest `6971991bf2dfc8e748f126ea776b2a845674644a23e38998a99c81b5c89ae78e`.
  `migration-v2.json` remains 60000:60000 0600 with SHA-256
  `3213ceff96d067da22c5b243a213f39a00e7f9cce74905fc53c5d5229ac1f4a5` and its historical
  `verified` / `full_read_data_check=true` result. No receipt or journal was rewritten.
- All nine units' observed states, execution timestamps and timer scheduling
  properties were identical before/after. Both timers remain active/enabled;
  recovery remains enabled. The historical Proton maintenance exit status remains
  1. This retirement did not run or qualify backup, maintenance or recovery.
- `/run/lock/home-lab-backup.lock` retains its inode and root:60000 0660 metadata;
  the final held-lock sample found no relevant holder. No lock was cleared.

Only the two approved unlinks changed host artifacts; journals, evidence, locks,
credentials, repositories and active backup/recovery tools were preserved.
No Proton request, repository operation, secret decryption, credential change,
VM9900/Proxmox access, disk/ACL/transport change or qualification-infrastructure
operation was performed. The VM and generic qualification blockers below are
unchanged. No commit or push was authorized or performed.

## Retained qualification and backup dependencies

Keep `qualify-proton-backup`, its role installer, `qualify-proton-backup.yml`,
`recover-proton-qualification.yml`, `resume-proton-qualification.yml` and
`finalize-proton-empty-recovery`, with their tests and exact pins unchanged.
`recover-proton-qualification.yml` consumes the immutable reset/authentication
records above, not their removed writers. Generic qualification recovery remains
available for a separately reviewed exact retained owner; historical inert/Offen/
policy guards are not waived and these plays are not offered as currently runnable
routine maintenance.

The runner, credential bootstrap, bundle builder/consumer, `restore-critical-backup`,
active password-only/TOTP support, tool pins, backup scope, policy, repository
identities, unit definitions and schedule activation receipts are unchanged.
Removing incident writers is not removing authentication support or proving backup
integrity. See [operations](operations.md) and [recovery](../recovery/README.md).

## VM recovery — partial lineage closure, source retained

The **September 15, 2026, 22:19–22:27 UTC** read-only reconciliation used local
records and native SSH/sudo inventory on Proxmox, against repository `42611822`.
No guest was accessed, booted or mounted; no decryption, provider/recovery execution,
access change or deletion occurred. Subsequent documentation work used those
observations and safe local inspection only; it performed no further host operations.
These are dated findings, not new operational receipts or permanent absence proofs.

The same **39** local `.reconcile/restic-recovery-vm/*/journal.json` files remain.
Their immutable labels are: seven `destroy-applied`, ten `run-disk-prepared`, five
`new`, four `create-planned`, four `create-replanning`, two `create-applying`, four
`create-applied` and three `run-pretransfer-observed`. The evidence-based
classification below does not rewrite those labels or certify failed-run cleanup.

Directory prefixes below are unique within this inventory; all full directories,
source bindings, keys and manifests remain unchanged.

For all seven terminal directories (`0e6fd718`, `3b0870dc`, `5931961f`, `72909b57`,
`cfe57952`, `e6e4a2f5`, `f91421b1`), `destroy-applied.json` owner equals the journal
and destroy manifest owner, and its `state_after_sha256` matches the retained
state file bytes. The later inspection also found those seven states empty.
Only nonsecret identity/equality summaries were returned, never raw state or saved
plans. Only **three** also record `plaintext-cleanup-and-evidence-complete` / `run-complete`
and have `run-evidence.json` with `state=restored-verified`:

| Directory | `run-evidence.json` SHA-256 |
| --- | --- |
| `5931961f561de11a167858960b22555579b770c6` | `a3952f60f121fac2450a583571eed92bf7c9b8857d87d2e09f6b646c55927bf6` |
| `72909b5723ae8d586f5b3db428b7d73f6c610e97` | `ad308dc8d9fd05fd014a0c97189c78b77446c0972a3814cb036cc78f0d4d8b5c` |
| `e6e4a2f5fd0613e703d36c0a53c95f80c741608c` | `82537efde96231435da520e0f0dc472f1808e0c24dad0fef8b7b659c6c2ba1cc` |

Ten `prior-disk-authorization.json` records match their predecessor's **actual
journal SHA-256**, establishing these directed adoption chains:

```text
3a15f009 → e177528a → 22b42d2d → 2a971fa2 → 021f8326 → 1371b101
         → bbc93467 → dc0868de → 5931961f (run-complete, destroy-applied)
53b6fd50 → 0e6fd718 (destroy-applied, no run-complete)
4135a92b → e6e4a2f5 (run-complete, destroy-applied)
```

In particular, `1371b101…` remains `run-disk-prepared`; its journal SHA-256
`0360257c74bba6255e3d6f079bec6fd936d47bacf71c8c28c6cf15390fa932e9`
is explicitly referenced by `bbc93467…`, rather than inferred from a later success.
These links concern disk authorization/state adoption, not proof that each failed
attempt cleaned every plaintext/key path. `4b81eaa15abf71f77953b0c754070d75804a978e`
remains `create-applying`, journal SHA-256
`a5af4cc60fe634f5cc33a5c93c390e6447e5df85ed7ef046c5bf19fdc191050d`,
without a matched prior-disk link or run evidence. Its missing local state is not
proof of nonexecution. Generic adoption checkpoints without an exact predecessor
binding were not counted as transaction closure. All ten links also match the
predecessor create-marker state hash, successor manifest state-before hash and
expected `RESTIC-RECOVERY-128G` serial hash.

### Six additional resource-cohort bindings

| Previously unresolved attempts | Destroy-completed successor | Shared state SHA-256 |
| --- | --- | --- |
| `83151f5b`, `d97c6f41`, `b0caa543` | `f91421b1` | `e51c6b1258bd5de511a1fa7f17509f92bbd423d2860abbaceee275371ec97442` |
| `cc58d83e`, `29b89b29` | `3b0870dc` | `782a07d7d422a35b9ec55f950f9a3a6fc71489f067105fe9b9e5a16505f1b0b5` |
| `9f28d39e` | `53b6fd50`, then `0e6fd718` | `c4089ac5a2a426626d429b6e745078732efe7004fa04f958c3a8d779f7da6273` |

For each cohort, `create-applied.json` state-after equals successor
`create-manifest.json` state-before; journal/manifest/marker owners agree, successor
journals record adoption, and matching user/host public keys survive in the terminal
successor directory. These are **resource-cohort bindings**, not new exact
predecessor-journal receipts. Repeated identical state hashes do not uniquely identify
every immediate handoff. None proves the interrupted attempts' plaintext cleanup.

`f91421b1` preserves both predecessor public-key hashes, but its manifest cloud-init
hash differs from the predecessors and retained cloud-init bytes. Historical source
added privileged-root/sudo configuration. Preserve this distinction; do not rewrite
its manifest to assert snippet equality or successful guest configuration.

The resulting resource classification is **3 restore/cleanup/destroy completed,
4 destruction-only, 16 superseded, 16 unresolved**. Destruction-only owners are
`0e6fd718`, `3b0870dc`, `cfe57952`, `f91421b1`. The 16 superseded owners are the ten
prior-journal-linked attempts plus these six cohort-bound attempts; their journals
remain nonterminal. Only three attempts have positive recorded cleanup evidence.

### Sixteen attempts still needing an owner disposition

| Attempts | Evidence and remaining uncertainty |
| --- | --- |
| `3070f90b`, `7162e6d0`, `7ad128e4` | `new`, but saved-plan artifacts exist. No terminal owner binding; not proof of nonexecution. |
| `a69e697c`, `e6702439` | `new`, retained key material, no recorded progress. |
| `2014ab99`, `605fd090`, `67f898b9`, `edf1b64e` | Earlier apply checkpoints and retained replans; current states empty, no terminal receipt. |
| `09d091e5` | Legacy state adoption recorded; state still owns one download matching live `/var/lib/vz/import/home-lab-restic-recovery-debian-20260810-2566.qcow2`. The recovery HCL also references that image. |
| `c3692087`, `1a2a555a`, `40e45e08` | Adoption checkpoints lack exact predecessor-journal bindings. Their historical implementation moved state only, not keys; individual keys remain. |
| `01f52f18` | `create-applying`; no terminal receipt or sufficiently exact successor binding found. |
| `4b81eaa1` | `create-applying`; PVE records successful VM9900 creation at August 26, 10:03:37 UTC, contemporaneous with its apply checkpoint. Missing local state does not prove nonexecution; exact owner-chain closure remains missing. |
| `7430c19c` | Create recorded, bounded-destroy artifacts and empty serial-2 state retained, but no destroy receipt. PVE records destruction at August 26, 10:24:31 UTC, including cloud-init and both disks. This corroborates removal, not owner-bound cleanup. |

The plausible early sequence from `4b81eaa1` through the adoption attempts to
`7430c19c` remains a reconstruction, not a certified chain. The relevant PVE task is
`UPID:proxmox:00176CA2:01E3E03E:6A8EBEDF:qmdestroy:9900:root@pam!tofu-apply:`;
its retained log SHA-256 is
`eacf63d234c13cfb4d8d0ab81f2b162d7c7c74bc1fb5d95c7176b56d5be25e28`.
VMID, timestamps and reused disk names alone do not identify a transaction owner.

### Plaintext cleanup is a separate finding

Only the three `run-complete` records above positively record cleanup. A cleanup
function or `finally` block is not evidence that it completed on a failed run.
`29b89b29` reached `run-disk-prepared` before a later retry ended at
`run-pretransfer-observed`; its final label is not a transfer boundary.

Historical source, checked against the selected manifests' runner hashes, used
`/run/restic-recovery-input`, `/run/restic-recovery/bundle.*` and `/run/restic-fixture`
before moving to `/var/tmp/restic-recovery-input`, `/var/tmp/restic-recovery/bundle.*`
and `/var/tmp/restic-fixture`. Both generations also used
`/tmp/restic-recovery-transfer` and `/srv/home-lab-recovery/restic-proton-proof`.
Any disposition must cover the applicable historical paths, not only current code.
Their absence on the PVE host says nothing about former guest contents.
Logical-volume removal is not secure erasure or proof about other copies/snapshots.

Local VM directories retain 23 SSH private keys, 22 host private keys, four
cloud-init files, 13 state files and eight state backups, all observed non-symlink
mode 0600. Cloud-init contains host private keys and is sensitive. The ten exact
disk links and six cohorts do not retroactively prove cleanup of every predecessor's
keys, guest workspace or copied input. Where further proof is unavailable, use the
preferred administrative disposition below, not a synthetic cleanup receipt.

### Live VM/resource boundary

At **21:43 UTC**, reconfirmed during **22:19–22:27 UTC**, Proxmox VM9900 was stopped and named
`home-lab-debian-lifecycle-qualification`, tagged
`debian-lifecycle;disposable;qualification`. Its boot disk is
`local-lvm:vm-9900-disk-0`, 32 GiB, serial `DEB-LIFE-ROOT-32G`; cloud-init is
`local-lvm:vm-9900-cloudinit`. LVM including hidden-volume inventory found only those
two VM9900 volumes; ZFS volume/snapshot inventory found no `vm-9900-*`.
Boot LV UUID is `OKJ0NY-Uiqm-CkgE-jRbL-FqH2-GzoE-uExP6U`; cloud-init LV UUID is
`teapke-MKJb-JJWB-fc48-LtE9-yc23-KugY3b`. The current config hash was
`b77c18e41896a4986e8b89c6b4772b257db56c50a4a61e20f600b08eaf139afa`.
This is **another lane's current VM**, not an abandoned Proton restore fixture.

Current MAC `BC:24:11:61:ED:75` matches the VM in
`.local/qualification-route/clean-first-boot-foundation-final/state.tfstate`, SHA-256
`87ca813d8a68913208f2223ef9d6446fbd7751c939571e825c05ad1b1dea511b`.
In that same directory, `cd6a77371f93fa19699af14e7f8c46454999167a118c8f77597f5850155927a8.receipt.json`
is the interrupted-restart recovery-stop receipt and binds those state bytes.
`09f7429ea9d5a0bf9d059470c8eb16fe10faf56b81e87fcfbaa942081f9c2976.invocation-failure.json`
records `incorrect-snippet-receipt-path`, the same state hash, stopped VM and no
automatic retry. It requires fresh observation and separately authorized new planning.

The retained `03ce83efae9185e07da2047ff7f6075cbe969dd4ce88710e957135068ebade4e.json`
reports a verified clean-first-boot observation for this lifecycle generation on
September 5 at 18:13:36 UTC. Its foundation/start references and canonical observation
hash match retained records; observed installed helper/transport hashes match its
producer fields. This historical scoped receipt does not resolve the later restart,
requalify today's guest, or prove Restic restore, cold rebuild or production activation.

`/var/lib/vz/snippets/home-lab-restic-recovery-cloud-init.yaml` is absent.
`/var/lib/vz/snippets/home-lab-debian-lifecycle-qualification.yaml` remains root:root
0600, SHA-256 `a66a0d7e284a7c46cdf4e91e1096373efeaceaed867fa7aadd756981f0bb67ae`.
The VM firewall file remains, SHA-256
`2ca450cc2b81a9b5108d68a6f6bee6c134fdae90ed6f91bb4423bc107c588644`, with DROP
policies, bounded controller SSH, DHCP and private/CGNAT egress denies before public
egress. This is configuration observation, not a new isolation test.
The `/vms/9900` ACL for `root@pam!tofu-plan` / `HomeLabTofuPlanDiskInspect` remains;
that role grants **VM.Config.Disk** as well as VM.Audit. Local
`clean-first-boot-foundation-final/acl-apply-result.json` binds plan `716ffefd…`
in `.local/proxmox-vm9900-plan-acl/`. Shared root-level plan/apply token ACLs remain;
both tokens have privilege separation and no expiry, not Proton-only scope.

`qualification-apply` remains UID/GID 1900 with fixed
`debian-qualification-snippet-transport` shell and its sudo capability. Its `.ssh`
directory was empty; conventional sshd public-key authentication was disabled.
The lifecycle snippet key matches `.local/qualification-route/guest-key.pub`,
fingerprint `SHA256:Di2jPsrFj81QWSSdVA4PFHXTW+wqXxO8ev03JgmmRNU`.
The retained `c7936fb2…host-key-receipt.json` in the current lifecycle directory
binds fingerprint `SHA256:B72eI8kFMiU0DUKHjMtx+lWaQ4AWvHGtE5HU+nRkk2Q` to its
historical stopped state and clean-boot receipt, not a fresh guest key observation.
Local `guest-key` and `pve-key` remain protected 0600 files; a retained key alone
does not prove current authorization or independent recovery custody.

No VM config lock, relevant held lock,
production/reconciliation apply lock, firewall transaction marker or systemd job
was observed. The local `transaction.lock` remains mode 0600; `lsof -t` found no
open holder (exit 1), not a reservation or deletion authorization.

`/usr/local/libexec/home-lab/proxmox-restic-recovery-transport` remains installed,
SHA-256 `186d6adf91649182d063165e50a4ab961968876c8a65254be53b6258bd2e95e1`,
with actual callers in `proxmox-ansible-deploy-transport` and
`/etc/sudoers.d/ansible-deploy`. The capability directory
`/var/lib/home-lab/restic-recovery-capability/240db6d859e21f633e3cbe9bed93414c8ebeda58a9717d70d02566744776d4b5`
and transport lock remain. Its protected root:root 0600 `state.json`, SHA-256
`708af9c013eea53a8158df668d75261037f05a5f95a3718811029494ace269dc`,
records `status=committed` with plan/receipt-plan equal to that directory ID.
Its installed-after hashes still match sudoers, but differ from both current
transports. **The later inspection explains this succession**, as follows.

### Explained transport succession

The exact successor plan is
`.local/proxmox-deploy-upgrade/44faa63889fd6dabd381087d77252e2750f1e0dc7636f45053dc105e3fbf8944.json`;
its bytes hash to its filename. Authorization
`authorized-35d626c892167c21ff7be3e2dd8aaef90b3e3be6831c73a5470f61bbe1dca761.json`
in that directory binds the plan and commit `53b6fd50…`, September 1, 20:36:52 UTC.
The live `/var/lib/home-lab/deploy-upgrade/<full-plan-hash>/receipt.json` is committed,
SHA-256 `597e74231ca232b278bb16582b9f69a9c58a6cdc49eacf2e92f7e38a34155689`,
and records both transports and the observer as changed.

| Transport basename under `/usr/local/libexec/home-lab/` | Original capability after / successor before SHA-256 | Successor after / current installed SHA-256 |
| --- | --- | --- |
| `proxmox-ansible-deploy-transport` | `3ea5fc22784626c4d2e981c892be6a58470c8ce413b48206062c9c83429e4809` | `78ea4536a580dce08ffed3edd43a19b77c12407a9ed8d35c2f1bf17a808e8a39` |
| `proxmox-restic-recovery-transport` | `2cf14845477402bd7f6bc8627399640b4d01110a0f6cee5bda7b89ccccef2fd5` | `186d6adf91649182d063165e50a4ab961968876c8a65254be53b6258bd2e95e1` |

The successor's live `rollback.json` bytes hash to
`0588d3d3ae84775d97c0d9fac5b41e0b19b1e4e1291ce3d001c9942ca4775a96`;
its stored before-images independently hash to both predecessor values above.
This closes the previously unexplained replacement lineage, not the consumers'
retirement gate. Do not replay the original installer or rewrite its receipt hashes.
Guest-disk plaintext absence remains unverified.

## Historical material — disposition choices pending approval

Preserve current runtime/recovery dependencies and active qualification state.
**Leave VM9900 unchanged; continuation or retirement is a separate task.** No active
recovery capability is being retired. There is no retention schedule or new framework.

For inactive historical attempts with evidence gaps, the operator prefers
**historical outcome unknown; attempt abandoned; no replay** over further open-ended
investigation. This is an administrative disposition, not a change to journals or
receipts, proof of plaintext cleanup, or release of files with surviving consumers.
Keep known destruction/supersession facts alongside the unknown cleanup outcome.
`09d091e5` and its live import-image dependency are excluded and require a separate
resource-ownership decision; neither its state nor that image is a disposal candidate.

### Small local candidate list

All paths below are relative to **`.reconcile/restic-recovery-vm/`**; filenames are
literal, not globs. Sizes are regular-file logical bytes, not allocated/reclaimable
space. Local inspection found all ten files single-link, non-symlink, mode 0600.
No sensitive contents were printed or decrypted, and no further host inspection ran.

| ID | Exact relative paths | Total bytes | Sensitivity / remaining consumer | Recommended disposition, pending approval |
| --- | --- | ---: | --- | --- |
| A | `a69e697cac4118adaa4956156d2d8b03f8a68a97/ssh-key`<br>`a69e697cac4118adaa4956156d2d8b03f8a68a97/ssh-key.pub` | 524 | Private SSH key plus public key. Only the historical attempt route in `prove-restic-recovery-vm` was identified; no recorded progress. External key reuse is unverified. | Encrypted archive, not direct deletion. Abandoning replay does not revoke any deployed copy. |
| B | `e6702439a5682df14d73e197078c6a3a160b9473/ssh-key`<br>`e6702439a5682df14d73e197078c6a3a160b9473/ssh-key.pub`<br>`e6702439a5682df14d73e197078c6a3a160b9473/ssh-host-key`<br>`e6702439a5682df14d73e197078c6a3a160b9473/ssh-host-key.pub` | 1,053 | Private user/host keys plus public keys. Same historical consumer/unknown reuse boundary as A; no recorded progress. | Encrypted archive, not direct deletion. |
| C1 | `1a2a555a1f54c2bad486833ce52354a7c57f5e26/diagnostic.tfplan` | 7,114 | Sensitive saved diagnostic plan. No tracked caller or retained journal/manifest reference found; historical diagnostic use only. | Delete this file only if loss of its diagnostic evidence is accepted; keep the distinct `create.tfplan`, journal, keys and state-related records. |
| C2 | `40e45e0853d6a0e63e24915a6a43b864240b467c/diag.tfplan` | 8,515 | Sensitive saved diagnostic plan. Same reference boundary as C1; equal size does not make it a duplicate of `create.tfplan`. | Delete this file only, with the same diagnostic-evidence acceptance as C1. |
| D | `7430c19cd23c47d6af42348f49aa56669f82fe7f/bounded-destroy.tfplan`<br>`7430c19cd23c47d6af42348f49aa56669f82fe7f/bounded-destroy-plan.json` | 28,710 | Sensitive saved plan/JSON; historical destruction reconstruction remains its purpose. No tracked caller or retained journal/manifest reference found, but no owner-bound destroy receipt exists. | Encrypted archive, not direct deletion or replay. Keep the journal, create evidence and both state generations untouched. |

**Total: 10 files, 45,916 bytes** — archive candidates A/B/D: **30,287 bytes**;
direct-delete candidates C1/C2: **15,629 bytes**. This is a deliberately small
shortlist, not a claim that whole transaction directories are disposable or a
repository-wide space-reclamation estimate.

Before adding this list, the local reference scan covered 632 tracked regular files
and 93 Restic VM journal/manifest/prior-disk records; it found no candidate exact-path
or file-hash references. References added here are documentation only.
Both diagnostic plans are byte-distinct from their retained create
plans. Generic filename-based historical consumers are identified above; the scan
is not proof against arbitrary external callers or key reuse. Any eventual action
must recheck exact file identity and references; it must not acquire/clear a lock,
replay a plan or rewrite a binding to make disposal possible.
The proposed direct-delete files are bound to these observed SHA-256s:

- C1: `11d9ce358738fd16fca8acac23f041679057d4c65f9acc8caed28e28f8147f18`.
- C2: `86b6c4ec74d4bc7ae00824b27e90e892244bff478b3d7878d522e394fc766758`.

### Exclusions and next decisions

- Keep all journals, receipts, manifests, state/backups, locks, bundles, before-images
  and active credentials outside this shortlist. Terminal status alone is insufficient:
  `restic_backup` still consumes restore/Offen proofs; generic qualification recovery
  consumes the closed reset records; `proton-canonical-recovery-bundles.json` references
  `72909b57`'s run-evidence hash. Keep that exact evidence accessible. Installed transport
  callers and current lifecycle state/key consumers remain as documented above.
- Approve or reject **C1/C2 exact-file deletion**, explicitly accepting loss of those
  diagnostic plans while the attempts remain outcome-unknown and abandoned.
- For **A/B/D**, approve archive-only copying and choose the exact protected destination
  and encryption recipient. Leave originals untouched; any later removal requires
  separate approval after archive verification and consumer checks. No key rotation,
  decryption or archive creation is authorized by this document.
- Unlinking is not secure erasure on SSD/thin/COW storage or proof that backup copies
  vanished. No snapshot, shared credential or remote object-version disposal is included.
  No host operation, operational-artifact change, commit or push has been authorized.

## Validation and review provenance

The initial `fa7214f` pass's test results and independent review remain historical
in that commit. Its reviewer did not inspect hosts and did not review this follow-up.
No new independent review or delegation was requested or claimed here.

Follow-up validation is local synthetic/static testing, not recovery execution or
live integrity proof. Only the dedicated removed tests were dropped; surviving
focused tests were inspected before execution. Parent-observed outcomes:

- `python3 -B scripts/test-restic-tools.py` — passed. Remaining real subprocesses
  are local Node YAML loading and a disposable failing shell fixture; runner,
  credential and qualification effects use synthetic inputs/temporary paths.
- `python3 -B scripts/test-proton-qualification.py` — passed; rclone calls mocked,
  configuration/results confined to temporary fixtures.
- `python3 -B scripts/test-proton-transaction-boundaries.py` — passed; static
  publication-before-release and wrong-transaction refusal assertions retained.
- `python3 -B scripts/test-restic-proton-sandbox.py` — passed; unit-template checks
  only, no systemd probe or repository request.
- `PYTHONDONTWRITEBYTECODE=1 bash scripts/test-restic-recovery-bundle` — passed;
  fake tools/credentials/restore in disposable directories, including password-only,
  TOTP and interruption cleanup. No real encrypted bundle was opened.
- Python AST parsing of the changed test, existing `js-yaml` parsing of all three
  surviving Proton playbooks, 23 local Markdown paths/anchors across the three
  changed documents, and `git diff --check` — passed. No retained YAML/HCL changed;
  no Ansible playbook or provider command was invoked.
- `docker compose config --quiet` — **blocked (exit 1)** by absent interpolation
  inputs `INTERNAL_HOST_IP`, `LITELLM_MASTER_KEY`, `OPENROUTER_API_KEY`, with further
  unset-variable warnings. No decrypted environment or resolved configuration was
  printed. Validation needs the existing protected inputs through a separately
  approved secret-handling path; no dummy values or decryption were substituted.

That source follow-up diff was limited to twelve source/test deletions,
dedicated-block removal and retired-source assertions in
`scripts/test-restic-tools.py`, and updates to this file, `docs/operations.md` and
`recovery/README.md`. No dependencies were installed.

The subsequent approved host retirement changes only this file and
`docs/operations.md` in the repository; no runtime source, tests, YAML, HCL,
evidence or pins changed. Its host checks and preservation results are recorded
above. No independent review or delegation was requested or claimed.

Host-retirement local validation:

- Local Markdown path/anchor checks — **15 links across both changed documents
  passed**; `git diff --check` passed.
- `docker compose config --quiet` — **blocked (exit 1)** by missing
  `INTERNAL_HOST_IP`, `LITELLM_MASTER_KEY` and `OPENROUTER_API_KEY`, with additional
  unset-variable warnings. No secrets were decrypted, dummy inputs substituted or
  resolved Compose configuration printed.
- No helper test, YAML parse, HCL check, Ansible playbook or provider operation was
  needed for this documentation-only repository diff. No dependencies were installed.

### VM reconciliation documentation validation

The reconciliation used the earlier authorized read-only inspection; the subsequent
retention/documentation pass made **no further host connection or operation**.
Historical evidence checks found all 37 top-level VM manifests' saved-plan hashes
matching, all seven archived manifests matching journal references and all 14
hash-prefixed archived plan files matching. No receipt, state or journal was changed.

For the documentation-only diff in this file, `docs/operations.md` and
`recovery/README.md`:

- Local Markdown path/anchor checks: **28 links passed**; `git diff --check` passed.
- `docker compose config --quiet`: **blocked (exit 1)** by missing
  `INTERNAL_HOST_IP`, `LITELLM_MASTER_KEY` and `OPENROUTER_API_KEY`, with additional
  unset-variable warnings. No decryption, dummy inputs or resolved configuration.
- No helper, YAML or HCL changed; no runtime test, Ansible/provider operation,
  dependency installation, archival, deletion, commit or push was performed.
  The archive/delete choices above remain pending approval; no schedule is proposed.
