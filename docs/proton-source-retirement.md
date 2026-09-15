# Proton incident source retirement

## Scope and result

The initial source-only pass in `fa7214f` used baseline `c4e7371`. This follow-up
starts from `fa7214f` and includes operator-authorized read-only local and live-host
inspection on **September 15, 2026**, beginning at **21:42 UTC**. It retires the
completed password-reset/authentication lane, quota diagnostic and one-off staged
qualification supervisors. VM recovery remains: some exact lineages are completed
or superseded, but others remain interrupted/unknown and installed consumers exist.

No live mutation, credential change, Proton request, repository operation, recovery
execution, provider initialization/plan, installed-file/resource deletion, commit
or push was performed. All evidence, local journals/manifests, locks, bundles,
credentials and state remain intact. Historical source is available in Git, not
an instruction to replay old writers. No new cleanup framework was introduced.

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
repository health. The installed `/var/lib/restic-proton/migrate-proton-restic-v2`
remains UID/GID 60000, mode 0700, SHA-256
`b0ea9aeb571c0f5f87df68f947ff3e692b290eaf5ded8737aef0c6d0053fbca9`.
It was not executed or deleted. The incident receipt's `canonical_creation=copied`,
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
  An old `cleanup-damaged-proton-restic-v1` bytecode cache also remains installed;
  its presence was recorded, not treated as an active caller or deleted.

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

The same **39** local `.reconcile/restic-recovery-vm/*/journal.json` files remain:

| Label | Count | Classification |
| --- | ---: | --- |
| `destroy-applied` | 7 | Recorded destruction completed for these owners; not seven successful restores. |
| `run-disk-prepared` | 10 | Interrupted historical runs with exact later prior-journal adoption links; superseded disk lineage, not retroactive `run-complete`. |
| `new` | 5 | `3070f90b`, `7162e6d0`, `7ad128e4`, `a69e697c`, `e6702439`: no recorded progress; unknown beyond the journal. |
| `create-planned` | 4 | `2014ab99`, `605fd090`, `67f898b9`, `edf1b64e`: nonterminal plan; expiry is not closure. |
| `create-replanning` | 4 | `09d091e5`, `1a2a555a`, `40e45e08`, `c3692087`: nonterminal; no complete predecessor/cleanup proof established here. |
| `create-applying` | 2 | `01f52f18`, `4b81eaa1`: interrupted/unknown outcome; do not retry against today's VM9900. |
| `create-applied` | 4 | `7430c19c`, `83151f5b`, `9f28d39e`, `d97c6f41`: create recorded, run/cleanup outcome unresolved. |
| `run-pretransfer-observed` | 3 | `29b89b29`, `b0caa543`, `cc58d83e`: interrupted/unknown transfer and cleanup outcome. |

Directory prefixes below are unique within this inventory; all full directories,
source bindings, keys and manifests remain unchanged.

For all seven terminal directories (`0e6fd718`, `3b0870dc`, `5931961f`, `72909b57`,
`cfe57952`, `e6e4a2f5`, `f91421b1`), `destroy-applied.json` owner equals the journal
and destroy manifest owner, and its `state_after_sha256` matches the retained
state file bytes. State contents and saved plans were not printed or interpreted.
Only **three** also record `plaintext-cleanup-and-evidence-complete` / `run-complete`
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
binding were not counted as transaction closure.

### Live VM/resource boundary

At **21:43 UTC**, Proxmox VM9900 was stopped and named
`home-lab-debian-lifecycle-qualification`, tagged
`debian-lifecycle;disposable;qualification`. Its boot disk is
`local-lvm:vm-9900-disk-0`, 32 GiB, serial `DEB-LIFE-ROOT-32G`; cloud-init is
`local-lvm:vm-9900-cloudinit`. Read-only LVM inventory found those two volumes;
ZFS volume inventory found no `vm-9900-*`. The current config hash was
`b77c18e41896a4986e8b89c6b4772b257db56c50a4a61e20f600b08eaf139afa`.
This is **another lane's current VM**, not an abandoned Proton restore fixture.

The Restic cloud-init snippet is absent. The lifecycle snippet remains root:root
0600, SHA-256 `a66a0d7e284a7c46cdf4e91e1096373efeaceaed867fa7aadd756981f0bb67ae`.
The VM firewall file and `/vms/9900` ACL for `root@pam!tofu-plan` /
`HomeLabTofuPlanDiskInspect` remain. No VM config lock, relevant held lock,
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
Its installed-after hashes still match sudoers, but **do not match either transport**.
The current Restic transport does match current repository source; this alone does
not establish the historical handoff for both replacements. Preserve the committed
record and before-images; do not replay its installer or rewrite receipt hashes.
Full ACL/key scope, replacement lineage and guest-disk plaintext absence remain
unverified. No VM was started, mounted, reused or removed; no guest secrets were
inspected.

## Remaining blockers and exact next gates

| Retained dependency | Evidence/approval needed |
| --- | --- |
| VM recovery runner, validator, Tofu root/locks, transport/capability and VM fixture helpers | For the 22 nonterminal journals without the ten exact disk-adoption links: bind each owner/manifest to a terminal operation or exact successor (including moved state/key/snippet identities). Establish plaintext cleanup for `/tmp/restic-recovery-transfer`, `/var/tmp/restic-recovery-input`, `/var/tmp/restic-recovery/bundle.*`, `/var/tmp/restic-fixture` and `/srv/home-lab-recovery/restic-proton-proof` on the exact historical disk/VM, or explicit owner-approved preservation/recovery disposition. The three successful run records and today's different VM cannot substitute for this. Keep `prove-restic-recovery-vm`, `test-restic-activation-fixture` and `activate-restic-staging-fixture` meanwhile. |
| Live VM9900, disks, firewall, ACL, lifecycle snippet and installed recovery transport/capability | Review lifecycle ownership and actual capability/ACL/key scope together with retained recovery consumers before proposing retirement. Bind both changed installed transports to their authorized successor installation evidence; the old capability's `committed` label does not explain the hash drift. Any guest boot/mount, recovery, provider operation, ACL/key change or exact resource/installed-file deletion needs a **separate explicit approval**. Never apply an old Proton destroy plan to the lifecycle VM. |
| Generic qualification/empty/resume recovery and immutable reset evidence | Remaining installed role/recovery consumers need an independently reviewed replacement or deliberate retirement decision before source removal. Published evidence remains a consumer input even though its writers are gone. A newly found owner/staged result needs its own transaction-specific inspection, not reuse of these closed IDs or generic lock clearing. |
| Installed obsolete v2 writer and incident bytecode cache | No source dependency remains for the v2 writer, but deletion requires explicit approval of the exact installed path/hash/metadata and a fresh caller/process check. Keep `migration-v2.json`, all incident records and locks regardless. This pass does not request or assume repository cleanup. |
| Commit/push | Review this source diff and authorize commit and, separately, push. Neither was performed. |

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

The diff is limited to twelve source/test deletions, dedicated-block removal and
retired-source assertions in `scripts/test-restic-tools.py`, and updates to this
file, `docs/operations.md` and `recovery/README.md`. No dependencies were installed.
