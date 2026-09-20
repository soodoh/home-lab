# Recovery readiness assessment and isolated qualification plan

## Status and authority

This is a source, retained-evidence and non-secret metadata assessment at commit
`8338de78f1014672d5d740a8e309a46d39b426d9`. It authorizes no restore, credential
decryption, backup or maintenance run, repository write, infrastructure creation,
provider operation, account or ACL change, production activation, or cleanup.
Those actions require separately reviewed approval.

The target outcome is a new, timed recovery qualification on a genuinely isolated
target with a newly admitted identity. VMID 9900 is retired and must not be reused.
No replacement VMID is selected here: a candidate must be checked against fresh
live inventory immediately before provisioning. Separate state alone is not an
isolation boundary.

## Assessment

The repository retains a strong **exact Restic snapshot to private staging** path,
but not a qualified fresh-server or application-activation path. The September 19
observation met the 24-hour recovery-point objective at that instant; it does not
qualify the ongoing objective. The assessment-only eight-hour service-recovery
criterion remains unqualified.

| Capability | Current evidence | Assessment |
|---|---|---|
| Scheduled backup configuration | The nine installed unit definitions matched source on September 14. A September 19 passive observation matched successful September 18 units to one exact games → NFS → Proton chain with zero pending entries. | Current point-in-time chain and schedule evidence; no backup was forced and no restore integrity was tested. |
| Canonical off-site repository | The canonical Proton repository was promoted after a zero-error full-data read on September 2. The September 19 observer opened the exact repository and matched its latest copied snapshot. | Present-tense read and identity proof for that snapshot, but not a repository check or full-data read. Monthly maintenance still has an unresolved historical failure. |
| Exact staging restore | `restore-critical-backup` binds repository, snapshot, copied ancestry, policy, Compose artifact and pinned binaries, restores only to an empty private staging tree, and uses `restic restore --verify`. | Retained and source-tested. Historical VM9900 execution restored 22,031 files and 6,982,221,998 bytes without starting services. |
| Independent recovery bundle | Canonical historical bundle B remains versioned in KMS-backed AWS storage. On September 19 a separately authorized live build created two distinct 114,746,920-byte ciphertexts bound to the observed September 18 chain and the independent recipient. | Current bundle creation and protected local custody passed. Bundle B remains unpublished; independent retrieval, decryption and restore remain unexecuted. |
| Recovery credentials | The bundle format carries only the Restic and dedicated Proton recovery fields, with optional TOTP, and excludes host tokens. The publication credential is SOPS-encrypted to production and independent recipients. | The live build exercised protected host SOPS decryption and reduced-environment bundle creation without exposing values. Credentials remain encrypted inside the new bundles; bundle decryption was not exercised. |
| Independent age identity | On September 19 the operator confirmed an exact plaintext identity copy on an offline USB stored securely offsite. The controller-local and home Vaultwarden copies are not independent boundaries. | Key location custody is closed. Historical GPG ciphertext is optional legacy material, not a required recovery dependency. |
| Recovery compute | The retired VM9900 harness and its provider roots, host transport and access grants are absent. | Correctly retired. There is intentionally no callable replacement provisioning path yet. |
| Application artifacts | Restic includes protected production environment data and application state. Source retains Compose definitions and pinned images; host generations and image state are retained separately. | A snapshot's artifact tag is an identity, not the artifact itself. Independent custody and reconstruction of the matching source/image generation must be proven. |
| Application activation | The contract exposes staging only. Existing activation code expects the old `backup/` archive format and must reject Restic staging. External-data services remain pending. | Blocked pending an isolated activation design and proof. A staging restore cannot qualify service RTO. |
| External/user data | Nextcloud external data and other excluded or regenerable classes are deliberately outside the application-state snapshot. | Must have separate availability checks or explicit degraded-service acceptance. |
| RPO/RTO | The lifecycle backup-age admission remains 24 hours. The former eight-hour contract value is retained here only as a recovery-assessment criterion. The September 18 source snapshot was 58,532 seconds old at the fresh pre-build observation. | The RPO passed at build admission but is not qualified as an ongoing guarantee. The assessment-only eight-hour service-recovery criterion remains unqualified. |

### Evidence limits

The important retained evidence is internally consistent. Most records are
historical; the September 19 observations are bounded point-in-time checks:

- `proton-qualified-promotion.json` records the September 2 canonical repository
  promotion and full read.
- `natural-restic-daily-2026-09-03.json` records one natural scheduled chain.
- `natural-restic-daily-2026-09-18.json` records the current tagged three-repository
  chain, zero pending entries and its observed age.
- `proton-canonical-recovery-bundles.json` records canonical bundle B publication
  and its exact ciphertext identity.
- `proton-canonical-recovery-vm.json` records a verified staging restore without
  application startup and explicitly leaves external user data pending.
- `aws-recovery-publication-credential-rotation.json` records the publication
  credential rotation and then-current object check.
- `aws-recovery-bundle-access-2026-09-19.json` records the later expected-caller,
  exact-version, KMS, ciphertext and cleanup result.
- `current-restic-recovery-bundles-2026-09-19.json` records the fresh observation,
  current metadata, two distinct local ciphertexts and post-build host cleanup.

The September 19 build establishes a bundle bound to the selected snapshot and
independent recipient. It does not establish publication, independent retrieval,
bundle decryption, restore integrity, available recovery compute, ongoing schedule
success or service activation. The bundle's embedded snapshot ID prevents silently
substituting a newer daily snapshot; historical confirmations must not be replayed.

### Independent dependency chain

A controller-loss exercise must prove every edge below without borrowing production
host credentials or an old runner workspace:

1. independently available repository/source checkpoint and runbook;
2. the confirmed offline offsite USB recovery age identity;
3. decryption of `secrets/recovery-publication.sops.json` without printing or
   persisting plaintext beyond a protected temporary workspace;
4. authenticated read of the exact versioned AWS bundle object, including KMS
   permission, size and ciphertext SHA-256 verification;
5. verified `age` binary and private in-memory or tmpfs bundle decryption;
6. the bundle's pinned Restic, rclone and restore runner, exact repository and
   snapshot bindings, and dedicated Proton credentials/TOTP;
7. fresh isolated compute with Python 3, adequate private storage, clock/DNS and
   only the network egress required for retrieval and the Proton backend; and
8. a separately retained, artifact-matched application generation and an isolated
   activation procedure if service RTO is in scope.

The September 19 [AWS retrieval drill](../recovery/aws-bundle-retrieval.md) proved
that the accepted identity copy decrypts the publication credential and retrieves
the exact historical KMS-backed bundle version. It used the controller copy rather
than literally reading the confirmed USB, and did not decrypt the bundle. Bundle A
on the developer machine remains outside off-machine bundle-access proof.

## Qualification scope

Use two explicit gates rather than calling one staging restore an end-to-end service
recovery.

### Gate 1 — independent custody and exact staging restore

Qualifies independently retrieving, decrypting and restoring one current exact
snapshot to a private isolated staging tree. It does not start applications or
satisfy the assessment-only eight-hour service-recovery criterion.

Success requires:

- the selected copied snapshot completed within 24 hours of the declared disaster
  time and has the required cadence, policy and artifact tags plus exact original
  ancestry;
- the canonical repository identity and a fresh read-only structural check pass;
- a new bundle is built from reviewed current metadata and credentials, encrypted
  to the independently held recipient, published as a new version, retrieved
  through the independent path, and matched byte-for-byte by ciphertext digest;
- no production host token, mount, state tree, credential file or Tailscale node
  identity is present on the target;
- the bundle consumer accepts all bindings and `restic restore --verify` succeeds
  into its fixed empty root-owned target;
- representative protected files and database structures pass offline checks,
  with only secret-free counts, hashes and outcomes recorded; and
- for this assessment, elapsed time from declared disaster to verified staging is at most eight hours,
  reported as **staging RTO only**.

### Gate 2 — isolated application rebuild and activation

Qualifies the actual service RTO. Do not authorize this gate until its missing source
and side-effect controls have been designed, tested locally and reviewed. The
[Nextcloud isolated logical recovery plan](../recovery/nextcloud-isolated-recovery-plan.md)
is a bounded database/control-plane precursor; because external user data is absent
from Restic, it is not Gate 2 qualification by itself.

Success additionally requires:

- an exact base-OS and container-runtime build path independent of VM100 and the
  retired VM9900 source;
- independent retrieval of the tracked application generation matching the selected
  snapshot's artifact identity, with every image bound by repository digest;
- an explicit mapping from every Restic path class (`replace-tree`,
  `replace-entries`, `preserve`, `regenerate`, `retain`, `external`) into a new
  empty recovery root without weakening the old archive activator's guards;
- offline database-specific checks before startup, then ordered startup with
  migration and rollback boundaries;
- network enforcement that prevents DDNS, mail, webhooks, hardware control,
  federation, public ingress and writes to production external systems;
- distinct service, DNS and Compose identities, with no production Tailscale tags
  or routes;
- representative authenticated read checks for each critical service and an
  explicit result for every external-data dependency; and
- completion against the assessment-only criterion within eight hours from the
  declared disaster point, including infrastructure provisioning, custody retrieval,
  restore, activation and checks.

A Gate 1 success must not be reported as Gate 2 or as qualification against the
assessment-only eight-hour service-recovery criterion.

## Isolated target admission

Before choosing a VMID or provisioning method, capture a fresh read-only inventory
and admit one target against all of these conditions:

- a unique, currently absent VMID or equivalent identity; never 9900 or 100;
- one declared owner and one exact lifecycle state, with create and destroy plans
  bound to that state; no `state rm`, import into a retired root or guessed ownership;
- dedicated blank disks with recorded size/serial/provenance and enough capacity
  for the selected snapshot, bundle workspace, database checks and safety margin;
- no production storage passthrough, NFS mount, bind mount, ZFS dataset, Docker
  socket, cloud-init credential, SSH host key, age identity or repository cache;
- an isolated network segment with default-deny reachability to the production LAN,
  VM100, Proxmox management and external service endpoints not required by the
  reviewed phase;
- independent console plus an ephemeral qualification access identity, neither of
  which is a production host credential;
- no production DNS name, Tailscale tag, ACL grant, firewall identity, VM MAC or
  application project name; and
- an exact cleanup plan that removes only the admitted target while preserving
  encrypted evidence and required operation journals.

If the target shares the production hypervisor or storage pool, document that
remaining fault-domain risk. A unique VMID prevents identity collision; it does not
by itself provide genuine isolation. The September 19
[read-only target survey](../infrastructure/evidence/nextcloud-isolated-target-survey-2026-09-19.json)
found unused VMID 9000 and sufficient `local-lvm` disk capacity, but no isolated
bridge. It authorizes no provisioning or network change. The follow-on
[detached-NIC design](../recovery/nextcloud-detached-nic-isolation.md) requires
firewall-confined retrieval followed by provider-verified NIC removal before service
startup; its open source, bundle, memory and firewall-test blockers leave target
admission incomplete.

## Separately authorized run plan

Each phase is a stop/go boundary. Record UTC start/end times and only non-secret
identities and outcomes.

1. **Freeze and observe.** Freeze dashboard/policy and recovery-source changes for
   the window. Re-observe provider ownership, candidate identity absence, production
   writers, backup locks/journals, timers, mounts and console access. Stop on an
   unknown owner, active writer, unresolved journal or unavailable independent
   operator path.
2. **Select the recovery point.** Read the canonical repository without mutation;
   select one exact completed daily snapshot and verify repository ID, tags,
   ancestry, timestamp and expected policy/artifact identities. Do not initialize,
   unlock, forget, prune or repair.
3. **Prepare current protected inputs.** **Completed for the selected chain on
   September 19.** The authorized build used an owner-only temporary workspace,
   reviewed pinned binaries and runner, produced two metadata-bound ciphertexts,
   and removed the host workspace. The bundles remain encrypted locally.
4. **Publish and retrieve independently.** Publish a new version without replacing
   history, verify its KMS/version metadata and ciphertext hash, then retrieve it
   using the documented independent path rather than the creating process's local
   file. Preserve the prior canonical bundle.
5. **Provision the admitted target.** Apply only the exact reviewed create plan.
   Re-observe the unique identity, blank disks, network isolation and absence of
   production tokens/mounts before transferring ciphertext.
6. **Run Gate 1.** Decrypt only into a protected tmpfs or directly into the bundle
   consumer. Use the consumer's required disposable-VM confirmation and fixed
   `/srv/home-lab-recovery/restic-proton-proof` target. Keep the Proton account's
   exclusive-client rule and backup-writer quiescence explicit. Stop on any binding,
   repository, lock, network, capacity or verification failure; do not weaken a
   guard or retry with a different snapshot under the same record.
7. **Decide Gate 2 separately.** Preserve Gate 1 staging and evidence while an
   operator reviews the result. Start no service unless Gate 2 source, firewall,
   artifact and rollback plans were independently approved.
8. **Verify and close.** Re-observe production backup schedules, locks, journals,
   VM100, storage and policy. Destroy only through the qualification's owning state
   using an exact reviewed plan. Confirm target disks, identity and temporary
   plaintext are absent; retain encrypted bundles, state generations and secret-free
   evidence according to the approved retention decision.

## Stop conditions

Stop without cleanup-by-guessing if any of the following occurs:

- the USB identity, AWS/KMS access or the exact bundle version cannot be proven
  independently;
- the candidate target identity exists, ownership is ambiguous, or isolation differs
  from the reviewed plan;
- a backup, maintenance, deployment or restore writer is active, or a lock/journal
  outcome is unknown;
- repository, snapshot, ancestry, policy, artifact, binary or ciphertext identity
  differs;
- the target can see a production token, mount, state tree or management network;
- Restic/rclone reports repository, password, integrity, backend, network, capacity,
  permission or lock failure;
- plaintext cannot be confined to the approved protected workspace; or
- an activation step would contact an unapproved external system or needs a guard
  weakened.

Preserve the target and operation state needed for diagnosis. Do not clear locks,
delete journals, rotate credentials, repair/prune the repository, apply a historical
plan or destroy evidence merely to obtain a passing result.

## Required decisions before implementation

1. Choose Gate 1 only or Gate 1 plus Gate 2. Only the latter can qualify service RTO.
2. Select the isolation platform and fault-domain acceptance criteria.
3. Define a periodic read-only verification and media-replacement cadence for the
   confirmed USB without recording its physical location in Git.
4. Define independent custody for the matching source checkpoint and application
   generation; image references remain exact repository digests.
5. Decide how excluded/external data affects acceptable degraded service.
6. Define encrypted evidence retention and the target cleanup authority.
7. Approve a bounded implementation pass for the new target owner and, for Gate 2,
   the new activation path. This must not reconstruct the retired VM9900 roots.

Until these decisions and a separately authorized timed run are complete, report
recovery as **exact private staging supported; independent age-key custody and exact
historical AWS bundle retrieval confirmed; September 19 point-in-time RPO and
current local bundle creation passed; current publication, independent retrieval,
decryption and restore unverified; application activation unavailable; ongoing
24-hour RPO and the assessment-only eight-hour service-recovery criterion
unqualified**.
