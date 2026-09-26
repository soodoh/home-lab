# Legacy AWS recovery retirement: owner cutover

This is a **plan, not authorization to apply it**. The reviewed source cutover
removes legacy desired resources, but remote state and live AWS retain them
until the independent owner finishes the migration. The normal OpenTofu plan
inspector forbids deletions and managed IAM mutations; the
controller apply role cannot write IAM. Do not target around either refusal,
remove `prevent_destroy` to force an apply, or silently abandon a live resource
in state. Use an independent AWS owner and private, versioned remote-state
before-images. Reobserve every predicate below in the cutover session; an old
inventory or a saved plan from this design session is not evidence.

## Boundary and rollback decisions

- Recurring Restic remains local → NFS → Proton. Require a fresh backup observer
  and separately protected encrypted bundle, age identity, and verified private
  restore before deleting any remaining recovery data.
- The legacy bucket is to be **deleted**, not reserved empty. Its globally
  unique name may be reused by another account. Verify all clients are stopped;
  never assume a stale request to that name is safe after deletion.
- The separately supplied `s3-backup-user` is **not** the managed
  `home-lab-recovery` user. Keep its single key inactive and retain that user
  until the recovery KMS key has actually finished its deletion window. Only
  then review detaching `AmazonS3FullAccess`, permanently deleting the key, and
  deleting the user. Reactivation remains possible only while the original key
  exists; any newly observed consumer stops the cutover.
- S3 version deletion is irreversible: a copied bundle can be restored but its
  old S3 version IDs cannot. A scheduled KMS deletion can be canceled during
  its 30-day window; a completed KMS deletion cannot be undone. Keep key IDs,
  state version IDs, object names, policy documents, and restore receipts in
  independent protected storage, never Git or console logs.

## Source and policy review before a provider mutation

1. Prepare a separate reviewed source change removing the recovery-only bucket,
   bucket configuration/policy, KMS key and alias, managed recovery IAM user and
   inline policy, recovery-only inputs and outputs, and recovery references from
   both controller state policies. Retain the **transitional recovery-region
   provider alias** until externally retired resources are removed from remote
   state. Preserve the active state bucket, its KMS key, all six state/lock keys,
   both controller roles and profiles, and their owner-controlled boundaries.
   Neither `s3-backup-user` nor its key is managed by this OpenTofu root.
2. Privately inspect a production-backed plan from that source. The expected
   proposal is exactly 11 recovery-resource deletes, two IAM policy updates
   removing only legacy bucket/KMS references, and two recovery output removals.
   No state-bucket/firewall action, replacement, import, unknown identity result,
   unrelated drift, or extra action is acceptable. **Do not apply that plan**:
   its inspector refusal is intentional. Keep the candidate out of the deployed
   checkout until the independent owner approves the cutover and its rollback.
3. Independently review **four** policy versions: the two Git-owned controller
   state policies and both external permissions boundaries. Remove only recovery
   bucket/KMS grants. Keep the previous defaults available, preserve exact state
   object and lock permissions for all six active roots, and privately simulate
   plan/apply access before and after each default-version switch. Check the
   exact state/lock Get/Put/Delete matrix, state-key KMS crypto, and denial of
   legacy S3 object/list and recovery-key cryptographic access. The apply
   boundary's generic read-only KMS inventory permission can still allow
   `DescribeKey` on the pending recovery key; do not broaden this cutover to
   remove unrelated inventory access. IAM changes belong to the independent
   owner, not an ordinary controller apply.

## Bounded owner cutover (separate approvals for each destructive phase)

1. Require a clean reviewed checkout, no concurrent state or backup owner, a
   private encrypted state-object version before-image, a current empty-bucket
   inventory of **all** versions, delete markers, and multipart uploads, an
   inactive backup key, and the independently verified recovery copy. Verify
   the state and recovery KMS keys are distinct. Coordinate the reviewed source
   cutover before any state removal so normal planning cannot silently recreate
   retired resources. Pause on any unexpected access or drift.
2. With the independent owner, publish and verify the two reviewed external
   boundary versions and the two controller policy versions. Keep the previous
   defaults for rollback. Remove the keyless managed `home-lab-recovery` user's
   inline policy and then that user only after verifying it has no credential or
   other attachment. The separate backup user and inactive key remain untouched.
3. Recheck that the recovery bucket has no versions, delete markers or uploads,
   and that no writer remains. Delete only this bucket with the independent owner;
   verify its absence and preserve the state bucket. Deleting the bucket also
   removes its bucket policy and configuration; do not attempt to delete an
   active state-bucket rule. Stop if the name or ownership unexpectedly changes.
4. Reconfirm no remaining S3 ciphertext, KMS grants or other dependents. Delete
   only the recovery alias, then schedule **that recovery key** for deletion with
   the reviewed 30-day window. Verify `PendingDeletion`. Keep an independent
   protected owner record of its identity and due date until AWS confirms final
   deletion. Do not schedule the active OpenTofu state KMS key.
5. After independently verifying each bucket/IAM resource absent and explicitly
   accepting custody of the pending KMS deletion, reconcile **only** the 11
   externally retired managed-resource addresses from remote OpenTofu state using
   the controller state writer and its backend lock. This is a deliberate owner
   handoff of the pending key, not a silent `state rm` shortcut: retain the
   encrypted before-image and a private pending-deletion owner record. Verify
   each address individually against live AWS before the state write:

   ```text
   aws_iam_user.recovery
   aws_iam_user_policy.recovery
   aws_kms_alias.recovery
   aws_kms_key.recovery
   aws_s3_bucket.recovery
   aws_s3_bucket_lifecycle_configuration.recovery
   aws_s3_bucket_ownership_controls.recovery
   aws_s3_bucket_policy.recovery
   aws_s3_bucket_public_access_block.recovery
   aws_s3_bucket_server_side_encryption_configuration.recovery
   aws_s3_bucket_versioning.recovery
   ```

   Remove only the two obsolete `data.aws_iam_policy_document.recovery*`
   state entries if they remain; review the two recovery output removals
   separately. Then inspect a fresh saved
   `-refresh-only` plan: it may record only the two owner-approved controller
   policy documents and reviewed output removals, with no cloud action or other
   identity drift. Apply that **same** state-only plan only after owner approval.
   Require a fresh, driftless, normal `aws-foundation` plan and native policy
   admission before calling the root converged.
6. Once no remote recovery address remains in state, remove the transitional
   provider alias and recovery-region input and revoke the old recovery-address
   allowlist entries in a separate reviewed Git change. Require another no-op
   foundation plan. Reobserve live KMS state throughout the deletion window;
   cancellation/rollback is an owner decision, not an automatic retry.
7. Only after AWS confirms final recovery-key deletion, recheck the separate
   backup user's inactivity and zero consumers. Request **another explicit
   approval** before detaching its broad S3 policy, permanently deleting its
   access key, and deleting the user. Verify the active state bucket, KMS key,
   firewall backend, and local → NFS → Proton backup chain remain healthy.

Any failed predicate stops at its current phase. Preserve nonterminal locks,
private before-images, and owner records for inspection. A Git revert alone
cannot restore deleted S3 versions, a deleted bucket name, or a completed KMS
key deletion.
