# OpenTofu state-object cleanup

The versioned state bucket separates active backend keys from retired keys in [`infrastructure/tofu/aws-foundation/state-objects.json`](../infrastructure/tofu/aws-foundation/state-objects.json).

The active list is the IAM allowlist for controller backend access. Retired keys receive exact-prefix S3 lifecycle rules that expire current objects and noncurrent versions after one day. Active `.tflock` prefixes retain only current lock behavior; noncurrent lock versions expire after one day and expired delete markers are removed. State history for active `.tfstate` objects is not expired.

Audit the live bucket with the read-only controller identity:

```sh
scripts/audit-opentofu-state-objects
```

The audit rejects every key outside the exact active and retired state/lock sets. After applying the AWS foundation lifecycle configuration, allow for S3 lifecycle processing and require complete retired-prefix removal:

```sh
scripts/audit-opentofu-state-objects --require-retired-empty
```

Only after that command passes may the retired entries be removed from `state-objects.json`. This two-stage process preserves a reviewed cleanup declaration until S3 proves that every obsolete state version and delete marker is gone. Never apply a bucket-wide state expiration rule.
