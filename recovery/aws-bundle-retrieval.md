# Read-only AWS recovery-bundle retrieval drill

## Status and authority

This runbook is **prepared, not executed**. Source review does not authorize age-key
use, SOPS decryption, AWS authentication, S3/KMS reads, bundle download or any
cloud mutation. A live drill requires explicit authorization for those exact reads.

The drill proves only that the independently held age identity can unlock the
publication credential and retrieve the exact historical canonical bundle
ciphertext. It does not decrypt the bundle, contact Proton or Restic, restore data,
prove a current recovery point, or qualify RPO/RTO.

## Fixed scope

Allowed live calls, once separately authorized:

1. SOPS decryption of `secrets/recovery-publication.sops.json` into one child
   process environment using the USB-held independent age identity.
2. `sts:GetCallerIdentity`.
3. `s3:ListBucketVersions` on the exact recovery bucket.
4. `s3:GetObjectVersion` for the one evidence-bound bundle version.
5. KMS decrypt performed by that exact S3 read.

No put, copy, delete, restore, policy, IAM, KMS, lifecycle or state operation is in
scope. The credential currently has broader publication authority, so command
review and an empty ambient AWS environment are mandatory; IAM alone does not make
this drill read-only.

## Evidence-bound expectations

Use the tracked evidence rather than manually transcribing protected coordinates:

- [`proton-canonical-recovery-bundles.json`](../infrastructure/evidence/proton-canonical-recovery-bundles.json)
- [`aws-recovery-publication-credential-rotation.json`](../infrastructure/evidence/aws-recovery-publication-credential-rotation.json)

The selected historical object must match all of these non-secret expectations:

| Field | Expected value |
|---|---|
| Ciphertext SHA-256 | `4b62aaa4857ec68822392752d3cce758af981e106b79d8cb969cd6538bb14164` |
| Bytes | `114746920` |
| Object-key SHA-256 | `597d15ebe79ac54dbdd3a787867bf44c38379901e3dbd33a6e16d36898307324` |
| Version-ID SHA-256 | `a4612764198e566db4990bb054a0a9184e8b5e4d86fa1e9f037a017b90b95565` |
| AWS principal-ARN SHA-256 | `cbfd4986207c28758c6d4561f6636cbaf31bbeca8972891d347ed25180be2ac7` |
| Server-side encryption | `aws:kms` |
| Region | `us-west-2` |

Object keys, version IDs, bucket names, account details, credential values and
decrypted SOPS content are protected inputs. Never print or add them to evidence.
A newer object or version does not silently replace this selection; it requires a
new review.

## Preconditions

Before the live window:

- use a clean reviewed repository checkpoint containing this runbook, the encrypted
  publication credential and both evidence files;
- mount the confirmed offsite USB only for the drill and verify its identity derives
  the documented independent recovery recipient;
- use reviewed `age`, `sops`, AWS CLI and Python binaries already present; install or
  upgrade nothing as part of the drill;
- create a new owner-only mode-0700 workspace on an encrypted local filesystem or
  tmpfs with enough space for the 114,746,920-byte ciphertext;
- disable shell tracing, terminal recording and command history for the child;
- start with no `AWS_*`, `SOPS_*`, shared-credentials or config-file fallback other
  than the exact values intentionally supplied to the child;
- confirm no other recovery publication or credential-rotation operation is active;
  and
- bind the authorization to the repository commit, expected values above, workspace
  path and maximum duration.

The home Vaultwarden copy is a convenience copy and must not be used for this proof.
The historical GPG ciphertext is not a prerequisite. The age identity must be read
from the confirmed USB path and must never be copied into the repository or command
arguments.

## Planned execution

The narrow helper is [`scripts/verify-aws-recovery-bundle-access`](../scripts/verify-aws-recovery-bundle-access).
Its only public interface is one guarded invocation; it accepts no arguments. After
disabling history and recording the separately approved window, supply the USB key
and new private workspace-parent paths through the environment:

```sh
SOPS_AGE_KEY_FILE=<usb-identity-file> \
RECOVERY_RETRIEVAL_WORKSPACE_PARENT=<owner-only-mode-0700-directory> \
RECOVERY_READ_ONLY_CONFIRMED=retrieve-exact-historical-bundle-read-only \
  scripts/verify-aws-recovery-bundle-access
```

Optional `HOME_LAB_SOPS_BINARY`, `HOME_LAB_AWS_BINARY` and
`HOME_LAB_AGE_KEYGEN_BINARY` overrides select already reviewed binaries; they do not
authorize installation or upgrades. Do not improvise a pipeline that displays
decrypted JSON or AWS output.

The helper performs these steps:

1. Validate the USB identity path is a regular, non-symlink file and derive only its
   public recipient with `age-keygen -y`. Stop if it differs from `.sops.yaml`.
2. Validate the workspace and create a new mode-0600 destination. Refuse an existing
   destination, symlink or hard-linked file.
3. Invoke `sops exec-env` with `SOPS_AGE_KEY_FILE` pointing at the USB identity. The
   child must accept exactly `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
   `AWS_S3_BUCKET_NAME` from the decrypted document; reject extra decrypted fields.
4. Give the child an empty temporary `HOME`, set `/dev/null` as the AWS shared
   credentials/config source, disable EC2 metadata lookup and set the fixed region.
5. Call STS without printing its response. Hash the returned ARN and require the
   expected principal hash.
6. List bucket versions without printing the response. Select exactly one version
   whose key hash, version-ID hash and size match the table. Zero or multiple matches
   fail closed.
7. Retrieve only that exact key and version into the new destination. Suppress normal
   AWS response output and require `aws:kms` server-side-encryption metadata.
8. `fsync`/close the file, then require exact size and SHA-256. Record whether the
   selected version is currently latest, but do not treat a newer version as the
   historical object.
9. Emit only the bounded result described below, unset the child environment, remove
   the ciphertext and workspace, and verify both are absent.

The synthetic CLI regression is
[`scripts/controller/test-aws-recovery-bundle-access.py`](../scripts/controller/test-aws-recovery-bundle-access.py).
It uses fake SOPS, age-keygen and AWS adapters, checks the exact three-call read path,
refuses forged success and unexpected credential fields, and exercises bounded
failure cleanup. It performs no credential decryption or network access. Passing
fixtures do not authorize or prove the live drill.

## Secret-free result

A successful result may contain only:

```json
{
  "aws_identity": "matched",
  "bundle_bytes": 114746920,
  "bundle_ciphertext_sha256": "4b62aaa4857ec68822392752d3cce758af981e106b79d8cb969cd6538bb14164",
  "exact_version": "matched",
  "kms_encryption": "matched",
  "selected_version_current": true,
  "state": "retrieved-verified-removed",
  "verified_at": "<UTC timestamp>",
  "version": 1
}
```

`selected_version_current` is an observed boolean, not a required historical value.
Do not record raw caller identity, bucket, object key, version ID, ETag, credentials,
USB path or physical custody location.

## Stop conditions

Stop and preserve only protected diagnostics if:

- USB recipient, caller, object key, version, size, encryption or ciphertext hash
  differs;
- SOPS exposes unexpected fields or AWS obtains credentials from another source;
- more than one evidence-bound object is found;
- any requested command is not one of the five allowed read classes;
- a write-capable operation, shell trace, terminal capture or plaintext file is
  detected;
- cleanup cannot prove the downloaded ciphertext and child workspace absent; or
- the operation becomes ambiguous.

Do not rotate credentials, edit IAM/KMS/S3 policy, upload a replacement, choose a
newer object, decrypt the bundle or weaken a guard to make the drill pass. A failure
requires a specific diagnosis and separately reviewed recovery decision.

## Acceptance boundary

Success closes only the independent **key → publication credential → AWS/KMS → exact
historical bundle ciphertext** path. Gate 1 still requires a current evidence-bound
bundle, isolated target and verified Restic staging restore. Gate 2 remains required
to qualify application activation and the eight-hour service RTO.
