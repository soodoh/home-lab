# Current Restic recovery bundles

## Status and authority

A separately authorized live build completed on September 19. Two distinct current
encrypted bundles now exist in protected controller-local storage. Bundle B has not
been published; neither bundle has been decrypted or restored, and AWS was not
contacted. Build authority is consumed and does not authorize publication,
decryption, restore or another live invocation.

The September 19 passive observation selected this exact natural chain:

- games/original snapshot `50c0a57fe0fe5df34dce465d641dedb2f202c1886b99d909b7aca3408f4d1e9b`;
- NFS copy `22d0601caeeca059533af4c71f927b4ac8d9a3dd01d337d137be568f260682eb`;
- Proton snapshot `9ac6ef90f30c87326fb73788e95f9de86fac4c01c421ab63e14b667a9b58f3fc`;
- policy SHA-256 `81b1f0dd0f1a2fd596c13ee3b6a79e7bb181ae5d0b80e3e942ab69f96d77a6ff`;
- artifact SHA-256 `2f12e384fdc0ce759d23b0bd9e16ad402d3ecd2985b4ecdfe048127f1c5748be`.

The retained point-in-time observation is
[`natural-restic-daily-2026-09-18.json`](../infrastructure/evidence/natural-restic-daily-2026-09-18.json).
Immediately before the live build, a fresh private observation revalidated the same
chain at `2026-09-19T04:22:05Z`, with snapshot age 58,532 seconds, no interruption,
no pending replication and inactive successful writers. Its SHA-256 is
`e7bf314b36551b04d3ed3b8a7752020710d966d977c73b15327ba50334832754`.

## Secret-free metadata plan

[`scripts/prepare-restic-recovery-bundle-metadata`](../scripts/prepare-restic-recovery-bundle-metadata)
accepts one observed chain and creates one new owner-only mode-0600 metadata file:

```sh
scripts/prepare-restic-recovery-bundle-metadata \
  --observation infrastructure/evidence/natural-restic-daily-2026-09-18.json \
  --output <new-private-directory>/metadata.json
```

The planner:

- requires the natural completed state, zero interruption/pending entries and an
  observed age below 24 hours;
- binds exact original and Proton snapshot IDs, policy, artifact and repository ID;
- reads the current Restic/rclone installed hashes from the contract;
- hashes the retained first-run and Proton qualification evidence plus the current
  restore runner; and
- refuses an existing output, writable input, malformed identity or repository
  mismatch.

The fresh build metadata retained the same exact content identity, SHA-256
`bd5bf9e21da50e0e36b1cb38b5714db513d36626c5318169bb74e75877a2dad8`.
Its existence alone is not build proof; the tracked live outcome is
[`current-restic-recovery-bundles-2026-09-19.json`](../infrastructure/evidence/current-restic-recovery-bundles-2026-09-19.json).

## Separately authorized bundle build

[`scripts/build-current-restic-recovery-bundles`](../scripts/build-current-restic-recovery-bundles)
consumes the exact metadata and a new output root:

```sh
RECOVERY_BUNDLE_BUILD_CONFIRMED=build-two-current-encrypted-restic-recovery-bundles \
  scripts/build-current-restic-recovery-bundles \
  --metadata <exact-private-metadata.json> \
  --output-root <new-private-output-directory>
```

The helper must run only in a protected temporary workspace on the production
credential host, under a separately reviewed SOPS child environment. It reads only
`RESTIC_PROTON_PASSWORD`, `PROTON_BACKUP_USERNAME`, `PROTON_BACKUP_PASSWORD` and
`PROTON_BACKUP_TOTP_SECRET`, maps them into a clean child environment, and delegates
to the retained generic bundle builder. Never print the decrypted environment or
run with shell tracing.

Both A and B are separately encrypted to the USB-backed independent recipient
`age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm`.
They must have one plaintext hash and two different ciphertext hashes. The builder
verifies every produced ciphertext against its result, writes only mode-0600
ciphertext/results, and removes the entire output root on failure. Bundle A and B
therefore have independent encryption randomness and storage destinations, but one
intentional recovery-key dependency.

The controller entrypoint is
[`ansible/playbooks/build-current-restic-recovery-bundles.yml`](../ansible/playbooks/build-current-restic-recovery-bundles.yml).
Its authorized run passed 36 tasks with eight changed task groups, no failures and
no unreachable hosts. It deliberately refuses check mode because staging, SOPS
execution and encrypted output creation are the operation being approved.

Before a future invocation, create a new mode-0700 controller output parent and
copy [`current-restic-bundle-build.example.yml`](current-restic-bundle-build.example.yml)
to an ignored mode-0600 extra-vars file containing only exact approval, commit,
input path and hash values. Do not put credentials in extra vars. The entrypoint
shape is:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml \
  ansible/playbooks/build-current-restic-recovery-bundles.yml \
  -e @<protected-build-authorization.yml>
```

The playbook requires:

- a clean exact reviewed commit and explicit build confirmation;
- owner-protected metadata and passive observation files with reviewed hashes;
- an observation no older than one hour and a selected snapshot younger than 24
  hours at invocation time;
- exact observation-to-metadata snapshot, repository, policy and artifact bindings;
- four loaded, successful and inactive Restic writer units;
- absent interruption and apply-ownership paths;
- exact pinned SOPS, age, Restic and rclone host binaries plus the protected active
  SOPS identity; and
- a new output root under an existing owner-only mode-0700 parent.

It stages only metadata, the encrypted SOPS document and reviewed source helpers
into a new root-owned host workspace. The build runs under the backup flock and
SOPS `exec-env --pristine` with `no_log`; decrypted values are passed only to the
pair builder, which creates a reduced child environment. The playbook verifies the
four host outputs, creates the new local output root only after successful build,
fetches only encrypted bundles and secret-free results, then verifies local hashes
against the host files.

An Ansible `always` block removes and verifies absence of the host workspace. A
native transient systemd timer is armed immediately after workspace creation to
remove it after 30 minutes if the controller is interrupted, and is disarmed on
normal return. A controller failure in the small interval between workspace
creation and timer arming can leave an empty private directory; inspect and remove
that exact directory before retrying. Partial controller outputs are removed on a
controlled failure.

The two mode-0600 outputs each contain 114,746,920 bytes. Their ciphertext
SHA-256 values are respectively
`8d2026d97ffef00666a708e00460a7c11aad48535e900e5be42af77ea462e4b2` and
`ac648bc28652d72811bb1496a865702863a447c9c6323758461cd91e9787c17d`.
They share plaintext SHA-256
`1ad80df3f3c7706004e995d40e3d7b6078d85ddbd667a92ba08d52a007547507`
and recipient SHA-256
`492589a8d4a4a0670834f2d5ad9d6ef000186e66171d10d72740b9b30f20cbbf`.
Post-build observation found no residual workspace or transient cleanup unit, and
all four writer units remained inactive/successful.

A fresh passive chain observation remains a prerequisite for any future build; this
playbook validates but does not generate that evidence. Another host connection,
SOPS decryption, bundle creation or transfer requires new explicit authorization.

## Publication remains separate

Building does not authorize publication. Bundle B publication must use the
controller-only `secrets/recovery-publication.sops.json`, create a new version
without replacing history, and verify KMS metadata, checksum, version identity and
readback. The ignored historical `build-live-bundles.yml`, `build-on-host.py`,
`upload-live-bundle.yml` and `upload-bundle.py` are stale operational artifacts:
they include retired recipient or credential-location assumptions and must not be
executed or edited into admission.

Bundle A must be retained under a new protected local identity rather than replacing
the canonical historical bundle. Preserve all prior bundle versions and evidence.

## Source verification

```sh
python3 -B scripts/controller/test-current-restic-recovery-bundles.py
python3 -B scripts/controller/test-current-restic-recovery-controller.py
node scripts/controller/test-current-restic-recovery-bundle-evidence.js
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml \
  ansible/playbooks/build-current-restic-recovery-bundles.yml --syntax-check
bash scripts/test-restic-recovery-bundle
```

The tests exercise the public planner and pair-builder interfaces with synthetic
contract, credential and binary adapters, and inspect the controller safety
boundary. Syntax checking parses but does not run the playbook. These checks prove
no live host, credential, repository or AWS behavior.
