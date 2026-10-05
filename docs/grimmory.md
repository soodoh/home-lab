# Grimmory

Follow [operations](operations.md), [security](security.md) and
[recovery](../recovery/README.md). Git owns runtime configuration, authentication
policy and recovery scope; Grimmory owns its catalog and individual user data.
Source changes are not proof of a deployed or recovered instance.

## Runtime and library ownership

[`services/grimmory.yml`](../services/grimmory.yml) pins Grimmory and its dedicated
MariaDB. Neither publishes a host port; MariaDB has an internal bridge.
`books.diloreto.com` is the sole HTTPS entrypoint and uses Grimmory's native
authentication, not remote-header login.
Do not expose an uninitialized first-user setup.

Grimmory is the catalog/file writer. `/srv/home-lab-state/grimmory-books` is
mounted writable at `/books`, with `DISK_TYPE=LOCAL`. Each library has one root:

| Library | Scan root | Access |
| --- | --- | --- |
| Paul | `/books/paul` | Paul |
| Sarabeth | `/books/sarabeth` | Paul and Sarabeth |

Use `BOOK_PER_FOLDER` to group multiple formats into one catalog book. Library
assignment, not Kobo shelf membership, defines web access. Changing a device
selection does not change library access. Preserve book/file identities when
moving an existing book between roots; replacing scan paths can remove catalog
records and their associated history. Qualify native move behavior before bulk
changes, including a rescan and exact identity/history readback.

New books enter through Grimmory uploads or its native BookDrop workflow.
BookDrop has a separate protected `/srv/home-lab-state/grimmory-bookdrop`
directory mounted at `/bookdrop`; select the destination library during import.
Do not restore a second catalog/file writer against `/books`.
Metadata write-back, organization and automatic device selections are separate
native settings; a writable mount does not approve arbitrary settings changes.
Keep original formats, including KEPUB derivatives that the generic scanner does
not ingest directly. Avoid duplicate catalog entries for formats of one book.

The app, database, books and BookDrop state belong to the `books` recovery group
and managed Restic scope. Directory roots are UID/GID 1000, mode `0700`, except
MariaDB's UID/GID 999 data directory. Backups stop Grimmory before MariaDB.
After data/path/schema changes, obtain a fresh complete chain and verify a
private restored application/database with its current library paths, covers,
identities, assignments, shelves and progress. Empty-directory coverage and an
older restore do not qualify a changed catalog. Verify the existence and coverage
of historical backups and device evidence before relying on them; they are not
active writers.

## Authentication and secret delivery

Authentik owns the confidential `grimmory` OIDC provider/application, the exact
public callback, authorization-code/refresh grants and stable UUID subjects.
The existing personal entitlement admits Paul and Sarabeth. Application admission
is not an administrator role or a library grant. Group-driven in-app privilege
synchronization and local-account linking are disabled.

Automatic provisioning creates issuer/subject-linked non-admin accounts with
empty default permissions and library assignments. Grant access separately in
Grimmory. Entitlement does not remove existing accounts or synchronize their
permissions; review sessions and target access when offboarding.
Do not recycle an OIDC username while its Grimmory account exists: the pinned
login implementation also falls back to usernames, not only issuer/subject.

The client secret has one authority:
`infrastructure/tofu/authentik/client-secrets.sops.json`, under
`oauthProviders.grimmory`. It is not copied to production SOPS or Docker
interpolation. The Ansible `grimmory` role reads it on the controller and
converges only managed native authentication settings over verified HTTPS,
without redirects or secret logging. This is not an atomic provider/consumer
rotation. Use a fresh remote-backed provider plan and separate apply approval;
verify discovery, JWKS and real login after authentication changes.

A dedicated create-only RSA signer uses
`infrastructure/tofu/authentik/signing-keys.sops.json`. Preserve its native PEM
representation and existing signing authorities. Exact-name discovery, private-key
reads, certificate validity and a fresh no-op plan are required for provider
management. Monitor expiry and review renewal separately; managing supplied PEM
does not automate issuance. Never self-enlarge a provider identity's grants.
See [Authentik ownership](authentik-ownership.md).

Database and separate `grimmory-admin` bootstrap passwords come from
`secrets/production.sops.yaml`. OIDC-only mode retains the native local-admin
exception for protected recovery. Do not reset accounts or promote users during
convergence. Initialization requires `grimmory_initialize_confirmed=true` on an
explicitly approved empty instance.

MariaDB uses native password-file inputs; Spring imports
`/run/secrets/spring.datasource.password` through `configtree:`. Delivery files
are root-owned mode `0440`: database readers use group 999 and Spring uses its
separate group-1000 file. The app never receives the DB root password. Changing
initialization files does not rotate existing DB accounts; rotation requires a
separately admitted native account change and Spring restart.

For an admitted instance:

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/converge-grimmory.yml --check
# Separate approval after fresh host/Compose/strict-backup observation:
ansible-playbook ansible/playbooks/converge-grimmory.yml -e grimmory_apply_confirmed=true
```

Check mode creates a short-lived native admin session but does not write settings.
Failures retain production ownership for inspection. Sequential native writes
require concurrent-edit guards and exact readback; never blindly clear a failed
lock or restore a secret from historical notes.

## Reading history and Kobo

Check personalized statuses through `/api/v1/books`, not the unpersonalized
library endpoint. Preserve unknown completion dates as unknown; status-modification
and start timestamps are not completion dates. Native reading-session and
completion charts cannot reconstruct events absent from the source.
Keep unsupported historical fields and removed-book references in independently
verified encrypted archives, never phantom catalog entries or fabricated dates.
Preservation is not proof of native UI parity.

Kobo selection uses each owner's dedicated `Kobo` shelf. Device tokens are
separate credentials from OIDC: keep tokens and token-bearing URLs private.
Ordinary/history shelves must not expand selection or enable automatic addition.
Pinned v3.5.0's direct Kobo download route does not enforce assigned-library
access; this native behavior is accepted for this deployment. Do not describe
library grants as complete device-route isolation.

Before changing or re-syncing a physical device, take a fresh protected backup
of its configuration, SQLite/WAL state, downloaded books and annotations. Keep
original evidence untouched and inspect a working copy. Never automatically reset
or delete device content. Numeric Grimmory identities and conversion output can
differ from legacy UUID-based entitlements/KEPUBs. Verify duplicates/deletions,
selection, collections, statuses, percentages, exact resume passages, annotations
and round-trip progress on one backed-up device before the second. A preserved
percentage or encrypted annotation archive is not exact resume/native annotation
qualification. See [outstanding work](migrations.md).

## Behavior validation

```sh
python3 scripts/controller/test-grimmory.py
scripts/test-authentik-tofu
python3 scripts/controller/test-authentik-secret-readability.py
GRIMMORY_RUNTIME_TEST=1 python3 scripts/controller/test-grimmory-runtime.py
```

Pinned-image tests qualify native secret readers, permission boundaries and
settings behavior using disposable synthetic data. They do not prove real OIDC
login or physical Kobo interoperability. Run the relevant Compose/SOPS, Ansible,
image-pin, ingress, recovery and OpenTofu validators from operations/CI as well.
Keep one-off executors, mappings, credentials, archives and receipts outside Git;
remove completed plaintext/tooling after verification while preserving necessary
protected recovery evidence and unresolved journals.
