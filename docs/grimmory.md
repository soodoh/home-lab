# Grimmory operation and CWA transition

Follow [operations](operations.md), [security](security.md) and
[recovery](../recovery/README.md). Source approval is not deployment approval.
The committed configuration is the **read-only overlap phase**, not a completed
migration. Calibre and CWA remain declared until Grimmory and one Kobo have been
qualified. No application data is OpenTofu-owned.

## Runtime and ownership

[`services/grimmory.yml`](../services/grimmory.yml) pins Grimmory and its dedicated
MariaDB. Neither publishes a host port; the database has an internal bridge.
Grimmory's private HTTPS route is `grimmory.ts.diloreto.com`, using the existing
tailnet Traefik and wildcard certificate. `books.diloreto.com` still reaches CWA.
Do not expose a pending first-user setup through public ingress.

The existing `/srv/home-lab-state/calibre-data/books` directory is mounted at
`/books`, initially **read-only**, with `DISK_TYPE=NETWORK` disabling file
operations. Choose **BOOK_PER_FOLDER** when creating the library: Calibre stores
multiple formats of one book in each folder. Disable metadata write-back and
file organization during the overlap. BookDrop uses a separate protected
`grimmory-bookdrop` directory, not CWA's active ingest queue.

The app, database and BookDrop state are in the managed Restic scope and `books`
recovery group. Backups stop Grimmory before MariaDB. A matching fresh backup
and private restore of the changed scope are required before claiming coverage.
Initial activation needs a separately reviewed backup-scope transition: strict
observation binds the reviewed policy to the installed policy, so the existing
chain does not qualify a not-yet-installed scope. Admit protected directory
creation and native backup-policy convergence, then obtain a fresh complete chain
under that scope before site convergence. The prepared runner selects stop-group
members from the active Compose declarations: undeployed candidates are not
queried, but a declared service without its container still refuses the backup
before any stop or journal write. Install the reviewed runner with the new policy;
this behavior is only synthetically qualified until separately approved host
execution. Never bypass the observer or count empty-directory coverage as
migrated-data coverage. Compose-only deployment does not extend backup policy.

Bookshelf also mounts `/books`, and its native root-folder settings can use the
Calibre integration. Before retiring Calibre, privately observe and separately
review those settings, outstanding downloads and import consumers. Do not infer
that a Docker mount grants safe simultaneous writing. Prefer one catalog/file
writer: either direct Bookshelf imports with Grimmory scanning and file-moving
features constrained, or a reviewed download-to-BookDrop workflow. Grimmory is
not a replacement Calibre content-server API.

## Authentication and secret delivery

Authentik creates a distinct confidential `grimmory` provider and application,
without inventing an import ID. The existing personal entitlement admits only
Paul and Sarabeth; no new directory users or administrator group are created.
The client uses authorization-code/refresh grants, exact HTTPS callbacks and
stable UUID subjects. It reuses the already managed RSA signing certificate:
Grimmory requires RSA/EC signatures through JWKS; do not copy CWA's
provider with a null signing-key selector. Review certificate validity and JWKS during activation.

- The OIDC secret has one authority:
  `infrastructure/tofu/authentik/client-secrets.sops.json`, under
  `oauthProviders.grimmory`. It is **not** copied into production SOPS or Docker
  environment variables. Apply the independently reviewed Authentik plan first.
  After creation, independently grant the plan identity the new provider's
  required view/change permissions before another secret-bearing plan.
- Database and separate `grimmory-admin` bootstrap passwords come from
  `secrets/production.sops.yaml`. MariaDB uses its native password-file inputs;
  Spring Boot imports `/run/secrets/spring.datasource.password` through native
  `configtree:`. The pinned UBI MariaDB runs as UID 999 and must read its
  files directly. All delivery files remain root-owned, mode `0440`: database
  readers use group 999, while Spring uses a separate group-1000 delivery of the
  same `GRIMMORY_DB_PASSWORD` authority. The app receives no database root password.
  These files initialize MariaDB users; changing their contents does not alter an
  existing database account. Database-password rotation requires a separately
  admitted native account change and Spring restart, not just new SOPS ciphertext.
- Grimmory has no native OIDC secret-file setting. The `grimmory` Ansible role
  uses its admin settings API with controller-side SOPS lookup, verified HTTPS,
  no redirects and `no_log`. It compares and writes only managed authentication
  settings, then checks secret persistence and unchanged unrelated settings.
  This is not an atomic provider/consumer rotation.
- Automatic user provisioning and group-driven in-app privilege changes are
  disabled. OIDC-only mode retains Grimmory's native local-admin exception for
  protected recovery/convergence. The role does not reset existing passwords,
  create Paul/Sarabeth, or write their shelves/progress.

The first approved site apply also needs
`grimmory_initialize_confirmed=true`. It initializes only an empty instance with
its separate protected administrator. An existing instance must accept that
administrator's stored password; a mismatch refuses rather than resetting it.
Treat bootstrap-password rotation as a separate native account change.

For an existing admitted instance:

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/converge-grimmory.yml --check
# Separate owner approval after fresh host/Compose/strict-backup observation:
ansible-playbook ansible/playbooks/converge-grimmory.yml -e grimmory_apply_confirmed=true
```

Check mode reads settings through a short-lived admin login, which creates a
native login/session record; it does not initialize an instance or write
settings. Failures retain production ownership for inspection. Settings updates
are sequential: do not clear a failed lock or silently restore an old secret.
Always verify real fresh OIDC login, account identity, unauthorized-user denial
and a fresh Authentik no-op plan before declaring activation/rotation complete.

## Migration admission and data mapping

Keep execution tools, exports, account tokens, mapping files, approvals and
receipts in a **new private per-run directory outside Git**. Reobserve rather
than replaying an earlier export. Before final extraction, take consistent
protected before-images of the library and CWA configuration, including
`app.db`, `cwa.db` and Calibre `metadata.db`. Quiesce CWA, Calibre, Bookshelf and
other observed library writers under production/backup ownership. Do not copy
a live SQLite database without accounting for WAL; use native SQLite backup or
copy the complete stopped state. Preserve unknown locks/journals.

Rehearse on isolated copied data before loading the production candidate. Map
books using exact relative file paths/formats and verified content hashes,
never title matching or coincidental numeric IDs. Compare the filesystem inventory
as well as Calibre's catalog: a generic scan can include unindexed ebook files.
Classify each extra file explicitly, without deleting it or guessing its identity
from a directory's numeric suffix. All catalog files must map unambiguously;
group formats into one target book. Preserve the original files,
including KEPUB derivatives and OPF metadata that Grimmory's generic scanner does
not directly consume. Transfer Calibre metadata through native metadata APIs;
classify custom columns explicitly instead of silently dropping them.

| CWA state | Grimmory handling |
| --- | --- |
| Paul/Sarabeth identity | Create distinct target accounts; map actual target IDs by username, preserve permissions/library access, then link to the correct issuer/subject. Never copy password hashes or assume user IDs match. |
| Private shelves and membership | Native shelf APIs preserve owner/privacy and exact book sets. Use supported native sorting; retain exact source member order and shelf/membership dates in the protected legacy archive. This disposition does not claim full shelf-schema/UI parity. |
| System magic shelves | Recreate equivalent rules/native views; do not import caches or assume rule JSON compatibility. |
| Unread/in-progress/finished | Map `0/2/1` to `UNREAD/READING/READ` on `user_book_progress`. Preserve status-modification/start timestamps separately. CWA has no dedicated completion-date field: do not label a generic modification date as completion, or use the bulk-status API's import-time completion date. |
| Kobo progress/location | Map percentage, source percentage, location type/source/value and timestamps to target per-book state and Kobo reading-state JSON. Preserve statistics where representable. Validate exact resume location against the actual served KEPUB. |
| Browser/KOReader/annotations | Inventory afresh and migrate only observed data with compatible locators/checksums. Server absence does not prove a device has no annotations. |
| Historic activity/preferences | Preserve compatible preferences. Represent historic CWA downloads as a separate private `Previous CWA Downloads` shelf per user, using native title sorting and identity-qualified current catalog books. Archive original download records, including removed-book references; do not invent activity timestamps or catalog entries. Classify other unsupported preferences separately. |
| Records for removed books | Account for them in the private reconciliation; do not recreate phantom catalog entries or silently count them as migrated. |

Use native APIs where they preserve ownership and history. The API cannot
express every historic Kobo field/date; any necessary target-DB import is a
version/schema-qualified **one-off**, with Grimmory stopped, a target before-image,
transactional writes, foreign-key checks and restart/read-back validation. Do not
add a recurring database writer or custom application entrypoint to the repo.

The pinned progress tables have second-precision `TIMESTAMP` columns; preserve
full source timestamps in compatible Kobo JSON and reconcile the native precision
explicitly. Kobo's response timestamps are second-precision in both applications.
Native metadata and cover-upload APIs support catalog transfer, but the pinned
author update DTO does not expose its stored `sort_name`: qualify any necessary
supplement with the same stopped-schema transaction. Check personal read status
through `/api/v1/books`, not the library's unpersonalized catalog endpoint.
Custom text columns, untimestamped download history, UI preferences and unsupported
shelf fields need a meaningful native mapping or separately approved protected
retention. Merely retaining the original OPF/SQLite files is not target UI parity.
An empty custom-column definition has no per-book values to transfer: retain its
schema in the archive, but recheck both value and link tables during final
extraction rather than assuming it stays empty.

Keep the legacy archive outside Git, encrypted to the existing SOPS age
recipients. Include source field definitions, exact values and identity mappings;
verify native decryption and byte-identical read-back in a fresh private working
directory without logging its content. An observation-time archive is not the
final quiesced extraction or a full source backup. Obtain verified independent
retention and refresh/reconcile the final archive before retiring source state;
one local ciphertext copy is not a durable multi-copy backup. Keep the device
before-images untouched and classify annotation retention separately from
native annotation access. Remove disposable exports and execution tools after
verification; retain the protected recovery payload and receipt, not those tools.

Create each history shelf through its owner's native API session, with
`publicShelf=false`, and reconcile exact UUID/path-qualified membership after
restart. Never merge it into the dedicated Kobo selection shelf or enable
`autoAddToShelf`: download history is not a device download request. Pinned
Grimmory emits ordinary shelves as Kobo collections, with membership intersected
against its dedicated Kobo shelf. Expect an additional history collection for
already-selected books during separately approved device testing; verify that
it neither expands the entitlement set nor leaks between users. Native sorting
and these shelves still need isolated runtime qualification before admission.

Local-account linking is disabled by default. Open only the reviewed two-account
linking window with `grimmory_allow_local_account_linking=true`; auto-provisioning
remains off. Have both people authenticate through Authentik, verify the **same**
Grimmory user IDs still own their imported data, then converge the default again.
Do not promote Paul to administrator merely because he is an App Operator.

## Kobo and final cutover gates

CWA uses Calibre UUIDs for Kobo entitlements; Grimmory uses its own numeric book
IDs and `/api/kobo/{token}` URLs. A URL-only replacement is not a transparent
migration. Back up each device's configuration, SQLite database and annotations
privately before changing it. Test one device first; never automatically factory
reset or delete its existing books. Keep the verified raw device copy untouched;
run SQLite integrity/backup and inspection on a separate working copy, accounting
for any WAL. Inventory native `Bookmark` rows (including highlights and dogears),
volume/chapter identities, container paths and offsets. Preserve them alongside
reading-state history even when CWA has no annotation-sync records.

Match the current per-user download selections using Grimmory's dedicated Kobo
shelf: populate the full admitted catalog for whole-library sync, and the exact
selected shelf set for shelf-only sync. Do not accidentally expand Sarabeth's
selection. Keep Kobo tokens private and avoid logging token-bearing URLs. OIDC
protects the web UI; device tokens remain separate native credentials.

Require on the first device: correct book identities without unexpected
duplicates/deletions, collections, finished/in-progress status, percentages,
representative exact resume locations, annotations and a round-trip progress
update. Different KEPUB conversion/identities can invalidate old span locators;
percentage preservation is not proof of exact-location preservation. Compare the
resolved chapter, span ID and span text in the old and actually served new KEPUB,
not just the stored location string. A locator absent from the current CWA file
may still resolve in an older device copy: inspect the backed-up device ebook
before assuming it is lost or replacing it with an approximate percentage.
Check download state and percentage as well: devices can retain reading-state
records for ebooks no longer downloaded, and a zero-percent image-only opening
page can carry a synthetic text-span locator absent from the archive. Preserve
the original state and distinguish this from a missing mid-book passage; do not
reset status or substitute an approximate location without approval. Qualification
still needs a real device round trip, not just database/ZIP inspection.
Resolve that discrepancy before migrating the second device or retiring CWA.

After both user-data reconciliation and device qualification, review a final
cutover change: stop all source writers, import the final delta, retire Calibre
and CWA, admit the Bookshelf workflow, switch `/books` to writable/local mode and
route `books.diloreto.com` to Grimmory. Retire the candidate route/callback if it
is no longer needed. Removing old Authentik applications/providers/outpost
references must produce a complete reviewed destroy plan, not state removal.
Verify both OIDC accounts, device sync, catalog/shelf/progress parity, unrelated
services and a fresh backed-up private restore before cleaning up old state.
Remove transition-only declarations, allowances and this migration section
once verified; Git history preserves the explanation, not the recovery data.

## Behavior validation

```sh
python3 scripts/controller/test-grimmory.py
scripts/test-authentik-tofu
python3 scripts/controller/test-authentik-secret-readability.py
# Explicit local Docker only; synthetic accounts, data and disposable volumes:
GRIMMORY_RUNTIME_TEST=1 python3 scripts/controller/test-grimmory-runtime.py
```

The pinned-image test qualifies Spring's secret reader, declared credential modes,
the MariaDB identity and
the real settings API/idempotency/rotation. Discovery is synthetic; it does not
prove a real OIDC login, migration parity or Kobo interoperability. Run the
native Compose/SOPS, Ansible, image-pin, ingress and recovery validators described
in operations/CI as well.
