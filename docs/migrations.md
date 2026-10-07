# Outstanding work

This lists unresolved **decisions**, not migration receipts. Reobserve the host,
remote state, provider and backup repositories before acting; Git history is not
proof of current state.

## Proxmox provider adoption

New native declarations for the existing boot disk, storage registrations,
management bridge, node settings and snippets need a reviewed clean checkout,
fresh observation and a whole remote-backed plan before adoption. Preserve the
current volumes, PVE bus attachments, network path and cloud-init instance ID.
Snippet import reconstructs no source content and requires exact-plan replacement approval;
qualify the real credential-free uploader and independent hash readback before
completion. Do not bypass plan policy or infer a no-op apply from mock tests.

The owner-only `proxmox-access` root additionally needs independently approved
provider identities and exact-key backend/lock grants in a separately controlled
protected bucket outside ordinary controller object-write and bucket-policy
authority. Native storage reads and snippet visibility additionally require the
staged, scoped `Datastore.Allocate` exception. It permits volume/snippet deletion,
so explicit owner risk acceptance and aligned sealed observation bindings are
required before activation. The bridge's implicit MTU needs a no-op import phase
before separately reviewing explicit MTU configuration/reload. Old partial VM disk
state needs independently approved provider state repair, not an allowlist bypass.
Original role imports must be no-op before separately updating privileges; stage
any fresh readback override privately using native OpenTofu overrides, not a
policy bypass. Desired `Sys.Modify` moves from the global apply role to a node-only
role/ACL, and global cluster options are declared in the owner root. Cluster
firewall mutations retain their separate state root but require independent owner
Proxmox apply credentials after this change. Align both principals' approved
observer bindings before post-activation admission. Nothing is activated merely
because these declarations and CI validation exist.
The normal AWS grant manifest intentionally excludes its key. See
[Proxmox ownership](proxmox-ownership.md) for durable resource boundaries and
remaining API readback gaps.

## Physical Kobo continuity

Physical-device resume and native annotation continuity remain unqualified
independently of Grimmory catalog operation. The accepted
[Kobo authorization exception](security.md#grimmory-account-and-device-access) is
separate from device continuity. Before changing or re-syncing either device, take
a fresh protected backup of configuration, SQLite/WAL state, downloaded books and
annotations; inspect a working copy and preserve originals until the owner
separately approves disposal. Device backups are outside the managed `books`
Restic scope; verify their existence before relying on them.

Legacy UUID-based entitlements and KEPUB output can differ from Grimmory identities
and conversion output. Qualify duplicates/deletions, selections, collections,
statuses, percentages, exact resume passages, annotations and round-trip progress
on one backed-up device before the second. Stored percentages and archived annotations do not prove exact resume or
native annotation parity. Never automatically reset or delete device content.
For disposable qualification work, follow the [workspace lifecycle](../AGENTS.md).

## AWS recovery-key and separate backup identity

The recovery KMS key was scheduled for deletion under independent AWS owner
custody. Verify its **current** state and dependencies with that owner. Keep the
independently owned `s3-backup-user` and inactive key until AWS confirms final
key deletion and a separately approved owner cutover confirms no consumers.
Do not infer nonuse from IAM last-used timestamps, a single host, or a past
bucket inventory. Before changing this identity, verify independent custody of
required encrypted recovery material and a fresh private restore; privately
review its policy attachments and all consumers. Only the independent owner
may approve credential revocation, policy detachment or deletion. Preserve
protected state versions and any nonterminal owner records outside Git.

## Recovery activation

[Recovery](../recovery/README.md) supports fresh snapshot discovery and verified
private staging, **not** production data activation. A reusable activation
procedure must define writer exclusion, database validation, external storage,
before-images, rollback and post-activation health before production restore.

## Authentik notification recipient policy

Decide whether `default-notify-configuration-warning` should notify administrators
or be intentionally suppressed. Its recipient policy is outside the Authentik
adoption scope. Reobserve the live rule, event-user destination and policy bindings
before proposing a separately approved notification change.

## Deferred ingress qualifications

Actual ephemeral CI/application access, isolated authenticated GOST destination
denials (without a client-side bypass), and private-route UDP/HTTP3 negatives
were not qualified as part of the prior ingress change. Test these against
fresh live state before relying on those boundaries. System PAC on the work Mac
is off; its reported CLIProxyAPI/Omada access is not a browser-path test.
