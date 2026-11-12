# Outstanding work

This lists unresolved **decisions**, not migration receipts. Reobserve the host,
remote state, provider and backup repositories before acting; Git history is not
proof of current state.

## Proxmox host and provisioning qualification

Native control-plane ownership does not qualify cold guest provisioning,
reinitialization or storage activation. Preserve independently tested console
access, verify affected-data recovery and inspect current consumers before
separately reviewing those operations. Native snippet readback does not remove
legacy credentials from a running guest.

ZFS topology/property drift, the storage `mountpoint` setting, complete APT
repository/signing-key policy and the firewall's omitted forward-policy readback
remain outside the pinned provider's complete coverage. Preserve native host
observation and Ansible/systemd ownership rather than adding competing or
experimental writers. See [Proxmox ownership](proxmox-ownership.md) for the durable
boundaries and API gaps.

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

## Recovery activation

[Recovery](../recovery/README.md) supports fresh snapshot discovery and verified
private staging, **not** production data activation. A reusable activation
procedure must define writer exclusion, database validation, external storage,
before-images, rollback and post-activation health before production restore.

## Complete-backup runtime qualification

The complete staged-capture source is not a production installation receipt.
Before separately approving installation/cutover, reobserve the selected data,
source-pool health and protected staging/repository capacity. Qualify Nextcloud's
SQL-export/snapshot/restart window, Tailscale-interface-bound snapshot RPC socket,
allowed/denied peers, host-namespace worker lifecycle and temporary read-only NFS
export. This does not delegate SSH, SFTP or forwarding access.
The snapshot covers the existing shared dataset; dataset isolation is deferred,
not permission to migrate data or broaden exports. New source snapshots refuse an
unhealthy pool; an independently approved rescue capture is not a standing bypass.
Measure stop/copy/restart windows for other large coupled trees rather than
assuming online SQL exports make those files atomic or interruption-free. Exercise
native mounted-source capture, lost acknowledgements, ready-source retry,
completion cleanup and 72-hour abandonment on disposable infrastructure before
installing the scheduled path; mock ZFS tests alone do not qualify it.

Qualify native PostgreSQL/MariaDB imports, Jellyfin archive restoration and
representative application/user files from the same full capture. Verify selected
Wolf saves/settings (including per-game paths outside standard Proton user
folders), resolved links and refusal during active game sessions. Do not expand
coverage to entire Steam installations or all Proton prefixes to avoid mapping
that boundary. Confirm both production ACME account keys in private staging.

Enable Z-Wave's native NVM schedule only through its separately approved restart
interface, verify actual fresh NVM output, and qualify supported ZHA/Z-Wave
recovery for the hardware. Install the new native units/tools only after reviewing
ownership, current repositories and interruption state. Establish matching NFS and
Proton baseline copies before enabling deployment admission. Exercise interrupted
capture/upload/copy, deferred retention and ordinary deployment during replication
on disposable infrastructure first; qualification is not permission to activate
production restore. Keep independent recovery tools, keys and required backups.

## Authentik notification recipient policy

Decide whether `default-notify-configuration-warning` should notify administrators
or be intentionally suppressed. Its recipient policy is outside the Authentik
adoption scope. Reobserve the live rule, event-user destination and policy bindings
before proposing a separately approved notification change.

## Host-local deployment qualification

Observe the first wall-clock timer activation as operational follow-up. Native
timer tests and a successful live composed backup/deployment chain establish
ordering and execution, but do not themselves observe the scheduled activation.
Verify terminal backup phases, exact-SHA CI admission, unchanged manual-backup
behavior, healthy convergence and cleanup without automatically clearing failed
production ownership. Preserve independent custody of the host decryption identity.

## CI operational integration

Wire the useful dormant controller tests into CI:

- `scripts/controller/test-gost-private-subdomain-boundary.test.cjs`;
- `scripts/controller/test-mindwtr-service.test.cjs`;
- `scripts/controller/test-traefik-ingress.test.cjs`;
- `scripts/controller/test-traefik-tailnet.test.cjs`;
- the controller-only cases in `scripts/controller/test-proxmox-controller-observer.py`.

Keep native APT cases separately opt-in: they require the approved, isolated Linux
fixture, not a deployment host. Source/configuration tests do not replace live
application access or negative-path qualification.

## VFIO recovery ownership

Before retiring or re-adopting the VFIO recovery source, independently inspect the
installed Proxmox helper, policy, consumers and retained owners. The repository
helper has no declarative installation entrypoint; do not infer nonuse from that
absence or delete the recovery path merely to tidy the checkout. Resolve installed
and source identities before choosing an owner and qualifying recovery behavior.

## Deferred ingress qualifications

Isolated authenticated GOST destination denials (without a client-side bypass)
and private-route UDP/HTTP3 negatives remain unqualified. Test these against
fresh live state before relying on those boundaries. System PAC on the work Mac
is off; its reported CLIProxyAPI/Omada access is not a browser-path test.
