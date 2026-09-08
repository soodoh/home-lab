# Inactive workload definitions (source slice, not readiness)

Both hosts already have Ansible ownership. This is one bounded implementation
slice toward the **entire** migration, not replacement acceptance or a new cutover.
ADR 0001 and its shared-hypervisor amendment govern operations; ADR 0002 defers
reporting. No deployment, qualification retry or live observation is authorized
by these declarations. VM 9900's failed qualification remains failed. Preserve
VM 100's `scsi3;net0`, absent retired `scsi0`, all production disks, application
state, credentials and backup receipts; none are fixture inputs.

## Closed declaration API

`site.yml` dispatches inactive `docker` and `compose` task groups only for `inert`
or `recovery`, behind the existing lifecycle/apply guards and host lock. The
production role bodies are unchanged. Exactly one explicit tag is required in
**check mode too**: broad inactive `--check` now refuses at these task groups.

- `docker`: only `/etc/systemd/system/docker.service.d/10-home-lab-storage.conf`,
  plus its exactly named missing `docker.service.d` directory. No other ancestry
  is created or repaired.
- `compose`: only `home-lab-compose.service`, the retained
  `home-lab-production-guard.service`, and its helper. The guard is an explicit
  Compose prerequisite, not an unrelated tag side effect. No Docker drop-in is
  published by this tag.

The existing service roles import one transaction-role admission/publication
seam. There is no caller-supplied selector, free-form file list or generic unit
framework. `debian.systemd` is a closed contract section; schema constants bound
the supported renderer. Templates consume that contract directly, reusing
`debian.transaction.compose_command` and `production_systemd_dependencies` rather
than a second argv/graph authority. Descriptor paths, source paths, modes, tags,
descriptions, policy, helper digest and command/graph grammar are checked before
host observations/effects. Internal observed registers are trusted Ansible
execution data, not an independently authenticated observation capability.

The three rendered definitions preserve the reviewed service semantics, including
oneshot/remain-after-exit, HOME=/root, no-pull Compose start, bounded stop, guard
and all protected mount dependencies, network-online ordering, and the guard's
existing Before list (including Tailscale). Dependency list order follows the
contract; it need not reproduce the order in sequential `systemctl cat` streams.
The five-unit/two-drop-in capture was framing, not per-file native byte/mode or
loaded-body proof. No vendor Docker service/socket bodies are copied or read.

## Admission and publication

One full pass admits all four Home Lab assets and the guard, Compose, Docker and
vendor socket units **before any directory/file effects**, regardless of which
tag publishes. Only absent files may be copied (`force:false`, `follow:false`);
existing files must already have exact rendered bytes, root:root ownership,
single-link regular metadata, and the contracted mode. Divergence is a refusal,
not a repair. Final selected-file digests verify on-disk publication only.

The supported topology is the fixed systemd search-root list from the admission
tasks. All those roots are scanned, even if omitted by the manager; extra manager
roots refuse. Only the exact root-owned `/lib -> usr/lib` merged-usr alias is
admitted when the manager names `/lib/systemd/system`. Required parents, including
`/usr/local/sbin`, must already exist and be safe. Optional parents/roots may be
absent. No arbitrary ancestry repair occurs.

Type, applicable dash-prefix and exact-unit overrides, competing fragments,
masks, aliases, unsafe or incomplete root/pull-in discovery, and named or aliased
wants/requires/upholds entries (including dangling enable links) refuse. Only the
retained Docker `10-...` file is admitted in its safe exact directory. Guard and
Compose `.d` directories are conservatively refused, even empty.

**Ordering limitation:** the capability lane's `50-home-lab-production-dependencies.conf`
files are not admitted by this slice. Install durable definitions before that
separate lane. This intentionally lacks general post-capability rerun/recovery
closure rather than accepting insufficient effective-definition evidence. The
capability executor, policy, dependency graph and reload behavior are unchanged.

All four units must be inactive/dead, unaliased, unqueued and absent or explicitly
static (guard)/disabled (others) at their supported fragment paths. Cached
active/exited guard or Compose state refuses. Known Home Lab fragments may be
on disk while still not-found in the manager: this is deferred publication, not
loaded readiness. Vendor fragments must be absent with not-found observations,
or safe root:root0644/nlink1 regular files at their designated `/usr/lib` paths
with consistent loaded/disabled/inactive/dead observations. This is **path,
ownership and inactivity admission only**, not package provenance, vendor-body
identity, Docker socket safety or installed readiness. The socket is also in the
existing lifecycle inactive audit; the retained guard is now explicitly included.

Gate/ancestry/vendor/alias metadata stats disable checksums, MIME and attribute
probes and use `follow:false`. Known Home Lab asset digests are the only content
reads in admission. Absence of the storage token and both legacy guard gates is
required by metadata only, after other admission. Neither legacy gate is created,
read for content, adopted, removed or used as an activation authorization.

## Retained guard and remaining qualification

The helper is retained exactly: 234 bytes, SHA256
`ebaef168ef89defe8806237272d77a5c0dee4f62749896cc7a1955d2f6201be6`, source/install
mode0755. Separately approved read-only capture observed root:root0755/nlink1.
Its Bash/jq/PATH behavior is unchanged: legacy format/committed activation record
OR the `/run` transaction flag. No test executes it, including on the controller.
Bash syntax validation is not execution. Neither referenced production input was
read; tests model only synthetic presence metadata.

jq readiness, fresh guard execution, cached-success behavior under native
systemd, compatibility with the newer transaction/marker publication order, and
the Tailscale access/bootstrap circularity remain **unqualified**. Copying this
helper closes none of those gates. No package installation/query, service
start/stop/enable/disable/reload, Docker invocation, mount/device probing,
credential handling or marker/token publication is part of this slice.

Pathname checks assume trusted cooperating ancestry and the existing host lock;
`stat follow:false` can still resolve symlink metadata and is not descriptor
confinement. Observations and multi-file publication are non-atomic. Partial
publication, a later unrelated reload, concurrent manager changes, reboot, and
power loss are not made safe by “no reload now.” Failed applies retain their
existing failed lock boundary; no automatic cleanup, rollback, repair or retry is
provided. A new separately reviewed plan is required. Full indirect pull-in and
vendor/runtime body closure, first installation/start, boot and interruption
acceptance require separate native qualification, not modeled fixtures.

The focused controller fixture evaluates actual Ansible imports, tags, conditions,
Jinja and module arguments with closed controller-only effect adapters. Unknown
modules, commands, imports and arguments refuse before dispatch. Synthetic JSON
metadata/events are not native systemd, installation, boot, recovery, activation
or production receipts. Successful test roots may be cleaned; unexpected failures
and standalone planned RED roots are retained.
