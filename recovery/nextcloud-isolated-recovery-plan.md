# Nextcloud isolated logical recovery plan

## Purpose and claim boundary

This plan closes the remaining Nextcloud database/application recovery prerequisite
without touching production. It is a design and review artifact only; it does not
authorize target provisioning, credential decryption, repository access, data
transfer, container startup, live acceptance, rollback, cleanup, or source retirement.

Keep three claims separate:

1. **Logical database recovery:** a writable copy of the restored MariaDB tree starts
   under the pinned image and passes logical checks.
2. **Isolated application control-plane recovery:** pinned Nextcloud starts against
   that database and reports the expected installed version and schema state without
   public ingress or external side effects.
3. **User-data and production acceptance:** login, WebDAV, representative file reads,
   reversible upload, proxy behavior and cron are separate proofs. The Restic snapshot
   does not contain `/mnt/storage/media/nextcloud/data`, so the first two claims cannot
   establish user-file recovery or full service RTO.

Do not report this plan or a later database-only rehearsal as the broader Gate 2
fresh-server qualification in
[`recovery-readiness-assessment.md`](../docs/recovery-readiness-assessment.md).

## Admitted inputs

Bind any execution to these reviewed identities rather than `latest`, mutable tags or
checkout defaults:

| Input | Required identity |
| --- | --- |
| Games snapshot | `abbf7d3543bb031ab80d97b69dde24de3b8c1a23ad47e4bb8c471a8dbbde128f` |
| Games repository | `b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f` |
| Restic policy | `81b1f0dd0f1a2fd596c13ee3b6a79e7bb181ae5d0b80e3e942ab69f96d77a6ff` |
| Snapshot artifact | `2f12e384fdc0ce759d23b0bd9e16ad402d3ecd2985b4ecdfe048127f1c5748be` |
| Scoped-equivalent active artifact | `3e5600bfa5ff9441d729e4e81634854435cea13f15568337adbc87911468569e` |
| Restore outcome evidence | `infrastructure/evidence/restic-restore-rehearsal-2026-09-19.json` |
| Nextcloud image | `nextcloud:34.0.2-apache@sha256:d7666d54d87c58d52869ddda36d1acbd4a7f53faf8ab6b91293daf204f3434e8` |
| MariaDB image | `mariadb:lts-ubi9@sha256:29dd37f5df222f7c2668b51d412536ffeff0efc4d4b68d849e9bcead913bffe0` |
| Redis image | `redis:8.2-m01-alpine@sha256:73785dd3f61435fbea1a14bafd2c6509f9df112f50953e09eb31c94717c77e76` |
| Expected application state | Nextcloud `34.0.2.1`, installed, maintenance disabled, no database upgrade required |

The completed private staging tree at
`/srv/home-lab-recovery/restic-migration-retirement` is canonical evidence, not a
writable database target. Never start MariaDB or Nextcloud against it and never pass
it to `activate-recovered-data.py`.

## Target admission

Do not run this rehearsal on VM100. Its retained staging tree consumes approximately
19.35 GB and leaves only approximately 6.12 GB free, which is not safe capacity for a
writable database copy, container layers and failure retention.

Admit a fresh isolated target only when all of these are reviewed:

- a unique non-production VM or equivalent identity, with no collision with VM100 or
  retired VM9900;
- at least one blank **64 GiB** private disk for the restored snapshot, writable
  database copy, regenerated application root, image layers, logs and safety margin;
- additional independently sized private storage if representative external user data
  will be tested;
- no production NFS mount, Docker socket, Tailscale identity, host SSH key, DNS name,
  MAC address, Compose project name, credentials, cache, or state directory;
- default-deny reachability to the production LAN, VM100, Proxmox management, SMTP,
  DDNS, webhooks, federation endpoints and public ingress;
- only explicitly approved retrieval egress during restore, removed before service
  startup;
- console access plus one ephemeral qualification identity; and
- an exact destroy plan limited to the admitted target and disks.

If the target shares the production hypervisor or storage pool, record that remaining
fault-domain risk.

### September 19 target survey

An authorized native read-only survey found VMID 9000 unused, VM100 as the only
running guest, VM9900 absent, and sufficient 64 GiB disk capacity on `local-lvm` and
the `storage` ZFS pool. `local-lvm` is the preferred disk candidate because using the
production `storage` pool would add an avoidable shared-data fault domain. The node
reported 13,829,181,440 bytes free memory; guest allocation and required host reserve
remain unadmitted.

The target is **blocked** because `vmbr0` is the only bridge and has a physical port;
there is no active isolated bridge. Do not treat attachment to `vmbr0` plus an
unreviewed firewall toggle as equivalent isolation, and do not create a bridge, VLAN,
firewall policy or guest under this survey authority. A reviewed network design must
provide retrieval-only egress followed by startup-time default denial before VMID
9000 can be admitted. The reviewed
[detached-NIC isolation design](nextcloud-detached-nic-isolation.md) conditionally
avoids a new bridge by requiring firewall-confined retrieval and provider-verified
physical NIC removal before service startup. Secret-free survey evidence is recorded
in [`nextcloud-isolated-target-survey-2026-09-19.json`](../infrastructure/evidence/nextcloud-isolated-target-survey-2026-09-19.json).

## Protected inputs

Use the independent recovery path, not files copied from VM100. Decrypt the exact
SOPS generation only inside root-owned tmpfs with shell tracing disabled. Materialize
only the database application and root password files, mode 0600, one link, and delete
them after the target is destroyed. Never print their paths together with values,
place values on command lines, or commit rendered Compose configuration.

The exact artifact and image-lock generation must be independently available on the
target. Verify hashes before reading it. Do not reuse `/etc/docker-compose`, the
production environment file, or production container names.

## Phase 1 — restore into immutable input

This phase requires separate authorization.

1. Re-observe the selected snapshot and repository identities without selecting
   `latest`.
2. Restore with native `restic restore --verify` into a new root-owned mode-0700
   input directory on the isolated target.
3. Compare the Nextcloud database, config, custom-app and theme path/type/size
   manifests to the recorded snapshot listing.
4. Mark the restored input read-only and record its device/inode, manifest hashes and
   total bytes.
5. Confirm that no external Nextcloud data tree was restored.

Stop on any identity, manifest, ownership, link, special-file or byte-verification
mismatch.

## Phase 2 — logical MariaDB recovery

This phase requires a new authorization after Phase 1 evidence is reviewed.

1. Copy only `nextcloud-db-data` from immutable input to a new private writable work
   directory. Preserve ownership, modes, ACLs, xattrs and hard links. Never use the
   canonical staging tree as the datadir.
2. Create a distinct Compose project with no `container_name`, no published ports,
   no production mounts and one internal-only network.
3. Start only the pinned MariaDB image against the work copy with
   `--transaction-isolation=READ-COMMITTED`. Supply exact recovered secrets through
   temporary Compose secret files.
4. Refuse automatic schema or application upgrades. `MARIADB_AUTO_UPGRADE` must not
   turn a recovery check into a migration; inspect the image entrypoint behavior and
   use a reviewed check-only startup shape before execution.
5. Require a clean engine startup, exact expected database presence, bounded
   table/schema counts, and native logical checks such as `mariadb-check` against all
   recovered databases. Record no table names, users, SQL values or credentials.
6. Shut down cleanly, require zero running containers, preserve logs and the work copy
   for review, then prove the immutable input manifest is unchanged.

A successful engine start plus logical checks qualifies the database copy only. It
does not establish application or user-file recovery.

## Phase 3 — isolated Nextcloud control plane

This phase requires another authorization after the database proof.

1. Reconstruct a new application root from the pinned Nextcloud image without running
   the web entrypoint, then bind the recovered config, custom apps and themes from
   separate writable work copies.
2. Use a fresh ephemeral Redis instance. Do not restore production Redis state.
3. Start MariaDB, Redis and Nextcloud in dependency order on the internal network.
   Do not start cron, Caddy or any mail/federation helper and do not publish a host
   port.
4. Do not mount production external data. A control-plane-only run may use an
   explicitly labeled private placeholder sufficient for bounded `occ` checks, but
   must report external data as unavailable. It must not claim file recovery.
5. Run only bounded local checks as `www-data`:
   - `occ status --output=json`;
   - installed version exactly `34.0.2.1`;
   - maintenance disabled;
   - no database upgrade required;
   - selected setup-check category counts, without URLs, paths or private values.
6. Reject any attempted SMTP, webhook, federation, DDNS, public ingress or production
   network connection. Capture aggregate network-denial evidence.
7. Stop cleanly and prove immutable restored inputs unchanged.

Do not run `occ upgrade`, repair, missing-index installation, arbitrary queued jobs,
cron, or an upload during this phase.

## External user-data decision

Full authenticated read/WebDAV testing requires an independently recoverable copy of
representative `/mnt/storage/media/nextcloud/data` content with matching database
metadata. That tree is classified `external` and is absent from Restic. Choose one of
these in a later reviewed decision:

- establish an independent external-data backup and restore path, then use its private
  restored copy in the isolated target; or
- explicitly accept that disaster recovery is limited to application/database state
  and that user-data service RTO remains unqualified.

Never mount the production NFS tree into the isolated rehearsal, even read-only:
Nextcloud startup and apps may attempt metadata writes, and shared storage would
invalidate the isolation claim.

## Production acceptance and retirement gate

After isolated database/application proof, production acceptance still requires its
own approval: login, representative listing/read, WebDAV, reversible upload, proxy
headers/HSTS and two observed cron cadences. Record only aggregate outcomes.

Only after those proofs may a source-retirement review consider:

- removing the historical Nextcloud forward-migration branch;
- replacing or removing the stale 41-service rollback play;
- deleting old NFS application/config/custom-app/theme copies after the seven-day
  retention and exact private cleanup manifest; and
- retiring legacy Compose model/action/recovery helpers with no remaining callers.

## Evidence and cleanup

Record timestamps, target identity, input hashes, image digests, bounded counts,
logical-check outcomes, network-denial results and immutable-manifest comparisons.
Never record database rows, usernames, filenames, secrets or rendered configuration.

Target shutdown is not target deletion. Preserve failed workspaces for diagnosis.
Destroy only the reviewed isolated project, credentials, VM and blank disks after an
explicit cleanup decision. The existing VM100 staging tree and production/NFS data are
outside that cleanup authority.
