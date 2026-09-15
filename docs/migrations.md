# Outstanding migrations and adoption

These are retained hazards and next adoption boundaries, not permission to run
mutations. The [September 14 read-only observation](operations.md#observed-baseline--2026-09-14)
updates selected installed-state assumptions; it does not close migration or
rollback-retirement checks.

## Authentik PostgreSQL

**PostgreSQL 18 is already in use.** On September 14 the running Authentik database
container mounted `/srv/home-lab-state/authentik-data/postgresql` at
`/var/lib/postgresql`, containing `18/docker/PG_VERSION=18`. The retained
`postgresql-16/PG_VERSION=16` was also present. Do not rerun the forward migration.

Keep the [PostgreSQL 16 → 18 runbook](authentik-postgres-18-migration.md) for
migration provenance and rollback constraints. Verify functional acceptance,
backup/restore coverage and custody of the dump/cold copy before retiring the old
directory or closing rollback. Those checks were not performed by observation.
No generic Compose update or automatic database rollback is safe here. Future
artifact publication needs a native implementation, not the removed controller.

## Nextcloud, Calibre and Caro

Keep the [Nextcloud five-mount/configuration and rollback procedure](nextcloud-34-configuration.md)
and its paired playbooks/roles. External data at
`/mnt/storage/media/nextcloud/data` stays mounted in place: never copy into, restore
over or recursively delete it with managed application state. Keep old NFS
application/config/custom-app/theme copies for seven days after full recovery,
rollback and user-data proofs. Cron activation, database maintenance and exact
old-path/log cleanup remain separate approvals.

The old Nextcloud procedure predates Offen retirement. Its references to the two
Offen schedulers and fixed service counts are historical, not current startup
instructions. On September 14 both Nextcloud and its cron container were running
with the five intended mounts; cron therefore is not awaiting initial activation.
Do not rerun forward migration/start steps. Verify application integrity, retained
old copies and remaining rollback requirements before claiming completion. Use the
actual Restic timers and service set; do not reinstall or start Offen.

The complete Calibre library (`metadata.db`, books and covers) belongs at
`/srv/home-lab-state/calibre-data/books` and is included in Restic. The NFS copy is
retained as a rollback source. Caro application/database state belongs at
`/srv/home-lab-state/caro-tachidesk-data`; only downloads use
`${MEDIA_PATH}/caro-tachidesk`. The preserved-data forward migration is historical;
do not rerun it simply because its recovery-dependent role remains.

The 2026-08-27 Calibre local correction recorded artifact
`2468c26a15c921877da3d1ca6887cd9c2e81be1f467873d9f9edc1386782c6db`,
2,195 files, 8,004,800,651 bytes and 1,063 ebooks plus `metadata.db`, with snapshots:

- games `91e4e2378de3ae97efa075468ac0334fec80b324c7c8df664b05089f1254390f`;
- NFS `32f2e3c378df0238c3e99da59701dc7e33fe73a13f88eda01b02f0c1e2f4e9ed`;
- Proton `41f4fac702126014bb6989b09dd158a2f9a3c56e4a99440df799bb55e4a28d55`.

The retained `compose_deploy` role contains the interrupted Calibre lane, bound to
`rollback-calibre-to-local:<artifact-hash>`. It requires exact three-consumer and
two-policy-file scope, endpoint/device/UUID identity checks, stops both Restic
timers, holds the backup mutex, reconciles NFS into local with checksum/delete
semantics, checks zero difference and SQLite integrity, then activates policy
before container convergence. A resume must adopt only the exact retained owner
and repeat all guards. The general deploy entrypoint was already non-operational
and is removed; the retained role is **not** a newly supported standalone recovery
command. A separately reviewed recovery invocation is needed for an actual retained
operation; preserve its inputs meanwhile.

## Retired LiteLLM deployment lane

The callback/config remain; the dedicated source-only approval/transport lane is
removed rather than carried into native delivery. Its installed success was not
established. Preserve any `/var/lib/docker-compose/.litellm-<document-sha256>`
attempts and `/srv/docker-compose/.litellm-<plan-sha256>/` recovery sets, current
and previous artifacts/environments, image locks/override and old marker. The
previous generation was deliberately untouched by that lane. Failure after
publication can leave new files with old/failed processes; a lost result does not
prove the host failed. There was no automatic rollback/resume lane. Inspect actual
host/process/owner state and get a recovery decision; never retry or clear an owner
based only on delivery failure. Native replacement must explicitly recreate
LiteLLM for changed bind-file contents and distinguish liveness from provider/model
usability.

## Provider and host adoption gaps

- **Proxmox VM100:** `scsi1` games, `scsi2` state, `scsi3` boot and `ide2` cloud-init
  identities stay fixed. The production HCL does not fully model the boot disk;
  ignored disk-list positions encode adoption history. Do not reorder/remove the
  tombstone or change addresses/imports. Existing image/snippet prerequisites and
  the stale candidate move require separate state-aware adoption, not cosmetic cleanup.
- **Tailscale:** the Tofu root is a `terraform_data` placeholder, not a policy
  writer. The universal reconciler that issued policy API writes is removed.
  Native provider adoption/import and concurrency semantics remain follow-on work;
  running the current root will not converge tailnet policy.
- **Omada:** the LAN/reservation root reads a private export. Verify imports,
  desired ownership, TLS/CA and certificate hostname (`Omada`) before replacing
  that input. Setting management false after adoption may propose destruction.
- **Authentik API:** source expects 23 applications/18 proxies/5 OAuth providers/
  28 bindings; historical adoption reported 25/19/6/30 and 85 imported objects.
  Verify actual desired and imported identities before plan. Factory objects and
  users/groups/runtime identities remain database-owned. Proxy factory mapping
  membership is deliberately omitted from resource configuration. Client secrets
  remain encrypted separately and also occur in protected resource state; tokens
  are ephemeral inputs. Historical token expiry was `2026-11-25T19:16:43Z`—verify
  current credentials privately rather than assuming they still work.
- **Access/host convergence:** native SSH/become observation now works over the
  existing Tailscale route; no account/key changes were needed. Retain other routes
  and verify independent console access before risky work. The approved native
  `update-policy.yml` corrected Debian unattended apt installation and Proxmox
  Tailscale auto-apply on September 14; checks remain enabled and the second run
  was unchanged. Other host domains and legacy bootstrap policy still need adoption.
- **Recovery/VM9900:** VM9900 was observed present and stopped on September 14;
  preserve failed qualification and state ownership. Separate local backends do
  not isolate two roots using the same VMID on production PVE. Stopped state alone
  does not authorize reuse or destruction.
  Fresh boot and end-to-end production activation remain unqualified.
