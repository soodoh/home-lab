# Authentik PostgreSQL 16 to 18 migration

**Historical forward procedure: do not rerun on the current installation.**
The September 14 observation found the running database using the PostgreSQL 18
layout and the old PostgreSQL 16 directory retained. See [remaining acceptance and
rollback checks](migrations.md#authentik-postgresql); observation did not verify
functional acceptance or backup/restore integrity.

## Purpose

PostgreSQL 18 cannot open the PostgreSQL 16 data directory directly. The official
image also changed its persistent-data layout:

- PostgreSQL 16 stores data at `/var/lib/postgresql/data`;
- PostgreSQL 18 stores data at `/var/lib/postgresql/18/docker`; and
- PostgreSQL 18 expects the persistent volume mounted at `/var/lib/postgresql`.

The [`services/authentik.yml`](../services/authentik.yml) change required a logical
dump/restore, not an image-only deployment. The original forward commands are in
Git history for this file (baseline `1165675`), not a current setup procedure.
The procedure required stopping Authentik/Redis writers before dumping, validating
the dump's table of contents, stopping PostgreSQL, preserving the old cluster,
initializing 18 and restoring with `pg_restore --exit-on-error --clean --if-exists --create`.
It required analyze to rebuild optimizer statistics and comparison of extensions,
public-table counts and `django_migrations` counts against the stopped source before
starting applications. This is procedural provenance, not completed acceptance proof.

## Deployment boundary

There is no supported general deployment entrypoint today. Artifact staging,
publication and rollback invocation require separate review and approval. Do not
use the removed controller or retained roles as an implicit replacement.

Preserve all three sensitive, root-only rollback inputs:

1. the custom-format `authentik-postgres-16.dump` and its validated `.toc` in the migration directory;
2. the original cluster renamed to `postgresql-16` inside `authentik-data`;
3. the cold copy in the separate Docker backup volume.

Preserve before/after extension/count records, the exact PostgreSQL 16 image and
both generations' artifacts/environments/image locks. Do not delete any input
until the rollback window closes and a new encrypted backup is independently verified.

## Historical rollback inputs

The rollback example below describes **pre-promotion** identities. They must be
recovered from the exact retained migration, not inferred from today's container
or substituted with the current bind mount. The original procedure derived
`old_image` and `authentik_volume` from the stopped PostgreSQL 16 container,
required `postgres:16-alpine@sha256:*` and the `authentik-data` Compose volume
label, then made the cold copy with no network and a read-only source mount.
It refused an existing backup volume or `postgresql-16` destination.

These Bash definitions preserve the original example's variable context; they
are not an instruction to recreate staging or a migration directory. The final
volume/image lookups apply only to the original stopped PostgreSQL 16 container,
not today's PostgreSQL 18/bind-mounted installation:

```bash
sudo -i
set -euo pipefail
umask 077

project=docker-compose
candidate_hash='<reviewed-artifact-sha256>'
current_root=/srv/docker-compose/current
current_env=/etc/docker-compose/production.env
candidate_root="/srv/docker-compose/staging/$candidate_hash"
candidate_env="/etc/docker-compose/staging/$candidate_hash.env"
migration_root="/var/lib/authentik-postgres-migration/$candidate_hash"
backup_volume="authentik-postgres-16-backup-${candidate_hash:0:12}"

current=(
  /usr/bin/docker compose
  --project-name "$project"
  --project-directory "$current_root"
  --env-file "$current_env"
  --file "$current_root/docker-compose.yml"
)
candidate=(
  /usr/bin/docker compose
  --project-name "$project"
  --project-directory "$candidate_root"
  --env-file "$candidate_env"
  --file "$candidate_root/docker-compose.yml"
)

[[ $candidate_hash =~ ^[0-9a-f]{64}$ ]]
[[ -d $current_root && -d $candidate_root && -d $migration_root ]]
[[ -f $current_env && -f $candidate_env ]]
[[ $(stat -c '%U:%G:%a' "$current_env") == root:root:600 ]]
[[ $(stat -c '%U:%G:%a' "$candidate_env") == root:root:600 ]]
cmp --silent "$current_env" "$candidate_env"
[[ $(python "$candidate_root/scripts/compose-artifact.py" \
  --root "$candidate_root" --no-git hash) == "$candidate_hash" ]]
old_image=$(docker inspect authentik-postgres --format '{{.Config.Image}}')
authentik_volume=$(docker inspect authentik-postgres --format \
  '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')
[[ $old_image == postgres:16-alpine@sha256:* ]]
[[ -n $authentik_volume ]]
[[ $(docker volume inspect "$authentik_volume" --format \
  '{{index .Labels "com.docker.compose.volume"}}') == authentik-data ]]
```

An approved invocation must establish `authentik_volume` from retained evidence,
verify the exact 64-hex candidate artifact hash/content, existing paths, root:root
0600 environments and root-only migration directory, and use root with
`set -euo pipefail` and `umask 077`. The original environments had to be byte-equal:
a database migration must not be combined with secret/configuration changes.
`current` meant PostgreSQL 16 and `candidate` meant PostgreSQL 18; those meanings
no longer follow automatically from these paths after publication. The historical
18 image was `postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.

## Functional acceptance

Before declaring the migration accepted or retiring rollback:

- verify PostgreSQL health, `PG_VERSION=18` and `PGDATA=/var/lib/postgresql/18/docker`;
- verify Redis/server health and a running worker;
- compare the retained extension/schema-count records;
- log in to the Authentik admin interface and load dashboard/directory objects;
- authenticate through at least one protected application;
- check PostgreSQL/server/worker logs for restore or migration errors without disclosing sensitive output;
- verify Home Assistant remains healthy;
- verify the active artifact is idempotent and proposes no further PostgreSQL recreation.

## Rollback before candidate promotion

**Historical example only:** review all inputs above before any recovery invocation.
Rollback loses writes accepted by PostgreSQL 18 after cutover. Keep writers/users
out throughout the reviewed maintenance window; retain the failed 18 cluster.

```bash
"${candidate[@]}" stop authentik-server authentik-worker redis postgres

new_image=$(docker inspect authentik-postgres --format '{{.Config.Image}}')
docker run --rm --network none --entrypoint sh \
  --mount "type=volume,source=$authentik_volume,target=/volume" \
  "$new_image" -ec '
    test "$(cat /volume/postgresql/18/docker/PG_VERSION)" = 18
    test "$(cat /volume/postgresql-16/PG_VERSION)" = 16
    test ! -e /volume/postgresql-18-failed
    mv /volume/postgresql /volume/postgresql-18-failed
    mv /volume/postgresql-16 /volume/postgresql
  '

"${current[@]}" up --detach --no-deps --force-recreate postgres
for _ in $(seq 1 60); do
  status=$(docker inspect authentik-postgres --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  [[ $status == healthy ]] && break
  sleep 2
done
[[ $status == healthy ]]
"${current[@]}" up --detach redis authentik-server authentik-worker
```

If the candidate has already been promoted, stop all Authentik writers before
changing directories and separately review how to restore the exact PostgreSQL 16
artifact. This document does not supply a qualified post-promotion invocation.
Never start PostgreSQL 16 against the PostgreSQL 18 directory.

## Cleanup

Keep all three rollback inputs until the artifact is active/idempotent, functional
acceptance passes, and a new encrypted scheduled backup containing PostgreSQL 18
has completed with independently verified integrity/restore coverage. The original
archive ciphertext/checksum-replica checks are historical; they do not substitute
for [current Restic recovery verification](../recovery/README.md).

Both `postgresql/18/docker` and retained `postgresql-16` consume backup storage
during the rollback window. Only after an explicit rollback-retirement decision
may the exact reviewed old subdirectory, migration backup volume and root-only
migration directory be removed. Never use an unrestricted volume prune.

## References

- [Authentik: Upgrade PostgreSQL on Docker Compose](https://docs.goauthentik.io/troubleshooting/postgres/upgrade_docker/)
- [PostgreSQL Docker image `PGDATA` change](https://github.com/docker-library/docs/blob/master/postgres/README.md#pgdata)
- [PostgreSQL 18: Upgrading a cluster](https://www.postgresql.org/docs/18/upgrading.html)
