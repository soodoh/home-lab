# Authentik PostgreSQL 16 to 18 migration

## Purpose

The PostgreSQL 18 container cannot open the PostgreSQL 16 data directory directly. The official image also changed its persistent-data layout:

- PostgreSQL 16 stores data at `/var/lib/postgresql/data`;
- PostgreSQL 18 stores data at `/var/lib/postgresql/18/docker`; and
- PostgreSQL 18 expects the persistent volume to be mounted at `/var/lib/postgresql`.

The Compose change in [`services/authentik.yml`](../services/authentik.yml) therefore requires a logical dump and restore. A normal image-only deployment must not perform this migration.

This procedure preserves three rollback inputs:

1. a PostgreSQL custom-format logical dump;
2. the original cluster renamed to `postgresql-16` inside `authentik-data`; and
3. a cold copy in a separate Docker volume.

The dump and cold copy contain sensitive Authentik data. Keep them root-only and delete them only after the rollback window closes and a new encrypted backup is verified.

## Deployment boundary

Stage and review the exact committed Compose artifact through the normal repository-driven deployment flow, but do **not** converge the PostgreSQL service yet. The active artifact must still describe PostgreSQL 16 while the staged candidate describes PostgreSQL 18.

Run the migration on the Docker host as root. Substitute the reviewed candidate artifact hash below:

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
[[ -d $current_root && -d $candidate_root ]]
[[ -f $current_env && -f $candidate_env ]]
[[ $(stat -c '%U:%G:%a' "$current_env") == root:root:600 ]]
[[ $(stat -c '%U:%G:%a' "$candidate_env") == root:root:600 ]]
cmp --silent "$current_env" "$candidate_env"
[[ $(python "$candidate_root/scripts/compose-artifact.py" \
  --root "$candidate_root" --no-git hash) == "$candidate_hash" ]]
install -d -m 0700 "$migration_root"
```

The environment identity check intentionally prevents combining the database migration with a secret or configuration change.

## 1. Verify the current and candidate models

Resolve each Compose model in memory and verify only the PostgreSQL fields required by this migration:

```bash
"${current[@]}" config --format json | python -c '
import json, sys
service = json.load(sys.stdin)["services"]["postgres"]
assert service["image"].startswith("postgres:16-alpine@sha256:")
mount = next(item for item in service["volumes"] if item["source"] == "authentik-data")
assert mount["target"] == "/var/lib/postgresql/data"
assert mount["volume"]["subpath"] == "postgresql"
'

"${candidate[@]}" config --format json | python -c '
import json, sys
service = json.load(sys.stdin)["services"]["postgres"]
assert service["image"] == "postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
mount = next(item for item in service["volumes"] if item["source"] == "authentik-data")
assert mount["target"] == "/var/lib/postgresql"
assert mount["volume"]["subpath"] == "postgresql"
'

[[ $(docker inspect authentik-postgres --format '{{.State.Status}}') == running ]]
[[ $(docker exec authentik-postgres sh -ec 'cat "$PGDATA/PG_VERSION"') == 16 ]]
```

Pull the already reviewed PostgreSQL 18 image before downtime:

```bash
"${candidate[@]}" pull postgres
```

## 2. Stop writers and create the logical backup

Stop Authentik before taking the dump so the migration has a fixed write boundary. Redis is stopped with the application stack, while PostgreSQL remains running for the dump.

```bash
"${current[@]}" stop authentik-server authentik-worker redis

"${current[@]}" exec -T postgres sh -ec '
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align \
    --command="SELECT extname FROM pg_extension ORDER BY extname"' \
  >"$migration_root/extensions-before.txt"

"${current[@]}" exec -T postgres sh -ec '
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align \
    --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = '\''public'\'' AND table_type = '\''BASE TABLE'\''; SELECT count(*) FROM django_migrations"' \
  >"$migration_root/counts-before.txt"

"${current[@]}" exec -T postgres sh -ec '
  exec pg_dump --format=custom --create \
    --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
  >"$migration_root/authentik-postgres-16.dump"

test -s "$migration_root/authentik-postgres-16.dump"
"${current[@]}" exec -T postgres pg_restore --list \
  <"$migration_root/authentik-postgres-16.dump" \
  >"$migration_root/authentik-postgres-16.toc"
test -s "$migration_root/authentik-postgres-16.toc"
```

Stop PostgreSQL only after the dump and table-of-contents validation succeed:

```bash
"${current[@]}" stop postgres
```

## 3. Preserve the physical PostgreSQL 16 cluster

Derive the actual volume and image from the stopped container rather than assuming an engine volume name:

```bash
old_image=$(docker inspect authentik-postgres --format '{{.Config.Image}}')
authentik_volume=$(docker inspect authentik-postgres --format \
  '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')

[[ $old_image == postgres:16-alpine@sha256:* ]]
[[ -n $authentik_volume ]]
[[ $(docker volume inspect "$authentik_volume" --format \
  '{{index .Labels "com.docker.compose.volume"}}') == authentik-data ]]

backup_volume="authentik-postgres-16-backup-${candidate_hash:0:12}"
! docker volume inspect "$backup_volume" >/dev/null 2>&1
docker volume create "$backup_volume" >/dev/null

docker run --rm --network none --entrypoint sh \
  --mount "type=volume,source=$authentik_volume,target=/from,readonly" \
  --mount "type=volume,source=$backup_volume,target=/to" \
  "$old_image" -ec '
    test "$(cat /from/postgresql/PG_VERSION)" = 16
    test -z "$(find /to -mindepth 1 -print -quit)"
    mkdir /to/postgresql
    cp -a /from/postgresql/. /to/postgresql/
    test "$(cat /to/postgresql/PG_VERSION)" = 16
  '
```

Retain the original cluster inside `authentik-data` and create the empty subpath PostgreSQL 18 will initialize:

```bash
docker run --rm --network none --entrypoint sh \
  --mount "type=volume,source=$authentik_volume,target=/volume" \
  "$old_image" -ec '
    test "$(cat /volume/postgresql/PG_VERSION)" = 16
    test ! -e /volume/postgresql-16
    mv /volume/postgresql /volume/postgresql-16
    mkdir /volume/postgresql
  '
```

Do not start the complete Compose project at this point.

## 4. Initialize PostgreSQL 18 and restore

Start only PostgreSQL using the staged candidate:

```bash
"${candidate[@]}" up --detach --no-deps --force-recreate postgres

for _ in $(seq 1 60); do
  status=$(docker inspect authentik-postgres --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  [[ $status == healthy ]] && break
  [[ $status != exited && $status != dead ]] || {
    docker logs --tail 100 authentik-postgres >&2
    exit 1
  }
  sleep 2
done
[[ $status == healthy ]]
[[ $(docker exec authentik-postgres sh -ec 'cat "$PGDATA/PG_VERSION"') == 18 ]]
[[ $(docker exec authentik-postgres sh -ec 'printf %s "$PGDATA"') == /var/lib/postgresql/18/docker ]]
```

Restore the dump with the target database connection set to `postgres`. `--clean --create` replaces the empty database initialized from the unchanged `POSTGRES_*` environment values.

```bash
"${candidate[@]}" exec -T postgres sh -ec '
  exec pg_restore --exit-on-error --clean --if-exists --create \
    --username="$POSTGRES_USER" --dbname=postgres' \
  <"$migration_root/authentik-postgres-16.dump"

"${candidate[@]}" exec -T postgres sh -ec '
  exec vacuumdb --analyze-in-stages \
    --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"'
```

The staged analyze rebuilds optimizer statistics that are not carried by a logical dump. Compare extensions and stable schema counts with the stopped PostgreSQL 16 source:

```bash
"${candidate[@]}" exec -T postgres sh -ec '
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align \
    --command="SELECT extname FROM pg_extension ORDER BY extname"' \
  >"$migration_root/extensions-after.txt"

"${candidate[@]}" exec -T postgres sh -ec '
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align \
    --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = '\''public'\'' AND table_type = '\''BASE TABLE'\''; SELECT count(*) FROM django_migrations"' \
  >"$migration_root/counts-after.txt"

cmp --silent "$migration_root/extensions-before.txt" "$migration_root/extensions-after.txt"
cmp --silent "$migration_root/counts-before.txt" "$migration_root/counts-after.txt"
```

## 5. Start and verify Authentik

Start Redis first, then the Authentik processes. The Compose health dependencies prevent future normal starts from racing unhealthy PostgreSQL or Redis containers.

```bash
"${candidate[@]}" up --detach --no-deps redis
for _ in $(seq 1 30); do
  redis_status=$(docker inspect authentik-redis --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  [[ $redis_status == healthy ]] && break
  sleep 2
done
[[ $redis_status == healthy ]]

"${candidate[@]}" up --detach --no-deps authentik-server authentik-worker
for _ in $(seq 1 60); do
  server_status=$(docker inspect authentik-server --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  [[ $server_status == healthy ]] && break
  sleep 2
done
[[ $server_status == healthy ]]
[[ $(docker inspect authentik-worker --format '{{.State.Status}}') == running ]]

"${candidate[@]}" ps postgres redis authentik-server authentik-worker
"${candidate[@]}" logs --since 10m postgres authentik-server authentik-worker
```

Complete these functional checks before publishing the candidate as current:

- log in to the Authentik admin interface;
- confirm the dashboard and directory objects load;
- authenticate through at least one protected application;
- confirm PostgreSQL, server, and worker logs contain no restore or migration errors; and
- verify Home Assistant remains healthy after Authentik returns.

Once these checks pass, run the existing protected `steady` apply for this exact committed candidate. Because the containers already match the candidate, the repeated Compose action plan must propose no further PostgreSQL recreation before the artifact is promoted to `/srv/docker-compose/current`.

## Rollback before candidate promotion

Rollback loses any writes accepted by PostgreSQL 18 after cutover. Keep the maintenance window closed to users until validation finishes.

Stop the candidate services and retain the failed PostgreSQL 18 cluster separately:

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

If the candidate has already been promoted, stop all Authentik writers before changing database directories and use the repository's separately reviewed Compose rollback path to restore the PostgreSQL 16 artifact. Do not attempt to start PostgreSQL 16 against the PostgreSQL 18 directory.

## Cleanup

Keep all three rollback inputs until:

1. the candidate artifact is active and idempotent;
2. functional verification has passed;
3. a new encrypted scheduled backup containing the PostgreSQL 18 cluster has completed; and
4. that backup's ciphertext and checksum replicas have been verified.

During this window, scheduled backups include both `postgresql/18/docker` and `postgresql-16`, so archive size will temporarily increase.

After the rollback window, remove only the reviewed `postgresql-16` subdirectory, the exact migration backup volume printed above, and the root-only migration directory. Never use an unrestricted volume prune.

## References

- [Authentik: Upgrade PostgreSQL on Docker Compose](https://docs.goauthentik.io/troubleshooting/postgres/upgrade_docker/)
- [PostgreSQL Docker image `PGDATA` change](https://github.com/docker-library/docs/blob/master/postgres/README.md#pgdata)
- [PostgreSQL 18: Upgrading a cluster](https://www.postgresql.org/docs/18/upgrading.html)
