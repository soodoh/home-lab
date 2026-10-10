# Compose credential delivery audit

## Scope and terminology

This catalogs credential inputs in the committed root Compose project and the
file-delivery interfaces of its pinned images. It is design guidance, **not** a
host observation receipt or deployment approval. Reobserve with
[`observe-compose.yml`](../ansible/playbooks/observe-compose.yml) and inspect
only credential names, source compatibility and protected file metadata before
activation. Never print resolved Compose, container environment values or
application configuration containing credentials.

The pinned applications use native file readers or supported image startup
adapters, except Openfit's intentionally deferred dotenv-file candidates. The
OpenVPN username and AWS access-key ID are credential-pair components. Other
usernames, OAuth client IDs and camera addresses are cataloged separately below.
Shared Arr keys have one authority but separately scoped consumer delivery.
Openfit's admin password is bootstrap-only. `ZWAVE_SECRET` is not consumed by the
pinned application; its encrypted source is not a declaration of runtime use.

Credential-file inputs other than Vaultwarden's OIDC secret originate in
[`production.sops.yaml`](../secrets/production.sops.yaml). Its OIDC secret comes
from the separately authoritative
[`Authentik client secrets`](../infrastructure/tofu/authentik/client-secrets.sops.json).
[`credentials.json`](../services/credentials.json) now declares native file
delivery, actual host permissions and explicit interpolation inputs. Ansible
renders these through protected `copy`/`template` tasks. Vaultwarden's secret
retains its separate Authentik authority. Openfit is deliberately excluded; its
two credentials remain environment-based. The unused `ZWAVE_SECRET` injection
is removed, but its encrypted source is neither deleted nor revoked.
`production.env` is CLI interpolation, not a blanket service `env_file`.

Grimmory uses production-SOPS database/bootstrap credentials.
Its database reads native MariaDB password files; the app reads the protected
database-password file as `spring.datasource.password` through Spring Boot
`configtree:`. Grimmory's OIDC secret remains solely in Authentik SOPS and is
converged through its native settings API, not mounted under a fictional `_FILE`
setting or copied into Docker environment values. The administrator password is
controller-only bootstrap/authentication input, not a Compose credential mount.
The shared production SOPS `HARDCOVER_API_KEY` is merged through that same native
settings API into `metadataProviderSettings.hardcover.apiKey`, preserving provider
enablement and unrelated settings/credentials. It is not a Compose credential
mount or environment input. Per-user reading-progress sync tokens remain
application-owned.
The app never receives the database root password. Initialization password files
do not rotate existing database accounts; rotation needs a separately admitted
native account change and app restart. See
[native authentication convergence](operations.md#grimmory-native-authentication-and-library-ownership).

These declarations are **not proof of current live state**. Frigate camera
URLs use its native credential placeholders, and Recyclarr API-key references
use native `!secret` tags. Preserve those interfaces when editing or recovering
application-owned configuration; mounting secret files alone does not rewrite
application references. Reobserve native delivery, application behavior and the
backup chain before each approved convergence.

There are two different improvements:

- **File delivery:** plaintext disappears from Compose interpolation and Docker's
  stored container environment (`Config.Env`).
- **Application-native file reads:** the application reads the file into its
  configuration without a startup wrapper exporting its contents as environment
  variables. LinuxServer's `FILE__` mechanism provides the first, not the second.
  PostgreSQL's official entrypoint also exports the file-loaded password.

Compose secrets are not an encrypted vault on a standalone Docker host. File
sources are read-only bind mounts; host custody, SOPS and encrypted backups still
matter. Merely moving a value into a service `env_file` does not remove it from
Docker's environment metadata. [D1, D2]

## Native file-delivery candidates

Paths below describe supported container interfaces, not instructions to create
plaintext files manually. The Compose declarations use these interfaces except
Openfit's intentionally deferred dotenv candidate. Ansible renders exact raw
values from the same authoritative encrypted sources.

| Service(s) | Source → legacy container variable | Supported file interface | Notes / evidence |
| --- | --- | --- | --- |
| `postgres` | `AUTHENTIK_DB_PASSWORD` → `POSTGRES_PASSWORD` | `POSTGRES_PASSWORD_FILE=/run/secrets/authentik_db_password` | Official entrypoint `file_env`; preserves DB initialization semantics and still exports the loaded password. Changing delivery must **not** change the database role password. [P1] |
| `authentik-server`, `authentik-worker` | `AUTHENTIK_DB_PASSWORD` → `AUTHENTIK_POSTGRESQL__PASSWORD` | Keep the variable name; set its value to `file:///run/secrets/authentik_db_password` | Python and Go configuration loaders support file URIs. Share the existing password with PostgreSQL. [A1–A3] |
| `authentik-server`, `authentik-worker` | `AUTHENTIK_SECRET_KEY` | `AUTHENTIK_SECRET_KEY=file:///run/secrets/authentik_secret_key` | Preserve bytes; changing the key invalidates sessions. [A1, A2] |
| `authentik-server`, `authentik-worker` | `AUTHENTIK_EMAIL__PASSWORD` | `AUTHENTIK_EMAIL__PASSWORD=file:///run/secrets/authentik_smtp_password` | Native configuration URI, **not** an invented `_FILE` suffix. [A1, A2] |
| `authentik-ldap` | `AUTHENTIK_LDAP_TOKEN` → `AUTHENTIK_TOKEN` | `AUTHENTIK_TOKEN=file:///run/secrets/authentik_ldap_token` | The pinned Go outpost loader explicitly processes this field through its URI resolver; core Python documentation alone would not prove outpost support. [A3, A4] |
| `vaultwarden` | `VAULTWARDEN_SMTP_PASSWORD` → `SMTP_PASSWORD` | `SMTP_PASSWORD_FILE=/run/secrets/vaultwarden_smtp_password` | Native Rust reader. Remove the direct variable: defining both forms panics. Admin-saved `config.json` can override environmental configuration. [V1–V3] |
| `vaultwarden` | `VAULTWARDEN_SSO_CLIENT_SECRET` (Authentik OAuth provider 47) → `SSO_CLIENT_SECRET` | `SSO_CLIENT_SECRET_FILE=/run/secrets/vaultwarden_sso_client_secret` | Preserve the Authentik SOPS authority; do not duplicate this secret in production SOPS. Same precedence caveat. [V1–V3] |
| `gluetun` | `WIREGUARD_PRIVATE_KEY`, `WIREGUARD_ADDRESSES` | `WIREGUARD_PRIVATE_KEY_SECRETFILE=/run/secrets/wireguard_private_key`, `WIREGUARD_ADDRESSES_SECRETFILE=/run/secrets/wireguard_addresses` | Native readers; both paths are also defaults. Generate the Proton key with NAT-PMP enabled and moderate NAT disabled. Keep resolved values out of Docker's stored environment. [G1] |
| `traefik-tailnet` | `TRAEFIK_TAILNET_AWS_ACCESS_KEY_ID` → `AWS_ACCESS_KEY_ID`; `TRAEFIK_TAILNET_AWS_SECRET_ACCESS_KEY` → `AWS_SECRET_ACCESS_KEY` | `AWS_SHARED_CREDENTIALS_FILE=/run/secrets/traefik_tailnet_aws_credentials` | Render an AWS INI credentials file with a `[default]` profile. Remove both direct AWS credential variables, which take precedence. Lego's Route 53 provider **does not support** `AWS_ACCESS_KEY_ID_FILE` or `AWS_SECRET_ACCESS_KEY_FILE`. Keep region/zone as nonsecret env configuration; grant this file only to private Traefik. [T1] |
| `nextcloud`, `nextcloud-cron` | `NEXTCLOUD_SMTP_PASSWORD` → `SMTP_PASSWORD` | `SMTP_PASSWORD_FILE=/run/secrets/nextcloud_smtp_password` | Native PHP SMTP config reads the file on configuration load. Both containers need the mount; cron overrides the image entrypoint, so do not rely on an entrypoint export. The PHP/cron service user must be able to read the file. [N1] |
| `frigate` | `FRIGATE_MQTT_PASSWORD` | File `/run/secrets/FRIGATE_MQTT_PASSWORD`; remove the value from `environment` | Frigate discovers files by their **exact uppercase names**, populating its substitution dictionary. Retain `{FRIGATE_MQTT_PASSWORD}` in app config. It does not require `FRIGATE_MQTT_PASSWORD_FILE`. [F1] |
| `frigate` | `FRIGATE_BACKYARD_PW`, `FRIGATE_DOORBELL_PW`, `FRIGATE_DRIVEWAY_PW`, `FRIGATE_BACK_STUDIO_PW`, `FRIGATE_FRONTYARD_PW`, `FRIGATE_STUDIO_PW`, `FRIGATE_BACK_HOUSE_PW` | One `/run/secrets/<exact variable name>` file each | Supported by Frigate and the go2rtc config generator. This only helps if camera config actually uses those placeholders; migrate inline URL credentials separately and investigate unused supplied vars before adding more files. [F1, F2] |
| `unpackerr` | `SONARR_API_KEY` → `UN_SONARR_0_API_KEY`; `RADARR_API_KEY` → `UN_RADARR_0_API_KEY`; `RADARR_4K_API_KEY` → `UN_RADARR_1_API_KEY` | Keep each container variable; replace the value with `filepath:/run/secrets/<corresponding key>` | Version 0.16.1 recursively resolves `filepath:` strings **after** environment parsing. No custom wrapper or plaintext TOML file is necessary. Do not invent `UN_*_API_KEY_FILE`. [U1, U2] |
| `mindwtr-cloud` | `MINDWTR_CLOUD_AUTH_TOKENS` | `MINDWTR_CLOUD_AUTH_TOKENS_FILE=/run/secrets/mindwtr_cloud_tokens`, with `user: "0:0"` | Version 1.2.6 already supports this. Its official entrypoint requires root for file input, copies to a protected runtime file and drops to `bun:bun`. The server reads that file directly. Inline and file tokens are **unioned**, not overridden: remove the old inline input. Preserve token bytes and data namespaces. [M1, M2] |
| `zwave` | `SESSION_SECRET` | Preserve the existing secret in `/usr/src/app/store/.session-secret`; remove the environment input | Version 11.24.1 reads this fixed file after checking the environment. Render into the existing backed-up store, or mount a protected file at that exact location. There is **no** `SESSION_SECRET_FILE` setting. Do not merely unset the variable: a different persisted value or newly generated key would change sessions/JWTs. [Z3] |

Frigate's username and camera-address variables can use the same named-file
mechanism if confidentiality is desired. Use Compose's long secret syntax with
`target: FRIGATE_MQTT_PASSWORD`, etc.; a lowercase default target will not match
the discovery prefix. Its generated go2rtc configuration and ffmpeg arguments
may still contain resolved camera credentials: file delivery is not universal
redaction. [F1, F2]

## Supported image startup adapters

These are existing image features, not a reason to write a custom entrypoint.
They prevent Compose/Docker metadata exposure but **still provide plaintext
values to the application environment**. The LinuxServer adapter copies file
contents into s6's container environment without trimming; render raw values
without an extra trailing newline. [L1, L2]

| Service | Source → legacy container variable | File-delivery interface |
| --- | --- | --- |
| `sonarr` | `SONARR_API_KEY` → `SONARR__AUTH__APIKEY` | `FILE__SONARR__AUTH__APIKEY=/run/secrets/sonarr_api_key` |
| `radarr` | `RADARR_API_KEY` → `RADARR__AUTH__APIKEY` | `FILE__RADARR__AUTH__APIKEY=/run/secrets/radarr_api_key` |
| `radarr-4k` | `RADARR_4K_API_KEY` → `RADARR__AUTH__APIKEY` | `FILE__RADARR__AUTH__APIKEY=/run/secrets/radarr_4k_api_key` |
| `prowlarr` | `PROWLARR_API_KEY` → `PROWLARR__AUTH__APIKEY` | `FILE__PROWLARR__AUTH__APIKEY=/run/secrets/prowlarr_api_key` |

Do not infer support solely from an image family. Verify `init-envfile` exists
in each pinned image and test the actual application consumer. [L1, L2]

## Native protected configuration file

Recyclarr's legacy environment supplied `SONARR_API_KEY`, `RADARR_API_KEY` and
`RADARR_4K_API_KEY`. Its native mechanism is a protected `/config/secrets.yml`
(or `.yaml`) and `api_key: !secret <key>` in its instance configuration.
Replace existing `!env_var` key references, then remove the three credential
variables from Compose. URLs can remain environmental configuration. This
requires managing the relevant existing instance configuration, not just adding
Compose mounts. The container runs as `1000:1000`. [R1, R2]

A single read-only secrets YAML file is preferable to a custom adapter that
loads three files into environment variables. Ansible can render it from the
same three production SOPS keys; do not introduce a second credential authority.

## Openfit runtime delivery and obsolete input

Openfit's application and admin seeder have no per-value `_FILE` interface.
Its pinned source uses Bun for both seeding and server startup, with working
directory `/app`; Bun has a native dotenv file loader. A protected `/app/.env`
is therefore a file-delivery candidate without replacing the image entrypoint.
Bun 1.3.14's versioned documentation and loader establish support for both
startup paths. It still loads values into `process.env`, like the LinuxServer
adapters; it is not an Openfit per-value file reader. [O1–O5]

Remove direct credential variables, including empty placeholders, and verify
no higher-priority `.env.production.local`, `.env.local` or `.env.production`
file shadows `/app/.env`. Bun expands `$` references even in single-quoted
values; serialize literal dollars with the correct escaping and test passwords
containing quotes, backslashes, whitespace and newlines against the exact runtime.
Missing/empty default dotenv files can be ignored: qualify required-key loading,
not just file existence. Do not copy the existing Compose dotenv serialization
blindly. Openfit's Dockerfile does not freeze its separate runtime dependency
install, so build-lock inspection alone does not prove the installed Better Auth
version. [O3–O5]

`OPENFIT_SECRET` → `BETTER_AUTH_SECRET` remains an ongoing runtime secret.
`OPENFIT_ADMIN_PASSWORD` → `ADMIN_PASSWORD` is **bootstrap only**: the seeder
runs on every start but skips an existing matching account before password
hashing. Changing this value does not rotate that account's password. After
account and recovery qualification, omit this bootstrap credential from normal
runtime rather than preserving an unnecessary exposure. Retain protected
bootstrap custody: a blank database without a seeded admin allows first-user
admin signup. [O1, O2]

`ZWAVE_SECRET` is an **unused/no-op injection** in pinned Z-Wave JS UI 11.24.1:
its tracked application source contains no consumer, and its image starts Node
directly. Radio security uses `NETWORK_KEY`, `KEY_*` and `KEY_LR_*`, not this
name. Remove the obsolete Compose injection after independent consumer checks;
do not rename it to a radio key, revoke its source blindly, or claim that removal
rotates an actual network key. [Z1, Z2, Z4]

## Shelfmark native connection settings

Shelfmark v1.4.0 has no per-secret `_FILE` reader. Ansible merges only managed
fields into its native `/config/plugins/prowlarr_config.json`,
`prowlarr_clients.json` and `hardcover.json`, preserving unrelated settings.
Files belong to UID/GID 1000 with mode 0600 under the private, backed-up config
directory. Prowlarr uses the existing production SOPS key; Hardcover uses the
raw production SOPS `HARDCOVER_API_KEY` without an authorization-header prefix
or whitespace. qBittorrent login and SABnzbd use the existing download-client
SOPS authority. Hardcover enablement and sort/list settings remain
application-owned. No secret is supplied through Compose environment.
The native reader gives environment values precedence, so connection qualification
checks exact effective values as well as authentication.

Native settings are cached, and startup synchronizes environment values back to
files. Stop only Shelfmark for changed settings, guard against concurrent edits,
merge atomically, verify full readback and require healthy startup. Run native
connection qualification against ephemeral private copies, not by importing its
startup reader against live settings. See [operations](operations.md#shelfmark-acquisition-and-seeding).
The reusable tests exercise the actual Ansible merge seam and the pinned native
reader with synthetic secrets, including escaping, field preservation, idempotency
and unsafe/concurrent-file refusals.

Pinned source: [settings-file loading and environment precedence](https://github.com/calibrain/shelfmark/blob/v1.4.0/shelfmark/core/settings_registry.py),
[download-client settings](https://github.com/calibrain/shelfmark/blob/v1.4.0/shelfmark/download/clients/settings.py),
[Prowlarr settings](https://github.com/calibrain/shelfmark/blob/v1.4.0/shelfmark/release_sources/prowlarr/settings.py)
and [Hardcover settings and account test](https://github.com/calibrain/shelfmark/blob/v1.4.0/shelfmark/metadata_providers/hardcover.py).

## Credential-adjacent inputs

These are not included as additional passwords/API keys in the count:

| Inputs | Classification and optional treatment |
| --- | --- |
| `AUTHENTIK_DB_USER`, `AUTHENTIK_EMAIL__USERNAME` | Usernames, not authentication secrets alone; Authentik can read them through `file:///...`. PostgreSQL separately supports `POSTGRES_USER_FILE`; healthchecks currently expect `POSTGRES_USER` in the environment. |
| `VAULTWARDEN_SMTP_USERNAME`, `VAULTWARDEN_SSO_CLIENT_ID` | Username and public OAuth client ID; Vaultwarden's generic `_FILE` loader can read them. Keep the client ID sourced from reviewed Authentik desired configuration. |
| `NEXTCLOUD_SMTP_USERNAME` → `SMTP_NAME`; `NEXTCLOUD_DB_USER` → `MYSQL_USER` | Usernames. The SMTP config does not establish `SMTP_NAME_FILE` support; do not infer it from `SMTP_PASSWORD_FILE`. DB user has a separate native file interface. |
| `OPENFIT_ADMIN_USER` → `ADMIN_USER` | Login identifier; same bootstrap ownership considerations as its password. |
| `FRIGATE_MQTT_USER`, `FRIGATE_CAM_USER` | Usernames; optional exact-name Frigate secret files. |
| `FRIGATE_BACKYARD`, `FRIGATE_DOORBELL`, `FRIGATE_DRIVEWAY`, `FRIGATE_BACK_STUDIO`, `FRIGATE_FRONTYARD`, `FRIGATE_STUDIO`, `FRIGATE_BACK_HOUSE` | Camera addresses are private configuration, not automatically passwords. Inspect for embedded URI userinfo/tokens without printing values; exact-name file delivery is supported. |
| SMTP hosts/from-addresses, URLs, DB names, AWS region/zone ID, network addresses, paths | Configuration metadata, not credentials by themselves. Embedded userinfo/tokens would change that classification. |

## Already file-based or outside Compose environment injection

- [`nextcloud.yml`](../services/nextcloud.yml) already mounted its DB user and
  MariaDB root passwords through native `MYSQL_PASSWORD_FILE` /
  `MYSQL_ROOT_PASSWORD_FILE`. Ansible now provisions their unchanged SOPS values
  too. This does not change initialized database role passwords: database
  credential rotation remains a separately approved application operation.
- [`cli-proxy-api.yml`](../services/cli-proxy-api.yml) already mounts its protected
  rendered YAML configuration. Its API/management keys are not Compose env vars;
  OAuth refresh/session files remain sensitive application state.
- Home Assistant OIDC `!secret`, qBittorrent/SABnzbd credentials, DDNS provider
  credentials, Mosquitto password files and application database secrets are
  separate owners. This inventory does not imply those systems are secret-free.
- Gluetun and Prowlarr share the initial MAM ID at
  `indexers["8"].mamId` in `secrets/servarr.sops.yaml`. OpenTofu supplies
  Prowlarr's `mamId`; Ansible derives the root-only `mam-initial-id` file and
  Compose grants only Gluetun the `mam_initial_id` secret, read through
  `MAM_ID_FILE`. No duplicate SOPS value or secret environment variable is used.
  Each consumer maintains its own refreshed cookies. Gluetun's protected jar
  retains a bootstrap-generation comment so unchanged inputs preserve refreshed
  cookies, while missing jars or deliberate SOPS changes bootstrap anew. An
  explicit session rejection permits one bootstrap retry; failed requests never
  replace the existing jar. An expired/revoked initial ID still requires a new
  MAM session and convergence of both consumers; see [rotation](operations.md#mam-session-bootstrap-and-rotation).
- The previous whole-source dotenv export also included SOPS keys **not injected by Compose**:
  `LIDARR_API_KEY`, `NEXTCLOUD_DB_PASSWORD`, `NEXTCLOUD_DB_ROOT_PASSWORD`,
  `RESTIC_LOCAL_PASSWORD`, `RESTIC_PROTON_PASSWORD`, `PROTON_BACKUP_PASSWORD`
  and `PROTON_BACKUP_TOTP_SECRET` (plus Proton username and other configuration).
  Their presence in ciphertext is not proof they are unused elsewhere. Limit
  production dotenv rendering to required interpolation inputs; do not remove
  their encrypted authority or revoke credentials without independent checks.

## Requirements for a safe implementation

1. **Keep authorities and values unchanged.** Use `community.sops` and declarative
   Ansible `copy`/`template` with `no_log: true`, `diff: false`, protected ownership
   and narrowly granted read access. Do not rotate any credential as part of
   changing its transport. Parse SOPS data and render raw values for per-value
   files, not dotenv quoting or interpolation escapes. Traefik/Recyclarr's native
   structured files need format-specific serialization and exact-value tests.
   Openfit's combined dotenv candidate is not adopted.
2. **Separate interpolation from credential files.** Replace the entire-SOPS
   dotenv export with an explicit set of still-required interpolation fields.
   Migrating Compose declarations while leaving plaintext credential duplicates
   in `production.env` only solves part of the exposure. Update
   [`check-compose-with-sops.py`](../scripts/check-compose-with-sops.py) and its
   behavior tests to use the same source split; preserve the single Authentik
   authority for Vaultwarden OIDC.
3. **Declare and provision least-privilege mounts.** Add secret files to the owning
   included Compose documents and grant them only to consumers. Do not mount the
   whole credentials directory. Standalone Compose `secrets.file` ignores
   `uid`/`gid`/`mode` overrides: set real source-file metadata in Ansible. Authentik
   runs as UID 1000; Recyclarr explicitly runs as 1000:1000; Nextcloud's PHP/cron
   readers need their actual service UID/GID. Root-owned mode-0600 files work only
   when the reader is root. Prefer an appropriately scoped group-readable file
   or verified ACL to running applications as root or making secrets world-readable.
   Mindwtr is an explicit exception for **entrypoint** startup: its upstream root
   handoff copies the file and then drops the server to `bun:bun`.
   Adjust the observer's current root:root/0600-only assertion accordingly. [D2, M2]
4. **Recreate on changed secret-file contents.** Ansible's atomic file replacement
   can leave an existing bind mount pointing at the old inode. An unchanged file
   path is not a changed Compose environment, so do not rely on `recreate: auto`
   to propagate a new value. Register protected file changes and explicitly
   recreate consumers through native Compose convergence without exposing secret
   digests. The deployment interface observes live managed bind-mount
   inode/metadata changes and recreates only their declared consumers. Native
   rsync preserves unchanged source mounts, including directory mounts; native
   Compose handles image/model/environment changes with `recreate: auto`.
   Approval must cover affected consumers and any native dependency recreation,
   not an unconditional project-wide restart.
5. **Resolve recovery before removing dotenv copies.** The current Restic
   files-from list and recovery `common_paths` now declare both `production.env`
   and `/etc/docker-compose/credentials`. Recyclarr's read-only `secrets.yml` is
   backed up at its host credential-file source, not its container target.
   Qualify a fresh complete backup chain and private restore after activation;
   existing SOPS ciphertext and running containers do not prove recovery.
6. **Qualify behavior, not spelling.** Validate Compose quietly and Ansible
   natively, then test each pinned reader with synthetic credentials: direct values
   absent from `Config.Env`, files readable by the actual UID, exact values
   accepted, no silent fallback, and recreation after atomic replacement.
   During an approved deployment verify Authentik/LDAP auth, SMTP including
   Nextcloud cron, Vaultwarden OIDC, VPN health/port forwarding, private ACME,
   Frigate MQTT/cameras, Arr APIs, Unpackerr and Recyclarr. Preserve Arr/OpenTofu
   ownership and existing backup/host-lock admission; use fresh observations and
   approved convergence, not ad hoc production `docker exec` changes.

## Primary sources

- **D1:** [Docker Compose secret delivery](https://docs.docker.com/compose/how-tos/use-secrets/).
- **D2:** [Compose service secrets and file-source permission limitations](https://docs.docker.com/reference/compose-file/services/#secrets).
- **P1:** [Official PostgreSQL entrypoint: `file_env`, export and initialization](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).
- **A1:** [Authentik configuration URI documentation](https://docs.goauthentik.io/install-config/configuration/).
- **A2:** [Authentik 2026.8.3 Python config loader](https://github.com/goauthentik/authentik/blob/version/2026.8.3/authentik/lib/config.py).
- **A3:** [Authentik 2026.8.3 Go URI loader](https://github.com/goauthentik/authentik/blob/version/2026.8.3/internal/config/config.go).
- **A4:** [Authentik 2026.8.3 outpost token field](https://github.com/goauthentik/authentik/blob/version/2026.8.3/internal/config/struct.go).
- **V1:** [Vaultwarden configuration and precedence](https://github.com/dani-garcia/vaultwarden/wiki/Configuration-overview#loading-individual-values-from-files).
- **V2:** [Vaultwarden 1.37.3 generic `_FILE` reader](https://github.com/dani-garcia/vaultwarden/blob/1.37.3/src/util.rs).
- **V3:** [Vaultwarden 1.37.3 SMTP/SSO configuration](https://github.com/dani-garcia/vaultwarden/blob/1.37.3/src/config.rs).
- **G1:** [Gluetun Docker secrets and `_SECRETFILE` paths](https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/docker-secrets.md).
- **T1:** [Lego Route 53 credential chain and unsupported AWS `_FILE` names](https://go-acme.github.io/lego/dns/route53/).
- **N1:** [Official Nextcloud native SMTP file reader](https://github.com/nextcloud/docker/blob/master/.config/smtp.config.php).
- **F1:** [Frigate 0.18.0 named-file configuration reader](https://github.com/blakeblackshear/frigate/blob/v0.18.0/frigate/config/env.py).
- **F2:** [Frigate 0.18.0 go2rtc named-file reader](https://github.com/blakeblackshear/frigate/blob/v0.18.0/docker/main/rootfs/usr/local/go2rtc/create_config.py).
- **U1:** [Unpackerr 0.16.1 post-environment filepath resolution](https://github.com/Unpackerr/unpackerr/blob/v0.16.1/pkg/unpackerr/start.go).
- **U2:** [Its pinned `cnfgfile` recursive string-file reader](https://github.com/golift/cnfgfile/blob/a5436d84eb48/filepath.go).
- **L1:** [LinuxServer `FILE__` documentation](https://docs.linuxserver.io/images/docker-sonarr/#environment-variables-from-files-docker-secrets).
- **L2:** [LinuxServer Ubuntu noble `init-envfile` implementation](https://github.com/linuxserver/docker-baseimage-ubuntu/blob/noble/root/etc/s6-overlay/s6-rc.d/init-envfile/run).
- **R1:** [Recyclarr 8.7.2 native secrets file](https://github.com/recyclarr/recyclarr/blob/v8.7.2/src/Recyclarr.Core/Config/Secrets/SecretsProvider.cs).
- **R2:** [Recyclarr 8.7.2 `!secret` YAML interface](https://github.com/recyclarr/recyclarr/blob/v8.7.2/src/Recyclarr.Core/Config/Secrets/SecretsYamlBehavior.cs).
- **M1:** [Mindwtr 1.2.6 image-source native token-file reader](https://github.com/dongdongbh/Mindwtr/blob/2e95e500003bf76b75d61859b3f5c86fc85ae5cb/apps/cloud/src/server-auth.ts#L155-L209).
- **M2:** [Mindwtr root-to-bun entrypoint](https://github.com/dongdongbh/Mindwtr/blob/2e95e500003bf76b75d61859b3f5c86fc85ae5cb/docker/cloud/entrypoint.sh#L4-L22) and [official secrets overlay](https://github.com/dongdongbh/Mindwtr/blob/2e95e500003bf76b75d61859b3f5c86fc85ae5cb/docker/compose.secrets.yaml).
- **O1:** [Openfit image-source admin bootstrap behavior](https://github.com/soodoh/openfit/blob/39c29c53a52a42d92f3dfb91702774a1de2a09e8/apps/openfit/db/seed.ts#L370-L422) and [first-user admin signup](https://github.com/soodoh/openfit/blob/39c29c53a52a42d92f3dfb91702774a1de2a09e8/apps/openfit/src/lib/auth.ts#L143-L170).
- **O2:** [Openfit image-source runtime entrypoint](https://github.com/soodoh/openfit/blob/39c29c53a52a42d92f3dfb91702774a1de2a09e8/apps/openfit/scripts/docker-entrypoint.sh).
- **O3:** [Openfit image-source Dockerfile](https://github.com/soodoh/openfit/blob/39c29c53a52a42d92f3dfb91702774a1de2a09e8/apps/openfit/Dockerfile) and [seed/migration working directory](https://github.com/soodoh/openfit/blob/39c29c53a52a42d92f3dfb91702774a1de2a09e8/apps/openfit/scripts/init.sh).
- **O4:** [Bun native dotenv loading and interpolation](https://bun.sh/docs/runtime/environment-variables).
- **O5:** [Bun 1.3.14 versioned environment documentation](https://github.com/oven-sh/bun/blob/0d9b296af33f2b851fcbf4df3e9ec89751734ba4/docs/runtime/environment-variables.mdx) and [default-file loader, precedence and expansion](https://github.com/oven-sh/bun/blob/0d9b296af33f2b851fcbf4df3e9ec89751734ba4/src/dotenv/env_loader.zig).
- **Z1:** [Z-Wave JS UI 11.24.1 supported environment variables](https://github.com/zwave-js/zwave-js-ui/blob/df84037f78900d58ce3e7694dd39d02cad6e5d6e/docs/guide/env-vars.md).
- **Z2:** [Z-Wave JS UI 11.24.1 radio security-key loader](https://github.com/zwave-js/zwave-js-ui/blob/df84037f78900d58ce3e7694dd39d02cad6e5d6e/api/lib/utils.ts#L376-L413).
- **Z3:** [Z-Wave JS UI 11.24.1 fixed session-secret file loader](https://github.com/zwave-js/zwave-js-ui/blob/df84037f78900d58ce3e7694dd39d02cad6e5d6e/api/config/app.ts#L27-L86).
- **Z4:** [Z-Wave JS UI 11.24.1 direct Node startup](https://github.com/zwave-js/zwave-js-ui/blob/df84037f78900d58ce3e7694dd39d02cad6e5d6e/docker/Dockerfile#L91-L103).
