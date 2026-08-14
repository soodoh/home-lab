# VM 100 application OpenTofu import inventory

Captured from the running Arch workload on 2026-08-14 at revision `020760a2c9fce9a66bc4f67296f6f2255c86312a`. The read-only inventory did not stop, restart, or modify any container or application. Credentials were consumed only in-process on the production host; the committed inventory contains no credential values.

The machine-readable authority is [`infrastructure/applications/vm-100-application-imports.json`](../infrastructure/applications/vm-100-application-imports.json). Its schema fixes the provider versions, import addresses, import IDs, exclusions, source revision, and hashes of the protected local evidence.

## Provider pins

| Application | Provider | Exact version | Import form |
|---|---|---:|---|
| Authentik 2026.5.6 | `goauthentik/authentik` | `2026.5.1` | application slug; numeric provider PK |
| Sonarr 4.0.19 | `devopsarr/sonarr` | `3.4.2` | numeric API ID |
| Radarr 6.3.0 | `devopsarr/radarr` | `2.4.0` | numeric API ID |
| Prowlarr 2.6.0 | `devopsarr/prowlarr` | `3.2.1` | numeric API ID |

These are exact pins, not ranges. Generated provider schemas were inspected recursively, including nested attributes, before selecting any resource class.

## Adopted initial surface

The inventory selects 53 existing objects for import before any application apply:

- **Authentik:** 25 applications and 19 proxy providers. Application imports use the slug because the provider reads and persists the slug as the OpenTofu resource ID. Proxy-provider imports use the numeric provider PK. The 19 proxy resources expose no sensitive schema field; their generated client ID is read-only. Six OAuth2 providers remain unmanaged because `client_secret` is sensitive and would persist in state.
- **Sonarr:** root folders `7` and `8` only.
- **Radarr:** root folder `1` for the 1080p instance and root folder `5` for the 4K provider alias.
- **Prowlarr:** tags `2`, `3`, `4`, and `5`, plus sync profile `1`.

Every selected object already exists. The first successful plan must therefore follow completed imports and show no create, replace, update, or delete action.

## Explicit ownership exclusions

- Recyclarr owns the observed Sonarr/Radarr custom formats and quality-profile scoring. Its three live config files contain `custom_formats`; both Radarr files also contain `quality_profiles` and `delete_old_custom_formats`. OpenTofu must not adopt those classes.
- Prowlarr-created Sonarr/Radarr indexers remain Prowlarr-owned. The corresponding provider schemas also persist API keys or passkeys.
- Download clients, Prowlarr applications, Prowlarr indexers, and the Radarr 4K import list remain restored database state because their schemas persist credentials.
- Host/global singleton settings, notifications, media-management, naming, and other broad settings remain restored database state for the initial adoption.
- Authentik OAuth2 providers and every other Authentik resource with a sensitive schema attribute remain unmanaged.

A future expansion requires a new read-only inventory, explicit ownership review, protected-state threat model, and a separately reviewed import list.

## Import and plan gates

1. Create isolated `authentik` and `media-apps` S3 state/lock keys with KMS encryption, versioning, public-access blocking, and least-privilege plan/apply roles.
2. Scaffold disabled roots with the exact provider pins and resource addresses in the manifest.
3. Supply endpoints and API credentials only through the protected ephemeral controller environment. Keep `TF_LOG` disabled and plans, state, crash files, and JSON output in protected fixed directories.
4. Import every selected ID before the first plan. Abort on any pre-existing selected object not represented in state or any state object absent from the manifest.
5. Bind the reviewed plan to a secret-free hash of the live adopted fields. Immediately before apply, re-read those fields and require the same hash.
6. Require zero actions after import and again after any approved apply. No application root may run before Compose health succeeds.

## Protected local evidence

The untracked evidence remains under `.reconcile/vm-100/` with mode-restricted access:

- `application-arr-inventory.json`
- `application-authentik-inventory.json`
- `application-authentik-proxy-inventory.json`
- `application-recyclarr-overlap.json`

Only their SHA-256 values are committed in the manifest. The evidence payloads contain whitelisted non-secret fields, but they remain local because they include detailed production topology.
