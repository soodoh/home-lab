# Authentik OpenTofu management

## Status and ownership boundary

The `infrastructure/tofu/authentik` root is an import-first root for the production Authentik 2026.5.6 API configuration. A fresh read-only inventory captured on 2026-08-27 contains:

- 25 applications;
- 19 proxy providers;
- 6 direct OAuth2 providers;
- 30 application access bindings that reference existing users or groups without managing those identities;
- the custom Passwordless Authentication flow, its authenticator validation stage, and two stage bindings; and
- the custom Vaultwarden Email Scope property mapping.

The inventory found no other eligible custom flow, stage, policy, mapping, brand, certificate, source, or outpost. Authentik-managed and factory blueprint objects remain outside OpenTofu and are referenced by stable data-source names or IDs. `customBlueprints` is therefore empty; a blueprint must never overlap typed resources.

OpenTofu owns Authentik API configuration only. Compose continues to own the server, worker, PostgreSQL, Redis, networks, mounts, and images. Users, groups, service accounts, roles, sessions, events, notifications, schedules, tokens, WebAuthn devices, and other identity/runtime records remain database-owned.

The root remains disabled by default until the backend authorization, provider identities, imports, and zero-change proof are complete.

## Secret architecture

Two encrypted layers are required:

- `infrastructure/tofu/authentik/client-secrets.sops.json` contains the six current OAuth2 client secrets, encrypted to the three existing production/recovery age recipients.
- `home-lab/authentik/tofu.tfstate` uses the existing versioned, KMS-encrypted S3 backend. Provider resource secrets remain in state even when OpenTofu marks them sensitive.

The trusted local controller decrypts the SOPS file into `.local/authentik/client-secrets.json` with mode `0600`. The plaintext file and saved plans stay under ignored, mode-restricted paths. Protected controller credentials enter as `AUTHENTIK_URL` and `AUTHENTIK_TOKEN`; the controller maps them into an ephemeral, sensitive provider variable. The reconciler rejects the API token if it appears in a saved plan.

## Adoption plan

### 1. Apply backend authorization

The AWS foundation now grants plan/apply roles access to the Authentik state and lock keys. Run the ordinary guarded plan/apply while Authentik management is still disabled:

```bash
scripts/local-controller plan steady
scripts/local-controller apply steady
```

Inspect the existing S3 object versions before reusing the key. Historical Authentik state was deliberately emptied during retirement; retain those versions.

### 2. Bootstrap separate provider identities

`scripts/controller/authentik-bootstrap-service-account.py` creates two service accounts atomically:

- **plan**: view-only access to the exact application, provider, property-mapping, flow, stage, binding, and optional blueprint models;
- **apply**: view/add/change access to those models, without delete permissions.

Run the script only through `ak shell --no-imports` in the production server container. Supply a reviewed ISO-8601 expiry, run `inspect`, capture the emitted request hash, then rerun with operation `create`, the exact hash, and confirmation `create-reviewed-home-lab-opentofu-authentik-identities`. Capture the two token marker lines into protected local files without logging stdout. The helper refuses any pre-existing account, role, or token object.

### 3. Configure the trusted local controller

Run:

```bash
scripts/configure-local-provider-credentials
```

Enter the distinct plan/apply tokens. The credential files must remain mode `0600` inside the mode `0700` controller directory and retain the existing `SOPS_AGE_KEY_FILE` entry.

### 4. Import and prove zero change

The root contains declarative import blocks for all 85 managed objects. The first guarded plan must contain imports only. Any create, update, replace, or delete of a production object is a blocker.

```bash
scripts/local-controller plan steady
scripts/local-controller apply steady
```

The reconciler applies Compose before the Authentik saved plan so the API is healthy, consumes only the commit-bound reviewed plan, and immediately runs a fresh no-op verification. Every managed resource class uses `prevent_destroy`.

## Inventory refresh

A refresh must be read-only and must keep raw API output under `.reconcile/authentik/` with mode `0600`. The global configuration export is produced inside the worker:

```bash
docker exec authentik-worker ak export_blueprint > live-blueprint.yaml
```

OAuth client secrets are write-only in blueprint exports, so the API serializer inventory must be captured separately without terminal logging. `scripts/controller/authentik-normalize-inventory.mjs` validates the reviewed model counts and ownership exclusions, emits non-secret `desired.json`, and writes OAuth secrets to a separate protected plaintext file for immediate SOPS encryption. Delete all raw and plaintext captures after normalization and validation.

If a future inventory adds an eligible custom object, add its typed provider resource, schema, import, permissions, allowlist address, and tests. Use a database-backed blueprint only when the provider has no typed resource and a separately reviewed bootstrap can prove it does not modify existing configuration.

## Normal operation

After adoption, use:

```bash
scripts/local-controller plan steady
scripts/local-controller apply steady
```

Rotate both Authentik API tokens before expiry. Rotate an OAuth client secret only as a coordinated Authentik/application change, updating the SOPS ciphertext in the same reviewed change. Never commit plaintext exports, decrypted client secrets, provider tokens, state, plans, or crash logs.
