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

Proxy provider property-mapping membership is intentionally observed in `desired.json` but omitted from the resource blocks. Authentik automatically injects those five factory mappings, and provider 2026.5.1 cannot import that computed membership without proposing a redundant update. No custom proxy mapping membership exists.

OpenTofu owns Authentik API configuration only. Compose continues to own the server, worker, PostgreSQL, Redis, networks, mounts, and images. Users, groups, service accounts, roles, sessions, events, notifications, schedules, tokens, WebAuthn devices, and other identity/runtime records remain database-owned.

The root remains disabled by default for secret-free validation. The trusted local controller enables it with protected plan/apply credentials.

## Secret architecture

Two encrypted layers are required:

- `infrastructure/tofu/authentik/client-secrets.sops.json` contains the six current OAuth2 client secrets, encrypted to the three existing production/recovery age recipients.
- `home-lab/authentik/tofu.tfstate` uses the existing versioned, KMS-encrypted S3 backend. Provider resource secrets remain in state even when OpenTofu marks them sensitive.

The trusted local controller decrypts the SOPS file into `.local/authentik/client-secrets.json` with mode `0600`. The plaintext file and saved plans stay under ignored, mode-restricted paths. Protected controller credentials enter as `AUTHENTIK_URL` and `AUTHENTIK_TOKEN`; the controller maps them into an ephemeral, sensitive provider variable. The reconciler rejects the API token if it appears in a saved plan.

## Adoption record

Production adoption completed on 2026-08-27:

- the AWS foundation granted plan/apply access to the retained Authentik state and lock keys;
- separate `home-lab-opentofu-plan` and `home-lab-opentofu-apply` identities were created with 12 read-only and 36 read/add/change permissions respectively;
- both provider tokens expire at `2026-11-25T19:16:43Z`;
- the reviewed plan imported all 85 objects with zero add, change, replace, or destroy actions; and
- remote state serial `3` contains 85 managed instances plus two read-only stage data-source instances.

The guarded controller apply encountered an unrelated Compose dotenv-layout staging failure before reaching the Authentik root. The exact commit-bound Authentik saved plan was therefore applied separately under the controller-wide lock after its manifest hash and import-only actions were reverified. A fresh post-import plan reported no Authentik changes.

All managed Authentik resource classes use `prevent_destroy`. Historical empty state versions remain retained in S3.

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
