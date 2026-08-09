# SOPS and age production-secret foundation

## Status

The foundation is active for Compose. The trusted local controller stages the exact encrypted repository artifact, and the host decrypts it with `/etc/sops/age/keys.txt` into root-owned `/etc/docker-compose/production.env`; the legacy checkout `.env` is not a runtime input.

The repository contains only:

- SOPS dotenv ciphertext at `secrets/production.sops.env`;
- the sorted 90-name manifest at `secrets/production.env.keys`;
- a non-secret blank-line layout manifest at `secrets/production.env.layout.json`; and
- the public age recipient in `.sops.yaml`.

No production age identity is present in Git or repository files.

## Pinned tooling

Standalone binaries were installed without a package transaction:

| Tool | Version | SHA-256 |
|---|---:|---|
| `sops` | 3.13.3 | `e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b` |
| age release archive | 1.3.1 | `bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377` |
| `age` | 1.3.1 | `2e305637f2a0555305e21c17fb74446acbb39b53135d43d4b744e50c287133a5` |
| `age-keygen` | 1.3.1 | `c56ef69834e18ca4d3b953117f4481522c35fb6862a5d2871685aa4685893664` |

The versions, release URLs, and checksums are also recorded in `ansible/group_vars/docker_host.yml`. `scripts/install-sops-age.sh` verifies the release archives and installed binaries before reporting success.

## Server identity

The identity was generated directly on the server:

```text
/etc/sops/age             root:root 0700
/etc/sops/age/keys.txt    root:root 0600
```

Only this public recipient is recorded:

```text
age1vvzm5pczjum52v5alall8euucjen9q4v9xa5g0xmswhna5vare9qwv9rq6
```

The private identity was encrypted to the existing backup GPG recipient before transfer. The external recovery copy and its GPG ciphertext are stored on `Paul's MacBook` under `~/.config/sops/age-recovery`, both mode `0600` inside a mode `0700` directory. External `age-keygen -y` matched the server recipient, and an independent age encrypt/decrypt round trip passed. Private-key and passphrase content was never printed or placed in command arguments.

## Encryption and exact reconstruction

SOPS dotenv encryption preserves all variable names, values, comments, and ordering, but SOPS 3.13.3 removes blank lines. The original source had 20 blank lines. Exact reconstruction was proved before activation:

1. `scripts/extract-dotenv-keys.py` records sorted names and non-secret blank-line positions.
2. SOPS encrypts the source as dotenv using the single `.sops.yaml` creation rule.
3. `scripts/restore-dotenv-layout.py` deterministically restores those blank lines after decryption.
4. Root-only verification decrypted into a mode `0700` temporary directory, reconstructed the layout, and used `cmp --silent` against the migration source.

The final verification reported:

```text
server_sops_decryption=pass
source_byte_match=pass
variable_name_sets=pass count=90
```

The migrated source checksum and metadata were unchanged during encryption. Production now uses only the root-owned reconstructed environment.

## Secret-free validation

`scripts/validate-secrets` runs locally without an age identity and cannot decrypt production secrets. It:

1. rejects every tracked `*.env` except `secrets/production.sops.env`;
2. requires the exact single-file `.sops.yaml` rule and public recipient;
3. requires every application value and comment to use SOPS AES-GCM ciphertext;
4. validates SOPS age, MAC, version, and recipient metadata;
5. rejects missing, duplicate, or unexpected variable names; and
6. validates that the non-secret layout accounts for the exact ciphertext content-line count.

## Safety boundaries

- Do not use `SOPS_AGE_KEY`, which would place the private identity in an environment value.
- Host decryption must use `SOPS_AGE_KEY_FILE=/etc/sops/age/keys.txt` with Ansible `no_log: true` and a root-only temporary file.
- Never print `sops decrypt` output or resolved Compose configuration.
- Treat `/etc/docker-compose/production.env` and `/etc/docker-compose/previous.env` as root-only runtime and rollback inputs; never print or copy their contents.
- Do not copy the production identity into GitHub secrets, workflow files, artifacts, or summaries.
