# SOPS and age production-secret foundation

## Status

The foundation is active for Compose. The trusted local controller stages the exact encrypted repository artifact, and the host decrypts it with `/etc/sops/age/keys.txt` into root-owned `/etc/docker-compose/production.env`; the legacy checkout `.env` is not a runtime input.

The repository contains only:

- SOPS dotenv ciphertext at `secrets/production.sops.env`;
- its sorted 94-name and non-secret blank-line manifests; and
- three public age recipients in `.sops.yaml`: active Debian production, retained Arch rollback, and independent recovery.

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

## Production and retained rollback identities

The active Debian identity was generated directly on the server and was never exported:

```text
/etc/sops/age             root:root 0700
/etc/sops/age/keys.txt    root:root 0600
```

Its public recipient is `age1atumjua6hxyls6z8v20tsgy72304x72lqjstwmwzqy5ma4txyfsse7xakv`; the generation and recipient transition are bound to `infrastructure/evidence/vm-100-debian-age-identity.json` and `infrastructure/evidence/vm-100-debian-sops-recipient.json`.

The retained Arch rollback recipient is `age1vvzm5pczjum52v5alall8euucjen9q4v9xa5g0xmswhna5vare9qwv9rq6`. Its private identity was encrypted to the existing backup GPG recipient before transfer. The external recovery copy and its GPG ciphertext are stored on `Paul's MacBook` under `~/.config/sops/age-recovery`, both mode `0600` inside a mode `0700` directory. External `age-keygen -y` matched the retained recipient, and an independent age encrypt/decrypt round trip passed. Private-key and passphrase content was never printed or placed in command arguments.

## Independent recovery identity

The independent recovery recipient is `age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm`. Its private identity and GPG escrow are controller-local under `~/.config/sops/home-lab-recovery`, mode `0600` in a mode `0700` directory. The GPG ciphertext also has a byte-identical external recovery copy.

The cancelled NixOS runtime recipient was removed from `.sops.yaml` and the ciphertext with `sops updatekeys`. Decryption with the retained Arch recovery identity and secret-free two-recipient validation passed before the NixOS private identity and escrow were deleted; the active Debian recipient was added later through its separately attested transition.

## Encryption and exact reconstruction

SOPS dotenv encryption preserves all variable names, values, comments, and ordering, but SOPS 3.13.3 removes blank lines. The original source had 20 blank lines. Exact reconstruction was proved before activation:

1. `scripts/extract-dotenv-keys.py` records sorted names and non-secret blank-line positions.
2. SOPS encrypts the source as dotenv using the single `.sops.yaml` creation rule.
3. `scripts/restore-dotenv-layout.py` deterministically restores those blank lines after decryption.
4. Root-only verification decrypted into a mode `0700` temporary directory, reconstructed the layout, and used `cmp --silent` against the migration source.

The initial 90-variable migration verification reported:

```text
server_sops_decryption=pass
source_byte_match=pass
variable_name_sets=pass count=90
```

The migrated source checksum and metadata were unchanged during encryption. Production now uses only the root-owned reconstructed environment.

The credential-ready transition increases the current manifest to 94 names and the layout to 138 source lines with the same 20 blank-line positions; the additional six content lines are five variables plus one encrypted section comment. Protected local verification matched all decrypted key names to that exact manifest; the historical 90-variable byte-match evidence remains unchanged.

## Secret-free validation

Secret-free validation runs locally without an age identity and cannot decrypt production secrets. It:

1. rejects tracked plaintext production environment files;
2. requires the exact single-file `.sops.yaml` rule and all three distinct public recipients;
3. requires every application value and comment to use SOPS AES-GCM ciphertext;
4. validates SOPS age, MAC, version, and recipient metadata;
5. rejects missing, duplicate, or unexpected variable names;
6. validates that the non-secret layout accounts for the exact ciphertext content-line count; and
7. verifies that only the canonical ciphertext and metadata manifests are tracked.

## Safety boundaries

- Do not use `SOPS_AGE_KEY`, which would place a private identity in an environment value.
- Production-host decryption must use `SOPS_AGE_KEY_FILE=/etc/sops/age/keys.txt` with Ansible `no_log: true` and a root-only temporary file.
- Never print `sops decrypt` output or resolved Compose configuration.
- Treat all decrypted Compose environment paths as root-only runtime or rollback inputs; never print or copy their contents.
- Do not copy production identities into GitHub secrets, workflow files, artifacts, or summaries.
