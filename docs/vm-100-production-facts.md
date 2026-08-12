# VM 100 production fact inventory

This milestone defines a read-only, secret-free fact collector and validator for the subset of Gate A facts needed before NixOS base/storage design. It does **not** claim the complete Gate C cutover manifest required by `docs/vm-100-nixos-migration.md`.

## Captured scope

`scripts/controller/collect-vm-100-facts.py` records:

- the `docker` account's numeric identity and group memberships;
- Docker root/storage facts and the exact 30 declared plus 3 protected legacy Compose volumes;
- ownership, modes, mount identity, source, filesystem, options, ext4 features, capacity and selected size measurements for approved mutable roots;
- a zero multiply-linked-file count for roots planned for direct copy, preventing an unreviewed cross-root hardlink assumption;
- only the public SOPS recipient and identity-file metadata, never private identity or plaintext secret material; and
- explicit blockers for the independent recovery recipient, NixOS recipient and application import identifiers.

The runtime observation is written under ignored `.reconcile/vm-100/facts.json`, bound to the exact controller commit, and validated with `infrastructure/vm-100/facts.schema.json` plus repository-derived semantic checks.

## Deliberately deferred

The complete Gate C inventory still must add container/runtime state, every bind, writers and timers, hardware mappings, backup freshness, current/previous artifacts and images, full application API inventory/import IDs, and a reviewed transfer manifest. Pending values remain blockers rather than guessed desired state.

## Collection

Run from a clean pushed controller revision using the existing constrained Arch Ansible identity. Copy the collector to a root-executable temporary path, run it with `sudo -n`, remove the temporary file, and validate the result locally:

```bash
commit=$(git rev-parse HEAD)
mkdir -p .reconcile/vm-100
# Use the repository's isolated SSH options and existing ansible-deploy transport.
node scripts/controller/validate-vm-100-facts.js \
  --commit "$commit" .reconcile/vm-100/facts.json
```

The collector invokes only read operations: `getent`, `id`, `docker info/volume ls/volume inspect`, `findmnt`, `statvfs`, `du`, `find`, `tune2fs -l`, and `age-keygen -y`.

## Qualified observation

A read-only collection from pushed commit `2ee8690cc66440a3272913f9efd870756cfeac4e` passed the closed schema and semantic validator. The ignored canonical fact document had SHA-256 `17b651121b33a42408a13d6c6f4e59bb9f498fb5860a61af8c1a9319c999c263`.

It confirms UID/GID `1000:1000`, the exact 30 declared plus 3 protected legacy volume set, zero multiply-linked files in both copied roots, and expected ext4/NFS mount families. Application import identifiers, an independent recovery recipient, and a NixOS runtime recipient remain explicit blockers.
