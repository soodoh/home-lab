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

## Preliminary observation

A preliminary read-only run established the expected UID/GID, 30+3 volume set, mount families, and pending SOPS/application decisions. It was collected while this tooling was still uncommitted, so it is diagnostic only and is **not** qualified gate evidence.

After this collector/validator revision is pushed, recollect against that exact pushed commit before consuming these facts in the NixOS base or storage configuration. Application import identifiers remain uncollected and block application OpenTofu authoring.
