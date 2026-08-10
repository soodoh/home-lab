# Recovery rehearsal

Run the non-mutating static rehearsal from a clean controller:

```sh
scripts/rehearse-recovery --static
```

It validates the contract and provider locks, exercises hostile archive and volume fixtures, checks the completed LXC qualification evidence, and syntax-checks the retained recovery playbooks. A pass proves only static control flow; it performs no provider mutation, restore, or service activation.

## Live qualification

A live qualification must use an isolated Proxmox host and disposable recovery targets. Prepare the protected mode-`0600` recovery extra-vars file and follow the exact controller workflow:

```sh
scripts/local-controller plan recovery
scripts/local-controller review recovery
scripts/local-controller approve recovery --confirmation apply-reviewed-recovery
scripts/local-controller apply recovery
```

The qualification must demonstrate:

- exact saved-plan and backup-identity binding;
- Proxmox host and VM 100 recovery with hardware mappings;
- exact backup selection, version, and checksum verification;
- hostile-archive rejection and safe extraction;
- fresh-volume and bind-target inventory before activation;
- exact Compose artifact and recovery-plan identity;
- service, storage, network, passthrough, and Coral health;
- decrypted-staging cleanup;
- a complete cold boot; and
- final OpenTofu and Ansible no-op checks.

Measure elapsed time from the agreed recovery start to verified service health. Save only secret-free commit, plan, artifact, backup, health, and duration hashes/outcomes. The current eight-hour recovery-time objective is not qualified until this timed exercise passes.

Never call an unrehearsed production restore a rehearsal. This repository intentionally has no command that silently escalates `--static` into a live restore, and successful steady reconciliation is not a substitute for a cold-boot recovery exercise.
