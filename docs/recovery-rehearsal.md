# Recovery rehearsal

Run the non-mutating static rehearsal from a clean controller:

```sh
scripts/rehearse-recovery --static
```

It validates the contract and provider locks, exercises hostile archive and volume fixtures, and syntax-checks the retained recovery playbooks. A pass proves only static control flow; it performs no provider mutation, restore, or service activation.

## Live qualification

A live qualification is not currently exposed by `scripts/local-controller`. It must use an isolated Proxmox host, disposable recovery targets, and a separately reviewed procedure before any provider mutation or restore.

The qualification must demonstrate:

- exact saved-plan and backup-identity binding;
- Proxmox host and VM 100 recovery with hardware mappings;
- console-asserted official-PVE baseline, fixed `bootstrap-proxmox-nix-access install`, protected-input creation, Nix host check/install/verify, isolated firewall activation, protected summary readiness, fixed plan command success, and arbitrary-command denial;
- exact backup selection, version, and checksum verification;
- hostile-archive rejection and safe extraction;
- fresh-volume and bind-target inventory before activation;
- exact Compose artifact and recovery-plan identity;
- service, storage, network, and passthrough health;
- decrypted-staging cleanup;
- a complete cold boot; and
- final OpenTofu and Ansible no-op checks.

Measure elapsed time from the agreed recovery start to verified service health. Save only secret-free commit, plan, artifact, backup, health, and duration hashes/outcomes. The current eight-hour recovery-time objective is not qualified until this timed exercise passes.

Never call an unrehearsed production restore a rehearsal. This repository intentionally has no command that silently escalates `--static` into a live restore, and successful steady reconciliation is not a substitute for a cold-boot recovery exercise.
