# Home lab

This repository describes the desired state of an **existing** two-host home lab.
OpenTofu manages provider resources, Ansible converges the adopted hosts, and
Docker Compose defines applications. It is not a bare-metal bootstrap or an
automated disaster-recovery system. CI validates source; it does **not** deploy.

Git defines desired state, not proof of what is running. Base decisions on fresh
host and provider observations and remote OpenTofu state. Merge approval is not
deployment approval. A Git revert followed by approved site convergence can
roll back configuration, **not application data**.

## Start here

- [Operations](docs/operations.md): observe, review and converge live systems.
- [Recovery](recovery/README.md): discover snapshots and stage a private restore;
  production activation is not yet qualified.
- [Security](docs/security.md): protect credentials, state and recovery material.
- [Deployment access](docs/deployment-access.md): Tailscale SSH and controller access.

## Initial manual setup (or a new controller)

1. Obtain a reviewed checkout and independent console access to both hosts. From
   the controller, join the authorized tailnet and verify Tailscale SSH access
   and pinned host keys for the inventory's `ansible-deploy` accounts. These
   identities and the existing hosts must be established before Ansible can
   converge them. See [deployment access](docs/deployment-access.md).
2. Recover the SOPS age identity, separate plan/apply provider credentials,
   backend access, Restic passwords, Proton/rclone credentials and any recovery
   bundle identity from **independent protected storage**. The tracked SOPS
   ciphertext is not a substitute for the age identity. Follow
   [security](docs/security.md) and [controller preparation](docs/operations.md#prepare-a-disposable-controller);
   never commit a populated `.env`, print decrypted secrets, or reuse a
   provider-session directory.
3. Confirm live ownership before adopting anything: the remote S3 OpenTofu state
   and independently owner-controlled AWS permissions boundaries, existing
   Proxmox/Docker hosts, mounts and external storage, active Compose project,
   backup repositories and host locks/journals. The site playbook assumes an
   existing healthy deployment; it does not initialize Restic repositories,
   provision the hosts or resolve an interrupted operation for you. Do not
   create replacement state or repositories just because one is temporarily
   unavailable. Use [operations](docs/operations.md) for fresh observation,
   review and approved convergence.
4. Independently verify a current complete backup chain and a private test
   restore before depending on backups. The backup observer checks existing
   snapshots; installing the timers is not a first backup. External Nextcloud
   user data at `/mnt/storage/media/nextcloud/data` is **not** in the managed
   Restic recovery group and needs its own protected backup and restore plan.
   See [recovery](recovery/README.md).

## Disaster recovery and restore

- **Lost controller:** Use a fresh checkout and recover access and credentials
  from independent custody. Reobserve hosts, providers, remote state and backup
  repositories; controller caches, old plans and previous snapshot IDs are not
  recovery inputs. Follow [operations](docs/operations.md).
- **Lost application data / host:** Preserve any surviving disks, remote state,
  repository copies and nonterminal host locks, journals and before-images.
  Determine the affected recovery groups and external-storage dependencies.
  Follow [recovery](recovery/README.md): observe the live repositories, select
  and verify a current snapshot chain, then use `scripts/restore-critical-backup`
  to stage it into a new private root-owned directory. If recovering on a
  disposable VM from an encrypted bundle, use the bundle procedure there.
  Inspect database integrity and representative content privately. Recover
  external Nextcloud data separately.
- **Production activation is not automated or qualified.** Do not copy the
  staged files into production or start services from the staging procedure.
  Before activation, obtain an approved scope-specific plan for writer
  exclusion, protected before-images, database checks, external data, rollback
  and post-activation health. See
  [recovery's activation boundary](recovery/README.md#production-activation).

## Decisions that still require an operator

Review fresh observations and the complete saved plan before any OpenTofu apply,
particularly a deletion or replacement; obtain separate approval as described
in [operations](docs/operations.md#plan-and-apply-opentofu-resources). Approve
host changes only after a fresh observation and check run. Validate live
application behavior and access boundaries from real clients; source checks
and CI alone do not prove them. Some application state also lives outside the
configuration: create/revoke the `gost-proxy` Authentik app password manually
and protect the work-Mac client credential as described in
[security](docs/security.md#tailscale-coordination-proxy); after a restore,
verify Sonarr/Radarr/Radarr-4k's download-propers setting in their databases
(see [operations](docs/operations.md#operation-ownership-and-cleanup)). See
[outstanding work](docs/migrations.md) for unresolved recovery, identity and
ingress qualifications.

For routine validation and deployment commands use [operations](docs/operations.md)
and [CI](.github/workflows/ci.yml). For ownership boundaries see
[architecture](docs/architecture.md). Applications are defined in
[`docker-compose.yml`](docker-compose.yml) and [`services/`](services/);
provider roots in [`infrastructure/tofu/`](infrastructure/tofu/), and host
configuration in [`ansible/`](ansible/).
