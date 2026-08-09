# Ansible migration plan

## Current scope and stop point

The host migration is complete and GitHub-hosted execution is retired. Normal mutation is authorized only through an operation-specific, manifest-bound local approval.

```text
clean committed revision on the trusted MacBook
  -> separate local plan credential
  -> reviewed exact saved plan and single-use approval
  -> separate local apply credential
  -> direct operator Tailscale access
  -> Ansible and the existing Docker Compose project
```

Tailscale runs as the host-level `tailscaled.service`. Tailscale, SSH, firewall, mount, upgrade, and reboot work remains a
separate management plane excluded from routine application deployments.

## Superseded pre-Phase-4 baseline

Read-only inspection on 2026-07-30 historically confirmed:

- Arch Linux is running `7.1.3-arch1-3`; `linux` and `linux-headers` `7.1.5.arch1-2` are installed.
- Docker package/client is `29.6.2`; the running daemon reports `29.6.1`.
- Docker Compose is `5.3.1` and `docker compose config --quiet` succeeds.
- Docker, cronie, and sshd are enabled and active. Tailscale is absent.
- At that historical observation, all 41 declared Compose services were running while Gluetun and Seerr remained unhealthy; both are healthy in the current baseline.
- Compose declares 30 volumes. The Docker project owns 33 named volumes when the three legacy volumes are
  included.
- `happier-data`, `nzbget-data`, and `nzbhydra2-data` exist under their `docker-compose_` engine names.
- All 29 unique bind sources and all 8 unique device sources used by running containers exist.
- `/mnt/storage` is mounted as NFSv4 and `/mnt/games` is mounted as ext4. Their exact current fstab lines were
  read and are represented as assertions only.
- uinput, uhid, gasket, and apex are loaded. Coral, AMD GPU, serial, TUN, and virtual-input device paths exist.
- Gasket DKMS is installed for the deferred `7.1.5-arch1-2` kernel.
- All seven tracked Wolf host-file pairs still match byte for byte.
- `.env` remains mode `0644`, owned by `docker:docker`, within the mode `0700` `/home/docker` directory. Its
  contents were not read or printed.
- Five encrypted local backup files were observed; the newest had an mtime of 2026-07-30T06:38:34-07:00.
  Restore testing and remote-backup verification remain outstanding.
- Root's crontab exists as a mode `0600` root-owned file, but its contents remain uninspected without privilege.
- All eleven services sharing Gluetun's network namespace still have config-hash differences while their current
  containers remain running against the current Gluetun namespace.
- `docker compose --dry-run create --no-build` completed successfully and proposed no creates or recreates.

The historical Docker client/daemon mismatch was resolved by the separately approved controlled reboot in Phase 4.
The adopted current baseline now requires kernel `7.1.5-arch1-2` and Docker client/server `29.6.2`.

## Safety invariants

Until an approved later phase changes them:

- Never run an ordinary Ansible apply.
- Never run `docker compose up`, `down`, `pull`, `restart`, or recreate operations.
- Never use `docker compose down -v` or `--remove-orphans`.
- Never delete, rename, prune, or recreate Docker volumes.
- Never read, copy, template, or print `.env` values.
- Never run `pacman -Syu`, upgrade packages, reboot, or restart Docker.
- Never manage fstab, mounts, root cron, SSH, firewall, Tailscale, or filesystems from a routine deployment.
- Never expose SSH publicly or put the future deployment user in the `docker` group.
- Never automatically roll back a stateful service.
- Never commit secrets, host facts containing secrets, unredacted diffs, or CI artifacts containing secrets.

The `site.yml` playbook imports `apply_guard` with the `always` tag before any role. Check mode needs no confirmation.
Every normal run is refused unless it supplies both:

```sh
-e iac_apply_confirmed=true -e iac_apply_tag=<approved-tag>
```

The value of `iac_apply_tag` must match the single tag selected with `--tags`. Broad or untagged normal runs are
refused. This is an additional safeguard; it does not itself authorize an apply.

Routine `site.yml` roles contain no Tailscale, SSH, firewall, mount, filesystem, upgrade, reboot, deployment-user, or
plan-user management. Those roles exist only in separately guarded management-plane playbooks.

## Phase 1 audit scaffold

The audit uses only ansible-core built-ins. It gathers ordinary facts, performs metadata/stat inspections, runs
read-only CLI probes, and makes assertions. Every `command` task declares `changed_when: false`. Read-only command
probes execute during `--check`, so both ordinary audit and check-mode audit must finish with `changed=0`. There are
no handlers or Docker mutations.

Production inventory targets the stable Docker Tailscale identity. Historical hosted-controller audits completed with zero changes; the current authority is the manual trusted-controller workflow.

The operator separately installed `ansible` `14.2.0-1` (`ansible-core` `2.21.2`) using the previously approved
bootstrap command and reported that the audit completed with `changed=0`.

## Phase 3 desired-state check

`playbooks/site.yml` now models only the approved current state:

- `host_files` uses `copy` for the seven matching Wolf files with adopted ownership and modes; it has no handlers.
- `base` keeps only cronie present, enabled, and started using `state: present`/`state: started` without upgrades or
  restarts.
- `maintenance` asserts the deferred kernel state and root-cron metadata. It cannot read or manage root cron.
- `storage` asserts exact fstab lines and active mounts. It contains no file or mount module.
- `hardware` audits required modules, devices, and Gasket DKMS. It does not automate the patched AUR package.
- `docker` keeps Docker packages present and the service started/enabled without restart, image pull, or upgrade.
  It asserts the adopted aligned client/server version and refuses drift.
- `compose` performs only config, count, legacy-volume, and dry-run-create preflight checks. It never runs Compose
  up/down/pull/restart, removes orphans, or changes volumes.
- `health` verifies all 41 services remain running and requires Gluetun and Seerr to remain healthy.

Package, service, and copy tasks elevate only during a separately guarded normal run; check mode is unprivileged.
Run the complete plan from any trusted controller clone:

```sh
cd <repository-clone>/ansible
ansible-playbook -i inventory/production.yml --syntax-check playbooks/site.yml
ansible-playbook -i inventory/production.yml playbooks/site.yml --check --diff
```

Validation completed with `ok=33 changed=0 failed=0`; the follow-up audit completed with `ok=45 changed=0 failed=0`. The protected pipeline remains apply-disabled; no normal `site.yml` run is authorized.

## Phase 4 management plane

The approved architecture now has two paths:

- a dedicated unprivileged Proxmox LXC using hosted Tailscale as a tightly scoped subnet router for Proxmox API and
  Docker LAN bootstrap/recovery; and
- direct Tailscale SSH on the Docker VM for normal Ansible execution.

The gateway is specified in [`tailscale-gateway-lxc.md`](./tailscale-gateway-lxc.md). Protected unprivileged CT 101
runs Debian 13.6 at reserved `192.168.0.122` with native TUN, IPv4-only forwarding, and default-deny scoped firewall.
Tailscale 1.98.10 is healthy as `tag:infra-router`; exactly the PVE and Docker `/32` routes are operational and tested.
No OpenTofu code is added; future adoption must isolate this bootstrap dependency.

`playbooks/bootstrap.yml` converged direct Docker Tailscale and `ansible-deploy` through the guarded
`management_plane` apply. Docker is healthy as `tag:docker-host`; Tailscale SSH, locked account, private group,
passwordless sudo, and key cleanup were verified. A controlled reboot aligned kernel/modules and Docker daemon state.
Final bootstrap, audit, and site checks all report `changed=0`.

The completed record and rollback boundaries are in [`tailscale-bootstrap.md`](./tailscale-bootstrap.md). Production
inventory is now validated through the successful remote audit.

GitHub-hosted execution is retired. The manual workflow in [`local-controller.md`](./local-controller.md) permits any clean committed revision, separates plan/apply credentials, binds approvals to exact saved plans, retains the host lock, proves zero-change post-checks, and runs the complete audit.

The reusable `human_access` role now declares the human `docker` and `proxmox` accounts independently from automation identities. `playbooks/human-access.yml` is the narrow first-phase convergence path: it safely adopts existing numeric identities, enforces account-named primary groups with no supplementary groups, locks passwords, removes conventional SSH keys, installs validated account-specific passwordless sudo, and verifies the resulting boundary before the staged Tailscale policy migration.
## Recovery work still required

A manual restore drill is mandatory before any stateful Compose adoption or apply. It must be separately planned
and approved, and must not touch production volumes. At minimum:

1. Verify the decryption key is available from its recovery location outside Git and CI.
2. Select and hash a recent local encrypted backup. Independently inventory the separate weekly S3 archive for remote-RPO evidence, but do not block a local restore on weekly upload completion.
3. Restore into an isolated disposable destination, never over a production volume or bind directory.
4. Verify archive integrity, expected ownership/modes, and application-level readability for at least one stateful
   service.
5. Record recovery time, commands, evidence, and cleanup steps; obtain approval before cleanup.
6. Verify Proxmox console access and the existing LAN SSH path remain available as recovery paths.

The audit proves only that encrypted local backup files exist. It does not prove decryptability, restorability,
remote retention, or application consistency.

## Deferred phase gates

1. **Phase 4a stop:** create the hosted tailnet and review the exact Proxmox template/LXC creation plan; do not
   download a template, create CT 101, pass `/dev/net/tun`, or advertise routes without new approval.
2. **Phase 4b stop:** after gateway verification, review `bootstrap.yml --check --diff` for direct Docker Tailscale;
   do not run the normal Docker bootstrap without another explicit approval.
3. **Phase 5:** completed the manual remote audit with SHA-pinned actions, workload identity, minimal permissions,
   redaction, serialization, and a zero-change recap. Next, bootstrap and prove the unprivileged automatic-plan identity,
   then produce three stable plan-only runs.
4. **Phase 6:** after all apply blockers and fresh approval, converge one approved tag at a time in the order `host_files`,
   `base`, `maintenance`, `storage`, `docker`, with exact-plan review, protected-environment approval, guarded apply,
   second zero-change check, and runtime re-audit for each.
5. **Phases 7-8:** completed stable-root Compose adoption, SOPS activation, protected ongoing deployment, and the stateless Renovate canary. Active operation uses `/srv/docker-compose/current` and the root-only production environment; no host Git checkout is retained.
6. **Phase 9:** consider broader protected-main infrastructure automation only after host convergence. The staged Phase 6
   pipeline does not authorize Compose adoption, OpenTofu apply, management-plane changes, or removal of human approval.

OpenTofu and Proxmox VM import remain deferred until the Docker host has converged.
