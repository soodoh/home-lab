# Tailscale management-plane bootstrap plan

## Status

Phase 4a gateway routing and direct Docker Phase 4b are operational. Docker is enrolled as `tag:docker-host`, direct
Tailscale SSH works as `ansible-deploy`, and LAN/gateway/serial recovery paths remain available.

Selected dual-path design:

- Use hosted Tailscale with a separate unprivileged Proxmox LXC subnet router as the provisioning/recovery path.
- Keep direct Tailscale SSH on this Docker VM as the normal Ansible path.
- Require the gateway to route only Proxmox `192.168.0.123/32` and Docker `192.168.0.100/32` before this bootstrap.
- Enroll with a short-lived, preauthorized, one-use auth key supplied through controller-only `TAILSCALE_AUTH_KEY`.
- Advertise the persistent Docker host as `docker-host` with `tag:docker-host`.
- Do not accept Tailscale DNS or advertised routes during initial Docker bootstrap.
- Enable Tailscale SSH while leaving the existing OpenSSH service and LAN path untouched.
- Create locked `ansible-deploy` with no supplementary groups and specifically no `docker` group.
- Grant `ansible-deploy` passwordless sudo for unattended Ansible, restricted by tailnet SSH policy, protected GitHub
  environments, and later CI concurrency controls.

`tailscaled` can manage its own networking rules when started. The playbook contains no firewall module or firewall
command, but its effective networking changes must still be inspected after bootstrap.

## Current verified baseline

- `tailscale` `1.98.10-1` is enabled, active, Running, and healthy at `100.111.210.72` as `tag:docker-host`.
- No DNS, accepted routes, or advertised routes are enabled; Tailscale SSH is enabled.
- `ansible-deploy` has a locked password, private primary group only, and validated passwordless sudo.
- OpenSSH remains enabled/active on LAN; Proxmox serial and gateway recovery are verified.
- Kernel/package/module tree align at `7.1.5-arch1-2`; `xt_mark` is loaded.
- Docker client/server align at `29.6.2`; 41 Compose services and 33 project volumes are present.
- Temporary auth-key files are absent and the one-use key is consumed.

## Tailnet prerequisites

Completed prerequisites:

1. Protected unprivileged `tag:infra-router` CT 101 is healthy and independently recoverable.
2. Only `192.168.0.123/32` and `192.168.0.100/32` are advertised and approved.
3. Routed PVE TCP/8006 and Docker TCP/22 work; unapproved PVE TCP/22 is denied.
4. `tag:docker-host`, the original `tag:ci` manual-audit grant, and Tailscale SSH rules were saved and validated.
5. Fresh LAN SSH and Proxmox serial-console recovery were reconfirmed after gateway activation.

The one-use, non-ephemeral `tag:docker-host` key was supplied only through the controller environment and a root-only
temporary file. It was consumed during enrollment and removed immediately afterward.

Historical conceptual policy fragment used during bootstrap—its `tag:ci` workload identity was retired. These entries were preserved through initial OpenTofu adoption; the contract now selects the guarded `detached` transition that removes them, but the live policy remains unchanged until that exact `main` operation is dispatched:

```json
{
  "tagOwners": {
    "tag:docker-host": ["autogroup:admin"],
    "tag:ci": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:ci"],
      "dst": ["tag:docker-host"],
      "ip": ["tcp:22"]
    }
  ],
  "ssh": [
    {
      "action": "accept",
      "src": ["tag:ci"],
      "dst": ["tag:docker-host"],
      "users": ["ansible-deploy"]
    }
  ]
}
```

The retained live entries do not authorize a standing credential because no active workload identity can mint `tag:ci`. Their reviewed removal is now represented by `tailscale.gateway_policy_stage: detached` and must occur only through the saved-plan gateway-policy operation.

The trusted MacBook controller uses the owner's direct Tailscale path and separate local provider credentials as documented in [`local-controller.md`](./local-controller.md). The gateway, LAN SSH, and console remain independent recovery paths.

Official references:

- <https://tailscale.com/docs/install/arch>
- <https://tailscale.com/docs/features/tailscale-ssh>
- <https://tailscale.com/docs/how-to/connect-ssh-linux-vm>
- <https://tailscale.com/docs/features/workload-identity-federation>

## Check-mode plan

These commands are read-only, require no auth key, and may run from any trusted controller clone:

```sh
cd <repository-clone>/ansible
ansible-playbook -i inventory/production.yml --syntax-check playbooks/bootstrap.yml
ansible-playbook -i inventory/production.yml playbooks/bootstrap.yml --check --diff --tags management_plane
```

The final post-convergence checks are:

- `bootstrap.yml --check --diff`: `ok=13 changed=0 failed=0 skipped=21`.
- `audit.yml --check --diff`: `ok=45 changed=0 failed=0 skipped=0`.
- `site.yml --check --diff`: `ok=33 changed=0 failed=0 skipped=1`.

The first authorized attempt failed before change because local inventory disabled become. The override was removed and
password-based sudo preflight verified root. The successful guarded run reported `ok=26 changed=5 failed=0 skipped=2`;
three changed tasks were temporary auth-file create/write/removal.

## Apply record

The approved apply created/converged the deployment identity and sudoers policy, installed only Tailscale 1.98.10-1,
enrolled the host with no routes/DNS acceptance, and enabled Tailscale SSH. The role uses Tailscale's `file:` auth-key
syntax; the secret was never placed in command arguments, repository files, inventory, facts, or diffs.

A separately approved graceful reboot moved from kernel 7.1.3 to 7.1.5 because the old module tree was absent and
Tailscale could not load `xt_mark`. GRUB/initramfs/package integrity checks passed first. After reboot, `xt_mark` loaded,
Tailscale health became empty, Docker daemon version aligned, and only the three approved no-restart containers were
started directly. No Compose up/down, recreation, package operation, or volume mutation occurred.

## Post-bootstrap verification

Completed:

1. Tailscale is enabled/active, Running, healthy, and tagged `docker-host`.
2. Tailscale SSH from the administrator Mac works as `ansible-deploy`.
3. The deployment user has only its primary group and `sudo -n true` succeeds.
4. No `/run/tailscale-auth-*` file remains.
5. OpenSSH, serial-console, and scoped gateway recovery remain available.
6. Kernel/module, Docker client/server, 41-service, 33-volume, mount/device, and systemd baselines pass.
7. Bootstrap, audit, and site checks all report `changed=0`.

Production inventory remains `.invalid` until a separately reviewed remote read-only audit.

## Failure and rollback policy

There is no automatic rollback:

- If Tailscale enrollment or SSH verification fails, retain the LAN SSH session and use the Proxmox console.
- Do not stop or reconfigure OpenSSH.
- Do not change firewall policy automatically.
- Do not remove `ansible-deploy` or its sudoers file until another recovery path is confirmed.
- `tailscale down`, disabling tailscaled, package removal, user removal, and sudoers removal each require explicit
  approval and a fresh plan.
- Never restart Docker, recreate containers, prune volumes, or touch `.env` while diagnosing management-plane
  bootstrap failures.
