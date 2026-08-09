# Tailscale local-controller operation

Tailscale remains a separate OpenTofu failure domain with strict saved-plan controls. The trusted MacBook controller uses two independent OAuth clients stored only in its mode-`0600` credential JSON files:

- **plan**: `policy_file:read`, `devices:core:read`, `devices:posture_attributes:read`, and `federated_keys:read`;
- **apply**: the corresponding policy, posture-attribute, and federated-key write scopes, with device-core read access but no device deletion authority.

Neither client receives a GitHub subject, enrollment tag, or stale-device deletion capability. Direct access comes from the operator's existing Tailscale user/device identity.

## Human SSH migration

Tailscale's owner selector is singular: `autogroup:owner`. OpenTofu owns the tailnet grants, SSH rules, and positive/negative policy tests; Ansible owns the locked local `docker` and `proxmox` accounts, their account-named primary groups, `/bin/bash` shells, homes, absent conventional authorized keys, and validated per-user `NOPASSWD` sudo policies. Conventional OpenSSH excludes both human accounts; `ansible-deploy`, `tofu-plan`, `tofu-apply`, LAN recovery, and console recovery remain separate paths.

The contract deliberately selects `tailscale.human_ssh_policy_stage: transition` first. Converge the accounts independently before changing tailnet policy:

```sh
cd ansible
ansible-playbook -i inventory/infrastructure.yml playbooks/human-access.yml --check --diff
ansible-playbook -i inventory/infrastructure.yml playbooks/human-access.yml \
  -e human_access_apply_confirmed=true
cd ..
```

Then use the exact saved-plan operation that adds `proxmox@proxmox` while retaining the existing Proxmox root paths:

```sh
scripts/local-controller plan tailscale-human-ssh-transition
scripts/local-controller review tailscale-human-ssh-transition
scripts/local-controller approve tailscale-human-ssh-transition \
  --confirmation apply-reviewed-tailscale-human-ssh-transition
scripts/local-controller apply tailscale-human-ssh-transition
```

Before finalization, verify `tailscale ssh docker@docker-host`, `tailscale ssh proxmox@proxmox`, and `sudo -n true` in both sessions. Record the successful checks outside the repository without tailnet addresses or identity data.

Only after those checks may a separately reviewed commit change `human_ssh_policy_stage` to `final`. Finalization uses `tailscale-human-ssh-final` with confirmation `finalize-reviewed-tailscale-human-ssh`. The exact policy update preserves owner/admin automation accounts, denies owner/admin `root@proxmox`, denies `tag:docker-host` TCP/22 and Tailscale SSH to Proxmox, preserves the unrelated tagged-host TCP/8006 path, and proves the positive and negative access matrix through policy tests. Verify the two named logins still succeed and both human and tagged-machine root attempts fail after apply.

## CI identity retirement

The one-time `tailscale-controller-retirement` operation is policy-inspected and separately approved. Its exact plan must contain:

1. one complete live-policy transition removing `tag:ci`, `tag:ci-plan`, and `tag:ci-apply` ownership, grants, SSH rules, and tests while preserving owner/admin direct access; and
2. deletion of exactly the four obsolete federated identities.

```sh
scripts/local-controller plan tailscale-controller-retirement
scripts/local-controller review tailscale-controller-retirement
scripts/local-controller approve tailscale-controller-retirement \
  --confirmation retire-reviewed-tailscale-ci-identities
scripts/local-controller apply tailscale-controller-retirement
```

Apply rechecks the live policy SHA-256 and ETag against the exact saved-plan before identity, performs an `If-Match` update, applies the exact state plan, proves live policy equals state, and requires a fresh OpenTofu no-op plus host audit. It does not delete any Tailscale device.

Gateway policy stages remain `active`, `detached`, and `retired`. The current `detached` stage preserves the infra-router recovery path but contains no hosted-controller identity. Final gateway retirement still requires separate device-absence approval after CT retirement.
