# Proxmox local bootstrap

This is the only host bootstrap that must be launched locally. Keep physical console access and a tested LAN root session open throughout it. Do not run the playbook from the remote controller.

## Prepare protected inputs

On the Proxmox host, check out the exact reviewed commit:

```sh
git clone https://github.com/soodoh/home-lab.git /root/home-lab
cd /root/home-lab
git checkout <reviewed-commit>
install -m 0600 /dev/null /root/home-lab-usb-serials.env
printf '%s\n' \
  'HOMELAB_ZIGBEE_USB_SERIAL=<protected-zigbee-serial>' \
  'HOMELAB_ZWAVE_USB_SERIAL=<protected-zwave-serial>' \
  >/root/home-lab-usb-serials.env
scripts/collect-proxmox-protected-inputs \
  --serial-env /root/home-lab-usb-serials.env \
  --output /root/home-lab-hardware.env
install -m 0600 recovery/proxmox-bootstrap-extra-vars.example.yml \
  /root/proxmox-bootstrap-extra-vars.yml
```

Edit only the root-owned extra-vars file. Confirm the console and LAN rollback gates, leave mutation gates false, and run the check phase:

```sh
scripts/bootstrap-proxmox-host --mode check \
  --extra-vars /root/proxmox-bootstrap-extra-vars.yml \
  --hardware-env /root/home-lab-hardware.env
```

If check mode reports a ZFS userspace/kernel mismatch, align only the reviewed signed Proxmox kernel and ZFS packages:

```sh
scripts/migrate-proxmox-zfs-stack --check
export PROXMOX_CONSOLE_CONFIRMED=true
export PROXMOX_ZFS_MIGRATION_CONFIRMED=install-reviewed-zfs-and-kernel-packages
scripts/migrate-proxmox-zfs-stack --apply
systemctl reboot
```

After reconnecting through the console or trusted LAN, run `scripts/migrate-proxmox-zfs-stack --verify`, then rerun bootstrap check mode. The migration refuses degraded storage or stopped protected guests.

## Apply the reviewed bootstrap

Review the complete check result. Set only the reviewed mutation gates true, then provide a short-lived, preauthorized, single-use Tailscale key tagged `tag:proxmox` and distinct SSH public keys for the plan and apply identities:

```sh
export TAILSCALE_AUTH_KEY='<protected one-use key>'
export PROXMOX_PLAN_SSH_PUBLIC_KEYS='<plan public key>'
export PROXMOX_APPLY_SSH_PUBLIC_KEYS='<apply public key>'
export PROXMOX_BOOTSTRAP_EXECUTION_CONFIRMED=run-reviewed-proxmox-bootstrap-with-console
scripts/bootstrap-proxmox-host --mode apply \
  --extra-vars /root/proxmox-bootstrap-extra-vars.yml \
  --hardware-env /root/home-lab-hardware.env
```

Apply reruns check mode before mutation. The wrapper requires a clean checkout and root-owned protected inputs, installs its hash-locked Ansible controller in a temporary root-only executable cache, and removes it on exit. It creates separated `tofu-plan` and `tofu-apply` API/SSH identities and leaves token escrow only in root-readable files under `/root/.config/home-lab/`.

A failed apply intentionally retains `/var/lib/iac-ansible-production.lock`. Inspect its root-owned owner record before retrying. The wrapper clears only a structurally valid lock whose owner records `operation=proxmox-bootstrap`, and only with:

```sh
export PROXMOX_BOOTSTRAP_RESUME_CONFIRMED=resume-matching-failed-proxmox-bootstrap
```

Never remove an unknown or mismatched lock manually.

## Transfer controller capabilities

Transfer each token through a protected channel into the matching mode-`0600` local-controller credential JSON. Do not print it, paste it into shell history, store it in GitHub, or reuse the apply token for planning. `scripts/configure-local-provider-credentials` updates the protected controller files through hidden prompts.

From the trusted local controller, prove:

- `tofu-plan` can perform only the expected audit/read operations;
- `tofu-apply` has only the required mutation capability;
- the two SSH keys authenticate only as their intended service users;
- Tailscale reaches `proxmox` on the required SSH/API endpoints; and
- host fingerprints match the protected inventory.

Only after these checks may the steady Proxmox play set `proxmox_ssh_access_proven=true` and tighten password authentication.

## Current status

The guarded bootstrap and pinned Proxmox kernel/ZFS migration have been live-qualified with console-backed reboots. The host is enrolled as `tag:proxmox`, the separated service identities are active, the reviewed VFIO/IOMMU configuration is loaded, ZFS is `ONLINE`, and VM 100 is the protected managed workload.

Custom GPU ROM and stale local-media retirement follows the console-backed, evidence-first procedure in [`proxmox-local-artifact-cleanup.md`](proxmox-local-artifact-cleanup.md). It is not part of steady bootstrap convergence.

CT 101 and its routed-gateway role were subsequently retired through separate reviewed operations. The empty `proxmox-legacy` backend remains as a state tombstone and recovery does not recreate that container. Do not use historical CT or gateway instructions as a bootstrap target.
