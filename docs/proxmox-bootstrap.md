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

## Layer the Nix transport bootstrap

The existing local Ansible bootstrap remains the fresh-host authority until cutover. After it succeeds, build the sanitized bundle on the trusted controller and transfer only `bundle` and `bundle.sha256` to the fixed mode-`0700` `/var/lib/home-lab/bootstrap/incoming/` directory. Put the reviewed plan/apply public keys in the fixed mode-`0600` `/root/.config/home-lab/proxmox-{plan,apply}-authorized-keys` files; the token escrows and `/root/home-lab-hardware.env` already use fixed root-only paths. Create the canonical protected input without manual JSON assembly, then use the exact pushed checkout locally on the host:

```sh
export PROXMOX_NIX_PROTECTED_CREATE_CONFIRMED=create-reviewed-protected-runtime-input
scripts/prepare-proxmox-nix-protected-inputs
scripts/bootstrap-proxmox-nix-host check
export PROXMOX_NIX_BOOTSTRAP_CONSOLE_CONFIRMED=install-reviewed-helper-bundle
export PROXMOX_NIX_BOOTSTRAP_LAN_CONFIRMED=tested-lan-root-session-open
scripts/bootstrap-proxmox-nix-host install
scripts/bootstrap-proxmox-nix-host verify
```

The command accepts only `check`, `install`, `verify`, or explicitly gated `recover`; it accepts no paths, hosts, or caller commands. Install takes the shared operation mutex, then rejects both persistent Ansible and Nix ownership before mutation. Proxmox Ansible uses the identical mutex-first ordering and refuses a retained Nix `apply.lock`; the activator and private preparer refuse retained Ansible ownership. Install copies the three immutable verified helpers outside the Nix store, creates the root-only session key only when absent, copies protected inputs plus a root-only keyed runtime attestation only to fixed host-local paths, and writes only non-secret Git/tree/bundle/schema/helper hashes to the install manifest. It retains one bounded exact prior helper/manifest generation and refuses active Ansible/Nix ownership locks. Every atomic target uses one deterministic target-specific `.bootstrap-pending` name; startup inventories only that closed set, promotes a validated initial journal when needed, durably removes recognized uncommitted remnants (including session-key and protected-input bytes), and refuses unknown temporary entries. The fixed verified-bundle snapshot is likewise removed under both locks. Interrupted transactions—or exact prior-helper recovery for a matching retained active session—require `PROXMOX_NIX_BOOTSTRAP_RECOVER_CONFIRMED=recover-reviewed-helper-transaction` and `recover`.

Protected inputs and session keys have separate fixed no-argument lifecycle commands. `refresh-proxmox-nix-protected-inputs` requires `PROXMOX_NIX_PROTECTED_REFRESH_CONFIRMED=refresh-reviewed-protected-runtime-input`; `rotate-proxmox-nix-session-key` requires `PROXMOX_NIX_SESSION_KEY_ROTATE_CONFIRMED=rotate-reviewed-session-key-with-no-active-plans`. Both take the shared locks and refuse active or nonterminal state. Rotation atomically replaces the key and never retains its prior bytes; all uncommitted sidecars must be discarded before rotation.

After verify, prove the fixed plan identity command and denial of arbitrary SSH commands, then create a shadow plan. That console-backed bootstrap is complete and the tracked policy is now `shadow-required`; repository-side capture produces read-only, sequential audit evidence and never apply authority. Helper installation, protected-state creation, key creation, the `tofu-plan` sudo rule, and its forced-key change were explicitly approved production mutations performed with physical console access and a tested LAN root session. This milestone does not authorize apply, package/API/OpenTofu mutations, watchdog changes, or reboot. `tofu-apply` intentionally retains `NOPASSWD: ALL` for Ansible compatibility and remains a cutover blocker.

## Current status

The guarded bootstrap and pinned Proxmox kernel/ZFS migration have been live-qualified with console-backed reboots. The host is enrolled as `tag:proxmox`, the separated service identities are active, the reviewed VFIO/IOMMU configuration is loaded, ZFS is `ONLINE`, and VM 100 is the protected managed workload.

Custom GPU ROM and stale local-media retirement follows the console-backed, evidence-first procedure in [`proxmox-local-artifact-cleanup.md`](proxmox-local-artifact-cleanup.md). It is not part of steady bootstrap convergence.

CT 101 and its routed-gateway role were subsequently retired through separate reviewed operations. The empty `proxmox-legacy` backend remains as a state tombstone and recovery does not recreate that container. Do not use historical CT or gateway instructions as a bootstrap target.
