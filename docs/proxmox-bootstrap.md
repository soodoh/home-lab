# Proxmox local Nix bootstrap

This is the only fresh-host bootstrap and must be launched as root at a physical Proxmox console with a tested LAN root session retained. Nix remains controller-side; no Nix daemon or store is installed on Proxmox.

## Prepare protected inputs

Install official Debian-based Proxmox VE manually, check out the exact reviewed and pushed repository revision on the host, and prepare the protected hardware and access inputs described by the contract. Controller-specific tokens, keys, disk identities, pool identities, and USB serials remain in root-owned mode-`0600` inputs and never enter the Nix store, Git, plans, logs, or evidence.

Build `path:./nix#proxmox-host-bundle` on the trusted controller. Transfer only `bundle` and `bundle.sha256` into `/var/lib/home-lab/bootstrap/incoming/`. Put three distinct reviewed public-key sets in the fixed root-owned mode-`0600` `/root/.config/home-lab/proxmox-{plan,apply,firewall}-authorized-keys` files.

Before automation, establish only the destructive official-PVE baseline that cannot safely be inferred: configure the contract hostname and static bridge with the attached console available; import the already-existing ZFS pool by its independently verified protected GUID without creating or formatting storage; register its existing dataset; install the exact contract package versions from the official repositories; and enroll Tailscale with a protected single-use preauthorized key using the exact contract hostname/tag/DNS/routes/netfilter/SSH preferences. Assert that the pool is `ONLINE`, its exact six-mirror protected topology is present, VM storage is not overwritten, and the contract services/binaries are available. This is a deterministic manual assertion boundary, not permission for the bootstrap to discover, import, create, format, upgrade, or delete infrastructure.

Then run the closed console access bootstrap from `/dev/ttyN`. It installs only the fixed firewall login transport needed as the account shell; the complete firewall transaction is installed later by the host bootstrap:

```sh
export PROXMOX_NIX_ACCESS_INSTALL_CONFIRMED=install-reviewed-access-authority
scripts/bootstrap-proxmox-nix-access install
```

It creates exactly `tofu-plan`, `tofu-apply`, `firewall-apply`, and the locked non-SSH `proxmox` audit account, installs exact separated/forced service authorized keys plus contract-derived SSH/sudo files. `tofu-apply` has the fixed apply transport as both login shell and forced key command, no supplementary groups, and sudo access only to `proxmox-private-preparer prepare` and `proxmox-activator session`; creates the exact PVE roles, creates privilege-separated plan/apply tokens once, stores their one-time values only in root-owned mode-`0600` escrows, and installs exact token ACLs. It accepts no paths, identities, roles, commands, or token values from callers. An interruption rolls back created access authority; a retained journal is recovered only with:

```sh
export PROXMOX_NIX_ACCESS_RECOVER_CONFIRMED=recover-reviewed-access-bootstrap
scripts/bootstrap-proxmox-nix-access recover
```

Now create the protected runtime input without printing protected values:

```sh
export PROXMOX_NIX_PROTECTED_CREATE_CONFIRMED=create-reviewed-protected-runtime-input
scripts/prepare-proxmox-nix-protected-inputs
```

## Install and verify

From the same exact pushed checkout on the Proxmox console:

```sh
scripts/bootstrap-proxmox-nix-host check
export PROXMOX_NIX_BOOTSTRAP_CONSOLE_CONFIRMED=install-reviewed-helper-bundle
export PROXMOX_NIX_BOOTSTRAP_LAN_CONFIRMED=tested-lan-root-session-open
scripts/bootstrap-proxmox-nix-host install
scripts/bootstrap-proxmox-nix-host verify
```

The fixed bootstrap accepts only `check`, `install`, `verify`, or explicitly gated `recover`. It verifies the official bare-metal PVE target, exact Git revision, sanitized bundle, protected input, free space, and authority locks. Install is journaled and rollback-safe. It installs the immutable observer, private preparer, and activator plus every retained firewall host asset from `infrastructure/proxmox-firewall/host`: transaction/transport/boot helpers, canonical policy JSON, systemd units/drop-ins, and the root-only attestation key. It reloads systemd, enables boot recovery and the persistent rollback timer, starts the watchdog, and `verify` proves exact bytes, key metadata, enablement, and active watchdog state.

Only after those assets exist, follow [`proxmox-firewall-cutover.md`](proxmox-firewall-cutover.md): generate the exact fixed controller plan, review its SHA-256, perform the `/dev/ttyN` isolate/authorize ceremonies, apply that exact hash, require terminal commit and all canaries, then restore retained access. Fresh bootstrap does not activate firewall policy implicitly.

Interrupted installation requires:

```sh
export PROXMOX_NIX_BOOTSTRAP_RECOVER_CONFIRMED=recover-reviewed-helper-transaction
scripts/bootstrap-proxmox-nix-host recover
```

For an already-qualified live host that still has the legacy `/bin/bash`, unforced apply key, sudo group, and `NOPASSWD: ALL`, use the distinct console-only migration after reviewing and testing root/LAN rollback access:

```sh
export PROXMOX_NIX_ACCESS_CONVERGE_CONFIRMED=converge-reviewed-legacy-access-authority
scripts/bootstrap-proxmox-nix-access converge
```

It first proves every non-apply account, key, access file, token escrow, and protected input plus the exact legacy apply state. It then atomically installs the tracked apply transport/key/sudo policy and changes the shell/groups; it is not accepted on a fresh or partially divergent host.

For a reviewed additive privilege correction to the existing apply role, use the separate console-only role refresh. It proves the exact current `HomeLabTofuApply` privilege set and permits only adding contract-required `SDN.Use`; it does not recreate accounts, tokens, ACLs, keys, or sudo authority:

```sh
export PROXMOX_NIX_ACCESS_ROLE_REFRESH_CONFIRMED=refresh-reviewed-apply-role
scripts/bootstrap-proxmox-nix-access refresh-role
```

If interrupted, retain the journal and recover only from the physical console with `PROXMOX_NIX_ACCESS_ROLE_REFRESH_RECOVER_CONFIRMED=recover-reviewed-role-refresh scripts/bootstrap-proxmox-nix-access recover`.

The disposable VMID 9900 root additionally needs the plan token's existing disk-inspection role at `/vms/9900` after the VM exists. Add only that ACL through its separate exact-before-state console operation:

```sh
export PROXMOX_NIX_ACCESS_QUALIFICATION_ACL_CONFIRMED=refresh-reviewed-qualification-acl
scripts/bootstrap-proxmox-nix-access refresh-qualification-acl
```

If interrupted, recover with `PROXMOX_NIX_ACCESS_QUALIFICATION_ACL_RECOVER_CONFIRMED=recover-reviewed-qualification-acl scripts/bootstrap-proxmox-nix-access recover`. This operation does not change either role, token, production VM ACL, key, account, or sudo authority.

The VM cloud-image import uses the PVE API only after the existing `local` directory storage is explicitly enabled for `import` content. Apply the exact additive storage prerequisite at the physical console:

```sh
export PROXMOX_NIX_IMPORT_STORAGE_CONFIRMED=refresh-reviewed-import-storage
scripts/bootstrap-proxmox-nix-access refresh-import-storage
```

It accepts only the exact current `backup,iso,vztmpl` content set and only adds `import`. An interrupted operation is reversed with `PROXMOX_NIX_IMPORT_STORAGE_RECOVER_CONFIRMED=recover-reviewed-import-storage scripts/bootstrap-proxmox-nix-access recover`; no storage path, type, image, volume, or VM is created or deleted.

Do not remove journals or ownership locks manually. Protected inputs and the session key use their separate fixed refresh/rotation tools and explicit gates.

After bootstrap, prove that the fixed plan identity works and arbitrary SSH commands are denied. The controller then owns Proxmox host convergence through the exact manifest-bound Nix `plan`/guarded `prepare`/`apply`/fresh-zero-action `verify` flow. OpenTofu remains authoritative for VM 100 and PVE hardware mappings. Reboot remains a separate reviewed operation.
