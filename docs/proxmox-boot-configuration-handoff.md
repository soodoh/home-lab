# Proxmox boot-configuration handoff

This phase transfers only the reboot-bound GRUB, ZFS module-option, and VFIO module-policy source files from Nix to Ansible. Nix remains the mutation owner while `lifecycle.hosts.proxmox.domain_handoffs.boot_configuration.state` is `pending` or `ready`. `ready` freezes Nix mutation but does not authorize Ansible. Ansible may mutate only after the same reviewed source revision sets the state to `transferred` and the current owner to `ansible`.

## Exact scope

The contract is the sole desired-state authority for:

- the one required `GRUB_CMDLINE_LINUX_DEFAULT` assignment in `/etc/default/grub`;
- `/etc/modprobe.d/zfs.conf`;
- `/etc/modules-load.d/home-lab-vfio.conf`; and
- `/etc/modprobe.d/home-lab-vfio.conf`.

The VFIO modprobe file is a `protected-managed-file`: its device IDs must never enter the reduced Nix projection, public action catalog, Ansible output, or command line. Read-only plans expose only hashes, counts, booleans, and the installed observer's reduced protected-hardware summary.

The generated derivatives are `/boot/grub/grub.cfg` and the initramfs images for both contract-retained kernels. They are validation and rollback subjects, not independently authored configuration. The current kernel command line, loaded modules, ZFS ARC limit, exact PCI identities, IOMMU groups, and drivers are post-boot evidence.

This domain does not own packages, kernels, firmware, VM 100 configuration, PVE PCI mappings, the ZFS pool or datasets, the VFIO recovery helper/policy, device unbind/rebind, service restarts, or reboot. OpenTofu retains VM and hardware-mapping authority. VFIO recovery remains a separately confirmed protected session.

## Discovered retirement residue

Commit `129f186995283b4b8190a9a47306220d0c0f61f2` retired the Coral TPU from the contract, OpenTofu mapping, VM 100, packages, and workloads. The live `/etc/modprobe.d/home-lab-vfio.conf` nevertheless still contains `1ac1:089a`, and the present device at `0000:0b:00.0` remains bound to `vfio-pci`. The current contract permits only `1002:744c` and `1002:ab30`.

The residue must be removed through one exact protected cleanup session operating under the current ownership phase. The ordinary Nix catalog and generic Ansible execution surface are not allowed to carry the protected IDs. The fixed host activator must derive exact bytes from the checked-out contract, expose only opaque attestations, replace only the reviewed source file, and rebuild initramfs for the retained kernels. It must not reboot. Runtime driver disposition is verified only by a later, separately authorized guarded reboot. Ownership parity cannot become `ready` until the source file and generated initramfs evidence match the contract.

## Read-only parity

The Ansible plan must work in check mode with `changed=0` and must report deterministic normalized evidence for:

1. contract ownership and lifecycle state;
2. regular-file, no-symlink, single-link, root ownership, and exact modes for all four source paths;
3. an exactly-one GRUB assignment with the exact ordered token list;
4. exact full-file hashes for the ZFS and VFIO files, with protected VFIO values represented only by opaque expected hashes and mismatch counts;
5. absence of conflicting VFIO module declarations in the contract-listed legacy paths;
6. `grub.cfg` syntax, normal-entry token coverage, and source-to-generated freshness;
7. current and fallback initramfs presence and freshness relative to every module-policy source;
8. current kernel command-line tokens, loaded module state, and live `zfs_arc_max`;
9. exact GPU, GPU-audio, and host-iGPU PCI identity, IOMMU group, and driver evidence; and
10. absence of controller, host, firewall, VFIO, package, reboot, backup, or recovery lock conflicts.

Unavailable or ambiguous facts fail closed. Read-only parity never runs `update-grub`, `update-initramfs`, modprobe, driver bind/unbind, package commands, service changes, or reboot.

## Activation boundary

A future Ansible activation must be an immutable saved plan bound to the clean commit, contract and schema hashes, fixed role/helper hashes, strict host key, two equal observations, exact source and generated-artifact hashes, retained kernels, lock evidence, and expiry. Protected values are derived only inside the fixed root activator from the bound host checkout. Apply must re-observe before mutation, capture root-only rollback copies durably, replace only differing source records, run only the fixed generated-artifact commands named by the plan, and post-observe before committing a root-only journal.

Rollback restores the exact captured source file and both retained initramfs images from durable root-only backups. Ambiguous transport recovery recognizes only exact before or journaled committed states and rolls any nonterminal transaction back without invoking initramfs tooling. A source activation never reboots automatically. Any reboot uses the existing reboot lifecycle with fresh console, access, backup, VM, pool, service, dpkg, solver, kernel, and boot-ID evidence plus a separate exact confirmation.

## Handoff sequence

1. Add deterministic read-only parity and expose the retired Coral residue as a blocker.
2. Keep the protected VFIO modprobe file out of the reduced Nix projection and ordinary Ansible arguments.
3. Build, review, and separately authorize an exact fixed-host protected cleanup activation; rebuild initramfs without reboot.
4. Re-run Ansible parity and Nix planning until source and generated initramfs evidence match; runtime remains blocked until reboot.
5. Build, review, and separately authorize the existing guarded reboot workflow, then verify the retired device is no longer bound to `vfio-pci` while retained GPU devices and VM 100 remain healthy.
6. Re-run full parity, set the domain to `ready`, install and verify the frozen Nix bundle, and prove Nix has zero boot-domain mutation surface.
7. Transfer ownership in a source-only commit.
8. Apply one exact Ansible ownership activation, expected to make no file changes, and commit its durable journal.

## Current status

Read-only check-mode planning is implemented and reports `changed=0`. The first installed protected cleanup capability failed closed during its post-install observation because `/usr/bin/node` was absent; no source, initramfs, binding, or reboot mutation occurred. Commit `c6644fe7018ecad708df9602378ab59b354963aa` replaced that dependency with the installed host Python YAML parser, and the corrected fixed capability passed physical-console installation and observer canaries.

Protected cleanup activation `814c14f2da25d2121d270b7c21d9db214de7696aef806dcbf8e5f5f70dafa5a9` committed successfully. It changed only the protected VFIO source, durably retained root-only mode-`0600` single-link backups of that source and both retained initramfs images, rebuilt exactly kernels `7.0.14-14-pve` and `7.0.14-8-pve`, and did not reboot. Post-activation observation proves the source matches the protected expected hash, both retained GPU devices remain bound as expected, and the retired device remains bound at runtime until a separately authorized reboot. Ansible check mode remains `changed=0`; its remaining blockers correctly include runtime PCI parity, Nix ownership, immutable handoff/ownership authorization, and separate reboot authorization.
