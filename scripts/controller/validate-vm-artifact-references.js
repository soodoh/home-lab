"use strict";

function validateVmArtifactReferences(contract, proxmoxSource) {
  const failures = [];
  const vm = contract.proxmox.vm;
  const declaredBootDevices = new Set([
    vm.root_disk.interface,
    vm.games_disk.interface,
    "net0",
  ]);

  for (const device of vm.boot_order) {
    if (!declaredBootDevices.has(device)) {
      failures.push(`proxmox.vm.boot_order references undeclared device ${device}`);
    }
  }

  for (const [name, device] of Object.entries(vm.pci)) {
    if (Object.hasOwn(device, "rom_file")) {
      failures.push(
        `proxmox.vm.pci.${name}.rom_file is forbidden until its source, SHA-256, and host provisioning are declared`,
      );
    }
  }

  if (/^[\t ]*rom_file[\t ]*=/m.test(proxmoxSource) || /\bromfile[\t ]*=/.test(proxmoxSource)) {
    failures.push(
      "Proxmox Tofu cannot reference a custom ROM until its source, SHA-256, and host provisioning are declared",
    );
  }

  return failures;
}

module.exports = { validateVmArtifactReferences };
