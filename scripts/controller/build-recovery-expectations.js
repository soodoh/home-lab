#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const repository = path.resolve(__dirname, "../..");
const outputIndex = process.argv.indexOf("--output");
if (outputIndex < 0 || !process.argv[outputIndex + 1] || process.argv.length !== 4) {
  console.error("usage: build-recovery-expectations.js --output <path>");
  process.exit(64);
}

const contract = load(fs.readFileSync(path.join(repository, "infrastructure/contract/home-lab.yml"), "utf8"));
const vm = contract.proxmox.vm;
const node = contract.proxmox.node;
const gamesDiskById = process.env.TF_VAR_games_disk_by_id || process.env.HOMELAB_GAMES_DISK_BY_ID;
if (typeof gamesDiskById !== "string" || !gamesDiskById.startsWith("/dev/disk/by-id/")) {
  throw new Error("TF_VAR_games_disk_by_id or HOMELAB_GAMES_DISK_BY_ID must be an absolute /dev/disk/by-id path");
}
const serialUsbPaths = process.env.TF_VAR_serial_usb_paths
  ? JSON.parse(process.env.TF_VAR_serial_usb_paths)
  : {
      zigbee: process.env.HOMELAB_ZIGBEE_USB_PORT,
      zwave: process.env.HOMELAB_ZWAVE_USB_PORT,
    };
if (
  !serialUsbPaths ||
  !/^[0-9]+-[0-9]+(?:\.[0-9]+)*$/.test(serialUsbPaths.zigbee || "") ||
  !/^[0-9]+-[0-9]+(?:\.[0-9]+)*$/.test(serialUsbPaths.zwave || "") ||
  serialUsbPaths.zigbee === serialUsbPaths.zwave
) {
  throw new Error("TF_VAR_serial_usb_paths must contain unique Zigbee and Z-Wave physical USB paths");
}

const resources = {};
for (const [key, device] of Object.entries({ gpu: vm.pci.gpu, gpu_audio: vm.pci.gpu_audio })) {
  resources[`proxmox_hardware_mapping_pci.device["${key}"]`] = {
    type: "proxmox_hardware_mapping_pci",
    expected: {
      name: device.mapping,
      map: [{ id: device.vendor_device, node, path: device.bdf }],
    },
  };
}
for (const [key, device] of Object.entries({ bluetooth: vm.usb.bluetooth, zigbee: vm.usb.zigbee, zwave: vm.usb.zwave })) {
  resources[`proxmox_hardware_mapping_usb.device["${key}"]`] = {
    type: "proxmox_hardware_mapping_usb",
    expected: {
      name: device.mapping,
      map: [{
        id: device.vendor_device,
        node,
        path: serialUsbPaths[key] || null,
      }],
    },
  };
}
resources["proxmox_download_file.arch_recovery_image[0]"] = {
  type: "proxmox_download_file",
  expected: {
    content_type: "import",
    datastore_id: "local",
    node_name: node,
    url: vm.cloud_image.url,
    checksum: vm.cloud_image.sha256,
    checksum_algorithm: "sha256",
    file_name: `Arch-Linux-x86_64-cloudimg-${vm.cloud_image.version}.qcow2`,
  },
};
resources["proxmox_virtual_environment_vm.arch"] = {
  type: "proxmox_virtual_environment_vm",
  expected: {
    node_name: node,
    vm_id: vm.vmid,
    name: vm.name,
    machine: vm.machine,
    kvm_arguments: vm.cpu.kvm_arguments,
    boot_order: vm.boot_order,
    scsi_hardware: "virtio-scsi-single",
    on_boot: vm.on_boot,
    started: vm.started,
    protection: vm.desired_protection,
    cdrom: [{ file_id: "none", interface: "ide2" }],
    cpu: [{ cores: vm.cpu.cores, sockets: vm.cpu.sockets, type: vm.cpu.type }],
    memory: [{ dedicated: vm.memory_mb, floating: 0 }],
    disk: [
      {
        datastore_id: vm.root_disk.datastore,
        interface: vm.root_disk.interface,
        size: vm.root_disk.size_gb,
        iothread: vm.root_disk.iothread,
        backup: true,
        cache: "none",
        discard: "ignore",
        replicate: true,
        ssd: false,
      },
      {
        datastore_id: "",
        path_in_datastore: gamesDiskById,
        interface: vm.games_disk.interface,
        backup: vm.games_disk.backup,
        cache: "none",
        discard: vm.games_disk.discard,
        iothread: vm.games_disk.iothread,
        replicate: true,
        ssd: vm.games_disk.ssd,
      },
      {
        datastore_id: vm.state_disk.datastore,
        interface: vm.state_disk.interface,
        serial: vm.state_disk.serial,
        size: vm.state_disk.size_gb,
        iothread: vm.state_disk.iothread,
        backup: vm.state_disk.backup,
        cache: "none",
        discard: vm.state_disk.discard,
        replicate: true,
        ssd: vm.state_disk.ssd,
      },
    ],
    network_device: [{
      bridge: contract.network.bridge,
      firewall: true,
      mac_address: contract.network.arch.mac,
      model: "virtio",
    }],
    hostpci: [
      {
        device: "hostpci1",
        id: null,
        mapping: vm.pci.gpu.mapping,
        pcie: vm.pci.gpu.pcie,
        xvga: vm.pci.gpu.xvga,
        rombar: true,
      },
      {
        device: "hostpci2",
        id: null,
        mapping: vm.pci.gpu_audio.mapping,
        pcie: vm.pci.gpu_audio.pcie,
        rombar: true,
      },
    ],
    usb: [
      { host: null, mapping: vm.usb.zigbee.mapping },
      { host: null, mapping: vm.usb.zwave.mapping },
      { host: null, mapping: vm.usb.bluetooth.mapping, usb3: vm.usb.bluetooth.usb3 },
    ],
    smbios: [{ uuid: vm.smbios_uuid }],
  },
};

const output = path.resolve(process.argv[outputIndex + 1]);
fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
fs.writeFileSync(output, `${JSON.stringify({ version: 1, resources }, null, 2)}\n`, { mode: 0o600 });
fs.chmodSync(output, 0o600);
