#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const json = (relative) => JSON.parse(read(relative));
const tofuSource = (name) => fs.readdirSync(path.join(root, "infrastructure/tofu", name))
  .filter((entry) => entry.endsWith(".tf"))
  .sort()
  .map((entry) => read(`infrastructure/tofu/${name}/${entry}`))
  .join("\n");

const proxmoxInput = json("infrastructure/tofu/proxmox/vm.auto.tfvars.json");
const proxmox = proxmoxInput.proxmox_vm;
assert.equal(proxmoxInput.proxmox_endpoint, "https://proxmox:8006/api2/json");
assert.equal(proxmox.node, "proxmox");
assert.equal(proxmox.vm.vmid, 100);
assert.equal(proxmox.vm.name, "docker-host");
assert.deepEqual(proxmox.boot_order, ["scsi3", "net0"]);
assert.equal(proxmox.network.bridge, "vmbr0");
assert.equal(proxmox.network.docker_host_mac, "BC:24:11:89:19:5A");
assert.deepEqual([
  proxmox.vm.retired_disk_slot.interface,
  proxmox.vm.games_disk.interface,
  proxmox.vm.state_disk.interface,
  proxmox.cloud_init.drive_interface,
], ["scsi0", "scsi1", "scsi2", "ide2"]);
assert.equal(proxmox.vm.state_disk.serial, "QUAL-NIXOS-128G");
assert.equal(proxmox.vm.hardware_attachment_mode, "managed");

const proxmoxSource = tofuSource("proxmox");
for (const expected of [
  'resource "proxmox_virtual_environment_vm" "debian"',
  'resource "proxmox_hardware_mapping_pci" "device"',
  'resource "proxmox_hardware_mapping_usb" "device"',
  "vm                    = var.proxmox_vm.vm",
  "endpoint = var.proxmox_endpoint",
  "mac_address = var.proxmox_vm.network.docker_host_mac",
  "ignore_changes  = [disk[0], disk[1].file_format]",
]) assert.match(proxmoxSource, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
assert.doesNotMatch(proxmoxSource, /\b(?:rom_file|romfile)\s*=/);

const omada = json("infrastructure/tofu/omada/domain.auto.tfvars.json").omada_domain;
assert.deepEqual(omada, {
  controller_version: "6.2.14.11",
  endpoint: "https://Omada:8043",
});
const omadaSource = tofuSource("omada");
assert.match(omadaSource, /variable "omada_domain"/);
assert.match(omadaSource, /local\.export\.controller_version == var\.omada_domain\.controller_version/);
assert.match(read("scripts/configure-local-provider-credentials"), /infrastructure\/tofu\/omada\/domain\.auto\.tfvars\.json/);

const firewall = json("infrastructure/proxmox-firewall/host/proxmox-firewall-policy.json");
assert.deepEqual(firewall.options, { enable: true, policy_in: "DROP", policy_out: "ACCEPT" });
assert.equal(firewall.ownership, "pve-api");
assert.equal(firewall.activation, "pve-api");
assert.deepEqual(firewall.rules.map((rule) => [rule.source, rule.protocol, rule.destination_port]), [
  ["192.168.0.0/24", "tcp", 22],
  ["192.168.0.0/24", "tcp", 8006],
  ["192.168.0.100/32", "tcp", 2049],
  ["0.0.0.0/0", "udp", 41641],
  ["100.64.0.0/10", "tcp", 22],
  ["100.64.0.0/10", "tcp", 8006],
]);
const firewallController = read("scripts/controller/proxmox-firewall.py");
assert.match(firewallController, /infrastructure\/proxmox-firewall\/host\/proxmox-firewall-policy\.json/);
assert.doesNotMatch(firewallController, /infrastructure\/contract|home-lab\.yml/);
const canaryInstaller = read("ansible/playbooks/install-proxmox-firewall-nfs-canary.yml");
assert.match(canaryInstaller, /firewall_nfs_canary_expected_hostname: docker-host/);
assert.doesNotMatch(canaryInstaller, /infrastructure\/contract|home-lab\.yml/);

const dockerHostVars = load(read("ansible/group_vars/docker_host.yml"));
assert.equal(dockerHostVars.system_timezone, "America/Los_Angeles");

const tailscale = json("infrastructure/tofu/tailscale/policy.auto.tfvars.json").tailscale_policy_identity;
assert.deepEqual(tailscale, {
  owner_identity: "soodoh@github",
  tags: { docker_host: "tag:docker-host", proxmox: "tag:proxmox" },
});
const tailscaleSource = tofuSource("tailscale");
assert.match(tailscaleSource, /variable "tailscale_policy_identity"/);
assert.match(tailscaleSource, /tags\s*= var\.tailscale_policy_identity\.tags/);
assert.match(tailscaleSource, /owner_identity = var\.tailscale_policy_identity\.owner_identity/);
assert.match(tailscaleSource, /resource "tailscale_acl" "policy"/);

for (const name of ["proxmox", "omada", "tailscale"]) {
  const source = tofuSource(name);
  assert.doesNotMatch(source, /infrastructure\/contract|contract\/home-lab\.yml|local\.contract/,
    `${name} must consume only its typed root-local inputs`);
}

const contract = load(read("infrastructure/contract/home-lab.yml"));
const schema = json("infrastructure/contract/schema.json");
const contractVm = contract.proxmox.vm;
const pickNativeFields = (native, compatibility) => Object.fromEntries(
  Object.keys(native).map((name) => [name, compatibility[name]]),
);
assert.equal(proxmox.node, contract.proxmox.node);
assert.equal(proxmox.node, contract.network.proxmox.hostname);
assert.equal(proxmox.node, contract.network.proxmox.magicdns_name);
assert.equal(proxmox.vm.vmid, contract.vm_100.vmid);
assert.equal(proxmox.vm.name, contract.vm_100.host_name);
assert.equal(proxmox.vm.name, contract.debian.qualification.hostname);
assert.equal(proxmox.vm.vmid, contractVm.vmid);
assert.equal(proxmox.vm.name, contractVm.name);
assert.deepEqual(proxmox.boot_order, contract.debian.os_disk.boot_order);
assert.deepEqual(proxmox.boot_order, contractVm.boot_order);
assert.equal(proxmox.boot_order[0], contract.debian.os_disk.interface);
assert.deepEqual(proxmox.network, {
  bridge: contract.network.bridge,
  docker_host_mac: contract.network.docker_host.mac,
});
assert.equal(proxmox.network.docker_host_mac, contract.vm_100.networking.match_mac);
assert.deepEqual(proxmox.cloud_init, {
  datastore: contract.debian.cloud_init.datastore,
  drive_datastore: contract.debian.cloud_init.drive_datastore,
  drive_interface: contract.debian.cloud_init.drive_interface,
  meta_data_snippet_path: contract.debian.cloud_init.meta_data.snippet_path,
  network_data_snippet_path: contract.debian.cloud_init.network_data.snippet_path,
  user_data_snippet_path: contract.debian.cloud_init.user_data.snippet_path,
});
assert.equal(contract.debian.cloud_init.cicustom, [
  `meta=${proxmox.cloud_init.datastore}:snippets/${path.basename(proxmox.cloud_init.meta_data_snippet_path)}`,
  `network=${proxmox.cloud_init.datastore}:snippets/${path.basename(proxmox.cloud_init.network_data_snippet_path)}`,
  `user=${proxmox.cloud_init.datastore}:snippets/${path.basename(proxmox.cloud_init.user_data_snippet_path)}`,
].join(","));
for (const name of ["cpu", "retired_disk_slot", "games_disk", "state_disk"]) {
  assert.deepEqual(proxmox.vm[name], pickNativeFields(proxmox.vm[name], contractVm[name]));
}
for (const name of ["desired_protection", "hardware_attachment_mode", "machine", "memory_mb", "on_boot", "started"]) {
  assert.equal(proxmox.vm[name], contractVm[name]);
}
for (const name of ["gpu", "gpu_audio"]) {
  assert.deepEqual(proxmox.vm.pci[name], pickNativeFields(proxmox.vm.pci[name], contractVm.pci[name]));
}
for (const name of ["bluetooth", "zigbee", "zwave"]) {
  assert.deepEqual(proxmox.vm.usb[name], pickNativeFields(proxmox.vm.usb[name], contractVm.usb[name]));
}
assert.equal(proxmox.vm.pci.gpu.vendor_device, contract.vm_100.hardware.gpu.vendor_device);
assert.equal(proxmox.vm.pci.gpu.vendor_device, contract.debian.qualification.gpu_vendor_device);
assert.deepEqual(contract.proxmox.vfio.device_ids, [
  proxmox.vm.pci.gpu.vendor_device,
  proxmox.vm.pci.gpu_audio.vendor_device,
]);
assert.equal(proxmox.vm.usb.bluetooth.vendor_device, contract.vm_100.hardware.bluetooth.vendor_device);
assert.equal(proxmox.vm.usb.zigbee.vendor_device, contract.vm_100.hardware.serial.vendor_device);
assert.equal(proxmox.vm.usb.zwave.vendor_device, contract.vm_100.hardware.serial.vendor_device);
assert.deepEqual(tailscale.tags, contract.tailscale.tags);
assert.equal(tailscale.tags.proxmox, contract.proxmox.tailscale.advertise_tag);

for (const removed of ["aws", "compose_deployment", "omada", "recovery", "system_name", "system_timezone"]) {
  assert.equal(Object.hasOwn(contract, removed), false);
  assert.equal(Object.hasOwn(schema.properties, removed), false);
  assert.equal(schema.required.includes(removed), false);
}

assert.equal(Object.hasOwn(contract.proxmox, "api_endpoint"), false);
assert.equal(Object.hasOwn(contract.proxmox, "firewall"), false);
assert.equal(Object.hasOwn(schema.properties.proxmox.properties, "api_endpoint"), false);
assert.equal(Object.hasOwn(schema.properties.proxmox.properties, "firewall"), false);
assert.equal(schema.properties.proxmox.required.includes("api_endpoint"), false);
assert.equal(schema.properties.proxmox.required.includes("firewall"), false);
assert.equal(Object.hasOwn(contract.tailscale, "owner_identity"), false);
assert.equal(Object.hasOwn(contract.tailscale, "required_endpoints"), false);
assert.deepEqual(Object.keys(contract.tailscale).sort(), ["docker_host_client", "tags"]);
const validateContract = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
assert.equal(validateContract(contract), true, JSON.stringify(validateContract.errors));
for (const mutate of [
  (value) => { value.aws = { region: "us-east-1" }; },
  (value) => { value.compose_deployment = { version: 1, assets: [] }; },
  (value) => { value.omada = structuredClone(omada); },
  (value) => { value.recovery = { critical_rpo_hours: 24 }; },
  (value) => { value.system_name = "home-lab"; },
  (value) => { value.system_timezone = "America/Los_Angeles"; },
  (value) => { value.proxmox.api_endpoint = proxmoxInput.proxmox_endpoint; },
  (value) => { value.proxmox.firewall = structuredClone(firewall); },
  (value) => { value.tailscale.owner_identity = tailscale.owner_identity; },
  (value) => { value.tailscale.required_endpoints = ["docker-host:22"]; },
]) {
  const fixture = structuredClone(contract);
  mutate(fixture);
  assert.equal(validateContract(fixture), false, "compatibility schema accepted a provider-owned input");
}

console.log("domain_input_ownership=verified");
