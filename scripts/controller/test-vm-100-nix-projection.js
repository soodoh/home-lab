#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const { canonicalJson, projectVm100Scaffold, validateProjection } = require("./proxmox-nix-projection");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "nix/vm-100/projection.schema.json"), "utf8"));
const projectionPath = path.join(root, "nix/vm-100/projection.json");
const tracked = fs.readFileSync(projectionPath, "utf8");
const projected = projectVm100Scaffold(contract);
const rendered = canonicalJson(projected);

validateProjection(projected, schema);
if (tracked !== rendered) throw new Error("tracked VM 100 projection differs from pure allowlist output");
if (canonicalJson(JSON.parse(tracked)) !== tracked) throw new Error("tracked VM 100 projection is not canonical JSON");
if (canonicalJson(projectVm100Scaffold(structuredClone(contract))) !== rendered) {
  throw new Error("VM 100 projection bytes are not stable across equivalent inputs");
}

const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const unknown = structuredClone(projected);
unknown.unexpectedProjectionField = true;
if (validate(unknown)) throw new Error("VM 100 projection schema is open");

for (const mutation of [
  (value) => { value.vm_100.vmid = 101; },
  (value) => { value.vm_100.host_name = "other"; },
  (value) => { value.vm_100.network_identity = "other"; },
  (value) => { value.vm_100.deployment_authority = "nixos"; value.vm_100.nixos_activation_enabled = false; },
  (value) => { value.vm_100.workload_identity.uid = 1001; },
  (value) => { value.vm_100.access.authorized_login_keys = 1; },
  (value) => { value.vm_100.networking.match_mac = "AA:BB:CC:DD:EE:FF"; },
  (value) => { value.vm_100.storage.games.filesystem_uuid = "00000000-0000-0000-0000-000000000000"; },
  (value) => { value.vm_100.storage.shared.source = "192.0.2.1:/wrong"; },
]) {
  const invalid = structuredClone(contract);
  mutation(invalid);
  let rejected = false;
  try { projectVm100Scaffold(invalid); } catch { rejected = true; }
  if (!rejected) throw new Error("inconsistent VM 100 scaffold contract was accepted");
}

const excluded = structuredClone(contract);
excluded.proxmox.vm.smbios_uuid = "00000000-0000-0000-0000-000000000000";
excluded.proxmox.vm.pci = {};
excluded.proxmox.vm.usb = {};
if (canonicalJson(projectVm100Scaffold(excluded)) !== rendered) {
  throw new Error("unprojected protected hardware values changed VM 100 projection");
}

for (const forbidden of [
  contract.proxmox.vm.smbios_uuid,
  contract.proxmox.vm.games_disk.by_id_secret_ref,
  contract.recovery.recovery_age_recipient,
]) {
  if (tracked.includes(forbidden)) throw new Error(`VM 100 projection contains protected value ${JSON.stringify(forbidden)}`);
}
if (/secret|recipient|sops|smbios|pci|usb|authorizedKey/iu.test(tracked)) {
  throw new Error("VM 100 projection contains a forbidden protected-domain key or login key");
}

console.log("vm_100_nix_projection=verified");
