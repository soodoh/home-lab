#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const { validateVmArtifactReferences } = require("./validate-vm-artifact-references");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/contract/schema.json"), "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const proxmoxSource = fs.readFileSync(path.join(root, "infrastructure/tofu/proxmox/main.tf"), "utf8");

function check(value, expected, label) {
  const actual = validate(value);
  if (actual !== expected) {
    throw new Error(`${label}: expected valid=${expected}, got ${actual}: ${JSON.stringify(validate.errors)}`);
  }
}

check(structuredClone(contract), true, "current contract");

const missing = structuredClone(contract);
delete missing.arch.packages.kernel;
check(missing, false, "missing required package");

const unknown = structuredClone(contract);
unknown.arch.packages.parallel_runtime = "1.2.3-1";
check(unknown, false, "unknown package");

const customRom = structuredClone(contract);
customRom.proxmox.vm.pci.gpu.rom_file = "unmanaged.rom";
check(customRom, false, "custom ROM without artifact declaration");

const undeclaredBootDevice = structuredClone(contract);
undeclaredBootDevice.proxmox.vm.boot_order.push("ide2");
const bootFailures = validateVmArtifactReferences(undeclaredBootDevice, proxmoxSource);
if (!bootFailures.some((failure) => failure.includes("undeclared device ide2"))) {
  throw new Error(`undeclared boot device unexpectedly passed: ${JSON.stringify(bootFailures)}`);
}

const romFailures = validateVmArtifactReferences(contract, `${proxmoxSource}\n  rom_file = "unmanaged.rom"\n`);
if (!romFailures.some((failure) => failure.includes("source, SHA-256, and host provisioning"))) {
  throw new Error(`unmanaged Tofu ROM unexpectedly passed: ${JSON.stringify(romFailures)}`);
}

for (const key of ["kernel", "docker", "docker_compose", "tailscale"]) {
  const malformed = structuredClone(contract);
  malformed.arch.packages[key] = "latest";
  check(malformed, false, `malformed ${key} version`);
}

console.log("contract_package_schema=verified");
