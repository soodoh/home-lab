#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const { validateVmArtifactReferences } = require("./validate-vm-artifact-references");
const { validateProxmoxHostPolicy } = require("./validate-proxmox-host-policy");

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

function checkSemantic(value, expectedFailure, label) {
  check(value, true, `${label} schema`);
  const failures = validateProxmoxHostPolicy(value);
  if (failures.some((failure) => failure.includes(expectedFailure))) return;
  throw new Error(`${label}: expected semantic failure containing ${JSON.stringify(expectedFailure)}, got ${JSON.stringify(failures)}`);
}

check(structuredClone(contract), true, "current contract");
if (validateProxmoxHostPolicy(contract).length) {
  throw new Error(`current Proxmox host policy failed semantics: ${JSON.stringify(validateProxmoxHostPolicy(contract))}`);
}

const duplicateZfsMember = structuredClone(contract);
duplicateZfsMember.storage.zfs.members[1].secret_ref = duplicateZfsMember.storage.zfs.members[0].secret_ref;
check(duplicateZfsMember, false, "duplicate ZFS member identity");

const wrongMirrorIndex = structuredClone(contract);
wrongMirrorIndex.storage.zfs.members[10].mirror = 4;
check(wrongMirrorIndex, false, "missing exact mirror index");

const incompleteMirror = structuredClone(contract);
incompleteMirror.storage.zfs.members.pop();
check(incompleteMirror, false, "one-member mirror");

const pinnedSerialUsbPort = structuredClone(contract);
pinnedSerialUsbPort.proxmox.vm.usb.zigbee.host = "1-6";
check(pinnedSerialUsbPort, false, "serial USB mapping must resolve at runtime");

const unknownHostPolicy = structuredClone(contract);
unknownHostPolicy.proxmox.packages.optional = [];
check(unknownHostPolicy, false, "unknown host package policy");

for (const version of ["latest", "unstable1", "latest!", "1.0-"]) {
  const malformedDebianVersion = structuredClone(contract);
  malformedDebianVersion.proxmox.packages.direct[0].version = version;
  check(malformedDebianVersion, false, `malformed Debian package version ${version}`);
}

const epochAndColonVersion = structuredClone(contract);
epochAndColonVersion.proxmox.packages.direct[0].version = "1:2:3-1";
check(epochAndColonVersion, true, "valid epoch and upstream colon Debian package version");

for (const [field, value] of [["name", 42], ["version", 42], ["version", null]]) {
  const malformedPackageType = structuredClone(contract);
  malformedPackageType.proxmox.packages.direct[0][field] = value;
  check(malformedPackageType, false, `malformed package ${field} type`);
}

const duplicateDirectPackage = structuredClone(contract);
duplicateDirectPackage.proxmox.packages.direct.push(structuredClone(duplicateDirectPackage.proxmox.packages.direct[0]));
check(duplicateDirectPackage, false, "duplicate direct package entry");

const missingPackageManifestReference = structuredClone(contract);
delete missingPackageManifestReference.proxmox.packages.manifest;
check(missingPackageManifestReference, false, "missing package manifest reference");

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

const malformedService = structuredClone(contract);
malformedService.proxmox.services[0] = "chrony";
check(malformedService, false, "malformed systemd service");

const missingSshService = structuredClone(contract);
const sshServiceIndex = missingSshService.proxmox.services.indexOf(missingSshService.proxmox.ssh.service);
missingSshService.proxmox.services[sshServiceIndex] = "unrelated.service";
checkSemantic(missingSshService, "native service set", "missing SSH service");

const duplicatePveRole = structuredClone(contract);
duplicatePveRole.proxmox.access.pve.additional_roles[0].role = duplicatePveRole.proxmox.access.pve.accounts[0].role;
checkSemantic(duplicatePveRole, "PVE custom role names must be unique", "duplicate PVE role name");

const unknownAclRole = structuredClone(contract);
unknownAclRole.proxmox.access.pve.accounts[0].additional_acls[0].role = "HomeLabUnknown";
checkSemantic(unknownAclRole, "references unknown role", "unknown PVE ACL role");

const duplicateAcl = structuredClone(contract);
duplicateAcl.proxmox.access.pve.accounts[0].additional_acls.push(
  structuredClone(duplicateAcl.proxmox.access.pve.accounts[0].additional_acls[0]),
);
check(duplicateAcl, false, "duplicate PVE ACL");

const duplicateAclPath = structuredClone(contract);
duplicateAclPath.proxmox.access.pve.accounts[0].additional_acls.push({
  path: duplicateAclPath.proxmox.access.pve.accounts[0].additional_acls[0].path,
  role: duplicateAclPath.proxmox.access.pve.accounts[1].role,
});
checkSemantic(duplicateAclPath, "contains duplicate ACLs", "duplicate PVE ACL path");

const wrongAclPath = structuredClone(contract);
wrongAclPath.proxmox.access.pve.accounts[0].additional_acls[0].path = "/vms/101";
checkSemantic(wrongAclPath, "invalid role or ACL assignment", "wrong PVE ACL path");

const unapprovedKeyring = structuredClone(contract);
unapprovedKeyring.proxmox.apt.repositories[0].signed_by = "/usr/share/keyrings/unknown-archive-keyring.gpg";
checkSemantic(unapprovedKeyring, "uses an unapproved signing key", "unapproved repository keyring");

const malformedKeyringChecksum = structuredClone(contract);
malformedKeyringChecksum.proxmox.apt.permitted_keyrings[0].sha256 = "not-a-sha256";
check(malformedKeyringChecksum, false, "malformed keyring checksum");

const unsafeKeyringSymlink = structuredClone(contract);
unsafeKeyringSymlink.proxmox.apt.permitted_keyrings[0].symlink_target = "../debian-archive-keyring.pgp";
check(unsafeKeyringSymlink, false, "unsafe keyring symlink target");

const downloadedKeyringSymlink = structuredClone(contract);
downloadedKeyringSymlink.proxmox.apt.permitted_keyrings[2].symlink_target = "tailscale-target.gpg";
checkSemantic(downloadedKeyringSymlink, "must be a regular file", "downloaded keyring symlink");

const selfReferentialKeyring = structuredClone(contract);
selfReferentialKeyring.proxmox.apt.permitted_keyrings[1].symlink_target = "proxmox-archive-keyring.gpg";
checkSemantic(selfReferentialKeyring, "must not link to itself", "self-referential keyring symlink");

const expectedKeyringTargets = ["debian-archive-keyring.pgp", null, null];
const currentKeyringTargets = contract.proxmox.apt.permitted_keyrings.map((keyring) => keyring.symlink_target);
if (JSON.stringify(currentKeyringTargets) !== JSON.stringify(expectedKeyringTargets)) {
  throw new Error(`current keyring file-type parity changed: ${JSON.stringify(currentKeyringTargets)}`);
}

const wrongSshUsers = structuredClone(contract);
wrongSshUsers.proxmox.ssh.allow_users = ["root", "tofu-apply", "tofu-plan"];
checkSemantic(wrongSshUsers, "SSH allow-users", "wrong SSH allow-users order");

const wrongFirewallRule = structuredClone(contract);
wrongFirewallRule.proxmox.firewall.rules[0].source = "192.168.1.0/24";
checkSemantic(wrongFirewallRule, "firewall rules must match", "wrong firewall source");

const malformedFirewallPort = structuredClone(contract);
malformedFirewallPort.proxmox.firewall.rules[0].destination_port = 70000;
check(malformedFirewallPort, false, "invalid firewall destination port");

const wrongKeyReference = structuredClone(contract);
wrongKeyReference.proxmox.access.service_accounts[0].authorized_keys_secret_ref = "PROXMOX_OTHER_SSH_PUBLIC_KEYS";
checkSemantic(wrongKeyReference, "unexpected authorized-key reference", "wrong service-account key reference");

const malformedSecretReference = structuredClone(contract);
malformedSecretReference.proxmox.tailscale.auth_key_secret_ref = "tailscale-key";
check(malformedSecretReference, false, "malformed Tailscale auth-key reference");

const tokenWithoutPrivilegeSeparation = structuredClone(contract);
tokenWithoutPrivilegeSeparation.proxmox.access.pve.accounts[0].privilege_separation = false;
checkSemantic(tokenWithoutPrivilegeSeparation, "must remain privilege-separated", "disabled token privilege separation");

const unrelatedService = structuredClone(contract);
unrelatedService.proxmox.services[0] = "unrelated.service";
checkSemantic(unrelatedService, "native service set", "missing required native service");

const privilegedPlanAccount = structuredClone(contract);
privilegedPlanAccount.proxmox.access.service_accounts[0].groups.push("sudo");
checkSemantic(privilegedPlanAccount, "tofu-plan must remain unprivileged", "privileged plan account");

const extraApplyGroup = structuredClone(contract);
extraApplyGroup.proxmox.access.service_accounts[1].groups.push("docker");
checkSemantic(extraApplyGroup, "tofu-apply current sudo policy", "extra apply-account group");

const unlockedServiceAccount = structuredClone(contract);
unlockedServiceAccount.proxmox.access.service_accounts[0].password_lock = false;
checkSemantic(unlockedServiceAccount, "locked login identity", "unlocked service account");

const movedServiceSudoers = structuredClone(contract);
movedServiceSudoers.proxmox.access.service_accounts[1].sudoers_path = "/etc/sudoers.d/other-apply";
checkSemantic(movedServiceSudoers, "tofu-apply current sudo policy", "moved service-account sudoers path");

const unlockedHumanAccount = structuredClone(contract);
unlockedHumanAccount.proxmox.access.human_accounts[0].password_lock = false;
checkSemantic(unlockedHumanAccount, "locked Tailscale-SSH-only", "unlocked human account");

const escalatedPlanRole = structuredClone(contract);
escalatedPlanRole.proxmox.access.pve.accounts[0].privileges.push("Sys.Modify");
checkSemantic(escalatedPlanRole, "exceeds its privilege ceiling", "escalated plan role");

const escalatedInspectionRole = structuredClone(contract);
escalatedInspectionRole.proxmox.access.pve.additional_roles[0].privileges.push("VM.PowerMgmt");
checkSemantic(escalatedInspectionRole, "exceeds its privilege ceiling", "escalated inspection role");

const unknownApplyPrivilege = structuredClone(contract);
unknownApplyPrivilege.proxmox.access.pve.accounts[1].privileges.push("Permissions.Modify");
checkSemantic(unknownApplyPrivilege, "exceeds its privilege ceiling", "unknown apply privilege");

const alternateTailscaleKeySource = structuredClone(contract);
alternateTailscaleKeySource.proxmox.apt.permitted_keyrings[2].source_url = "https://example.invalid/trixie.noarmor.gpg";
checkSemantic(alternateTailscaleKeySource, "suite-derived checksum-bound", "alternate Tailscale key source");

const duplicatedValidKeyringChecksum = structuredClone(contract);
duplicatedValidKeyringChecksum.proxmox.apt.permitted_keyrings[2].sha256 =
  duplicatedValidKeyringChecksum.proxmox.apt.permitted_keyrings[0].sha256;
checkSemantic(duplicatedValidKeyringChecksum, "checksums must be unique", "valid-format keyring checksum drift");

const downloadedPackagedKey = structuredClone(contract);
downloadedPackagedKey.proxmox.apt.permitted_keyrings[0].source_url = "https://example.invalid/debian.gpg";
checkSemantic(downloadedPackagedKey, "must not declare a download URL", "downloaded packaged keyring");

const proxmoxHostTasks = fs.readFileSync(path.join(root, "ansible/roles/proxmox_host/tasks/main.yml"), "utf8");
for (const snippet of [
  "follow: false",
  "follow: true",
  "checksum_algorithm: sha256",
  "proxmox_host_keyring_metadata_inspection",
  "proxmox_host_keyring_content_inspection",
  "item.stat.lnk_target",
  "item.item.symlink_target",
  "(proxmox_host_keyring_content.stat.checksum | default('')) == item.item.sha256",
  "groups: \"{{ item.groups | join(',') }}\"",
  "Remove undeclared service-account sudo policies",
]) {
  if (!proxmoxHostTasks.includes(snippet)) throw new Error(`Proxmox host role lacks required policy use: ${snippet}`);
}

const apiTokenTasks = fs.readFileSync(path.join(root, "ansible/roles/proxmox_host/tasks/api-token.yml"), "utf8");
for (const snippet of ["token", "modify", "--privsep", "Require exact API token privilege separation"]) {
  if (!apiTokenTasks.includes(snippet)) throw new Error(`Proxmox token role lacks privilege-separation handling: ${snippet}`);
}
const apiCheckTasks = fs.readFileSync(path.join(root, "ansible/roles/proxmox_host/tasks/api-check.yml"), "utf8");
for (const snippet of ["proxmox_host_check_token_record.privsep", "proxmox_host_check_escrow_directory_result.stat.uid"]) {
  if (!apiCheckTasks.includes(snippet)) throw new Error(`Proxmox API check mode lacks drift detection: ${snippet}`);
}

const apiTasks = fs.readFileSync(path.join(root, "ansible/roles/proxmox_host/tasks/api.yml"), "utf8");
for (const snippet of ["follow: false", "item.0.stat.uid", "item.0.stat.islnk", "'/root/.config/home-lab'"]) {
  if (!apiTasks.includes(snippet)) throw new Error(`Proxmox API escrow validation lacks: ${snippet}`);
}

console.log("contract_schema=verified");
