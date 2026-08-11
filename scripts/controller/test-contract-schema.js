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

function valueAt(document, dottedPath) {
  return dottedPath.split(".").reduce((value, segment) => value[segment], document);
}

const closedRequiredPolicyObjects = [
  "network.ownership",
  "network.ownership.interfaces_file",
  "proxmox.grub",
  "proxmox.grub.file",
  "proxmox.vfio",
  "proxmox.vfio.absence_policy.0",
  "proxmox.vfio.absence_policy.2",
  "proxmox.vfio.modules_load_file",
  "proxmox.vfio.modprobe_file",
  "proxmox.vfio.soft_dependencies.0",
  "proxmox.apt",
  "proxmox.apt.repository_file_metadata",
  "proxmox.apt.inactive_sources_list",
  "proxmox.apt.inactive_sources_list.file",
  "proxmox.apt.permitted_keyrings.2.file",
  "proxmox.access",
  "proxmox.access.sudo_validation",
  "proxmox.access.service_accounts.0",
  "proxmox.access.service_accounts.0.ssh_directory",
  "proxmox.access.service_accounts.0.authorized_keys",
  "proxmox.access.service_accounts.0.authorized_keys.file",
  "proxmox.access.service_accounts.1.sudo",
  "proxmox.access.human_accounts.0",
  "proxmox.access.human_accounts.0.authorized_keys",
  "proxmox.access.human_accounts.0.authorized_keys.files.0",
  "proxmox.access.human_accounts.0.sudo",
  "proxmox.access.pve.accounts.0.token_escrow",
  "proxmox.access.pve.accounts.0.token_escrow.directory",
  "proxmox.access.pve.accounts.0.token_escrow.file",
  "proxmox.ssh",
  "proxmox.ssh.host_key_sentinel",
  "proxmox.tailscale",
  "proxmox.services.0",
  "proxmox.health",
  "proxmox.firewall",
  "proxmox.vm.usb.zigbee",
  "storage.zfs.arc_config",
  "storage.zfs.mirror_topology",
  "storage.zfs.dataset_properties",
  "storage.nfs",
  "storage.nfs.exports_file",
];
for (const objectPath of closedRequiredPolicyObjects) {
  const unknownField = structuredClone(contract);
  valueAt(unknownField, objectPath).unexpected_policy_field = true;
  check(unknownField, false, `${objectPath} must be closed`);
  for (const field of Object.keys(valueAt(contract, objectPath))) {
    const missingField = structuredClone(contract);
    delete valueAt(missingField, objectPath)[field];
    check(missingField, false, `${objectPath}.${field} must be required`);
  }
}

function collectPolicyRecords(value, records = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectPolicyRecords(item, records);
  } else if (value && typeof value === "object") {
    if (typeof value.kind === "string") records.push(value);
    for (const nested of Object.values(value)) collectPolicyRecords(nested, records);
  }
  return records;
}
const policyRecords = collectPolicyRecords(contract);
const managedFiles = policyRecords.filter((record) => record.kind === "managed-file");
const protectedRecords = policyRecords.filter((record) => record.kind.startsWith("runtime-protected-"));
if (!managedFiles.length || !protectedRecords.length) throw new Error("contract must classify managed and runtime-protected policies");
const knownPolicyKinds = new Set(["managed-file", "managed-file-metadata", "managed-directory", "runtime-protected-file", "runtime-protected-directory", "audit-absence", "api-owned"]);
if (policyRecords.some((record) => !knownPolicyKinds.has(record.kind))) throw new Error("contract contains an unknown projector-dispatch kind");
if (contract.proxmox.apt.repository_file_metadata.kind !== "managed-file-metadata" ||
    contract.proxmox.access.service_accounts[0].sudo.kind !== "audit-absence" ||
    contract.proxmox.vfio.absence_policy.some((record) => record.kind !== "audit-absence")) {
  throw new Error("metadata and absence expectations must use structurally truthful projector kinds");
}
if (managedFiles.some((file) => file.path === "/etc/pve" || file.path.startsWith("/etc/pve/"))) {
  throw new Error("PVE cluster state must not be projected as an ordinary managed file");
}
const unsafeRepositoryMetadata = structuredClone(contract);
unsafeRepositoryMetadata.proxmox.apt.repository_file_metadata.mode = "0666";
check(unsafeRepositoryMetadata, false, "APT repository files reject group/world-write access");
if (contract.proxmox.firewall.ownership !== "pve-api" || contract.proxmox.firewall.activation !== "pve-api") {
  throw new Error("PVE firewall must remain API-owned and API-activated");
}
for (const [index, file] of managedFiles.entries()) {
  const unsafePath = structuredClone(contract);
  collectPolicyRecords(unsafePath).filter((record) => record.kind === "managed-file")[index].path = `../${file.path.split("/").at(-1)}`;
  check(unsafePath, false, `managed file ${file.path} rejects a relative path`);
  const traversalPath = structuredClone(contract);
  collectPolicyRecords(traversalPath).filter((record) => record.kind === "managed-file")[index].path = "/etc/../shadow";
  check(traversalPath, false, `managed file ${file.path} rejects path traversal`);
  const unsafeMode = structuredClone(contract);
  collectPolicyRecords(unsafeMode).filter((record) => record.kind === "managed-file")[index].mode = "644";
  check(unsafeMode, false, `managed file ${file.path} rejects a non-octal mode`);
  const writableMode = structuredClone(contract);
  collectPolicyRecords(writableMode).filter((record) => record.kind === "managed-file")[index].mode = "0666";
  check(writableMode, false, `managed file ${file.path} rejects group/world-write access`);
}
for (const [index, record] of protectedRecords.entries()) {
  if (record.projectable !== false || record.materialization !== "metadata-only") {
    throw new Error(`protected policy ${record.path} must be discriminator-excludable metadata only`);
  }
  const materializable = structuredClone(contract);
  collectPolicyRecords(materializable).filter((item) => item.kind.startsWith("runtime-protected-"))[index].projectable = true;
  check(materializable, false, `protected policy ${record.path} rejects projection`);
}
for (const forbiddenPath of ["/etc/pve", "/etc/pve/firewall/ordinary.conf"]) {
  const pveManagedFile = structuredClone(contract);
  pveManagedFile.network.ownership.interfaces_file.path = forbiddenPath;
  checkSemantic(pveManagedFile, "must not enter PVE API-owned state", `ordinary managed path ${forbiddenPath}`);
}

const hostKeyModeDrift = structuredClone(contract);
hostKeyModeDrift.proxmox.ssh.host_key_sentinel.mode = "0640";
checkSemantic(hostKeyModeDrift, "host-key sentinel", "host-key sentinel mode drift");
const authorizedKeysOwnerDrift = structuredClone(contract);
authorizedKeysOwnerDrift.proxmox.access.service_accounts[0].authorized_keys.file.owner = "root";
checkSemantic(authorizedKeysOwnerDrift, "authorized-keys path", "authorized_keys owner drift");
const sshDirectoryModeDrift = structuredClone(contract);
sshDirectoryModeDrift.proxmox.access.service_accounts[0].ssh_directory.mode = "0750";
checkSemantic(sshDirectoryModeDrift, "authorized-keys path", "SSH directory mode drift");
const tokenFileModeDrift = structuredClone(contract);
tokenFileModeDrift.proxmox.access.pve.accounts[0].token_escrow.file.mode = "0640";
checkSemantic(tokenFileModeDrift, "escrow path", "token file mode drift");
const tokenDirectoryOwnerDrift = structuredClone(contract);
tokenDirectoryOwnerDrift.proxmox.access.pve.accounts[0].token_escrow.directory.owner = "daemon";
checkSemantic(tokenDirectoryOwnerDrift, "escrow path", "token directory owner drift");

const duplicateUsbPortRef = structuredClone(contract);
duplicateUsbPortRef.proxmox.vm.usb.zwave.port_secret_ref = duplicateUsbPortRef.proxmox.vm.usb.zigbee.port_secret_ref;
checkSemantic(duplicateUsbPortRef, "zwave USB port reference", "duplicate USB port reference");
const swappedUsbPortRefs = structuredClone(contract);
[swappedUsbPortRefs.proxmox.vm.usb.zigbee.port_secret_ref, swappedUsbPortRefs.proxmox.vm.usb.zwave.port_secret_ref] =
  [swappedUsbPortRefs.proxmox.vm.usb.zwave.port_secret_ref, swappedUsbPortRefs.proxmox.vm.usb.zigbee.port_secret_ref];
checkSemantic(swappedUsbPortRefs, "zigbee USB port reference", "swapped USB port references");

const disabledNativeService = structuredClone(contract);
disabledNativeService.proxmox.services[0].enabled = false;
checkSemantic(disabledNativeService, "native service set", "disabled native service");
const wrongVfioAbsencePath = structuredClone(contract);
wrongVfioAbsencePath.proxmox.vfio.absence_policy[0].path = "/etc/modules.other";
checkSemantic(wrongVfioAbsencePath, "VFIO audit-absence policy", "wrong VFIO absence path");
const mismatchedVmHealth = structuredClone(contract);
mismatchedVmHealth.proxmox.health.vm_status = "stopped";
checkSemantic(mismatchedVmHealth, "health VM status", "health VM status mismatch");
const mismatchedNfsExport = structuredClone(contract);
mismatchedNfsExport.storage.nfs.export = "/storage/other";
checkSemantic(mismatchedNfsExport, "NFS export", "NFS export and ZFS mountpoint mismatch");

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
const sshServiceIndex = missingSshService.proxmox.services.findIndex((service) => service.name === missingSshService.proxmox.ssh.service);
missingSshService.proxmox.services[sshServiceIndex].name = "unrelated.service";
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
wrongKeyReference.proxmox.access.service_accounts[0].authorized_keys.secret_ref = "PROXMOX_OTHER_SSH_PUBLIC_KEYS";
checkSemantic(wrongKeyReference, "unexpected authorized-key reference", "wrong service-account key reference");

const malformedSecretReference = structuredClone(contract);
malformedSecretReference.proxmox.tailscale.auth_key_secret_ref = "tailscale-key";
check(malformedSecretReference, false, "malformed Tailscale auth-key reference");

const tokenWithoutPrivilegeSeparation = structuredClone(contract);
tokenWithoutPrivilegeSeparation.proxmox.access.pve.accounts[0].privilege_separation = false;
checkSemantic(tokenWithoutPrivilegeSeparation, "must remain privilege-separated", "disabled token privilege separation");

const unrelatedService = structuredClone(contract);
unrelatedService.proxmox.services[0].name = "unrelated.service";
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
movedServiceSudoers.proxmox.access.service_accounts[1].sudo.file.path = "/etc/sudoers.d/other-apply";
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
  "item.file.path",
  "proxmox.apt.repository_file_metadata.owner",
  "proxmox.apt.inactive_sources_list.notice",
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
for (const snippet of ["follow: false", "item.0.stat.uid", "item.0.stat.islnk", "token_escrow.directory.path", "token_escrow.file.mode"]) {
  if (!apiTasks.includes(snippet)) throw new Error(`Proxmox API escrow validation lacks: ${snippet}`);
}

function parsedTask(relativePath, taskName) {
  const tasks = load(fs.readFileSync(path.join(root, relativePath), "utf8"));
  const task = tasks.find((candidate) => candidate.name === taskName);
  if (!task) throw new Error(`${relativePath} lacks active task ${taskName}`);
  return task;
}
function requireTaskArgument(relativePath, taskName, moduleName, argument, expected) {
  const task = parsedTask(relativePath, taskName);
  const actual = task[moduleName]?.[argument];
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${relativePath} ${taskName} ${moduleName}.${argument}=${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
}
requireTaskArgument("ansible/roles/proxmox_network/tasks/main.yml", "Converge the permanent Proxmox network", "ansible.builtin.template", "dest", "{{ network.ownership.interfaces_file.path }}");
requireTaskArgument("ansible/roles/proxmox_network/tasks/main.yml", "Converge the permanent Proxmox network", "ansible.builtin.template", "owner", "{{ network.ownership.interfaces_file.owner }}");
requireTaskArgument("ansible/roles/proxmox_network/tasks/main.yml", "Converge the permanent Proxmox network", "ansible.builtin.template", "group", "{{ network.ownership.interfaces_file.group }}");
requireTaskArgument("ansible/roles/proxmox_network/tasks/main.yml", "Converge the permanent Proxmox network", "ansible.builtin.template", "mode", "{{ network.ownership.interfaces_file.mode }}");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Enable IOMMU passthrough without globally blacklisting amdgpu", "ansible.builtin.lineinfile", "path", "{{ proxmox.grub.file.path }}");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Enable IOMMU passthrough without globally blacklisting amdgpu", "ansible.builtin.lineinfile", "line", "{{ proxmox.grub.variable }}=\"{{ proxmox.grub.default_tokens | join(' ') }}\"");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Enable IOMMU passthrough without globally blacklisting amdgpu", "ansible.builtin.lineinfile", "mode", "{{ proxmox.grub.file.mode }}");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Keep only the canonical VFIO modules in early boot configuration", "ansible.builtin.copy", "dest", "{{ proxmox.vfio.modules_load_file.path }}");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Keep only the canonical VFIO modules in early boot configuration", "ansible.builtin.copy", "content", "{{ proxmox.vfio.modules | join('\n') }}\n");
const vfioLineAbsenceTask = parsedTask("ansible/roles/proxmox_passthrough/tasks/main.yml", "Remove every duplicate VFIO module line from legacy module files");
if (vfioLineAbsenceTask["ansible.builtin.lineinfile"].path !== "{{ item.path }}" ||
    vfioLineAbsenceTask["ansible.builtin.lineinfile"].regexp !== "{{ item.pattern }}" ||
    !vfioLineAbsenceTask.loop.includes("proxmox.vfio.absence_policy")) {
  throw new Error("VFIO matching-line absence task must consume classified contract records");
}
const vfioLinePattern = new RegExp(contract.proxmox.vfio.absence_policy[0].pattern);
for (const line of ["vfio", " vfio_pci # duplicate", "\tvfio_virqfd"]) {
  if (!vfioLinePattern.test(line)) throw new Error(`VFIO absence regex must match legacy module line: ${JSON.stringify(line)}`);
}
for (const line of ["vfio-pci", "options vfio-pci ids=1002:73bf", "xvfio"]) {
  if (vfioLinePattern.test(line)) throw new Error(`VFIO absence regex must reject non-module line: ${JSON.stringify(line)}`);
}
const vfioFileAbsenceTask = parsedTask("ansible/roles/proxmox_passthrough/tasks/main.yml", "Remove the legacy duplicate VFIO modprobe file");
if (vfioFileAbsenceTask["ansible.builtin.file"].path !== "{{ item.path }}" || !vfioFileAbsenceTask.loop.includes("proxmox.vfio.absence_policy")) {
  throw new Error("VFIO file absence task must consume classified contract records");
}
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Bind only contract passthrough devices to vfio-pci", "ansible.builtin.copy", "dest", "{{ proxmox.vfio.modprobe_file.path }}");
requireTaskArgument("ansible/roles/proxmox_passthrough/tasks/main.yml", "Bind only contract passthrough devices to vfio-pci", "ansible.builtin.copy", "owner", "{{ proxmox.vfio.modprobe_file.owner }}");
requireTaskArgument("ansible/roles/proxmox_host/tasks/main.yml", "Keep required host services enabled and started", "ansible.builtin.systemd_service", "enabled", "{{ item.enabled }}");
requireTaskArgument("ansible/roles/proxmox_host/tasks/main.yml", "Keep required host services enabled and started", "ansible.builtin.systemd_service", "state", "{{ item.state }}");
requireTaskArgument("ansible/roles/proxmox_storage/tasks/main.yml", "Stage the contract ZFS ARC maximum for the next boot", "ansible.builtin.copy", "dest", "{{ storage.zfs.arc_config.file.path }}");
requireTaskArgument("ansible/roles/proxmox_storage/tasks/main.yml", "Export the Docker dataset only to the Arch VM", "ansible.builtin.template", "dest", "{{ storage.nfs.exports_file.path }}");
requireTaskArgument("ansible/roles/proxmox_health/tasks/main.yml", "Verify the Proxmox API responds locally", "ansible.builtin.uri", "url", "{{ proxmox_health_local_api_url }}");
requireTaskArgument("ansible/roles/proxmox_health/tasks/main.yml", "Verify the Proxmox API responds locally", "ansible.builtin.uri", "validate_certs", "{{ proxmox_health_local_api_validate_certs }}");
requireTaskArgument("ansible/roles/proxmox_health/tasks/main.yml", "Verify the Proxmox API responds locally", "ansible.builtin.uri", "status_code", "{{ proxmox_health_local_api_status_codes }}");
const vmHealthTask = parsedTask("ansible/roles/proxmox_health/tasks/main.yml", "Verify VM startup state when required");
if (!vmHealthTask["ansible.builtin.command"].argv.includes("{{ proxmox.vm.vmid }}")) throw new Error("VM health must consume the contract VM identity");
const healthAssertion = parsedTask("ansible/roles/proxmox_health/tasks/main.yml", "Assert Proxmox health gates");
if (!healthAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("proxmox_health_vm_status"))) {
  throw new Error("VM health assertion must consume the expected contract status");
}
requireTaskArgument("ansible/roles/proxmox_firewall/tasks/main.yml", "Install the reviewed Proxmox firewall policy", "ansible.builtin.template", "dest", "{{ proxmox.firewall.compatibility_config_path }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Keep the SSH host-key sentinel metadata protected", "ansible.builtin.file", "mode", "{{ ssh_host_key_sentinel_mode }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "dest", "{{ ssh_config_path }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "owner", "{{ ssh_config_owner }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "group", "{{ ssh_config_group }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "mode", "{{ ssh_config_mode }}");
const sshMetadataTask = parsedTask("ansible/roles/ssh/tasks/main.yml", "Keep the SSH host-key sentinel metadata protected");
if (!sshMetadataTask.when.includes("not ansible_check_mode or (ssh_host_key_sentinel_before.stat.exists | default(false))")) {
  throw new Error("SSH host-key metadata enforcement must skip an absent sentinel only in check mode");
}
const sharenfsTask = parsedTask("ansible/roles/proxmox_storage/tasks/main.yml", "Disable the ZFS-generated world export");
if (!sharenfsTask["ansible.builtin.command"].argv.includes("sharenfs={{ storage.zfs.dataset_properties.sharenfs }}")) {
  throw new Error("ZFS sharenfs mutation must derive the desired dataset property from contract");
}
requireTaskArgument("ansible/roles/tailscale/tasks/main.yml", "Keep tailscaled enabled and started without restarting it", "ansible.builtin.systemd_service", "state", "{{ tailscale_service_state }}");
const tailscaleAssertion = parsedTask("ansible/roles/tailscale/tasks/main.yml", "Assert local Tailscale verification passed");
if (!tailscaleAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("tailscale_expected_backend_state"))) {
  throw new Error("Tailscale verification must consume the expected backend state");
}
requireTaskArgument("ansible/roles/proxmox_host/tasks/main.yml", "Install the pinned Tailscale repository signing key", "ansible.builtin.get_url", "owner", "{{ proxmox_host_tailscale_keyring.file.owner }}");
requireTaskArgument("ansible/roles/proxmox_host/tasks/main.yml", "Install each canonical Deb822 repository definition", "ansible.builtin.copy", "mode", "{{ proxmox.apt.repository_file_metadata.mode }}");
requireTaskArgument("ansible/roles/proxmox_storage/tasks/main.yml", "Export the Docker dataset only to the Arch VM", "ansible.builtin.template", "owner", "{{ storage.nfs.exports_file.owner }}");
requireTaskArgument("ansible/roles/human_access/tasks/main.yml", "Remove contract-declared conventional OpenSSH authorized-key files for human accounts", "ansible.builtin.file", "path", "{{ item.1.path }}");
requireTaskArgument("ansible/roles/human_access/tasks/main.yml", "Install validated passwordless sudo policies for human accounts", "ansible.builtin.copy", "dest", "{{ item.sudo.file.path | default(item.sudoers_path) }}");
const removeServiceSudoTask = parsedTask("ansible/roles/proxmox_host/tasks/main.yml", "Remove undeclared service-account sudo policies");
for (const condition of ["(item.sudo.kind | default('')) == 'audit-absence'", "(item.sudo.absence | default('')) == 'file'"]) {
  if (!removeServiceSudoTask.when.includes(condition)) throw new Error(`service-account sudo absence guard must safely classify mixed records: ${condition}`);
}

const renderedConsumers = {
  "ansible/roles/proxmox_network/templates/interfaces.j2": ["network.ownership.managed_header", "network.ownership.bridge_stp", "network.ownership.bridge_forward_delay"],
  "ansible/roles/proxmox_storage/templates/home-lab.exports.j2": ["storage.nfs.options", "storage.nfs.squash_policy"],
};
for (const [relativePath, snippets] of Object.entries(renderedConsumers)) {
  const source = fs.readFileSync(path.join(root, relativePath), "utf8");
  for (const snippet of snippets) if (!source.includes(snippet)) throw new Error(`${relativePath} does not derive ${snippet}`);
}
const passthroughTasks = fs.readFileSync(path.join(root, "ansible/roles/proxmox_passthrough/tasks/main.yml"), "utf8");
if (passthroughTasks.includes("regex_replace('_SERIAL$', '_PORT')")) {
  throw new Error("protected USB port inputs must use explicit contract references rather than a naming convention");
}
const protectedReferenceValues = [];
(function collectProtectedReferences(value) {
  if (Array.isArray(value)) return value.forEach(collectProtectedReferences);
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (key.endsWith("_secret_ref") || key === "secret_ref") protectedReferenceValues.push(nested);
    else collectProtectedReferences(nested);
  }
})(contract);
if (protectedReferenceValues.some((value) => typeof value !== "string" || !/^[A-Z][A-Z0-9_]+$/.test(value))) {
  throw new Error("protected contract inputs must contain runtime reference names only");
}
for (const device of [contract.proxmox.vm.usb.zigbee, contract.proxmox.vm.usb.zwave]) {
  if (!/^HOMELAB_[A-Z0-9_]+_USB_PORT$/.test(device.port_secret_ref)) {
    throw new Error("serial USB devices must declare explicit protected port references");
  }
}

console.log("contract_schema=verified");
