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
const productionInventory = fs.readFileSync(path.join(root, "ansible/inventory/production.yml"), "utf8");
const infrastructureInventory = fs.readFileSync(path.join(root, "ansible/inventory/infrastructure.yml"), "utf8");

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

const invalidProxmoxLifecycleOwner = structuredClone(contract);
invalidProxmoxLifecycleOwner.lifecycle.hosts.proxmox.current_mutation_owner = "ansible";
checkSemantic(invalidProxmoxLifecycleOwner, "Proxmox lifecycle ownership", "Proxmox lifecycle owner changes only at reviewed handoff");
const invalidDebianBootstrapAuthority = structuredClone(contract);
invalidDebianBootstrapAuthority.lifecycle.hosts.debian.bootstrap_authority = "physical-console";
checkSemantic(invalidDebianBootstrapAuthority, "Debian lifecycle ownership", "Debian lifecycle bootstrap authority remains explicit");
const divergentLifecycleMarker = structuredClone(contract);
divergentLifecycleMarker.lifecycle.hosts.debian.marker.path = "/var/lib/home-lab/other-lifecycle-state.json";
check(divergentLifecycleMarker, false, "host lifecycle markers use one fixed path");
const invalidPackageReplan = structuredClone(contract);
invalidPackageReplan.lifecycle.maintenance.package_plan.apply_time_replan = true;
check(invalidPackageReplan, false, "package apply cannot replan");
const invalidMetadataAge = structuredClone(contract);
invalidMetadataAge.lifecycle.maintenance.package_plan.max_metadata_age_seconds = 172800;
check(invalidMetadataAge, false, "package metadata freshness remains bounded");
const invalidDebianPackageScope = structuredClone(contract);
invalidDebianPackageScope.lifecycle.maintenance.package_plan.hosts.debian.allowed_apply_scope = "reviewed-exact-set";
check(invalidDebianPackageScope, false, "Debian package apply remains security-only");
const invalidAutomaticReboot = structuredClone(contract);
invalidAutomaticReboot.lifecycle.maintenance.reboot_plan.automatic = true;
check(invalidAutomaticReboot, false, "host reboot cannot be automatic");
const invalidPendingTimezoneOwner = structuredClone(contract);
invalidPendingTimezoneOwner.lifecycle.hosts.proxmox.domain_handoffs.timezone.state = "pending";
check(invalidPendingTimezoneOwner, false, "pending timezone handoff retains Nix ownership");
const invalidTransferredTimezoneOwner = structuredClone(contract);
invalidTransferredTimezoneOwner.lifecycle.hosts.proxmox.domain_handoffs.timezone.current_owner = "nix";
check(invalidTransferredTimezoneOwner, false, "transferred timezone handoff requires Ansible ownership");
const invalidPendingAptOwner = structuredClone(contract);
invalidPendingAptOwner.lifecycle.hosts.proxmox.domain_handoffs.apt_repositories.current_owner = "ansible";
invalidPendingAptOwner.lifecycle.hosts.proxmox.domain_handoffs.apt_repositories.state = "pending";
check(invalidPendingAptOwner, false, "pending APT repository handoff retains Nix ownership");
const invalidTransferredChronyOwner = structuredClone(contract);
invalidTransferredChronyOwner.lifecycle.hosts.proxmox.domain_handoffs.chrony_service.current_owner = "nix";
check(invalidTransferredChronyOwner, false, "transferred chrony handoff requires Ansible ownership");
const invalidTransferredBootOwner = structuredClone(contract);
invalidTransferredBootOwner.lifecycle.hosts.proxmox.domain_handoffs.boot_configuration.current_owner = "nix";
check(invalidTransferredBootOwner, false, "transferred boot configuration handoff requires Ansible ownership");
const missingBootHandoff = structuredClone(contract);
delete missingBootHandoff.lifecycle.hosts.proxmox.domain_handoffs.boot_configuration;
check(missingBootHandoff, false, "Proxmox boot configuration handoff policy is required");
const invalidTransferredZfsOwner = structuredClone(contract);
invalidTransferredZfsOwner.lifecycle.hosts.proxmox.domain_handoffs.zfs_dataset.current_owner = "nix";
check(invalidTransferredZfsOwner, false, "transferred ZFS dataset handoff requires Ansible ownership");
const invalidTransferredNfsOwner = structuredClone(contract);
invalidTransferredNfsOwner.lifecycle.hosts.proxmox.domain_handoffs.nfs_export_service.current_owner = "nix";
check(invalidTransferredNfsOwner, false, "transferred NFS export handoff requires Ansible ownership");
const missingZfsHandoff = structuredClone(contract);
delete missingZfsHandoff.lifecycle.hosts.proxmox.domain_handoffs.zfs_dataset;
check(missingZfsHandoff, false, "Proxmox ZFS dataset handoff policy is required");
const missingNfsHandoff = structuredClone(contract);
delete missingNfsHandoff.lifecycle.hosts.proxmox.domain_handoffs.nfs_export_service;
check(missingNfsHandoff, false, "Proxmox NFS export handoff policy is required");
const invalidReadyNetworkOwner = structuredClone(contract);
invalidReadyNetworkOwner.lifecycle.hosts.proxmox.domain_handoffs.network_interfaces.current_owner = "ansible";
check(invalidReadyNetworkOwner, false, "ready network interface handoff retains Nix ownership");
const invalidPendingTailscaleOwner = structuredClone(contract);
invalidPendingTailscaleOwner.lifecycle.hosts.proxmox.domain_handoffs.tailscale_node.current_owner = "ansible";
check(invalidPendingTailscaleOwner, false, "pending Tailscale node handoff retains Nix ownership");
const missingNetworkHandoff = structuredClone(contract);
delete missingNetworkHandoff.lifecycle.hosts.proxmox.domain_handoffs.network_interfaces;
check(missingNetworkHandoff, false, "Proxmox network interface handoff policy is required");
const missingTailscaleHandoff = structuredClone(contract);
delete missingTailscaleHandoff.lifecycle.hosts.proxmox.domain_handoffs.tailscale_node;
check(missingTailscaleHandoff, false, "Proxmox Tailscale node handoff policy is required");
const invalidResolverOwnership = structuredClone(contract);
invalidResolverOwnership.network.ownership.resolver_management = "ansible";
check(invalidResolverOwnership, false, "resolver ownership is excluded from this handoff");
const invalidNetworkActivation = structuredClone(contract);
invalidNetworkActivation.network.ownership.runtime_activation = "automatic";
check(invalidNetworkActivation, false, "network runtime activation requires a separate watchdog transaction");
const missingAptHandoff = structuredClone(contract);
delete missingAptHandoff.lifecycle.hosts.proxmox.domain_handoffs.apt_repositories;
check(missingAptHandoff, false, "Proxmox APT repository handoff policy is required");
const missingProxmoxHandoff = structuredClone(contract);
delete missingProxmoxHandoff.lifecycle.hosts.proxmox.domain_handoffs;
check(missingProxmoxHandoff, false, "Proxmox timezone handoff policy is required");
const invalidDebianHandoff = structuredClone(contract);
invalidDebianHandoff.lifecycle.hosts.debian.domain_handoffs = structuredClone(contract.lifecycle.hosts.proxmox.domain_handoffs);
check(invalidDebianHandoff, false, "Debian cannot inherit Proxmox domain handoffs");
const missingDebianAccessCleanup = structuredClone(contract);
delete missingDebianAccessCleanup.lifecycle.hosts.debian.access_cleanup;
check(missingDebianAccessCleanup, false, "Debian access cleanup policy is required");
const invalidProxmoxAccessCleanup = structuredClone(contract);
invalidProxmoxAccessCleanup.lifecycle.hosts.proxmox.access_cleanup = structuredClone(contract.lifecycle.hosts.debian.access_cleanup);
check(invalidProxmoxAccessCleanup, false, "Proxmox cannot inherit Debian access cleanup policy");
const invalidDebianCleanupOrder = structuredClone(contract);
invalidDebianCleanupOrder.lifecycle.hosts.debian.access_cleanup.remove_keys_before_tightening = false;
check(invalidDebianCleanupOrder, false, "Debian conventional keys are removed before OpenSSH tightening");
const missingAccessCutover = structuredClone(contract);
delete missingAccessCutover.lifecycle.hosts.proxmox.access_cutover;
check(missingAccessCutover, false, "Proxmox access cutover policy is required");
const invalidRootTailnetAccess = structuredClone(contract);
invalidRootTailnetAccess.lifecycle.hosts.proxmox.access_cutover.forbidden_tailnet_users = ["tofu-plan", "tofu-apply"];
check(invalidRootTailnetAccess, false, "root must remain denied by tailnet SSH policy");
const invalidDebianAccessCutover = structuredClone(contract);
invalidDebianAccessCutover.lifecycle.hosts.debian.access_cutover = structuredClone(contract.lifecycle.hosts.proxmox.access_cutover);
check(invalidDebianAccessCutover, false, "Debian cannot inherit Proxmox access cutover policy");

const totpWithoutCredentialRef = structuredClone(contract);
delete totpWithoutCredentialRef.backups.restic.credential_refs.proton_totp_secret;
check(totpWithoutCredentialRef, false, "TOTP mode rejects an absent credential ref");
const passwordOnlyContract = structuredClone(contract);
passwordOnlyContract.backups.restic.proton.authentication_mode = "password-only";
delete passwordOnlyContract.backups.restic.credential_refs.proton_totp_secret;
check(passwordOnlyContract, true, "password-only mode omits the TOTP credential ref");
const passwordOnlyWithTotpCredentialRef = structuredClone(passwordOnlyContract);
passwordOnlyWithTotpCredentialRef.backups.restic.credential_refs.proton_totp_secret = "PROTON_BACKUP_TOTP_SECRET";
check(passwordOnlyWithTotpCredentialRef, false, "password-only mode rejects a TOTP credential ref");

const invalidQuiescedWithoutRetentionHold = structuredClone(contract);
invalidQuiescedWithoutRetentionHold.backups.legacy_offen.scheduler_state = "quiesced";
invalidQuiescedWithoutRetentionHold.backups.legacy_offen.migration_retention_hold = {
  state: "planned",
  current_object_retention_days: 365,
  plan_sha256: null,
  recovery_object_version_id_sha256: null,
  verified_at: null,
  review_deadline: null,
};
check(invalidQuiescedWithoutRetentionHold, false, "Offen quiescence requires an applied AWS retention hold");

const plannedRetentionHold = structuredClone(contract);
plannedRetentionHold.backups.legacy_offen.retirement.state = "preserved";
plannedRetentionHold.backups.legacy_offen.scheduler_state = "active";
plannedRetentionHold.backups.legacy_offen.migration_retention_hold = {
  state: "planned",
  current_object_retention_days: 365,
  plan_sha256: null,
  recovery_object_version_id_sha256: null,
  verified_at: null,
  review_deadline: null,
};
check(plannedRetentionHold, true, "AWS retention hold accepts a pre-apply planned state while Offen remains active");

const appliedRetentionHold = structuredClone(plannedRetentionHold);
appliedRetentionHold.backups.legacy_offen.migration_retention_hold = {
  state: "applied",
  current_object_retention_days: 365,
  lifecycle_rule_id: "critical-backup-retention",
  delete_marker_rule_id: "expired-delete-marker-cleanup",
  expected_principal_arn_sha256: "cbfd4986207c28758c6d4561f6636cbaf31bbeca8972891d347ed25180be2ac7",
  recovery_object_key: "weekly-backup-2026-08-23T06-00-00.tar.gz.gpg",
  recovery_object_bytes: 2399491160,
  recovery_object_last_modified: "2026-08-23T13:03:53Z",
  recovery_object_storage_class: "STANDARD",
  plan_sha256: "a".repeat(64),
  recovery_object_version_id_sha256: "b".repeat(64),
  verified_at: "2026-08-23T18:00:00Z",
  review_deadline: "2026-09-22T18:00:00Z",
};
check(appliedRetentionHold, true, "AWS retention hold accepts complete applied evidence");
const plannedArchivePreservation = structuredClone(appliedRetentionHold);
plannedArchivePreservation.backups.legacy_offen.scheduler_state = "quiesced";
plannedArchivePreservation.backups.legacy_offen.migration_archive_preservation.state = "planned";
plannedArchivePreservation.backups.legacy_offen.migration_archive_preservation.verified_at = null;
plannedArchivePreservation.backups.legacy_offen.final_archive = {
  basename: "daily-local-backup-2026-08-21T22-32-08.tar.gz.gpg",
  bytes: 2319938554,
  sha256: "0b46561cf52c15bfababef0f75fe3bbe2cf1f7e1305eb1f7cfe4c1ca0db5c431",
  replica_paths: ["/mnt/games/backups", "/mnt/storage/backups"],
  restore_proof_script: "scripts/run-backup-restore-proof.fish",
};
check(plannedArchivePreservation, false, "Offen quiescence rejects a planned-only archive preservation state");

const appliedArchivePreservation = structuredClone(appliedRetentionHold);
appliedArchivePreservation.backups.legacy_offen.scheduler_state = "quiesced";
appliedArchivePreservation.backups.legacy_offen.migration_archive_preservation.state = "applied";
appliedArchivePreservation.backups.legacy_offen.migration_archive_preservation.verified_at = "2026-08-23T20:00:00Z";
appliedArchivePreservation.backups.legacy_offen.final_archive = {
  basename: "daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg",
  bytes: 2411062883,
  sha256: "8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08",
  replica_paths: ["/mnt/games/backups/.migration-preserved-offen", "/mnt/storage/backups/.migration-preserved-offen"],
  restore_proof_script: "scripts/run-backup-restore-proof.fish",
  restore_proof: {
    evidence_file: "infrastructure/evidence/offen-final-archive-2026-08-23-restore-proof.json",
    evidence_sha256: "8".repeat(64),
    verifier_sha256: "9".repeat(64),
    started_at: "2026-08-23T12:16:17Z",
    finished_at: "2026-08-23T12:16:58Z",
    elapsed_seconds: 41,
    restore_pipeline: "pass",
    decrypted_cleanup: "pass",
    archive_integrity: "pass",
    safe_paths: "pass",
    member_count: 22877,
    regular_file_count: 21939,
    total_uncompressed_bytes: 7019884389,
    member_path_stream_sha256: "7".repeat(64),
  },
};
check(appliedArchivePreservation, true, "Offen quiescence accepts applied retention and archive preservation evidence");

const finalizingOffen = structuredClone(contract);
finalizingOffen.backups.legacy_offen.scheduler_state = "retired";
finalizingOffen.backups.legacy_offen.migration_retention_hold.state = "retired";
finalizingOffen.backups.legacy_offen.migration_archive_preservation.state = "retirement-finalizing";
finalizingOffen.backups.legacy_offen.retirement.state = "retirement-finalizing";
finalizingOffen.backups.legacy_offen.retirement.evidence_file = null;
finalizingOffen.backups.legacy_offen.retirement.evidence_sha256 = null;
check(finalizingOffen, true, "non-circular Offen finalizing state accepts pending evidence");
finalizingOffen.backups.legacy_offen.retirement.evidence_file = "infrastructure/evidence/offen-retirement-finalizing.json";
finalizingOffen.backups.legacy_offen.retirement.evidence_sha256 = "b".repeat(64);
check(finalizingOffen, true, "Offen finalizing state accepts exact staged evidence binding");
const invalidFinalizingOffen = structuredClone(finalizingOffen);
invalidFinalizingOffen.backups.legacy_offen.migration_archive_preservation.state = "applied";
check(invalidFinalizingOffen, false, "Offen finalizing state rejects unstaged local archives");

const retiredOffen = structuredClone(contract);
retiredOffen.backups.legacy_offen.scheduler_state = "retired";
retiredOffen.backups.legacy_offen.migration_retention_hold.state = "retired";
retiredOffen.backups.legacy_offen.migration_archive_preservation.state = "retired";
retiredOffen.backups.legacy_offen.retirement.state = "retired";
retiredOffen.backups.legacy_offen.retirement.evidence_file = "infrastructure/evidence/offen-retirement.json";
retiredOffen.backups.legacy_offen.retirement.evidence_sha256 = "a".repeat(64);
check(retiredOffen, true, "attested Offen retirement accepts exact retired state");
const invalidRetiredOffen = structuredClone(retiredOffen);
invalidRetiredOffen.backups.legacy_offen.retirement.evidence_sha256 = null;
check(invalidRetiredOffen, false, "retired Offen requires attested evidence hash");
if (!contract.tailscale.required_endpoints.includes("docker-host:22") ||
    !contract.tailscale.required_endpoints.includes("docker-host:8043") ||
    !productionInventory.includes("ansible_host: docker-host") ||
    !productionInventory.includes("ansible_user: ansible-deploy") ||
    !productionInventory.includes("ansible_python_interpreter: /usr/bin/python3") ||
    !infrastructureInventory.includes("ansible_host: docker-host") ||
    !infrastructureInventory.includes("ansible_user: ansible-deploy") ||
    !infrastructureInventory.includes("ansible_python_interpreter: /usr/bin/python3")) {
  throw new Error("production automation must target the verified Debian Tailscale identity");
}
const stateDisk = contract.proxmox.vm.state_disk;
if (stateDisk.interface !== "scsi2" || stateDisk.serial !== "QUAL-NIXOS-128G" ||
    stateDisk.filesystem_uuid !== "d4a19647-7879-4079-9fc9-b3e79711b449" ||
    stateDisk.filesystem_label !== "home-lab-state" || stateDisk.mountpoint !== "/srv/home-lab-state" ||
    stateDisk.size_gb !== 128 || stateDisk.backup !== true ||
    !proxmoxSource.includes("serial       = local.vm.state_disk.serial")) {
  throw new Error("production state disk must retain the exact scsi2 filesystem identity and lifecycle");
}

const validVmAuthority = structuredClone(contract);
validVmAuthority.vm_100.deployment_authority = "debian";
check(validVmAuthority, true, "VM 100 accepts Debian authority");
for (const authority of ["arch", "migration-in-progress", "nixos", "flatcar", "dual"]) {
  const invalidVmAuthority = structuredClone(contract);
  invalidVmAuthority.vm_100.deployment_authority = authority;
  check(invalidVmAuthority, false, `VM 100 rejects retired authority ${authority}`);
}
for (const mutate of [
  (value) => { value.vm_100.workload_identity.uid = 1001; },
  (value) => { value.vm_100.workload_identity.supplementary_groups = ["docker"]; },
  (value) => { value.vm_100.access.authorized_login_keys = 1; },
  (value) => { value.vm_100.access.password_authentication = true; },
  (value) => { value.vm_100.networking.ipv4 = "192.0.2.100/24"; },
  (value) => { value.vm_100.storage.games.filesystem_uuid = "00000000-0000-0000-0000-000000000000"; },
  (value) => { value.vm_100.storage.shared.source = "192.0.2.1:/wrong"; },
  (value) => { value.vm_100.hardware.gpu.vendor_device = "0000:0000"; },
  (value) => { value.vm_100.hardware.serial.protected_symlinks = ["/dev/zigbee"]; },
  (value) => { value.vm_100.hardware.sysctls["user.max_user_namespaces"] = 0; },
  (value) => { value.vm_100.hardware.tun.path = "/dev/wrong"; },
]) {
  const invalidBaseAccess = structuredClone(contract);
  mutate(invalidBaseAccess);
  check(invalidBaseAccess, false, "VM 100 Debian production identity and hardened access are closed");
}

function valueAt(document, dottedPath) {
  return dottedPath.split(".").reduce((value, segment) => value[segment], document);
}

const closedRequiredPolicyObjects = [
  "vm_100",
  "lifecycle",
  "lifecycle.transitions",
  "lifecycle.hosts",
  "lifecycle.maintenance",
  "lifecycle.maintenance.package_plan",
  "lifecycle.maintenance.package_plan.hosts",
  "lifecycle.maintenance.package_plan.hosts.debian",
  "lifecycle.maintenance.package_plan.hosts.proxmox",
  "lifecycle.maintenance.reboot_plan",
  "lifecycle.hosts.proxmox",
  "lifecycle.hosts.proxmox.marker",
  "lifecycle.hosts.proxmox.domain_handoffs",
  "lifecycle.hosts.proxmox.domain_handoffs.timezone",
  "lifecycle.hosts.proxmox.domain_handoffs.apt_repositories",
  "lifecycle.hosts.proxmox.domain_handoffs.chrony_service",
  "lifecycle.hosts.proxmox.access_cutover",
  "lifecycle.hosts.proxmox.access_cutover.target_identities",
  "lifecycle.hosts.debian",
  "lifecycle.hosts.debian.marker",
  "backups",
  "vm_100.workload_identity",
  "vm_100.access",
  "vm_100.networking",
  "vm_100.storage",
  "vm_100.storage.games",
  "vm_100.storage.shared",
  "vm_100.hardware",
  "vm_100.hardware.gpu",
  "vm_100.hardware.bluetooth",
  "vm_100.hardware.input",
  "vm_100.hardware.serial",
  "vm_100.hardware.tun",
  "vm_100.hardware.sysctls",
  "network.ownership",
  "network.ownership.interfaces_file",
  "proxmox.vm",
  "proxmox.vm.retired_disk_slot",
  "proxmox.vm.state_disk",
  "proxmox.vm.games_disk",
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
const protectedManagedFiles = policyRecords.filter((record) => record.kind === "protected-managed-file");
const protectedRecords = policyRecords.filter((record) => record.kind.startsWith("runtime-protected-"));
if (!managedFiles.length || !protectedManagedFiles.length || !protectedRecords.length) throw new Error("contract must classify managed, protected-managed, and runtime-protected policies");
if (protectedManagedFiles.some((record) => record.projectable !== false)) throw new Error("protected managed files must not enter the reduced projection");
const knownPolicyKinds = new Set(["managed-file", "protected-managed-file", "managed-file-metadata", "managed-directory", "runtime-protected-file", "runtime-protected-directory", "audit-absence", "api-owned"]);
if (policyRecords.some((record) => !knownPolicyKinds.has(record.kind))) throw new Error("contract contains an unknown projector-dispatch kind");
if (contract.proxmox.apt.repository_file_metadata.kind !== "managed-file-metadata" ||
    contract.proxmox.access.service_accounts[0].sudo.file.kind !== "managed-file" ||
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
checkSemantic(privilegedPlanAccount, "tofu-plan must have only the fixed observer capability", "privileged plan account");

const extraApplyGroup = structuredClone(contract);
extraApplyGroup.proxmox.access.service_accounts[1].groups.push("docker");
checkSemantic(extraApplyGroup, "tofu-apply must expose only the fixed preparation and activation session capability", "extra apply-account group");

const unlockedServiceAccount = structuredClone(contract);
unlockedServiceAccount.proxmox.access.service_accounts[0].password_lock = false;
checkSemantic(unlockedServiceAccount, "locked login identity", "unlocked service account");

const movedServiceSudoers = structuredClone(contract);
movedServiceSudoers.proxmox.access.service_accounts[1].sudo.file.path = "/etc/sudoers.d/other-apply";
checkSemantic(movedServiceSudoers, "tofu-apply must expose only the fixed preparation and activation session capability", "moved service-account sudoers path");

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

for (const removed of ["proxmox_host", "proxmox_network", "proxmox_passthrough", "proxmox_storage", "proxmox_health", "proxmox_firewall"]) {
  if (fs.existsSync(path.join(root, "ansible/roles", removed))) throw new Error(`retired Ansible role remains: ${removed}`);
}

function parsedTask(relativePath, taskName) {
  const tasks = load(fs.readFileSync(path.join(root, relativePath), "utf8"));
  const task = tasks.find((candidate) => candidate.name === taskName);
  if (!task) throw new Error(`${relativePath} lacks active task ${taskName}`);
  return task;
}
function parsedPlayTask(relativePath, taskName) {
  const plays = load(fs.readFileSync(path.join(root, relativePath), "utf8"));
  const task = plays.flatMap((play) => [...(play.pre_tasks || []), ...(play.tasks || []), ...(play.post_tasks || [])]).find((candidate) => candidate.name === taskName);
  if (!task) throw new Error(`${relativePath} lacks active play task ${taskName}`);
  return task;
}
function requireTaskArgument(relativePath, taskName, moduleName, argument, expected) {
  const task = parsedTask(relativePath, taskName);
  const actual = task[moduleName]?.[argument];
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${relativePath} ${taskName} ${moduleName}.${argument}=${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
}
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Keep the SSH host-key sentinel metadata protected", "ansible.builtin.file", "mode", "{{ ssh_host_key_sentinel_mode }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "dest", "{{ ssh_config_path }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "owner", "{{ ssh_config_owner }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "group", "{{ ssh_config_group }}");
requireTaskArgument("ansible/roles/ssh/tasks/main.yml", "Converge managed OpenSSH policy", "ansible.builtin.copy", "mode", "{{ ssh_config_mode }}");
const sshMetadataTask = parsedTask("ansible/roles/ssh/tasks/main.yml", "Keep the SSH host-key sentinel metadata protected");
if (!sshMetadataTask.when.includes("not ansible_check_mode or (ssh_host_key_sentinel_before.stat.exists | default(false))")) {
  throw new Error("SSH host-key metadata enforcement must skip an absent sentinel only in check mode");
}
requireTaskArgument("ansible/roles/tailscale/tasks/main.yml", "Keep tailscaled enabled and started without restarting it", "ansible.builtin.systemd_service", "state", "{{ tailscale_service_state }}");
const dockerHostTailscale = contract.tailscale.docker_host_client;
if (dockerHostTailscale.version !== "1.102.3" ||
    dockerHostTailscale.archive_sha256 !== "36ddd9b51be57ffc2990cf76323cfa13643bfbb1b8a969f6183fa164741cdef5" ||
    dockerHostTailscale.client_sha256 !== "d6ffcba02fa07728f0c4847fc06d61f239f763478bd59156abf3591bdb1a3ad1" ||
    dockerHostTailscale.daemon_sha256 !== "ce4770bbe6fc9dbcf47d8a2ccc5efad73e3f975460b01738dd0b059879d01221" ||
    dockerHostTailscale.auto_update_apply !== false || dockerHostTailscale.run_ssh !== true || dockerHostTailscale.update_check !== true) {
  throw new Error("Docker-host Tailscale must retain the adopted official pinned baseline");
}
const tailscaleBinaryAssertion = parsedTask("ansible/roles/tailscale/tasks/main.yml", "Require exact pinned standalone Tailscale binaries");
if (!tailscaleBinaryAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("stat.checksum"))) {
  throw new Error("Tailscale convergence must verify pinned binary hashes");
}
const tailscaleUpdatePolicyAssertion = parsedTask("ansible/roles/tailscale/tasks/main.yml", "Require the access-critical Tailscale update policy before ordinary convergence");
if (!tailscaleUpdatePolicyAssertion["ansible.builtin.assert"].that.every((condition) => condition.includes("AutoUpdate"))) {
  throw new Error("Ordinary Tailscale convergence must fail closed on update-policy drift");
}
const tailscalePreferenceConvergence = parsedTask("ansible/roles/tailscale/tasks/main.yml", "Converge complete Tailscale preferences");
const tailscalePreferenceArgs = tailscalePreferenceConvergence["ansible.builtin.command"].argv;
if (tailscalePreferenceArgs.some((value) => value.includes("--auto-update=") || value.includes("--update-check="))) {
  throw new Error("Ordinary Tailscale convergence must not mutate access-critical update policy");
}
const tailscaleReconciliationPlaybook = fs.readFileSync(path.join(root, "ansible/playbooks/reconcile-tailscale-baseline.yml"), "utf8");
for (const required of ["adopt-official-tailscale-1.102.3-disable-auto-apply", "lan_ssh_recovery_confirmed", "proxmox_console_recovery_confirmed", "tailscale_ssh_access_confirmed", "ActiveEnterTimestampMonotonic"]) {
  if (!tailscaleReconciliationPlaybook.includes(required)) throw new Error(`Tailscale reconciliation omits ${required}`);
}
const tailscaleBootstrapGuard = parsedPlayTask("ansible/playbooks/bootstrap.yml", "Require dual-path recovery and tailnet-policy confirmations before a normal bootstrap");
if (!tailscaleBootstrapGuard["ansible.builtin.assert"].that.some((condition) => condition.includes("tailscale_ssh_access_confirmed")) ||
    !tailscaleBootstrapGuard["ansible.builtin.assert"].fail_msg.includes("Tailscale SSH")) {
  throw new Error("Docker bootstrap must confirm Tailscale SSH access");
}
const tailscaleReconciliationPreflight = parsedPlayTask("ansible/playbooks/reconcile-tailscale-baseline.yml", "Require the exact official running Tailscale baseline before preference mutation");
if (!tailscaleReconciliationPreflight["ansible.builtin.assert"].that.some((condition) => condition.includes("docker_host_client.run_ssh"))) {
  throw new Error("Tailscale reconciliation preflight must bind RunSSH to contract");
}
const tailscaleAuditAssertion = parsedTask("ansible/roles/audit/tasks/main.yml", "Assert Docker, Compose, and Tailscale runtime versions");
if (!tailscaleAuditAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("RunSSH") && condition.includes("audit_expected_tailscale_run_ssh"))) {
  throw new Error("Tailscale audit must bind RunSSH to contract");
}
const tailscaleUpdateMutation = parsedPlayTask("ansible/playbooks/reconcile-tailscale-baseline.yml", "Disable Tailscale automatic update application without restarting tailscaled");
if (JSON.stringify(tailscaleUpdateMutation["ansible.builtin.command"].argv) !== JSON.stringify([
  "{{ tailscale.docker_host_client.client_path }}", "set", "--auto-update=false", "--update-check=true",
])) {
  throw new Error("Tailscale reconciliation mutation command differs from the exact reviewed preference change");
}
const tailscaleReconciliationAssertion = parsedPlayTask("ansible/playbooks/reconcile-tailscale-baseline.yml", "Require pinned Tailscale state with no service restart after reconciliation");
const tailscaleReconciliationConditions = tailscaleReconciliationAssertion["ansible.builtin.assert"].that.join("\n");
for (const required of ["dict2items", "docker_host_client.run_ssh", "Self.ID", "Self.NodeID", "Self.PublicKey", "Self.UserID", "Self.HostName", "Self.DNSName", "Self.TailscaleIPs", "Self.Tags", "version_after", "service_after", "stat.isreg", "stat.islnk", "stat.nlink", "stat.pw_name", "stat.gr_name", "stat.mode", "stat.checksum"]) {
  if (!tailscaleReconciliationConditions.includes(required)) throw new Error(`Tailscale reconciliation postconditions omit ${required}`);
}
const tailscaleAssertion = parsedTask("ansible/roles/tailscale/tasks/main.yml", "Assert local Tailscale verification passed");
if (!tailscaleAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("tailscale_expected_backend_state"))) {
  throw new Error("Tailscale verification must consume the expected backend state");
}
requireTaskArgument("ansible/roles/human_access/tasks/main.yml", "Remove contract-declared conventional OpenSSH authorized-key files for human accounts", "ansible.builtin.file", "path", "{{ item.1.path }}");
requireTaskArgument("ansible/roles/human_access/tasks/main.yml", "Install validated passwordless sudo policies for human accounts", "ansible.builtin.copy", "dest", "{{ item.sudo.file.path | default(item.sudoers_path) }}");


const renderedConsumers = {};
for (const [relativePath, snippets] of Object.entries(renderedConsumers)) {
  const source = fs.readFileSync(path.join(root, relativePath), "utf8");
  for (const snippet of snippets) if (!source.includes(snippet)) throw new Error(`${relativePath} does not derive ${snippet}`);
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
