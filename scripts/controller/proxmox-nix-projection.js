#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");

const root = path.resolve(__dirname, "../..");

function canonicalJson(value) {
  function sort(candidate) {
    if (Array.isArray(candidate)) return candidate.map(sort);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.keys(candidate).sort().map((key) => [key, sort(candidate[key])]));
    }
    return candidate;
  }
  return `${JSON.stringify(sort(value))}\n`;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function managedFile(file, content) {
  return {
    path: file.path,
    owner: file.owner,
    group: file.group,
    mode: file.mode,
    content,
  };
}

function projectProxmoxPolicy(contract, packageManifest) {
  const { network, proxmox, storage } = contract;
  if (packageManifest.architecture !== proxmox.packages.architecture || !Array.isArray(packageManifest.packages) ||
      packageManifest.packages.length < 1 || !Number.isInteger(packageManifest.provenance?.installedInventory?.installedRecords) ||
      packageManifest.provenance.installedInventory.installedRecords < 1 ||
      !Array.isArray(packageManifest.provenance?.solverResult?.changes)) {
    throw new Error("package manifest architecture, package set, or provenance is invalid");
  }
  const provenanceCount = packageManifest.provenance.solverResult.changes.reduce(
    (count, change) => count + (change.action === "install" ? 1 : change.action === "remove" ? -1 : 0),
    packageManifest.provenance.installedInventory.installedRecords,
  );
  if (provenanceCount !== packageManifest.packages.length) {
    throw new Error("package manifest count differs from provenance");
  }
  const serviceNames = proxmox.services.map((service) => service.name);
  const servicePolicyNames = proxmox.planning_policy.service_policies.map((policy) => policy.name);
  if (new Set(serviceNames).size !== serviceNames.length || new Set(servicePolicyNames).size !== servicePolicyNames.length ||
      serviceNames.length !== servicePolicyNames.length || serviceNames.some((name) => !servicePolicyNames.includes(name))) {
    throw new Error("native service policies must uniquely cover every native service")
  }
  const requiredServicePolicies = new Map([
    ["chrony.service", ["guarded", true, false]],
    ["nfs-server.service", ["data-critical", false, false]],
    ["ssh.service", ["access-critical", false, true]],
    ["tailscaled.service", ["access-critical", false, true]],
  ]);
  for (const policy of proxmox.planning_policy.service_policies) {
    const expected = requiredServicePolicies.get(policy.name);
    if (!expected || policy.safety_class !== expected[0] || policy.automatic !== expected[1] ||
        policy.requires_watchdog !== expected[2] || !policy.requires_approval || policy.requires_reboot) {
      throw new Error(`unsafe authoritative service policy: ${policy.name}`);
    }
  }
  const repositoryMetadata = proxmox.apt.repository_file_metadata;
  const booleanWord = (value) => (value ? "yes" : "no");
  const networkContent = `${network.ownership.managed_header}\n` +
    "auto lo\niface lo inet loopback\n\n" +
    `auto ${network.bridge_port}\niface ${network.bridge_port} inet manual\n\n` +
    `auto ${network.bridge}\niface ${network.bridge} inet static\n` +
    `  address ${network.proxmox.ipv4}\n  gateway ${network.gateway}\n` +
    `  bridge-ports ${network.bridge_port}\n` +
    `  bridge-stp ${network.ownership.bridge_stp ? "on" : "off"}\n` +
    `  bridge-fd ${network.ownership.bridge_forward_delay}\n`;
  const repositoryFiles = proxmox.apt.repositories.map((repository) => managedFile(
    { path: repository.file, ...repositoryMetadata },
    `Types: ${repository.types.join(" ")}\nURIs: ${repository.uris.join(" ")}\n` +
      `Suites: ${repository.suites.join(" ")}\nComponents: ${repository.components.join(" ")}\n` +
      `Signed-By: ${repository.signed_by}\n`,
  ));
  const sudoFiles = [
    ...proxmox.access.service_accounts,
    ...proxmox.access.human_accounts,
  ].filter((account) => account.sudo?.state === "present").map((account) =>
    managedFile(account.sudo.file, `${account.sudo.rule}\n`));
  const ssh = proxmox.ssh;
  const sshContent = `PubkeyAuthentication ${booleanWord(ssh.pubkey_authentication)}\n` +
    `PasswordAuthentication ${booleanWord(ssh.password_authentication)}\n` +
    `KbdInteractiveAuthentication ${booleanWord(ssh.kbd_interactive_authentication)}\n` +
    `PermitRootLogin ${ssh.permit_root_login}\n` +
    (ssh.allow_users.length ? `AllowUsers ${ssh.allow_users.join(" ")}\n` : "");
  const managedFiles = [
    managedFile(network.ownership.interfaces_file, networkContent),
    managedFile(proxmox.vfio.modules_load_file, `${proxmox.vfio.modules.join("\n")}\n`),
    managedFile(proxmox.apt.inactive_sources_list.file, `${proxmox.apt.inactive_sources_list.notice}\n`),
    ...repositoryFiles,
    ...sudoFiles,
    managedFile(ssh.config_file, sshContent),
    managedFile(
      storage.zfs.arc_config.file,
      `options ${storage.zfs.arc_config.module} ${storage.zfs.arc_config.option}=${storage.zfs.arc_max_bytes}\n`,
    ),
    managedFile(
      storage.nfs.exports_file,
      `${storage.nfs.export} ${storage.nfs.client}(${[...storage.nfs.options, storage.nfs.squash_policy].join(",")})\n`,
    ),
  ].sort((left, right) => compareText(left.path, right.path));

  const pveRoles = [
    ...proxmox.access.pve.accounts.map((account) => ({
      role: account.role,
      privileges: [...account.privileges],
    })),
    ...proxmox.access.pve.additional_roles.map((role) => ({
      role: role.role,
      privileges: [...role.privileges],
    })),
  ].sort((left, right) => compareText(left.role, right.role));
  const principalByRole = new Map([
    ["HomeLabTofuPlan", "plan"],
    ["HomeLabTofuApply", "apply"],
  ]);
  const pveBindings = proxmox.access.pve.accounts.map((account) => {
    const principal = principalByRole.get(account.role);
    if (!principal) throw new Error(`PVE account role has no semantic principal: ${account.role}`);
    return {
      principal,
      role: account.role,
      privilegeSeparation: account.privilege_separation,
      primaryAcl: account.primary_acl_path,
      additionalAcls: account.additional_acls.map((acl) => ({ path: acl.path, role: acl.role })),
    };
  }).sort((left, right) => compareText(left.principal, right.principal));
  if (new Set(pveBindings.map((binding) => binding.principal)).size !== principalByRole.size ||
      pveBindings.length !== principalByRole.size) {
    throw new Error("PVE semantic principals must contain exactly plan and apply");
  }

  return {
    version: 1,
    architecture: proxmox.packages.architecture,
    hostNetworking: {
      cidr: network.cidr,
      gateway: network.gateway,
      dns: [...network.dns],
      bridge: network.bridge,
      bridgePort: network.bridge_port,
      hostname: network.proxmox.hostname,
      magicDnsName: network.proxmox.magicdns_name,
      ipv4: network.proxmox.ipv4,
      permittedActiveSnippets: [...network.ownership.permitted_active_snippets],
    },
    managedFiles,
    managedFileFragments: [{
      path: proxmox.grub.file.path,
      owner: proxmox.grub.file.owner,
      group: proxmox.grub.file.group,
      mode: proxmox.grub.file.mode,
      strategy: "required-line",
      content: `${proxmox.grub.variable}=\"${proxmox.grub.default_tokens.join(" ")}\"`,
    }],
    managedArtifacts: proxmox.apt.permitted_keyrings.map((keyring) => ({
      name: keyring.name,
      path: keyring.file.path,
      owner: keyring.file.owner,
      group: keyring.file.group,
      mode: keyring.file.mode,
      sha256: keyring.sha256,
      sourceUrl: keyring.source_url,
      symlinkTarget: keyring.symlink_target,
    })).sort((left, right) => compareText(left.path, right.path)),
    managedFileMetadata: [{
      domain: "apt-repository-files",
      owner: repositoryMetadata.owner,
      group: repositoryMetadata.group,
      mode: repositoryMetadata.mode,
    }],
    auditAbsence: [
      ...proxmox.vfio.absence_policy.map((record) => ({
        absence: record.absence,
        path: record.path,
        ...(record.pattern === undefined ? {} : { pattern: record.pattern }),
      })),
      ...proxmox.access.service_accounts.filter((account) => account.sudo?.kind === "audit-absence")
        .map((account) => ({ absence: account.sudo.absence, path: account.sudo.path })),
    ].sort((left, right) => compareText(left.path, right.path)),
    nativeServices: proxmox.services.map((service) => ({ ...service })),
    accounts: {
      service: proxmox.access.service_accounts.map((account) => ({
        name: account.name,
        home: account.home,
        shell: account.shell,
        createHome: account.create_home,
        passwordLock: account.password_lock,
        groups: [...account.groups],
      })),
      human: proxmox.access.human_accounts.map((account) => ({
        name: account.name,
        comment: account.comment,
        group: account.group,
        home: account.home,
        shell: account.shell,
        passwordLock: account.password_lock,
        supplementaryGroups: [...account.supplementary_groups],
        localAuthorizedKeys: account.authorized_keys.state,
      })),
    },
    ssh: {
      service: ssh.service,
      pubkeyAuthentication: ssh.pubkey_authentication,
      passwordAuthentication: ssh.password_authentication,
      kbdInteractiveAuthentication: ssh.kbd_interactive_authentication,
      permitRootLogin: ssh.permit_root_login,
      allowUsers: [...ssh.allow_users],
    },
    tailscale: {
      package: proxmox.tailscale.package,
      service: proxmox.tailscale.service,
      serviceEnabled: proxmox.tailscale.service_enabled,
      serviceState: proxmox.tailscale.service_state,
      enrollmentTimeoutSeconds: proxmox.tailscale.enrollment_timeout_seconds,
      enrollmentSsh: proxmox.tailscale.enrollment_ssh,
      hostname: proxmox.tailscale.hostname,
      advertiseTag: proxmox.tailscale.advertise_tag,
      advertiseRoutes: [...proxmox.tailscale.advertise_routes],
      acceptDns: proxmox.tailscale.accept_dns,
      acceptRoutes: proxmox.tailscale.accept_routes,
      netfilterMode: proxmox.tailscale.netfilter_mode,
      ssh: proxmox.tailscale.ssh,
    },
    healthExpectations: {
      pveApiStatusCodes: [...proxmox.health.local_api_status_codes],
      tailscaleBackendState: proxmox.health.tailscale_backend_state,
      requireVm: proxmox.health.require_vm,
      vmStatus: proxmox.health.vm_status,
    },
    planningPolicy: {
      maxAgeSeconds: proxmox.planning_policy.max_observation_age_seconds,
      servicePolicies: proxmox.planning_policy.service_policies.map((entry) => ({
        name: entry.name,
        safetyClass: entry.safety_class,
        automatic: entry.automatic,
        requiresApproval: entry.requires_approval,
        requiresReboot: entry.requires_reboot,
        requiresWatchdog: entry.requires_watchdog,
      })).sort((left, right) => compareText(left.name, right.name)),
      managedFilePolicies: proxmox.planning_policy.managed_file_policies.map((entry) => ({
        path: entry.path,
        safetyClass: entry.safety_class,
        automatic: entry.automatic,
        requiresApproval: entry.requires_approval,
        requiresReboot: entry.requires_reboot,
        requiresWatchdog: entry.requires_watchdog,
      })).sort((left, right) => compareText(left.path, right.path)),
      domains: proxmox.planning_policy.domains.map((entry) => ({
        domain: entry.domain,
        safetyClass: entry.safety_class,
        automatic: entry.automatic,
        requiresApproval: entry.requires_approval,
        requiresReboot: entry.requires_reboot,
        requiresWatchdog: entry.requires_watchdog,
      })),
    },
    packagePolicy: {
      direct: proxmox.packages.direct.map((entry) => ({ ...entry })),
      critical: proxmox.packages.critical.map((entry) => ({ ...entry })),
      prohibited: [...proxmox.packages.prohibited],
      permittedManual: [...proxmox.packages.permitted_manual],
      manifestSha256: proxmox.packages.manifest.sha256,
      manifestPackageCount: packageManifest.packages.length,
    },
    kernelPolicy: {
      current: proxmox.kernels.current,
      fallback: proxmox.kernels.fallback,
      retentionCount: proxmox.kernels.retention_count,
      requireBootHistoryProof: proxmox.kernels.require_boot_history_proof,
    },
    storagePolicy: {
      expectedHealth: storage.zfs.expected_health,
      arcMaxBytes: storage.zfs.arc_max_bytes,
      mirrorTopology: { ...storage.zfs.mirror_topology },
      dataset: storage.zfs.dataset,
      datasetProperties: { ...storage.zfs.dataset_properties },
      mountpoint: storage.zfs.mountpoint,
      nfs: {
        export: storage.nfs.export,
        client: storage.nfs.client,
        clientVmid: storage.nfs.client_vmid,
        mountpoint: storage.nfs.mountpoint,
        options: [...storage.nfs.options],
        squashPolicy: storage.nfs.squash_policy,
      },
    },
    apiIntent: {
      pveAccess: { roles: pveRoles, bindings: pveBindings },
      pveFirewall: {
        ownership: proxmox.firewall.ownership,
        activation: proxmox.firewall.activation,
        options: { ...proxmox.firewall.options },
        rules: proxmox.firewall.rules.map((rule) => ({ ...rule })),
      },
      pveStorage: {
        id: storage.zfs.pve_storage.id,
        type: storage.zfs.pve_storage.type,
        pool: storage.zfs.pve_storage.pool,
        mountpoint: storage.zfs.pve_storage.mountpoint,
        content: [...storage.zfs.pve_storage.content],
        nodes: [...storage.zfs.pve_storage.nodes],
      },
    },
  };
}

function projectVm100Scaffold(contract) {
  const vm = contract.vm_100;
  if (vm.vmid !== contract.proxmox.vm.vmid || vm.vmid !== contract.storage.nfs.client_vmid ||
      vm.host_name !== contract.network.arch.hostname || vm.network_identity !== contract.network.arch.magicdns_name) {
    throw new Error("VM 100 scaffold identity differs from existing contract authority");
  }
  const expectedActivation = vm.deployment_authority === "nixos";
  if (vm.nixos_activation_enabled !== expectedActivation) {
    throw new Error("VM 100 authority and NixOS activation selection differ");
  }
  const identity = vm.workload_identity;
  const access = vm.access;
  const networking = vm.networking;
  const storage = vm.storage;
  if (networking.interface !== contract.arch.network_interface || networking.match_mac !== contract.network.arch.mac ||
      networking.ipv4 !== contract.network.arch.ipv4 || networking.gateway !== contract.network.gateway ||
      JSON.stringify(networking.dns) !== JSON.stringify(contract.network.dns) ||
      storage.games.mountpoint !== contract.arch.games_mountpoint ||
      storage.games.filesystem_uuid !== contract.proxmox.vm.games_disk.filesystem_uuid ||
      storage.shared.mountpoint !== contract.storage.nfs.mountpoint ||
      storage.shared.source !== `${contract.network.proxmox.ipv4.split("/")[0]}:${contract.storage.nfs.export}`) {
    throw new Error("VM 100 networking or storage differs from existing contract authority");
  }
  if (identity.user !== identity.primary_group || identity.uid !== identity.gid || access.authorized_login_keys !== 0) {
    throw new Error("VM 100 base identity or console-only access selection differs");
  }
  return {
    version: 1,
    vmid: vm.vmid,
    hostName: vm.host_name,
    networkIdentity: vm.network_identity,
    system: vm.system,
    stateVersion: vm.state_version,
    deploymentAuthority: vm.deployment_authority,
    nixosActivationEnabled: vm.nixos_activation_enabled,
    workloadIdentity: {
      user: identity.user,
      uid: identity.uid,
      primaryGroup: identity.primary_group,
      gid: identity.gid,
      home: identity.home,
      shell: identity.shell,
      supplementaryGroups: identity.supplementary_groups,
    },
    access: {
      opensshEnabled: access.openssh_enabled,
      authorizedLoginKeys: access.authorized_login_keys,
      passwordAuthentication: access.password_authentication,
      keyboardInteractiveAuthentication: access.keyboard_interactive_authentication,
      permitRootLogin: access.permit_root_login,
      allowTcpForwarding: access.allow_tcp_forwarding,
      x11Forwarding: access.x11_forwarding,
    },
    networking: {
      interface: networking.interface,
      matchMac: networking.match_mac,
      ipv4: networking.ipv4,
      gateway: networking.gateway,
      dns: networking.dns,
      dhcp: networking.dhcp,
    },
    storage: {
      games: {
        mountpoint: storage.games.mountpoint,
        filesystem: storage.games.filesystem,
        filesystemUuid: storage.games.filesystem_uuid,
        label: storage.games.label,
        options: storage.games.options,
      },
      shared: {
        mountpoint: storage.shared.mountpoint,
        filesystem: storage.shared.filesystem,
        source: storage.shared.source,
        options: storage.shared.options,
      },
    },
  };
}

function validateProjection(projection, schema) {
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  if (!validate(projection)) {
    throw new Error(`projection schema validation failed: ${JSON.stringify(validate.errors)}`);
  }
}

function main() {
  const args = process.argv.slice(2);
  let check = false;
  let target = "proxmox";
  let output;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--check") check = true;
    else if (args[index] === "--target" && args[index + 1]) target = args[++index];
    else if (args[index] === "--output" && args[index + 1]) output = path.resolve(args[++index]);
    else throw new Error("usage: proxmox-nix-projection.js [--check] [--target proxmox|vm-100] [--output PATH]");
  }
  const targets = {
    proxmox: {
      output: "nix/proxmox/projection.json",
      schema: "nix/proxmox/projection.schema.json",
      project: (contract) => projectProxmoxPolicy(contract, JSON.parse(fs.readFileSync(path.join(root, contract.proxmox.packages.manifest.path), "utf8"))),
    },
    "vm-100": {
      output: "nix/vm-100/projection.json",
      schema: "nix/vm-100/projection.schema.json",
      project: projectVm100Scaffold,
    },
  };
  const selected = targets[target];
  if (!selected) throw new Error(`unknown projection target: ${target}`);
  output ??= path.join(root, selected.output);
  const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
  const schema = JSON.parse(fs.readFileSync(path.join(root, selected.schema), "utf8"));
  const rendered = canonicalJson(selected.project(contract));
  validateProjection(JSON.parse(rendered), schema);
  if (check) {
    if (!fs.existsSync(output) || fs.readFileSync(output, "utf8") !== rendered) {
      throw new Error(`${path.relative(root, output)} is stale; regenerate it with scripts/controller/proxmox-nix-projection.js --target ${target}`);
    }
  } else {
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, rendered);
  }
}

if (require.main === module) main();
module.exports = { canonicalJson, projectProxmoxPolicy, projectVm100Scaffold, validateProjection };
