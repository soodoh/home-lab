"use strict";

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function sameMembers(actual, expected) {
  return actual.length === expected.length && actual.every((value) => expected.includes(value));
}

function outsideCapabilityCeiling(privileges, allowed) {
  return privileges.filter((privilege) => !allowed.has(privilege)).sort();
}

function validateProxmoxHostPolicy(contract) {
  const failures = [];
  const { proxmox } = contract;

  const repositoryNames = proxmox.apt.repositories.map((repository) => repository.name);
  const repositoryFiles = proxmox.apt.repositories.map((repository) => repository.file);
  const keyringNames = proxmox.apt.permitted_keyrings.map((keyring) => keyring.name);
  const keyringPaths = proxmox.apt.permitted_keyrings.map((keyring) => keyring.file.path);
  const keyringHashes = proxmox.apt.permitted_keyrings.map((keyring) => keyring.sha256);
  if (duplicates(repositoryNames).length) failures.push("APT repository names must be unique");
  if (duplicates(repositoryFiles).length) failures.push("APT repository files must be unique");
  if (duplicates(keyringNames).length) failures.push("APT keyring names must be unique");
  if (duplicates(keyringPaths).length) failures.push("APT keyring paths must be unique");
  if (duplicates(keyringHashes).length) failures.push("APT keyring checksums must be unique");
  for (const repository of proxmox.apt.repositories) {
    if (!keyringPaths.includes(repository.signed_by)) {
      failures.push(`APT repository ${repository.name} uses an unapproved signing key`);
    }
  }
  for (const keyring of proxmox.apt.permitted_keyrings) {
    if (!proxmox.apt.repositories.some((repository) => repository.signed_by === keyring.file.path)) {
      failures.push(`APT keyring ${keyring.name} is not referenced by a repository`);
    }
    if (keyring.source_url !== null && keyring.symlink_target !== null) {
      failures.push(`downloaded APT keyring ${keyring.name} must be a regular file`);
    }
    if (keyring.symlink_target === keyring.file.path.split("/").at(-1)) {
      failures.push(`APT keyring ${keyring.name} must not link to itself`);
    }
  }
  const tailscaleKeyring = proxmox.apt.permitted_keyrings.find((keyring) => keyring.name === "tailscale");
  const tailscaleRepository = proxmox.apt.repositories.find((repository) => repository.name === "tailscale");
  const expectedTailscaleKeyUrl = tailscaleRepository && tailscaleRepository.uris.length === 1 && tailscaleRepository.suites.length === 1
    ? `${tailscaleRepository.uris[0]}/${tailscaleRepository.suites[0]}.noarmor.gpg`
    : null;
  if (!tailscaleKeyring || tailscaleRepository?.signed_by !== tailscaleKeyring.file.path ||
      tailscaleKeyring.source_url !== expectedTailscaleKeyUrl) {
    failures.push("Tailscale repository must use its suite-derived checksum-bound downloadable keyring");
  }
  for (const keyring of proxmox.apt.permitted_keyrings.filter((entry) => entry.name !== "tailscale")) {
    if (keyring.source_url !== null) failures.push(`packaged APT keyring ${keyring.name} must not declare a download URL`);
  }

  const requiredServices = ["chrony.service", "nfs-server.service", proxmox.ssh.service, proxmox.tailscale.service];
  if (!sameMembers(proxmox.services.map((service) => service.name), requiredServices) ||
      proxmox.services.some((service) => !service.enabled || service.state !== "started")) {
    failures.push("native service set must contain exactly the required time, NFS, SSH, and Tailscale services");
  }

  const serviceAccounts = proxmox.access.service_accounts;
  const serviceAccountNames = serviceAccounts.map((account) => account.name);
  const serviceAccountHomes = serviceAccounts.map((account) => account.home);
  const serviceAccountKeyRefs = serviceAccounts.map((account) => account.authorized_keys.secret_ref);
  const sudoersPaths = serviceAccounts.map((account) => account.sudo?.file?.path).filter((value) => value !== undefined);
  if (duplicates(serviceAccountNames).length) failures.push("Proxmox service-account names must be unique");
  if (duplicates(serviceAccountHomes).length) failures.push("Proxmox service-account homes must be unique");
  if (duplicates(serviceAccountKeyRefs).length) failures.push("Proxmox service-account key references must be unique");
  if (duplicates(sudoersPaths).length) failures.push("Proxmox service-account sudoers paths must be unique");
  const expectedServiceAccounts = new Map([
    ["tofu-plan", "PROXMOX_PLAN_SSH_PUBLIC_KEYS"],
    ["tofu-apply", "PROXMOX_APPLY_SSH_PUBLIC_KEYS"],
    ["firewall-apply", "PROXMOX_FIREWALL_SSH_PUBLIC_KEYS"],
  ]);
  if (serviceAccounts.length !== expectedServiceAccounts.size) failures.push("exactly three Proxmox service accounts are required");
  for (const account of serviceAccounts) {
    if (expectedServiceAccounts.get(account.name) !== account.authorized_keys.secret_ref) {
      failures.push(`service account ${account.name} uses an unexpected authorized-key reference`);
    }
    if (account.home !== `/home/${account.name}`) failures.push(`service account ${account.name} home must match its name`);
    if (account.ssh_directory.path !== `${account.home}/.ssh` ||
        account.ssh_directory.owner !== account.name || account.ssh_directory.group !== account.name ||
        account.ssh_directory.mode !== "0700" || account.ssh_directory.kind !== "runtime-protected-directory" ||
        account.ssh_directory.projectable || account.ssh_directory.materialization !== "metadata-only" ||
        account.authorized_keys.file.path !== `${account.home}/.ssh/authorized_keys` ||
        account.authorized_keys.file.owner !== account.name || account.authorized_keys.file.group !== account.name ||
        account.authorized_keys.file.mode !== "0600" || account.authorized_keys.file.kind !== "runtime-protected-file" ||
        account.authorized_keys.file.projectable || account.authorized_keys.file.materialization !== "metadata-only") {
      failures.push(`service account ${account.name} authorized-keys path must stay under its home`);
    }
    const expectedShell = account.name === "firewall-apply" ? "/usr/local/libexec/home-lab/proxmox-firewall-transport" :
      account.name === "tofu-apply" ? "/usr/local/libexec/home-lab/proxmox-apply-transport" : "/bin/bash";
    if (account.shell !== expectedShell || !account.create_home || !account.password_lock) {
      failures.push(`service account ${account.name} must retain its locked login identity`);
    }
  }
  const planAccount = serviceAccounts.find((account) => account.name === "tofu-plan");
  const applyAccount = serviceAccounts.find((account) => account.name === "tofu-apply");
  const firewallAccount = serviceAccounts.find((account) => account.name === "firewall-apply");
  const observerCommand = "/usr/local/libexec/home-lab/proxmox-observer observe";
  const forcedPlanCommand = `restrict,command="sudo -n -- ${observerCommand}"`;
  if (planAccount && (planAccount.groups.length || planAccount.sudo?.state !== "present" ||
      planAccount.sudo?.file?.path !== `/etc/sudoers.d/${planAccount.name}` ||
      planAccount.sudo?.rule !== `${planAccount.name} ALL=(root) NOPASSWD: ${observerCommand}` ||
      planAccount.authorized_keys?.forced_command !== forcedPlanCommand)) {
    failures.push("tofu-plan must have only the fixed observer capability during parity");
  }
  const applyTransport = "/usr/local/libexec/home-lab/proxmox-apply-transport";
  const applySudo = "tofu-apply ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-private-preparer prepare, /usr/local/libexec/home-lab/proxmox-activator session";
  if (applyAccount && (applyAccount.groups.length || applyAccount.sudo?.state !== "present" ||
      applyAccount.sudo?.file?.path !== `/etc/sudoers.d/${applyAccount.name}` ||
      applyAccount.sudo?.rule !== applySudo ||
      applyAccount.authorized_keys?.forced_command !== `restrict,command="${applyTransport}"`)) {
    failures.push("tofu-apply must expose only the fixed preparation and activation session capability");
  }
  const firewallHelper = "/usr/local/libexec/home-lab/proxmox-firewall-transaction";
  const firewallSudo = `firewall-apply ALL=(root) NOPASSWD: ${["inspect","begin","status","commit","rollback"].map((command) => `${firewallHelper} ${command}`).join(", ")}`;
  if (firewallAccount && (firewallAccount.groups.length || firewallAccount.sudo?.state !== "present" ||
      firewallAccount.sudo?.file?.path !== "/etc/sudoers.d/firewall-apply" || firewallAccount.sudo?.rule !== firewallSudo ||
      firewallAccount.authorized_keys?.forced_command !== 'restrict,command="/usr/local/libexec/home-lab/proxmox-firewall-transport"')) {
    failures.push("firewall-apply must have only the fixed firewall transport capability");
  }

  const humanNames = proxmox.access.human_accounts.map((account) => account.name);
  if (duplicates(humanNames).length) failures.push("Proxmox human-account names must be unique");
  if (proxmox.access.human_accounts.length !== 1 || proxmox.access.human_accounts[0].name !== "proxmox") {
    failures.push("exactly the current Proxmox human administrator is required during parity");
  }
  for (const account of proxmox.access.human_accounts) {
    if (serviceAccountNames.includes(account.name)) failures.push(`human account ${account.name} conflicts with a service account`);
    if (account.home !== `/home/${account.name}` || account.group !== account.name) {
      failures.push(`human account ${account.name} home and primary group must match its name`);
    }
    const expectedHumanKeyPaths = [`${account.home}/.ssh/authorized_keys`, `${account.home}/.ssh/authorized_keys2`];
    const humanKeyFilesValid = account.authorized_keys.files.length === expectedHumanKeyPaths.length &&
      account.authorized_keys.files.every((file, index) => file.path === expectedHumanKeyPaths[index] &&
        file.owner === account.name && file.group === account.group && file.mode === "0600" &&
        file.kind === "runtime-protected-file" && !file.projectable && file.materialization === "metadata-only");
    if (!account.password_lock || account.supplementary_groups.length || account.authorized_keys.state !== "absent" ||
        !humanKeyFilesValid || account.ssh_directory.path !== `${account.home}/.ssh` || account.ssh_directory.owner !== account.name ||
        account.ssh_directory.group !== account.group || account.ssh_directory.mode !== "0700" ||
        account.ssh_directory.kind !== "runtime-protected-directory" || account.ssh_directory.projectable) {
      failures.push(`human account ${account.name} must retain the locked Tailscale-SSH-only policy`);
    }
    if (account.sudo.state !== "present" || account.sudo.file.path !== `/etc/sudoers.d/${account.name}` ||
        account.sudo.rule !== `${account.name} ALL=(root) NOPASSWD: ALL`) {
      failures.push(`human account ${account.name} sudo policy must remain explicit and name-derived`);
    }
  }

  const pveAccounts = proxmox.access.pve.accounts;
  const additionalRoles = proxmox.access.pve.additional_roles;
  const roleNames = [...pveAccounts.map((account) => account.role), ...additionalRoles.map((role) => role.role)];
  const tokenIds = pveAccounts.map((account) => `${account.user}!${account.token_name}`);
  const tokenPaths = pveAccounts.map((account) => account.token_escrow.file.path);
  if (duplicates(roleNames).length) failures.push("PVE custom role names must be unique");
  if (duplicates(tokenIds).length) failures.push("PVE API token identities must be unique");
  if (duplicates(tokenPaths).length) failures.push("PVE API token escrow paths must be unique");
  const knownRoles = new Set(roleNames);
  const expectedPveAccounts = new Map([
    ["tofu-plan", { user: "root@pam", role: "HomeLabTofuPlan", additionalAcls: [`/vms/${proxmox.vm.vmid}\0HomeLabTofuPlanDiskInspect`] }],
    ["tofu-apply", { user: "root@pam", role: "HomeLabTofuApply", additionalAcls: [] }],
  ]);
  const planPrivilegeCeiling = new Set([
    "Datastore.Audit", "Mapping.Audit", "SDN.Audit", "Sys.Audit", "VM.Audit",
  ]);
  const applyPrivilegeCeiling = new Set([
    ...planPrivilegeCeiling,
    "Datastore.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate", "Mapping.Modify", "Mapping.Use", "SDN.Use", "Sys.Modify",
    "VM.Allocate", "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Cloudinit", "VM.Config.Disk",
    "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options", "VM.Migrate", "VM.PowerMgmt",
  ]);
  const inspectionPrivilegeCeiling = new Set(["VM.Audit", "VM.Config.Disk"]);
  if (pveAccounts.length !== expectedPveAccounts.size) failures.push("exactly two PVE API accounts are required");
  for (const account of pveAccounts) {
    if (!account.privilege_separation) failures.push(`PVE token ${account.user}!${account.token_name} must remain privilege-separated`);
    if (account.token_escrow.directory.path !== "/root/.config/home-lab" ||
        account.token_escrow.directory.owner !== "root" || account.token_escrow.directory.group !== "root" ||
        account.token_escrow.directory.mode !== "0700" || account.token_escrow.directory.kind !== "runtime-protected-directory" ||
        account.token_escrow.directory.projectable || account.token_escrow.directory.materialization !== "metadata-only" ||
        account.token_escrow.file.path !== `/root/.config/home-lab/proxmox-${account.token_name.replace(/^tofu-/, "")}-token.env` ||
        account.token_escrow.file.owner !== "root" || account.token_escrow.file.group !== "root" ||
        account.token_escrow.file.mode !== "0600" || account.token_escrow.file.kind !== "runtime-protected-file" ||
        account.token_escrow.file.projectable || account.token_escrow.file.materialization !== "metadata-only") {
      failures.push(`PVE token ${account.user}!${account.token_name} escrow path must remain in the protected credential directory`);
    }
    if (account.primary_acl_path !== "/") failures.push(`PVE token ${account.user}!${account.token_name} primary ACL must remain at root`);
    const privilegeCeiling = account.token_name === "tofu-plan" ? planPrivilegeCeiling : applyPrivilegeCeiling;
    const excessivePrivileges = outsideCapabilityCeiling(account.privileges, privilegeCeiling);
    if (excessivePrivileges.length) {
      failures.push(`PVE token role ${account.role} exceeds its privilege ceiling: ${excessivePrivileges.join(", ")}`);
    }
    const aclTuples = account.additional_acls.map((acl) => `${acl.path}\0${acl.role}`);
    const expectedAccount = expectedPveAccounts.get(account.token_name);
    if (!expectedAccount || expectedAccount.user !== account.user || expectedAccount.role !== account.role ||
        JSON.stringify(aclTuples) !== JSON.stringify(expectedAccount.additionalAcls)) {
      failures.push(`PVE token ${account.user}!${account.token_name} has an invalid role or ACL assignment`);
    }
    const aclPaths = account.additional_acls.map((acl) => acl.path);
    if (duplicates(aclTuples).length || duplicates(aclPaths).length) {
      failures.push(`PVE token ${account.user}!${account.token_name} contains duplicate ACLs`);
    }
    if (aclPaths.includes(account.primary_acl_path)) {
      failures.push(`PVE token ${account.user}!${account.token_name} repeats its primary ACL path`);
    }
    for (const acl of account.additional_acls) {
      if (!knownRoles.has(acl.role)) failures.push(`PVE ACL ${acl.path} references unknown role ${acl.role}`);
    }
  }
  const inspectionRoleNames = new Set(pveAccounts.flatMap((account) => account.additional_acls.map((acl) => acl.role)));
  if (additionalRoles.length !== 1 || !inspectionRoleNames.has(additionalRoles[0].role)) {
    failures.push("exactly the ACL-referenced VM inspection role is required");
  }
  for (const role of additionalRoles) {
    const excessivePrivileges = outsideCapabilityCeiling(role.privileges, inspectionPrivilegeCeiling);
    if (excessivePrivileges.length) {
      failures.push(`PVE inspection role ${role.role} exceeds its privilege ceiling: ${excessivePrivileges.join(", ")}`);
    }
  }

  const expectedAllowUsers = ["root", ...serviceAccountNames];
  if (JSON.stringify(proxmox.ssh.allow_users) !== JSON.stringify(expectedAllowUsers)) {
    failures.push("SSH allow-users must be root followed by the declared service accounts");
  }
  if (!proxmox.ssh.pubkey_authentication || proxmox.ssh.password_authentication || proxmox.ssh.kbd_interactive_authentication) {
    failures.push("Proxmox SSH authentication policy must remain key-only");
  }
  if (proxmox.ssh.permit_root_login !== "prohibit-password") failures.push("Proxmox root SSH must remain key-only");
  const hostKey = proxmox.ssh.host_key_sentinel;
  if (hostKey.path !== "/etc/ssh/ssh_host_ed25519_key" || hostKey.owner !== "root" || hostKey.group !== "root" ||
      hostKey.mode !== "0600" || hostKey.kind !== "runtime-protected-file" || hostKey.projectable ||
      hostKey.materialization !== "metadata-only") {
    failures.push("SSH host-key sentinel must remain root-only runtime-protected metadata");
  }

  if (proxmox.tailscale.hostname !== contract.network.proxmox.magicdns_name) failures.push("Proxmox Tailscale hostname must match MagicDNS");
  if (proxmox.tailscale.advertise_tag !== contract.tailscale.tags.proxmox) failures.push("Proxmox Tailscale tag must match tailnet policy");
  const selectedPackageNames = [...proxmox.packages.direct, ...proxmox.packages.critical].map((entry) => entry.name);
  if (!selectedPackageNames.includes(proxmox.tailscale.package)) failures.push("Tailscale package must be selected on Proxmox");
  if (proxmox.tailscale.auth_key_secret_ref !== "TAILSCALE_AUTH_KEY") failures.push("Proxmox Tailscale auth-key reference is invalid");
  if (proxmox.tailscale.advertise_routes.length) failures.push("Proxmox must not advertise subnet routes");
  if (proxmox.tailscale.accept_dns || proxmox.tailscale.accept_routes) failures.push("Proxmox must not accept tailnet DNS or routes");
  if (proxmox.tailscale.netfilter_mode !== "on" || !proxmox.tailscale.ssh) failures.push("Proxmox Tailscale netfilter and SSH policy must remain enabled");

  const expectedVfioAbsence = [
    ["matching-lines", "/etc/modules", "^\\s*(vfio|vfio_iommu_type1|vfio_pci|vfio_virqfd)(?:\\s*(?:#.*)?)?$"],
    ["matching-lines", "/etc/modules-load.d/modules.conf", "^\\s*(vfio|vfio_iommu_type1|vfio_pci|vfio_virqfd)(?:\\s*(?:#.*)?)?$"],
    ["file", "/etc/modprobe.d/vfio.conf", null],
  ];
  const vfioAbsence = proxmox.vfio.absence_policy.map((entry) => [entry.absence, entry.path, entry.pattern ?? null]);
  if (JSON.stringify(vfioAbsence) !== JSON.stringify(expectedVfioAbsence) ||
      proxmox.vfio.absence_policy.some((entry) => entry.kind !== "audit-absence" || !entry.projectable)) {
    failures.push("VFIO audit-absence policy must retain the exact legacy file and matching-line expectations");
  }

  const expectedVmStatus = proxmox.vm.started ? "running" : "stopped";
  if (proxmox.health.vm_status !== expectedVmStatus) {
    failures.push("health VM status must match the OpenTofu-owned VM started intent");
  }
  if (contract.storage.nfs.export !== contract.storage.zfs.mountpoint) {
    failures.push("NFS export must equal the protected ZFS dataset mountpoint");
  }

  const dockerHostAddress = contract.network.docker_host.ipv4.split("/")[0];
  const expectedFirewallRules = [
    ["IN", "ACCEPT", contract.network.cidr, "tcp", 22, "nolog"],
    ["IN", "ACCEPT", contract.network.cidr, "tcp", 8006, "nolog"],
    ["IN", "ACCEPT", `${dockerHostAddress}/32`, "tcp", 2049, "nolog"],
    ["IN", "ACCEPT", "0.0.0.0/0", "udp", 41641, "nolog"],
    ["IN", "ACCEPT", "100.64.0.0/10", "tcp", 22, "nolog"],
    ["IN", "ACCEPT", "100.64.0.0/10", "tcp", 8006, "nolog"],
  ];
  const firewallRules = proxmox.firewall.rules.map((rule) => [
    rule.direction,
    rule.action,
    rule.source,
    rule.protocol,
    rule.destination_port,
    rule.log,
  ]);
  if (JSON.stringify(firewallRules) !== JSON.stringify(expectedFirewallRules)) {
    failures.push("Proxmox firewall rules must match the reviewed management and NFS policy");
  }
  if (!proxmox.firewall.options.enable || proxmox.firewall.options.policy_in !== "DROP" || proxmox.firewall.options.policy_out !== "ACCEPT") {
    failures.push("Proxmox firewall must remain enabled with default-deny ingress");
  }
  if (proxmox.firewall.kind !== "api-owned" || proxmox.firewall.ownership !== "pve-api" ||
      proxmox.firewall.activation !== "pve-api" || proxmox.firewall.projectable) {
    failures.push("PVE firewall must remain non-projectable API-owned state");
  }

  const expectedUsbPortRefs = new Map([
    ["zigbee", "HOMELAB_ZIGBEE_USB_PORT"],
    ["zwave", "HOMELAB_ZWAVE_USB_PORT"],
  ]);
  const usbPortRefs = [];
  for (const [deviceName, expectedReference] of expectedUsbPortRefs) {
    const device = proxmox.vm.usb[deviceName];
    usbPortRefs.push(device.port_secret_ref);
    if (device.port_secret_ref !== expectedReference ||
        device.port_secret_ref !== device.serial_secret_ref.replace(/_SERIAL$/, "_PORT")) {
      failures.push(`${deviceName} USB port reference must be explicit and paired with its serial reference`);
    }
  }
  if (duplicates(usbPortRefs).length) failures.push("USB port secret references must be unique");

  function inspectPolicyRecords(value) {
    if (Array.isArray(value)) return value.forEach(inspectPolicyRecords);
    if (!value || typeof value !== "object") return;
    if (["managed-file", "managed-directory", "audit-absence"].includes(value.kind) && typeof value.path === "string" &&
        (value.path === "/etc/pve" || value.path.startsWith("/etc/pve/"))) {
      failures.push(`ordinary managed path ${value.path} must not enter PVE API-owned state`);
    }
    for (const nested of Object.values(value)) inspectPolicyRecords(nested);
  }
  inspectPolicyRecords(contract);

  return failures;
}

module.exports = { validateProxmoxHostPolicy };
