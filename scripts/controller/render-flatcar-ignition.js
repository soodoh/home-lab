#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contractPath = path.join(root, "infrastructure/contract/home-lab.yml");

function fail(message) {
  throw new Error(message);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || !value) fail(`invalid argument near ${flag ?? "end of command"}`);
    args[flag.slice(2)] = value;
  }
  const required = ["ssh-key-file", "runtime-env-file", "credentials-file", "compose-artifact-dir", "butane", "output-dir"];
  for (const name of required) {
    if (!args[name]) fail(`missing --${name}`);
  }
  return args;
}

function readRegularFile(filePath, label, maxBytes = 8 * 1024 * 1024) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (stat.size < 1 || stat.size > maxBytes) fail(`${label} has an unsafe size`);
  return fs.readFileSync(resolved);
}

function requirePrivateFile(filePath, label) {
  const mode = fs.lstatSync(path.resolve(filePath)).mode & 0o777;
  if ((mode & 0o077) !== 0) fail(`${label} must not be accessible by group or other users`);
}

function collectArtifactFiles(artifactDir) {
  const base = path.resolve(artifactDir);
  const baseStat = fs.lstatSync(base);
  if (!baseStat.isDirectory() || baseStat.isSymbolicLink()) fail("compose artifact must be a regular directory");
  const files = [];

  function walk(directory) {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const relative = path.relative(base, absolute);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) fail(`compose artifact contains a symlink: ${relative}`);
      if (stat.isDirectory()) {
        walk(absolute);
      } else if (stat.isFile()) {
        if (stat.size > 8 * 1024 * 1024) fail(`compose artifact file is too large: ${relative}`);
        files.push({
          relative,
          content: fs.readFileSync(absolute, "utf8"),
          mode: stat.mode & 0o111 ? 0o755 : 0o644,
        });
      } else {
        fail(`compose artifact contains a non-regular entry: ${relative}`);
      }
    }
  }

  walk(base);
  if (!files.some((entry) => entry.relative === "docker-compose.yml")) {
    fail("compose artifact is missing docker-compose.yml");
  }
  return files;
}

function inlineFile(filePath, mode, inline, options = {}) {
  return {
    path: filePath,
    mode,
    ...(options.userId === undefined ? {} : { user: { id: options.userId } }),
    ...(options.groupId === undefined ? {} : { group: { id: options.groupId } }),
    ...(options.overwrite === undefined ? {} : { overwrite: options.overwrite }),
    contents: { inline },
  };
}


function mountUnit({ description, what, where, type, options }) {
  return `[Unit]\nDescription=${description}\nAfter=network-online.target\nWants=network-online.target\nBefore=home-lab-compose.service\n\n[Mount]\nWhat=${what}\nWhere=${where}\nType=${type}\nOptions=${options.join(",")}\n\n[Install]\nWantedBy=multi-user.target\n`;
}

function buildButaneConfig(contract, inputs) {
  const key = inputs.sshAuthorizedKey.trim();
  if (!/^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+(?: .*)?$/.test(key)) fail("SSH public key is invalid");
  if (!inputs.runtimeEnvironment.endsWith("\n")) fail("runtime environment must end with a newline");
  if (inputs.runtimeEnvironment.includes("\u0000")) fail("runtime environment contains a NUL byte");
  for (const [label, serial] of [["Zigbee", inputs.zigbeeSerial], ["Z-Wave", inputs.zwaveSerial]]) {
    if (!/^[A-Za-z0-9._-]+$/.test(serial)) fail(`${label} serial identity is invalid`);
  }
  if (inputs.zigbeeSerial === inputs.zwaveSerial) fail("USB serial identities must be distinct");

  const vm = contract.vm_100;
  const flatcar = contract.flatcar;
  const stateDisk = contract.proxmox.vm.state_disk;
  const composeRoot = "/opt/home-lab/compose";
  const installerScript = [
    "#!/bin/bash",
    "set -euo pipefail",
    "",
    "install_verified() {",
    "  local destination=\"$1\" url=\"$2\" expected=\"$3\" mode=\"$4\" temporary",
    "  if [[ -f \"$destination\" ]] && [[ \"$(sha256sum \"$destination\" | awk '{print $1}')\" == \"$expected\" ]]; then",
    "    return",
    "  fi",
    "  temporary=\"$(mktemp)\"",
    "  if ! curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output \"$temporary\" \"$url\"; then",
    "    rm -f \"$temporary\"",
    "    return 1",
    "  fi",
    "  if ! printf '%s  %s\\n' \"$expected\" \"$temporary\" | sha256sum --check --status; then",
    "    rm -f \"$temporary\"",
    "    return 1",
    "  fi",
    "  install -m \"$mode\" \"$temporary\" \"$destination\"",
    "  rm -f \"$temporary\"",
    "}",
    "",
    `install_verified /opt/bin/docker-compose '${flatcar.compose.url}' '${flatcar.compose.sha256}' 0755`,
    `install_verified /opt/tailscale/tailscale.tgz '${flatcar.tailscale.url}' '${flatcar.tailscale.sha256}' 0600`,
    "extract_directory=\"$(mktemp -d)\"",
    "trap 'rm -rf \"$extract_directory\"' EXIT",
    "tar --extract --gzip --file=/opt/tailscale/tailscale.tgz --strip-components=1 --directory=\"$extract_directory\"",
    "install -m 0755 \"$extract_directory/tailscale\" /opt/bin/tailscale",
    "install -m 0755 \"$extract_directory/tailscaled\" /opt/bin/tailscaled",
    "",
  ].join("\n");
  const files = [
    inlineFile("/etc/hostname", 0o644, `${vm.network_identity}\n`, { overwrite: true }),
    inlineFile("/etc/systemd/network/10-home-lab.network", 0o644,
      `[Match]\nName=${flatcar.network_interface}\nMACAddress=${vm.networking.match_mac}\n\n[Network]\nAddress=${vm.networking.ipv4}\nGateway=${vm.networking.gateway}\nDNS=${vm.networking.dns.join(" ")}\nDHCP=no\nIPv6AcceptRA=no\n`),
    inlineFile("/etc/modules-load.d/home-lab-hardware.conf", 0o644, `${vm.hardware.kernel_modules.join("\n")}\n`),
    inlineFile("/etc/modprobe.d/home-lab-amdgpu.conf", 0o644, "options amdgpu runpm=0\n"),
    inlineFile("/etc/sysctl.d/90-home-lab-wolf.conf", 0o644,
      "fs.inotify.max_user_instances = 1024\nfs.inotify.max_user_watches = 1048576\nuser.max_user_namespaces = 28633\n"),
    inlineFile("/etc/udev/rules.d/70-home-lab-hardware.rules", 0o644,
      "KERNEL==\"uinput\", GROUP=\"input\", MODE=\"0660\"\nKERNEL==\"uhid\", GROUP=\"input\", MODE=\"0660\"\nSUBSYSTEM==\"tty\", ATTRS{idVendor}==\"10c4\", ATTRS{idProduct}==\"ea60\", GROUP=\"uucp\", MODE=\"0660\"\n"),
    inlineFile("/etc/udev/rules.d/71-home-lab-usb-serial.rules", 0o600,
      `SUBSYSTEM==\"tty\", ATTRS{idVendor}==\"10c4\", ATTRS{idProduct}==\"ea60\", ATTRS{serial}==\"${inputs.zigbeeSerial}\", SYMLINK+=\"zigbee\", GROUP=\"uucp\", MODE=\"0660\"\n` +
      `SUBSYSTEM==\"tty\", ATTRS{idVendor}==\"10c4\", ATTRS{idProduct}==\"ea60\", ATTRS{serial}==\"${inputs.zwaveSerial}\", SYMLINK+=\"zwave\", GROUP=\"uucp\", MODE=\"0660\"\n`),
    inlineFile("/etc/ssh/sshd_config.d/40-home-lab.conf", 0o600,
      "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowTcpForwarding no\nX11Forwarding no\n"),
    inlineFile("/etc/flatcar/update.conf", 0o644, "GROUP=stable\nREBOOT_STRATEGY=off\n", { overwrite: true }),
    inlineFile("/etc/docker-compose/production.env", 0o600, inputs.runtimeEnvironment),
    inlineFile("/opt/bin/home-lab-install-runtime-tools", 0o700, `${installerScript}\n`),
    ...inputs.composeFiles.map((entry) => inlineFile(path.posix.join(composeRoot, entry.relative.split(path.sep).join("/")), entry.mode, entry.content)),
  ];

  const directories = [
    { path: "/etc/docker-compose", mode: 0o700 },
    { path: "/home/docker/backups", mode: 0o750, user: { id: vm.workload_identity.uid }, group: { id: vm.workload_identity.gid } },
    { path: "/home/docker/.ssh", mode: 0o700, user: { id: vm.workload_identity.uid }, group: { id: vm.workload_identity.gid } },
    { path: "/mnt/games", mode: 0o755 },
    { path: "/mnt/storage", mode: 0o755 },
    { path: "/opt/bin", mode: 0o755 },
    { path: "/opt/home-lab/compose", mode: 0o755 },
    { path: "/opt/tailscale", mode: 0o700 },
    { path: stateDisk.mountpoint, mode: 0o755 },
  ];

  const stateMount = mountUnit({
    description: "Home lab application state",
    what: `/dev/disk/by-uuid/${stateDisk.filesystem_uuid}`,
    where: stateDisk.mountpoint,
    type: stateDisk.filesystem,
    options: stateDisk.mount_options,
  });
  const gamesMount = mountUnit({
    description: "Home lab games disk",
    what: `/dev/disk/by-uuid/${vm.storage.games.filesystem_uuid}`,
    where: vm.storage.games.mountpoint,
    type: vm.storage.games.filesystem,
    options: vm.storage.games.options,
  });
  const sharedMount = mountUnit({
    description: "Home lab shared storage",
    what: vm.storage.shared.source,
    where: vm.storage.shared.mountpoint,
    type: vm.storage.shared.filesystem,
    options: vm.storage.shared.options,
  });
  const runtimeToolsUnit = `[Unit]\nDescription=Install verified home lab runtime tools\nAfter=network-online.target\nWants=network-online.target\nBefore=tailscaled.service home-lab-compose.service\n\n[Service]\nType=oneshot\nExecStart=/opt/bin/home-lab-install-runtime-tools\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n`;
  const composeUnit = `[Unit]\nDescription=Home lab Docker Compose stack\nRequires=docker.service home-lab-runtime-tools.service\nAfter=docker.service home-lab-runtime-tools.service network-online.target srv-home\\x2dlab\\x2dstate.mount mnt-games.mount mnt-storage.mount\nWants=network-online.target\nRequiresMountsFor=${stateDisk.mountpoint} ${vm.storage.games.mountpoint} ${vm.storage.shared.mountpoint}\nConditionPathIsMountPoint=${stateDisk.mountpoint}\nConditionPathIsMountPoint=${vm.storage.games.mountpoint}\nConditionPathIsMountPoint=${vm.storage.shared.mountpoint}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nWorkingDirectory=${composeRoot}\nExecStartPre=/opt/bin/docker-compose --project-directory ${composeRoot} --env-file /etc/docker-compose/production.env -f ${composeRoot}/docker-compose.yml config --quiet\nExecStartPre=/opt/bin/docker-compose --project-directory ${composeRoot} --env-file /etc/docker-compose/production.env -f ${composeRoot}/docker-compose.yml pull --quiet\nExecStart=/opt/bin/docker-compose --project-directory ${composeRoot} --env-file /etc/docker-compose/production.env -f ${composeRoot}/docker-compose.yml up --detach --no-build --remove-orphans\nExecStop=/opt/bin/docker-compose --project-directory ${composeRoot} --env-file /etc/docker-compose/production.env -f ${composeRoot}/docker-compose.yml stop --timeout 60\nTimeoutStartSec=0\nTimeoutStopSec=180\n\n[Install]\nWantedBy=multi-user.target\n`;
  const tailscaleUnit = `[Unit]\nDescription=Tailscale node agent\nRequires=home-lab-runtime-tools.service\nAfter=home-lab-runtime-tools.service network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nExecStartPre=/usr/bin/mkdir -p /var/lib/tailscale\nExecStart=/opt/bin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n`;

  return {
    variant: flatcar.butane.config_variant,
    version: flatcar.butane.config_version,
    passwd: {
      users: [{
        name: "core",
        groups: ["docker", "input", "render", "uucp", "wheel"],
        ssh_authorized_keys: [key],
      }],
    },
    storage: { directories, files },
    systemd: {
      units: [
        { name: "docker.service", enabled: true },
        { name: "qemu-guest-agent.service", enabled: true },
        { name: "home-lab-runtime-tools.service", enabled: true, contents: runtimeToolsUnit },
        { name: "tailscaled.service", enabled: true, contents: tailscaleUnit },
        { name: "srv-home\\x2dlab\\x2dstate.mount", enabled: false, contents: stateMount },
        { name: "mnt-games.mount", enabled: false, contents: gamesMount },
        { name: "mnt-storage.mount", enabled: false, contents: sharedMount },
        { name: "home-lab-compose.service", enabled: false, contents: composeUnit },
      ],
    },
  };
}

function expectedButanePin(contract) {
  if (os.platform() === "darwin" && os.arch() === "arm64") {
    return { url: contract.flatcar.butane.darwin_aarch64_url, sha256: contract.flatcar.butane.darwin_aarch64_sha256 };
  }
  if (os.platform() === "linux" && os.arch() === "x64") {
    return { url: contract.flatcar.butane.linux_x86_64_url, sha256: contract.flatcar.butane.linux_x86_64_sha256 };
  }
  fail(`unsupported Butane controller platform: ${os.platform()}/${os.arch()}`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const contract = load(fs.readFileSync(contractPath, "utf8"));
  const butanePath = path.resolve(args.butane);
  const butane = readRegularFile(butanePath, "Butane binary", 256 * 1024 * 1024);
  const expectedPin = expectedButanePin(contract);
  if (sha256(butane) !== expectedPin.sha256) fail(`Butane binary digest does not match ${expectedPin.url}`);

  const sshAuthorizedKey = readRegularFile(args["ssh-key-file"], "SSH public key", 64 * 1024).toString("utf8");
  requirePrivateFile(args["runtime-env-file"], "runtime environment");
  requirePrivateFile(args["credentials-file"], "controller credentials");
  const runtimeEnvironment = readRegularFile(args["runtime-env-file"], "runtime environment").toString("utf8");
  const credentials = JSON.parse(readRegularFile(args["credentials-file"], "controller credentials").toString("utf8"));
  const zigbeeRef = contract.proxmox.vm.usb.zigbee.serial_secret_ref;
  const zwaveRef = contract.proxmox.vm.usb.zwave.serial_secret_ref;
  const composeFiles = collectArtifactFiles(args["compose-artifact-dir"]);
  const config = buildButaneConfig(contract, {
    sshAuthorizedKey,
    runtimeEnvironment,
    zigbeeSerial: credentials[zigbeeRef] ?? "",
    zwaveSerial: credentials[zwaveRef] ?? "",
    composeFiles,
  });

  const outputDir = path.resolve(args["output-dir"]);
  const reconcileRoot = path.join(root, ".reconcile");
  if (outputDir !== reconcileRoot && !outputDir.startsWith(`${reconcileRoot}${path.sep}`)) {
    fail("Flatcar output must remain under the protected .reconcile directory");
  }
  fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(outputDir, 0o700);

  const butaneConfig = `${JSON.stringify(config, null, 2)}\n`;
  const result = spawnSync(butanePath, ["--pretty", "--strict"], {
    input: butaneConfig,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) fail(`Butane rejected the generated config:\n${result.stderr.trim()}`);

  const configOutput = path.join(outputDir, "vm-100-flatcar.bu.json");
  const ignitionOutput = path.join(outputDir, "vm-100-flatcar.ign");
  fs.writeFileSync(configOutput, butaneConfig, { mode: 0o600 });
  fs.writeFileSync(ignitionOutput, result.stdout, { mode: 0o600 });
  fs.chmodSync(configOutput, 0o600);
  fs.chmodSync(ignitionOutput, 0o600);

  const manifest = {
    butane_version: contract.flatcar.butane.version,
    butane_sha256: expectedPin.sha256,
    compose_file_count: composeFiles.length,
    butane_config_sha256: sha256(Buffer.from(butaneConfig)),
    ignition_sha256: sha256(Buffer.from(result.stdout)),
    ignition_path: ignitionOutput,
  };
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`error: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { buildButaneConfig, collectArtifactFiles, expectedButanePin, mountUnit, parseArgs, sha256 };
