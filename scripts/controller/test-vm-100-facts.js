#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { declaredVolumes, validateFacts } = require("./validate-vm-100-facts");

const commit = "a".repeat(40);
const declared = declaredVolumes();
assert.equal(declared.length, 30);
assert(declared.includes("openfit-data"));
const legacy = new Set(["happier-data", "nzbget-data", "nzbhydra2-data"]);
const volumeNames = [...new Set([...declared, ...legacy])].sort();
const rootEntries = [
  ["docker-volumes", "/var/lib/docker/volumes", "copy", "ext4", 29, "/dev/sda1", 100],
  ["home-assistant", "/home/docker/hass", "copy", "ext4", 29, "/dev/sda1", 10],
  ["compose-deployment", "/srv/docker-compose", "regenerate", "ext4", 29, "/dev/sda1", null],
  ["compose-runtime-inputs", "/etc/docker-compose", "regenerate", "ext4", 29, "/dev/sda1", null],
  ["compose-controller-state", "/var/lib/docker-compose", "regenerate", "ext4", 29, "/dev/sda1", null],
  ["home-backups", "/home/docker/backups", "pending", "ext4", 29, "/dev/sda1", 1],
  ["games-backups", "/mnt/games/backups", "pending", "ext4", 30, "/dev/sdb1", 1],
  ["storage-backups", "/mnt/storage/backups", "pending", "nfs4", 31, "192.0.2.1:/storage/docker", 1],
  ["media", "/mnt/storage/media", "reuse", "nfs4", 31, "192.0.2.1:/storage/docker", null],
  ["games", "/mnt/games", "reuse", "ext4", 30, "/dev/sdb1", null],
  ["wolf", "/mnt/games/wolf", "reuse", "ext4", 30, "/dev/sdb1", 10],
];
const facts = {
  applications: ["authentik", "sonarr", "radarr", "radarr-4k", "prowlarr"].map((name) => ({ importIdentifiers: [], inventoryStatus: "pending", name })),
  authority: { deploymentAuthority: "arch", hostName: "archlinux", networkIdentity: "docker-host", vmid: 100 },
  capturedAt: "2026-08-12T00:00:00Z",
  controllerCommit: commit,
  docker: {
    backingFilesystem: "extfs",
    declaredVolumeCount: 30,
    legacyVolumeCount: 3,
    observedProjectVolumeCount: 33,
    projectName: "docker-compose",
    rootDir: "/var/lib/docker",
    storageDriver: "overlay2",
    volumes: volumeNames.map((logicalName) => ({
      driver: "local",
      engineName: `docker-compose_${logicalName}`,
      legacy: legacy.has(logicalName),
      logicalName,
      mountpoint: `/var/lib/docker/volumes/docker-compose_${logicalName}/_data`,
    })),
  },
  findings: [
    { code: "application-import-identifiers-pending", message: "Application import identifiers remain pending.", severity: "blocker" },
    { code: "independent-recovery-recipient-pending", message: "Independent recovery recipient remains pending.", severity: "blocker" },
    { code: "nixos-recipient-pending", message: "NixOS runtime recipient remains pending.", severity: "blocker" },
  ],
  format: "home-lab-vm-100-facts-v1",
  identity: { gid: 1000, home: "/home/docker", primaryGroup: "docker", shell: "/bin/bash", supplementaryGroups: ["docker"], uid: 1000, user: "docker" },
  mutableRoots: rootEntries.map(([classification, path, disposition, filesystem, mountId, source, sizeBytes]) => ({
    bytesAvailable: 500,
    bytesTotal: 1000,
    class: classification,
    disposition,
    exists: true,
    filesystem,
    filesystemFeatures: filesystem === "ext4" ? ["extent"] : [],
    multiplyLinkedFileCount: disposition === "copy" ? 0 : null,
    gid: 0,
    mode: "0755",
    mountId,
    mountOptions: ["rw"],
    path,
    sizeBytes,
    source,
    uid: 0,
  })),
  sops: {
    identityGroup: "root",
    identityMode: "0600",
    identityOwner: "root",
    identityPath: "/etc/sops/age/keys.txt",
    independentRecoveryRecipient: false,
    nixosRecipientStatus: "pending",
    recipient: "age1vvzm5pczjum52v5alall8euucjen9q4v9xa5g0xmswhna5vare9qwv9rq6",
    roles: ["arch-runtime-decrypt", "externally-escrowed-recovery"],
  },
};

validateFacts(structuredClone(facts), commit);

for (const mutate of [
  (value) => { value.identity.uid = 1001; },
  (value) => { value.docker.volumes.pop(); value.docker.observedProjectVolumeCount = 32; },
  (value) => { value.docker.volumes[0].legacy = !value.docker.volumes[0].legacy; },
  (value) => { [value.docker.volumes[0].engineName, value.docker.volumes[1].engineName] = [value.docker.volumes[1].engineName, value.docker.volumes[0].engineName]; },
  (value) => { value.docker.volumes[0].mountpoint = value.docker.volumes[1].mountpoint; },
  (value) => { value.mutableRoots[0].path = "/var/lib/docker"; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "games").filesystem = "xfs"; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "home-backups").sizeBytes = null; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "media").sizeBytes = 1; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "games").filesystemFeatures = []; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "games-backups").mountId = 99; },
  (value) => { value.mutableRoots.find((entry) => entry.class === "storage-backups").source = "192.0.2.2:/storage/docker"; },
  (value) => { value.sops.recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"; },
  (value) => { value.sops.privateIdentity = "AGE-SECRET-KEY"; },
  (value) => { value.applications[0].inventoryStatus = "complete"; },
  (value) => { value.findings.pop(); },
  (value) => { value.findings[0].severity = "warning"; },
]) {
  const invalid = structuredClone(facts);
  mutate(invalid);
  assert.throws(() => validateFacts(invalid, commit));
}

console.log("vm_100_facts_tests=passed");
