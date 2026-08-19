#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "infrastructure/debian/rehearse-storage-readonly.sh"), "utf8");
const coordinator = fs.readFileSync(path.join(root, "scripts/qualify-debian-inert"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-debian-storage-rehearsal"), "utf8");
const finalizer = fs.readFileSync(path.join(root, "scripts/finalize-debian-storage-rehearsal"), "utf8");
const rehearsal = contract.debian.cutover.storage_rehearsal;

assert.equal(contract.debian.cutover.stage, "packages-prepared");
assert.equal(rehearsal.mode, "read-only");
assert.equal(rehearsal.isolated_mount_root, "/run/home-lab-storage-rehearsal");
assert.deepEqual(rehearsal.ext4_options, ["ro", "noload", "nodev", "nosuid", "noexec"]);
assert.equal(rehearsal.nfs_source, "192.168.0.123:/storage/docker");
assert.deepEqual(rehearsal.nfs_options, ["ro", "nodev", "nosuid", "noexec", "vers=4.2"]);
assert.ok(script.includes(`readonly STATE_MIN_AVAILABLE_BYTES=${rehearsal.state_min_available_bytes}`));
assert.ok(script.includes(`readonly GAMES_MIN_AVAILABLE_BYTES=${rehearsal.games_min_available_bytes}`));
assert.ok(script.includes(`readonly NFS_MIN_AVAILABLE_BYTES=${rehearsal.nfs_min_available_bytes}`));
for (const name of [...rehearsal.expected_state_directories, ...rehearsal.expected_games_directories, ...rehearsal.expected_nfs_directories]) {
  assert.ok(script.includes(name), `missing rehearsal directory ${name}`);
}
assert.match(script, /mount -t ext4 -o ro,noload,nodev,nosuid,noexec "\$state_device" "\$STATE_MOUNT"/);
assert.match(script, /mount -t ext4 -o ro,noload,nodev,nosuid,noexec "\$games_device" "\$GAMES_MOUNT"/);
assert.match(script, /mount -t nfs4 -o ro,nodev,nosuid,noexec,vers=4\.2,hard,timeo=600,retrans=2/);
assert.match(script, /FS-OPTIONS.*grep -Exq 'noload\|norecovery'/);
assert.match(script, /VFS-OPTIONS.*grep -Fxq ro/);
assert.match(script, /journalctl -k --after-cursor/);
assert.match(script, /EXT4-fs.*error.*NFS.*error.*I\/O error/);
assert.match(script, /verify_owner_manifest/);
assert.match(script, /docker-disabled-containerd-masked-inactive/);
assert.match(script, /\[\[ ! -e \/etc\/home-lab\/allow-storage-activation \]\]/);
assert.doesNotMatch(script, /docker compose (?:up|create|start)|systemctl (?:start|enable).*docker|tailscale up|sops decrypt|mount -o rw|mount .*\/srv\/home-lab-state|mount .*\/mnt\/games/);
const trapIndex = script.indexOf("trap unmount_rehearsal EXIT");
const firstMountIndex = script.indexOf("mount -t ext4");
const unmountIndex = script.indexOf('umount "$NFS_MOUNT"', firstMountIndex);
const markerIndex = script.indexOf('mv -T "$temporary" "$MARKER"');
assert.ok(trapIndex > 0 && trapIndex < firstMountIndex);
assert.ok(firstMountIndex < unmountIndex && unmountIndex < markerIndex);
assert.match(script, /for target in "\$STATE_MOUNT" "\$GAMES_MOUNT" "\$NFS_MOUNT"; do[\s\S]*! mountpoint -q/);

assert.ok(coordinator.includes("rehearsal_sha=c7ee3b85a274a56e2285a0819f004bb7dcc65330589982c207b8ecdae5126a9e"));
assert.match(coordinator, /games_volume_path=\$\{EFFECTIVE_SCSI1%%,\*\}/);
assert.match(coordinator, /blockdev --getsize64 "\$games_volume_device"\) -eq 4000787030016/);
assert.match(coordinator, /stage=verify-exclusive-protected-storage[\s\S]*fuser "\$protected_device"/);
assert.match(coordinator, /write_rehearsal_pending_evidence "\$rehearsal_marker"/);
assert.match(coordinator, /mark_rehearsal_evidence_awaiting_reboot "\$arch_reboot_config_sha"/);
assert.match(coordinator, /home-lab-debian-storage-transition-v1/);
assert.match(coordinator, /finalize_rehearsal_mode == true/);
assert.match(coordinator, /verify_arch_post_restore[\s\S]*mv -T "\$finalize_evidence" "\$REHEARSAL_LOG"/);
assert.ok(runner.includes("readonly CONFIRMATION=rehearse-reviewed-vm-100-debian-storage-readonly"));
assert.ok(finalizer.includes("readonly CONFIRMATION=finalize-reviewed-vm-100-debian-storage-after-reboot"));
for (const wrapper of [runner, finalizer]) {
  assert.match(wrapper, /\[\[ -t 0 \]\]/);
  assert.match(wrapper, /exec "\$root\/scripts\/qualify-debian-inert"/);
}

process.stdout.write("debian storage rehearsal tests passed\n");
