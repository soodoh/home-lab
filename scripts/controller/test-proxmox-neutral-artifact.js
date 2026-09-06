#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { build, sha256 } = require("./build-proxmox-ansible-observer");
const ROOT = path.resolve(__dirname, "../..");
const read = file => fs.readFileSync(path.join(ROOT, file));
const neutral = "infrastructure/host-lifecycle/proxmox/";
const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "neutral-artifact-test-"));
try {
  const first = path.join(dir, "first"), second = path.join(dir, "second");
  build(first); build(second);
  const expected = ["manifest.json", "observation-spec.json", "proxmox-controller-observer", "proxmox-observer", "proxmox-package-candidate-observer", "proxmox-protected-collector"].sort();
  assert.deepEqual(fs.readdirSync(first).sort(), expected);
  assert.deepEqual(fs.readdirSync(second).sort(), expected);
  for (const name of expected) {
    const source = path.join(first, name), info = fs.lstatSync(source);
    assert(info.isFile() && info.nlink === 1 && info.uid === process.getuid());
    assert.equal(info.mode & 0o777, name.endsWith(".json") ? 0o644 : 0o755);
    assert(fs.readFileSync(source).equals(fs.readFileSync(path.join(second, name))), `nondeterministic artifact: ${name}`);
    if (!name.endsWith(".json")) execFileSync("python3", ["-c", "import pathlib,sys;compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec')", source]);
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(first, "manifest.json")));
  assert.equal(manifest.controller_observer_sha256, sha256(fs.readFileSync(path.join(first, "proxmox-controller-observer"))));
  assert.equal(manifest.private_preparer_sha256, sha256(fs.readFileSync(path.join(first, "proxmox-protected-collector"))));
  assert.throws(() => build(path.join(dir, "bad"), "0".repeat(64)), /neutral source/);
  // Retained source evidence is read as bytes, never imported by the active path.
  for (const name of ["vfio-recover.py", "package-manifest.json", "package-manifest.schema.json"]) {
    assert(read(neutral + name).equals(read("nix/proxmox/" + name)), `retained asset parity differs: ${name}`);
  }
  assert(read("scripts/controller/controller_lock.py").equals(read("nix/proxmox/controller_lock.py")), "controller descriptor protocol changed");
  const active = ["scripts/reconcile-infrastructure", "scripts/local-controller", "scripts/controller/controller-apply-lock.py", "scripts/controller/proxmox-check-evidence.js",
    "scripts/controller/neutral-input.js", "scripts/controller/proxmox-ansible-audit.js", "scripts/controller/build-proxmox-ansible-observer.js", "scripts/controller/proxmox-host-projection.js"];
  for (const file of active) assert(!read(file).toString().includes("nix/proxmox"), `active Nix source import: ${file}`);
  execFileSync(process.execPath, [path.join(ROOT, "scripts/controller/test-proxmox-neutral-projection.js"), "--scan-path", first], { cwd: ROOT });
  // The same confidentiality scanner must fail on injected source/runtime identity.
  const injected = path.join(first, "forbidden.txt");
  fs.writeFileSync(injected, "HOMELAB_ZFS_POOL_GUID\n");
  assert.throws(() => execFileSync(process.execPath, [path.join(ROOT, "scripts/controller/test-proxmox-neutral-projection.js"), "--scan-path", first], { cwd: ROOT, stdio: "pipe" }));
  fs.unlinkSync(injected);
  console.log("neutral_artifact=passed deterministic_allowlist_source_and_output_confidentiality_asset_parity=true");
} finally { fs.rmSync(dir, { recursive: true, force: true }); }
