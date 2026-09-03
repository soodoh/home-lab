#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "../..");
const sourcePath = path.join(root, "infrastructure/maintenance/host/package-candidate-observer");
const source = fs.readFileSync(sourcePath, "utf8");
assert.equal((source.match(/@EXPECTED_PACKAGES_BASE64@/g) ?? []).length, 1);
for (const required of ["os.O_NOFOLLOW", "os.fstat", "st_nlink != 1", "apt-cache\", \"policy", "size_parse_complete",
  "apt_tree_safe", "active_lifecycle_locks", "Debug::NoLocking=1", "metadata_refresh_performed\": False"]) {
  assert(source.includes(required), `package observer omits ${required}`);
}
for (const forbidden of ['"update"', '"install"', '"remove"', "shell=True", "os.system", "Popen("]) {
  assert(!source.includes(`"/usr/bin/apt-get", ${forbidden}`), `package observer can mutate through ${forbidden}`);
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "package-observer-"));
try {
  const rendered = source.replace("@EXPECTED_PACKAGES_BASE64@", Buffer.from("[]").toString("base64"));
  const renderedPath = path.join(temporary, "observer.py");
  fs.writeFileSync(renderedPath, rendered, { mode: 0o755 });
  const checks = String.raw`
import importlib.util,json,os,pathlib,sys,tempfile
spec=importlib.util.spec_from_file_location("observer",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
assert module.parse_size("",[]) == (0,0,True)
assert module.parse_size("Need to get 1.5 MB of archives.\nAfter this operation, 2 kB of additional disk space will be used.\n",[{"name":"x"}]) == (1500000,2000,True)
assert module.parse_size("Need to get 1 kB of archives.\n",[{"name":"x"}]) == (1000,None,False)
assert module.parse_size("unexpected localized summary",[{"name":"x"}]) == (None,None,False)
with tempfile.TemporaryDirectory() as directory:
 path=pathlib.Path(directory); regular=path/"regular"; regular.write_text("value")
 unsafe_owner=module.file_tree((str(regular),)); assert unsafe_owner["safe"] is False
 link=path/"link"; link.symlink_to(regular)
 unsafe=module.file_tree((str(link),)); assert unsafe["safe"] is False
print(json.dumps({"observer":"verified"},sort_keys=True))
`;
  const result = spawnSync("python3", ["-c", checks, renderedPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { observer: "verified" });
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
console.log("package_candidate_observer=verified");
