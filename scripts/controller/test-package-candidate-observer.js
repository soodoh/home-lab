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
# Exercise the actual proposal producer with every external command and package
# filesystem observation confined to fakes. Retained records are real fixtures;
# lslocks reports no holder, including after the rebooting process has exited.
from types import SimpleNamespace
from unittest.mock import patch
retained="/var/lib/home-lab/reconciliation/apply.lock"
mutex="/var/lib/home-lab/reconciliation/operation.lock"
def command(argv, timeout):
 assert argv[0] in ("/usr/bin/dpkg-query", "/usr/bin/apt-mark", "/usr/bin/apt-get", "/usr/bin/lslocks"), argv
 if argv[0] == "/usr/bin/apt-get": assert "--simulate" in argv
 return SimpleNamespace(returncode=0,stdout=b'{"locks":[]}' if argv[0] == "/usr/bin/lslocks" else b"",stderr=b"")
with tempfile.TemporaryDirectory() as directory:
 record=pathlib.Path(directory)/"record"
 actual_lexists=os.path.lexists
 def exists(candidate):
  return actual_lexists(record) if candidate == retained else candidate == mutex
 with patch.object(module,"run",side_effect=command), patch.object(module.os,"walk",return_value=[]), \
      patch.object(module,"file_tree",return_value={"sha256":"a"*64,"safe":True,"unsafe_paths":[]}), \
      patch.object(module.os.path,"lexists",side_effect=exists):
  for kind in ("absent","regular","dangling-symlink","fifo"):
   if kind == "regular": record.write_bytes(b"retained exact reboot owner\n")
   elif kind == "dangling-symlink": record.symlink_to("missing-target")
   elif kind == "fifo": os.mkfifo(record)
   for host in ("debian","proxmox"):
    proposal=module.observe(host)
    assert proposal["active_lifecycle_locks"] == ([] if kind == "absent" else [retained]), (kind,proposal)
    assert proposal["metadata_refresh_performed"] is False
   if kind != "absent":
    if kind == "regular": assert record.read_bytes() == b"retained exact reboot owner\n"
    record.unlink()
# APT 3.0.3 produces both [] and [fixture-app:arm64 ] after the version/origin
# tuple while ordering real dependency upgrades. Replay those exact synthetic
# forms through both existing parsers; no APT/native command is executed here.
activator={"__name__":"fixture_activator","__file__":sys.argv[2]}
activator_source=pathlib.Path(sys.argv[2]).read_text()
assert activator_source.count("\ntry:\n    main()") == 1
# Match the existing confined protocol harness: never run the stdin dispatcher.
activator_source=activator_source.split("\ntry:\n    main()")[0]
with patch.object(module.subprocess,"Popen",side_effect=AssertionError("subprocess forbidden during load")):
 exec(compile(activator_source,sys.argv[2],"exec"),activator)
def transition_command(argv, timeout=300):
 if argv[0] == "/usr/bin/apt-get":
  assert "--simulate" in argv
  return SimpleNamespace(returncode=0,stdout=solver_raw,stderr=b"")
 if argv[0] == "/usr/bin/dpkg-query": return SimpleNamespace(returncode=0,stdout=b"ii \tfixture-app\t1\n",stderr=b"")
 if argv[0] == "/usr/bin/apt-mark": return SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
 if argv[0] == "/usr/bin/dpkg": return SimpleNamespace(returncode=1,stdout=b"",stderr=b"")
 if argv[0] == "/usr/bin/apt-cache": return SimpleNamespace(returncode=0,stdout=b"  Candidate: 2\n",stderr=b"")
 if argv[0] == "/usr/bin/lslocks": return SimpleNamespace(returncode=0,stdout=b'{"locks":[]}',stderr=b"")
 raise AssertionError(argv)
def activation_command(argv, **kwargs):
 result=transition_command(argv)
 return SimpleNamespace(returncode=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode())
activator["native"]=activation_command
with patch.object(module,"run",side_effect=transition_command), patch.object(module.os,"walk",return_value=[]), \
     patch.object(module,"file_tree",return_value={"sha256":"a"*64,"safe":True,"unsafe_paths":[]}), \
     patch.object(module.os.path,"lexists",return_value=False), \
     patch.object(module.subprocess,"Popen",side_effect=AssertionError("native commands forbidden")):
 for suffix in ("", " []", " [fixture-app:arm64 ]", " [fixture-app:arm64 fixture-lib:arm64 ]"):
  for line, action in (("Inst fixture-app [1] (2 localhost [all])", "upgrade"),
                       ("Inst fixture-app (2 localhost [all])", "install"),
                       ("Remv fixture-app [1]", "remove")):
   solver_raw=(line+suffix+"\n").encode()
   proposal=module.observe("proxmox")
   expected={"action":action,"candidate_version":None if action == "remove" else "2",
             "name":"fixture-app","origin":"" if action == "remove" else "localhost [all]",
             "previous_version":None if action == "install" else "1","security":False}
   observed=dict(proposal["changes"][0]); observed.pop("policy_sha256")
   assert observed == expected,(solver_raw,observed)
   activated, solver_hash=activator["solver_changes"]()
   assert activated == [expected]
   assert solver_hash == module.digest(solver_raw)
   assert proposal["solver"]["stdout_sha256"] == module.digest(solver_raw)
 for line in ("Inst fixture-app [1] (2 localhost [all])", "Remv fixture-app [1]"):
  for suffix in (" garbage", " [] garbage", " [fixture-app:arm64 ] garbage", " [bad=name ]", " [unclosed"):
   solver_raw=(line+suffix+"\n").encode()
   try: module.observe("proxmox")
   except RuntimeError as error: assert str(error) == "unrecognized APT transition"
   else: raise AssertionError("observer accepted unknown transition suffix")
   try: activator["solver_changes"]()
   except ValueError as error: assert str(error) == "unrecognized APT solver transition"
   else: raise AssertionError("activator accepted unknown transition suffix")
print(json.dumps({"observer":"verified"},sort_keys=True))
`;
  const result = spawnSync("python3", ["-B", "-c", checks, renderedPath,
    path.join(root, "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator")], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { observer: "verified" });
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
console.log("package_candidate_observer=verified");
