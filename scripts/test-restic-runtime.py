#!/usr/bin/env python3
"""Source-route checks and real local Ansible assertions with synthetic stat/policy.

Never imports a role or runs stat/slurp/copy/account/service modules. The only file
lookups read isolated copies of the three repo sources, never production policy.
This tests guards, not actual native copy/install behavior or backup health.
"""

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parent.parent
TASKS = ROOT / "ansible/roles/restic_backup/tasks"
SOURCES = ["scripts/restic-backup", "services/data/restic/files-from", "services/data/restic/excludes"]
DESTINATIONS = ["/usr/local/libexec/home-lab/restic-backup", "/etc/home-lab/restic/files-from", "/etc/home-lab/restic/excludes"]


def load(path):
    return yaml.safe_load(path.read_text())


class ResticRuntimeTests(unittest.TestCase):
    def test_native_scope_and_shared_declarations(self):
        tasks = load(TASKS / "runtime-native.yml")
        self.assertEqual([[k for k in t if k.startswith("ansible.builtin.")] for t in tasks], [
            ["ansible.builtin." + action] for action in
            ("stat", "assert", "stat", "assert", "slurp", "assert", "assert", "assert",
             "assert", "stat", "assert", "import_tasks", "import_tasks")
        ])
        for task in tasks:
            self.assertLessEqual(set(task), {"name", "register", "loop", "loop_control", "vars", "no_log"} |
                                 {k for k in task if k.startswith("ansible.builtin.")})
        self.assertEqual(tasks[0]["loop"], ["/", "/etc", "/etc/home-lab", "/etc/home-lab/restic",
                                          "/usr", "/usr/local", "/usr/local/libexec", "/usr/local/libexec/home-lab"])
        for index in (0, 2, 9):
            self.assertIs(tasks[index]["ansible.builtin.stat"]["follow"], False)
            self.assertIs(tasks[index]["ansible.builtin.stat"]["get_mime"], False)
        self.assertEqual(tasks[2]["ansible.builtin.stat"]["path"], "/etc/home-lab/restic-policy.json")
        self.assertEqual(tasks[4]["ansible.builtin.slurp"], {"src": "/etc/home-lab/restic-policy.json"})
        self.assertIs(tasks[4]["no_log"], True)
        self.assertIs(tasks[5]["no_log"], True)
        self.assertEqual(tasks[9]["ansible.builtin.stat"]["checksum_algorithm"], "sha256")
        expected = [{"src": "{{ playbook_dir }}/../../" + src, "dest": dest}
                    for src, dest in zip(SOURCES, DESTINATIONS)]
        self.assertEqual(tasks[9]["loop"], expected)
        self.assertEqual([t["ansible.builtin.import_tasks"] for t in tasks[11:]], ["inputs.yml", "runner.yml"])
        desired = json.loads((ROOT / "services/data/restic/policy.json").read_text())
        self.assertFalse({"qualification", "initialization", "first_run", "credentials", "credential_refs"} & set(desired))
        self.assertEqual(hashlib.sha256((ROOT / "scripts/restic-backup").read_bytes()).hexdigest(),
                         desired["runner"]["sha256"])
        self.assertEqual((ROOT / "services/data/restic/files-from").read_text().splitlines(),
                         [entry["path"] for entry in desired["sources"]])
        self.assertEqual((ROOT / "services/data/restic/excludes").read_text().splitlines(), desired["excludes"])
        self.assertNotIn("backups.", (TASKS / "runtime-native.yml").read_text())
        inputs, = load(TASKS / "inputs.yml")
        runner, = load(TASKS / "runner.yml")
        self.assertEqual(set(inputs), {"name", "ansible.builtin.copy", "loop"})
        self.assertEqual(set(runner), {"name", "ansible.builtin.copy", "loop"})
        self.assertEqual(inputs["ansible.builtin.copy"], {
            "src": "{{ item.src }}", "dest": "{{ item.dest }}", "owner": "root", "group": "restic-proton", "mode": "0440",
        })
        self.assertEqual(inputs["loop"], expected[1:])
        self.assertEqual(runner["ansible.builtin.copy"], {
            "src": "{{ item.src }}", "dest": "{{ item.dest }}", "owner": "root",
            "group": "{{ item.group | default('root') }}", "mode": "{{ item.mode }}",
        })
        self.assertEqual(runner["loop"], [dict(expected[0], mode="0755")])
        self.assertFalse((TASKS / "main.yml").exists())
        for retired in (
            "initialize-restic-repositories", "run-first-restic-backup", "qualify-proton-backup"
        ):
            self.assertFalse((ROOT / "scripts" / retired).exists())

    def test_runtime_native_assertions_fail_closed(self):
        executable = shutil.which("ansible-playbook")
        if not executable:
            self.skipTest("Ansible CLI unavailable: runtime assertions not executed")
        tasks = load(TASKS / "runtime-native.yml")
        guards = [tasks[i] for i in (1, 3, 8, 10)]
        self.assertTrue(all("ansible.builtin.assert" in task for task in guards))
        originals = [(ROOT / src).read_bytes() for src in SOURCES]
        cases = ["matching", "metadata-only", "systemd-path", "malformed-policy", "missing-policy-content"]
        cases += ["binding-" + key for key in ("path", "policy_path", "files_from_path", "exclude_file_path")]
        cases += ["source-" + str(i) for i in range(3)]
        cases += [f"file-{i}-{fault}" for i in range(3) for fault in ("missing", "type", "symlink", "hardlink", "checksum", "owner", "group-write", "other-write")]
        cases += ["ancestor-" + fault for fault in ("missing", "type", "symlink", "owner", "group-write", "other-write")]
        cases += ["policy-" + fault for fault in ("missing", "type", "symlink", "hardlink", "owner", "group-write", "other-write")]
        with tempfile.TemporaryDirectory(prefix="restic-runtime-test-") as directory:
            workspace = Path(directory)
            play = workspace / "ansible/playbooks/guards.yml"
            play.parent.mkdir(parents=True)
            cfg = workspace / "ansible.cfg"
            cfg.write_text("[defaults]\nretry_files_enabled=False\n")
            env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_NOCOLOR="1",
                       ANSIBLE_LOCAL_TEMP=str(workspace / "ansible-tmp"))
            for case in cases:
                for src, content in zip(SOURCES, originals):
                    path = workspace / src
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                policy = {
                    "runner": dict(zip(("path", "policy_path", "files_from_path", "exclude_file_path"),
                                       (DESTINATIONS[0], "/etc/home-lab/restic-policy.json", *DESTINATIONS[1:])),
                                   sha256=hashlib.sha256(originals[0]).hexdigest()),
                    "sources": [{"path": p} for p in originals[1].decode().splitlines()],
                    "excludes": originals[2].decode().splitlines(),
                    "private_fixture_marker": "SENSITIVE_RUNTIME_FIXTURE",
                }
                regular = {"exists": True, "isreg": True, "islnk": False, "nlink": 1, "uid": 0, "mode": "0440"}
                variables = {
                    "restic_systemd": {"runner_path": DESTINATIONS[0]},
                    "restic_runtime_ancestors": {"results": [
                        {"item": path, "stat": {"isdir": True, "islnk": False, "uid": 0, "mode": "0755"}}
                        for path in tasks[0]["loop"]]},
                    "restic_runtime_policy_file": {"stat": deepcopy(regular)},
                    "restic_runtime_files": {"results": [
                        {"item": {"src": str(workspace / src), "dest": dest},
                         "stat": dict(regular, checksum=hashlib.sha256(content).hexdigest())}
                        for src, dest, content in zip(SOURCES, DESTINATIONS, originals)]},
                }
                if case == "metadata-only":
                    for result in variables["restic_runtime_files"]["results"]:
                        result["stat"].update(gid=123, mode="0600")
                elif case == "systemd-path":
                    variables["restic_systemd"]["runner_path"] = "/wrong"
                elif case.startswith("binding-"):
                    policy["runner"][case.removeprefix("binding-")] = "/wrong"
                elif case.startswith("source-"):
                    i = int(case[-1])
                    changed = originals[i] + b"unexpected-source-line\n"
                    (workspace / SOURCES[i]).write_bytes(changed)
                    # Even source=installed drift must fail against the installed policy.
                    variables["restic_runtime_files"]["results"][i]["stat"]["checksum"] = hashlib.sha256(changed).hexdigest()
                elif case.startswith(("file-", "ancestor-", "policy-")):
                    if case.startswith("file-"):
                        _, i, fault = case.split("-", 2)
                        stat = variables["restic_runtime_files"]["results"][int(i)]["stat"]
                    elif case.startswith("ancestor-"):
                        fault = case.removeprefix("ancestor-")
                        stat = variables["restic_runtime_ancestors"]["results"][-1]["stat"]
                    else:
                        fault = case.removeprefix("policy-")
                        stat = variables["restic_runtime_policy_file"]["stat"]
                    if fault == "missing":
                        stat.clear()
                        stat["exists"] = False
                    else:
                        stat.update({
                            "type": {"isreg": False, "isdir": False}, "symlink": {"islnk": True},
                            "hardlink": {"nlink": 2}, "owner": {"uid": 123},
                            "group-write": {"mode": "0770"}, "other-write": {"mode": "0757"},
                            # Removing only the trailing newline proves hashing does not strip it.
                            "checksum": {"checksum": hashlib.sha256(originals[int(i)].rstrip(b"\n")).hexdigest()}
                            if case.startswith("file-") else {},
                        }[fault])
                content = json.dumps(policy) if case != "malformed-policy" else "SENSITIVE_RUNTIME_FIXTURE{"
                variables["restic_runtime_policy"] = {"content": base64.b64encode(content.encode()).decode()}
                if case == "missing-policy-content":
                    variables["restic_runtime_policy"] = {}
                play.write_text(yaml.safe_dump([{
                    "hosts": "localhost", "connection": "local", "gather_facts": False,
                    "become": False, "vars": variables, "tasks": guards,
                }]))
                with self.subTest(runtime_case=case):
                    result = subprocess.run([executable, "-i", "localhost,", str(play)], env=env,
                                            capture_output=True, text=True, timeout=30)
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0 if case in ("matching", "metadata-only") else 2, output)
                    self.assertNotIn("SENSITIVE_RUNTIME_FIXTURE", output)
                    if case.startswith(("binding-", "source-")) or case in ("systemd-path", "malformed-policy", "missing-policy-content"):
                        self.assertIn("censored", output)
        print(f"runtime_native_assertions={len(cases)} cases; assertion-only, no install effects")


if __name__ == "__main__":
    unittest.main()
