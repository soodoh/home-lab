#!/usr/bin/env python3
"""Local render/task regressions; Ansible executes only synthetic identity assertions.

Run with Ansible's Jinja2/PyYAML environment and CLI available. No account modules,
Restic, or host connections run. This does not prove Linux namespaces or backup health.
"""

import configparser
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "ansible/roles/restic_backup"
JINJA = Environment(undefined=StrictUndefined, keep_trailing_newline=True, trim_blocks=True)


def load(path):
    return yaml.safe_load(path.read_text())


class ResticSystemdTests(unittest.TestCase):
    def setUp(self):
        self.host = load(ROOT / "ansible/inventory/host_vars/docker-host.yml")
        self.config = self.host["restic_systemd"]
        self.names = load(ROLE / "vars/main.yml")["restic_systemd_unit_names"]

    def unit(self, name):
        template = (ROLE / "templates" / f"{name}.j2").read_text()
        rendered = JINJA.from_string(template).render(restic_systemd=self.config)
        self.assertTrue(rendered.endswith("\n"))
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read_string(rendered)
        return {section: dict(parser[section]) for section in parser.sections()}

    def test_all_nine_units_have_exact_rendered_semantics(self):
        c = self.config
        common = dict(Type="oneshot", NoNewPrivileges="true", PrivateTmp="true", ProtectSystem="strict")
        local = dict(common, User="root", Group="root", UMask="0027", ProtectHome="read-only")
        proton = dict(
            common, User="restic-proton", Group="restic-proton", UMask="0077",
            TimeoutStartSec="12h", KillSignal="SIGINT", PrivateDevices="true", ProtectHome="true",
            ProtectKernelTunables="true", ProtectKernelModules="true", ProtectControlGroups="true",
            RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6", RestrictNamespaces="true",
            LockPersonality="true", MemoryDenyWriteExecute="true",
            InaccessiblePaths="/srv/home-lab-state /mnt/storage /home/docker /etc/docker-compose",
            TemporaryFileSystem="/mnt/games:ro", BindReadOnlyPaths=c["games_repository_path"],
            BindPaths=c["games_repository_path"] + "/locks", ReadOnlyPaths="/etc/home-lab/restic",
            ReadWritePaths="/var/lib/home-lab-restic/replication /var/lib/restic-proton " + c["lock_path"],
        )
        writable = (
            f"{c['games_mountpoint']}/restic {c['nfs_mountpoint']}/restic "
            f"/var/lib/home-lab-restic /var/cache/home-lab-restic {c['lock_path']}"
        )
        expected = {}
        for cadence in ("daily", "maintenance"):
            prefix = f"home-lab-restic-{cadence}"
            daily = cadence == "daily"
            expected[prefix + "-local.service"] = {
                "Unit": {
                    "Description": "Home Lab Restic " + (
                        "daily local snapshot and NFS copy" if daily else "monthly local maintenance"
                    ),
                    "RequiresMountsFor": c["games_mountpoint"] + ("" if daily else " " + c["nfs_mountpoint"]),
                    "After": "docker.service network-online.target" if daily else "network-online.target",
                    "Before": prefix + "-proton.service",
                    **({"Wants": "network-online.target"} if daily else {}),
                },
                "Service": dict(
                    local, ExecStart=c["runner_path"] + (" daily-local" if daily else " maintenance"),
                    TimeoutStartSec="8h" if daily else "12h", KillSignal="SIGINT",
                    ReadWritePaths=writable + (" /run/docker.sock" if daily else ""),
                    **({} if daily else {"Environment": "HOME_LAB_RESTIC_MAINTENANCE_SCOPE=local"}),
                ),
            }
            expected[prefix + "-proton.service"] = {
                "Unit": {
                    "Description": "Home Lab Restic " + ("daily Proton replication" if daily else "monthly Proton maintenance"),
                    "Requires": prefix + "-local.service",
                    "After": prefix + "-local.service network-online.target",
                    **({"ConditionPathExists": c["accepted_path"]} if daily else {}),
                },
                "Service": dict(
                    proton, ExecStart=c["runner_path"] + (" daily-proton" if daily else " maintenance"),
                    **({} if daily else {"Environment": "HOME_LAB_RESTIC_MAINTENANCE_SCOPE=proton"}),
                ),
            }
            chain = prefix + "-local.service " + prefix + "-proton.service"
            expected[prefix + ".target"] = {"Unit": {
                "Description": "Home Lab Restic " + ("chained daily workflow" if daily else "monthly maintenance workflow"),
                "Requires": chain, "After": chain, "StopWhenUnneeded": "yes",
            }}
            expected[prefix + ".timer"] = {
                "Unit": {"Description": (
                    "Schedule the Home Lab chained Restic daily workflow" if daily else "Schedule Home Lab Restic monthly maintenance"
                )},
                "Timer": {
                    "OnCalendar": c[cadence + "_calendar"], "Persistent": "false",
                    "RandomizedDelaySec": "0" if daily else "1h", "Unit": prefix + ".target",
                },
                "Install": {"WantedBy": "timers.target"},
            }
        expected["home-lab-restic-recover.service"] = {
            "Unit": {
                "Description": "Recover services interrupted by a Restic snapshot window",
                "After": "docker.service", "ConditionPathExists": c["journal_path"],
            },
            "Service": dict(
                local, ExecStart=c["runner_path"] + " preflight", TimeoutStartSec="15m",
                ReadWritePaths=f"/var/lib/home-lab-restic {c['lock_path']} /run/docker.sock",
            ),
            "Install": {"WantedBy": "multi-user.target"},
        }
        self.assertEqual(len(self.names), 9)
        self.assertEqual(set(self.names), set(expected))
        self.assertEqual({p.name.removesuffix(".j2") for p in (ROLE / "templates").glob("*.j2")}, set(expected))
        for name in self.names:
            with self.subTest(unit=name):
                self.assertEqual(self.unit(name), expected[name])

    def test_native_route_keeps_existing_host_render_and_reload_seam(self):
        play, = load(ROOT / "ansible/playbooks/configure-backups.yml")
        self.assertEqual(set(play), {"name", "hosts", "gather_facts", "gather_subset", "tasks"})
        self.assertEqual(play["hosts"], "docker-host")
        self.assertIs(play["gather_facts"], True)
        self.assertEqual(play["gather_subset"], ["!all", "min"])
        tools, identity, runtime, entry = play["tasks"]
        self.assertEqual(set(tools), {"name", "ansible.builtin.import_role"})
        self.assertEqual(tools["ansible.builtin.import_role"], {"name": "restic_backup", "tasks_from": "tools-native"})
        self.assertEqual(set(identity), {"name", "ansible.builtin.import_role"})
        self.assertEqual(identity["ansible.builtin.import_role"], {"name": "restic_backup", "tasks_from": "identity-native"})
        self.assertEqual(set(runtime), {"name", "ansible.builtin.import_role"})
        self.assertEqual(runtime["ansible.builtin.import_role"], {"name": "restic_backup", "tasks_from": "runtime-native"})
        self.assertEqual(set(entry), {"name", "ansible.builtin.import_role"})
        self.assertEqual(entry["ansible.builtin.import_role"], {"name": "restic_backup", "tasks_from": "systemd"})
        tasks = load(ROLE / "tasks/systemd.yml")
        actions = [[key for key in task if key.startswith("ansible.builtin.")] for task in tasks]
        self.assertEqual(actions, [["ansible.builtin." + action] for action in (
            "assert", "stat", "assert", "import_tasks", "systemd_service",
        )])
        allowed_keys = {"name", "register", "loop", "loop_control", "when"}
        for task, action in zip(tasks, actions):
            self.assertLessEqual(set(task), allowed_keys | set(action))
        self.assertEqual(tasks[0]["ansible.builtin.assert"]["that"], [
            "restic_systemd_existing_host | default(false) == true", "restic_systemd is defined",
        ])
        self.assertIs(self.host["restic_systemd_existing_host"], True)
        self.assertEqual(tasks[1]["ansible.builtin.stat"], {
            "path": "/etc/systemd/system/{{ item }}", "follow": False, "get_checksum": False, "get_mime": False,
        })
        self.assertEqual(tasks[1]["loop"], "{{ restic_systemd_unit_names }}")
        self.assertEqual(tasks[2]["loop"], "{{ restic_systemd_existing_units.results }}")
        self.assertEqual(tasks[2]["ansible.builtin.assert"]["that"], [
            "item.stat.isreg | default(false)", "not (item.stat.islnk | default(false))",
        ])
        self.assertEqual(tasks[3]["ansible.builtin.import_tasks"], "units.yml")
        self.assertEqual(tasks[4]["ansible.builtin.systemd_service"], {"daemon_reload": True})
        self.assertEqual(tasks[4]["when"], "restic_backup_units.changed")
        self.assertFalse((ROLE / "meta/main.yml").exists())
        self.assertFalse((ROLE / "handlers/main.yml").exists())
        self.assertFalse((ROLE / "defaults/main.yml").exists())
        self.assertEqual(set(load(ROLE / "vars/main.yml")), {"restic_systemd_unit_names"})

    def test_confined_identity_guards_and_declarations(self):
        tasks = load(ROLE / "tasks/identity-native.yml")
        self.assertEqual([[k for k in t if k.startswith("ansible.builtin.")] for t in tasks], [
            ["ansible.builtin.assert"], ["ansible.builtin.getent"],
            ["ansible.builtin.assert"], ["ansible.builtin.import_tasks"],
        ])
        self.assertEqual(tasks[1]["ansible.builtin.getent"], {
            "database": "{{ item }}", "key": "restic-proton", "fail_key": True,
        })
        self.assertEqual(tasks[1]["loop"], ["passwd", "group"])
        self.assertIs(tasks[1]["no_log"], True)
        self.assertEqual(tasks[3]["ansible.builtin.import_tasks"], "identity.yml")
        group, user = load(ROLE / "tasks/identity.yml")
        self.assertEqual(set(group), {"name", "ansible.builtin.group"})
        self.assertEqual(set(user), {"name", "ansible.builtin.user"})
        self.assertEqual(group["ansible.builtin.group"], {
            "name": "restic-proton", "gid": "{{ restic_proton_gid }}", "system": True, "state": "present",
        })
        self.assertEqual(user["ansible.builtin.user"], {
            "name": "restic-proton", "uid": "{{ restic_proton_uid }}", "group": "restic-proton",
            "groups": [], "append": False, "create_home": False, "home": "/var/lib/restic-proton",
            "shell": "/usr/sbin/nologin", "password_lock": True, "system": True, "state": "present",
        })
        self.assertEqual((self.host["restic_proton_uid"], self.host["restic_proton_gid"]), (60000, 60000))

        # Execute ONLY source assertion tasks with synthetic facts. No role imports,
        # getent, user/group modules, real accounts, or host connections are used.
        executable = shutil.which("ansible-playbook")
        if not executable:
            self.skipTest("Ansible CLI unavailable: identity assertions not executed")
        guards = [tasks[0], tasks[2]]
        for guard in guards:
            self.assertEqual(set(guard), {"name", "ansible.builtin.assert"})
        with tempfile.TemporaryDirectory(prefix="restic-identity-test-") as directory:
            workspace = Path(directory)
            cfg = workspace / "ansible.cfg"
            cfg.write_text("[defaults]\nretry_files_enabled=False\n")
            env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_NOCOLOR="1",
                       ANSIBLE_LOCAL_TEMP=str(workspace / "ansible-tmp"))
            for case in ("matching", "configured-uid", "configured-gid", "account-uid", "primary-gid",
                         "group-gid", "matching-wrong-ids", "missing-user", "missing-group"):
                facts = {
                    "getent_passwd": {"restic-proton": ["x", "60000", "60000", "", "/var/lib/restic-proton", "/usr/sbin/nologin"]},
                    "getent_group": {"restic-proton": ["x", "60000", ""]},
                }
                variables = {"restic_proton_uid": 60000, "restic_proton_gid": 60000, "ansible_facts": facts}
                if case.startswith("configured-"):
                    variables["restic_proton_" + case.split("-")[1]] = 59999
                elif case in ("account-uid", "primary-gid"):
                    facts["getent_passwd"]["restic-proton"][1 if case == "account-uid" else 2] = "59999"
                elif case == "group-gid":
                    facts["getent_group"]["restic-proton"][1] = "59999"
                elif case == "matching-wrong-ids":
                    variables.update(restic_proton_uid=59999, restic_proton_gid=59999)
                    facts["getent_passwd"]["restic-proton"][1:3] = ["59999", "59999"]
                    facts["getent_group"]["restic-proton"][1] = "59999"
                elif case.startswith("missing-"):
                    facts["getent_passwd" if case == "missing-user" else "getent_group"] = {}
                play = workspace / "guards.yml"
                play.write_text(yaml.safe_dump([{
                    "hosts": "localhost", "connection": "local", "gather_facts": False,
                    "become": False, "vars": variables, "tasks": guards,
                }]))
                with self.subTest(identity_case=case):
                    result = subprocess.run([executable, "-i", "localhost,", str(play)], env=env,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0 if case == "matching" else 2,
                                     result.stdout + result.stderr)

    def test_render_seam_is_shared_without_legacy_activation(self):
        render, = load(ROLE / "tasks/units.yml")
        self.assertEqual(set(render), {"name", "ansible.builtin.template", "loop", "register"})
        self.assertEqual(render["ansible.builtin.template"], {
            "src": "{{ item }}.j2", "dest": "/etc/systemd/system/{{ item }}",
            "owner": "root", "group": "root", "mode": "0644",
        })
        self.assertEqual(render["loop"], "{{ restic_systemd_unit_names }}")
        self.assertEqual(render["register"], "restic_backup_units")
        legacy = load(ROLE / "tasks/main.yml")  # Source parsing only: never run legacy main.
        self.assertEqual([task["ansible.builtin.import_tasks"] for task in legacy if "ansible.builtin.import_tasks" in task], ["tools.yml", "identity.yml", "inputs.yml", "runner.yml", "units.yml"])
        self.assertFalse(any("ansible.builtin.template" in task for task in legacy))
        bridge = load(ROOT / "ansible/group_vars/docker_host.yml")
        self.assertEqual(bridge["restic_systemd"], "{{ restic_systemd_legacy_contract }}")
        self.assertEqual(set(bridge["restic_systemd_legacy_contract"]), set(self.config))
        # Native configuration remains independent of legacy desired values and receipt hashes.
        native_source = (ROOT / "ansible/inventory/host_vars/docker-host.yml").read_text()
        self.assertNotIn("backups.", native_source)
        self.assertNotIn("lookup(", native_source)


if __name__ == "__main__":
    unittest.main()
