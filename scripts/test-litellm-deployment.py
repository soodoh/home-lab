#!/usr/bin/env python3
"""Offline vertical tests; synthetic OS/process effects never qualify a live host."""
import copy
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
import subprocess
import time
import shutil
import sys
import re
from types import SimpleNamespace


@contextmanager
def workspace():
    path = Path(tempfile.mkdtemp(prefix="litellm-test-", dir=os.environ["LITELLM_TEST_SCRATCH"]))
    try:
        yield str(path)
    finally:
        # Fixtures exercise native artifact modes while running; retain their bytes privately afterwards.
        for entry in path.rglob("*"):
            if not entry.is_symlink():
                entry.chmod(0o700 if entry.is_dir() else 0o600)
        path.chmod(0o700)  # No cleanup, including on failed tests.


def save(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


REAL_RUN = subprocess.run


def source_git(command, **kwargs):
    if command[:3] == ["git", "rev-parse", "HEAD"] or command[:3] == ["git", "rev-parse", "origin/main"]:
        return subprocess.CompletedProcess(command, 0, "a" * 40 + "\n", "")
    if command[:2] == ["git", "status"]:
        return subprocess.CompletedProcess(command, 0, "", "")
    if command[:2] == ["git", "ls-files"]:
        return REAL_RUN(command, **kwargs)
    raise AssertionError("unexpected external operation: " + repr(command))
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("litellm_deployment", ROOT / "scripts/litellm-deployment.py")


def load():
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    return module


class NativeSnapshotJobTests(unittest.TestCase):
    def check_job_gate(self, output=None, returncode=0, refusal=None):
        m = load()
        calls = []
        daemon_argv = ["/usr/bin/systemctl", "show", "docker.service",
                       "--property=ActiveState,SubState,MainPID"]
        jobs_argv = ["/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager"]

        def run(command, **kwargs):
            calls.append(command)
            if command == daemon_argv:
                return subprocess.CompletedProcess(command, 0,
                    "MainPID=12\nSubState=running\nActiveState=active\n", "")
            self.assertEqual(command[:2], jobs_argv[:2])
            # systemd list-jobs prints plaintext; --no-legend suppresses the idle message.
            stdout = output if output is not None else ("" if "--no-legend" in command else "No jobs running.\n")
            return subprocess.CompletedProcess(command, returncode, stdout, "")

        class ReachedArtifacts(Exception):
            pass

        host = m.NativeHost(ROOT, run, ROOT)
        with patch.object(host, "conflicts") as conflicts, \
                patch.object(host, "artifact", side_effect=ReachedArtifacts) as artifact:
            if refusal is None:
                with self.assertRaises(ReachedArtifacts):
                    host.snapshot({}, {})
                artifact.assert_called_once_with(m.CURRENT)
            else:
                with self.assertRaises(SystemExit) as raised:
                    host.snapshot({}, {})
                self.assertEqual(str(raised.exception), refusal)
                artifact.assert_not_called()
            conflicts.assert_called_once_with(None)
        # Exact all-jobs argv: no filters, JSON output flag, Docker call or retry.
        self.assertEqual(calls, [daemon_argv, jobs_argv])

    def test_snapshot_documented_no_jobs_reaches_artifact_boundary(self):
        self.check_job_gate()

    def test_snapshot_queued_job_row_refuses_without_exposing_output(self):
        self.check_job_gate("123 example.service start waiting\n",
                            refusal="systemd job output is nonempty (queued work or unexpected output)")

    def test_snapshot_unexpected_text_json_and_whitespace_refuse(self):
        for output in ("unexpected text\n", "No jobs running.\n", "[]", "[]\n", " ", "\n", "\t\r\n"):
            with self.subTest(output=repr(output)):
                self.check_job_gate(output,
                                    refusal="systemd job output is nonempty (queued work or unexpected output)")

    def test_snapshot_failed_job_command_refuses_even_with_empty_stdout(self):
        self.check_job_gate("", returncode=1,
                            refusal="native command failed (output suppressed); retain ownership, no retry")


class OperatorTests(unittest.TestCase):
    def test_plan_rejects_refused_partial_capture_without_external_effects(self):
        m = load()
        with workspace() as directory:
            root = Path(directory)
            capture = root / "capture.json"
            capture.write_text(json.dumps({"status": "refused", "partial": True}))
            capture.chmod(0o600)
            with patch("subprocess.run", side_effect=AssertionError("offline plan invoked external authority")):
                with self.assertRaisesRegex(SystemExit, "successful attended capture"):
                    m.main(["plan", "--capture", str(capture), "--output", str(root / "plan.json")])

    def test_config_only_plan_binds_source_before_state_and_forces_only_litellm(self):
        m = load()
        with workspace() as directory, patch("subprocess.run", side_effect=source_git):
            root = Path(directory)
            known = root / "known-hosts"
            known.write_text("docker-host ssh-ed25519 independently-established-test-key\n")
            request_path = root / "request.json"
            m.main(["request", "--known-hosts", str(known), "--output", str(request_path)])
            request = json.loads(request_path.read_bytes())
            state = {"current": copy.deepcopy(request["artifact"]), "current_sha256": "b" * 64,
                     "host": {"hostname": "docker-host", "machine_id_sha256": "c" * 64, "boot_id": "test-boot"}}
            state["current"]["services/data/litellm/config.yaml"]["sha256"] = "d" * 64
            capture = {"format": "home-lab-litellm-v1", "status": "captured", "request": request,
                       "state": state, "captured_at": int(time.time())}
            path = root / "capture.json"
            save(path, capture)
            output = root / "plan.json"
            m.main(["plan", "--capture", str(path), "--output", str(output)])
            plan = json.loads(output.read_bytes())
            self.assertEqual(plan["effects"]["recreate"], ["litellm"])
            self.assertEqual(plan["effects"]["changed_paths"], ["services/data/litellm/config.yaml"])
            self.assertFalse(plan["authorized"])
            self.assertEqual(plan["before"], state)
            self.assertEqual(plan["request"], request)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            for name in ("services/apps.yml", "services/data/litellm/custom_callbacks.py", "secrets/production.sops.env"):
                wrong = copy.deepcopy(capture)
                wrong["state"]["current"][name]["sha256"] = "e" * 64
                save(path, wrong)
                with self.assertRaisesRegex(SystemExit, "exact config-only"):
                    m.main(["plan", "--capture", str(path), "--output", str(root / "forbidden.json")])
            save(path, capture)
            # A CLI digest is not permission, and failure must precede any Ansible access.
            with self.assertRaisesRegex(SystemExit, "exact approval file or real terminal"):
                m.main(["apply", "--plan", str(output), "--known-hosts", str(known),
                        "--output", str(root / "result.json")])

    def test_exact_approved_operator_apply_crosses_guarded_transaction_once(self):
        with prepared_apply() as (m, root, bundle, plan, fake):
            approval = root / "apply-approval.json"
            m.main(["approval-template", "--input", str(root / "plan.json"), "--output", str(approval)])
            invocations = []
            launcher = root / "ansible-playbook"
            launcher.write_text("#!" + sys.executable + "\n")
            def transport(command, **kwargs):
                if str(launcher) not in command:
                    return source_git(command, **kwargs)
                self.assertEqual(command[:4], [sys.executable, "-I", "-B", str(launcher)])
                invocations.append(command)
                values = json.loads(Path(command[command.index("--extra-vars") + 1][1:]).read_bytes())
                workspace_path = Path(values["litellm_bundle"])
                arguments = {}
                for phase in m.TRANSPORT_PHASES:
                    m.validate_bundle(workspace_path, phase=phase, known_hosts=root / "known-hosts",
                                      transport=transport_fixture(root / "known-hosts"))
                    arguments[phase] = json.loads(m.validate_bundle(workspace_path, phase=phase, view="arguments",
                                      known_hosts=root / "known-hosts", transport=transport_fixture(root / "known-hosts")))
                received = root / "received"
                received.mkdir(mode=0o700)
                for entry in json.loads(base64.b64decode(arguments["transfer"]["content"]))["files"]:
                    path = received / entry["path"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(base64.b64decode(entry["data"]))
                    path.chmod(entry["mode"])
                self.assertEqual(arguments["execute"]["argv"][-1], m.sha(arguments["transfer"]["content"].encode()))
                fixture_receipts(m, received, "apply", plan)
                result = m.host_transaction(received, root=root, run=fake.run, sleep=lambda _: None)
                save(Path(arguments["fetch"]["dest"]), result)
                Path(arguments["fetch"]["dest"]).chmod(0o644)
                self.assertNotIn("TAILSCALE_OAUTH_CLIENT_SECRET", kwargs["env"])
                self.assertEqual(kwargs["env"]["ANSIBLE_SSH_RETRIES"], "0")
                return subprocess.CompletedProcess(command, 0, b"", b"")
            with patch("subprocess.run", side_effect=transport), patch("shutil.which", return_value=str(launcher)):
                args = ["apply", "--plan", str(root / "plan.json"), "--approval-file", str(approval),
                        "--known-hosts", str(root / "known-hosts"), "--output", str(root / "operator-result.json")]
                m.main(args)
                self.assertEqual(json.loads((root / "operator-result.json").read_bytes())["status"], "applied")
                with self.assertRaises(FileExistsError):
                    m.main(args[:-1] + [str(root / "second-result.json")])
            self.assertEqual(len(invocations), 1)

    def test_direct_bundle_transport_cannot_change_approved_trust_or_connection(self):
        for failure in ("trust", "host", "user", "connection", "port", "ssh_args", "ssh_common_args",
                        "ssh_extra_args", "ssh_executable", "private_key_file", "become_user", "retries",
                        "facts_modules", "legacy", "check_mode", "inventory_hostname"):
            with self.subTest(failure=failure), prepared_apply() as (m, root, bundle, plan, fake):
                bundle = controller_fixture(m, root, bundle, plan)
                save(root / ("litellm-" + m.sha(m.canonical(plan)) + ".attempt.json"), m.approval_for("apply", plan))
                settings = transport_fixture(root / "known-hosts")
                if failure == "trust":
                    (root / "known-hosts").write_text("different trust bytes")
                else:
                    settings[failure] = "changed"
                with self.assertRaisesRegex(SystemExit, "SSH trust binding" if failure == "trust" else "effective Ansible transport"):
                    m.main(["validate-bundle", "--phase", "target", "--workspace", str(bundle), "--known-hosts", str(root / "known-hosts"),
                            "--transport", json.dumps(settings)])
                self.assertFalse((bundle / "transport-execute.json").exists())
                self.assertFalse(fake.recreated)

    def test_transport_boundaries_require_ordered_one_shot_admission(self):
        with prepared_apply() as (m, root, bundle, plan, fake):
            bundle = controller_fixture(m, root, bundle, plan)
            save(root / ("litellm-" + m.sha(m.canonical(plan)) + ".attempt.json"), m.approval_for("apply", plan))
            before = sorted(path.name for path in bundle.iterdir())
            for _ in range(2):
                with redirect_stdout(io.StringIO()) as output:
                    m.main(["validate-bundle", "--phase", "target", "--workspace", str(bundle),
                            "--known-hosts", str(root / "known-hosts"),
                            "--transport", json.dumps(transport_fixture(root / "known-hosts"))])
                self.assertEqual(output.getvalue(), "docker-host-production\n")
                self.assertEqual(sorted(path.name for path in bundle.iterdir()), before)
            for phase in ("transfer", "execute", "fetch"):
                with self.assertRaises(FileNotFoundError):
                    m.validate_bundle(bundle, known_hosts=root / "known-hosts",
                                      transport=transport_fixture(root / "known-hosts"), phase=phase)
            for phase in m.TRANSPORT_PHASES:
                m.validate_bundle(bundle, known_hosts=root / "known-hosts",
                                  transport=transport_fixture(root / "known-hosts"), phase=phase)
                with self.assertRaises(FileExistsError):
                    m.validate_bundle(bundle, known_hosts=root / "known-hosts",
                                      transport=transport_fixture(root / "known-hosts"), phase=phase)
            self.assertFalse(fake.recreated)

    def test_prepared_bundle_rejects_changed_missing_extra_linked_and_oversized_files(self):
        for failure in ("main", "helper", "missing", "extra", "link", "size", "mode", "artifact"):
            with self.subTest(failure=failure), prepared_apply() as (m, root, raw, plan, fake):
                bundle = controller_fixture(m, root, raw, plan)
                save(root / ("litellm-" + m.sha(m.canonical(plan)) + ".attempt.json"), m.approval_for("apply", plan))
                main = bundle / "litellm-deployment.py"
                if failure in ("main", "helper", "artifact"):
                    path = main if failure == "main" else bundle / ("compose-artifact.py" if failure == "helper" else "artifact/" + m.CONFIG)
                    path.write_bytes(path.read_bytes() + b"\nchanged-unapproved-bytes\n")
                elif failure == "missing":
                    main.unlink()
                elif failure == "extra":
                    (bundle / "unselected.txt").write_text("unapproved")
                elif failure == "link":
                    secret = root / "secret-fixture"
                    secret.write_text("never transferred")
                    main.unlink()
                    main.symlink_to(secret)
                elif failure == "size":
                    with main.open("wb") as stream:
                        stream.truncate(m.PAYLOAD_LIMIT + 1)
                else:
                    main.chmod(0o644)
                with self.assertRaises((SystemExit, OSError)):
                    m.validate_bundle(bundle, phase="target", known_hosts=root / "known-hosts",
                                      transport=transport_fixture(root / "known-hosts"))
                self.assertFalse(list(bundle.glob("transport-*.json")))
                self.assertFalse(fake.recreated)

    def test_phase_arguments_bind_actual_buffer_destination_bootstrap_and_argv(self):
        for failure in ("destination", "bootstrap", "argv", "digest", "late-source", "override"):
            with self.subTest(failure=failure), prepared_apply() as (m, root, raw, plan, fake):
                bundle = controller_fixture(m, root, raw, plan)
                save(root / ("litellm-" + m.sha(m.canonical(plan)) + ".attempt.json"), m.approval_for("apply", plan))
                settings = transport_fixture(root / "known-hosts")
                for phase in ("allocate", "transfer", "execute"):
                    m.validate_bundle(bundle, phase=phase, known_hosts=root / "known-hosts", transport=settings)
                transfer = json.loads(m.validate_bundle(bundle, phase="transfer", view="arguments",
                                      known_hosts=root / "known-hosts", transport=settings))
                execute = json.loads(m.validate_bundle(bundle, phase="execute", view="arguments",
                                     known_hosts=root / "known-hosts", transport=settings))
                self.assertNotIn("src", transfer)
                self.assertEqual(execute["argv"], ["/usr/bin/python3", "-I", "-B", "-c", m.PREEXEC,
                                  m.sha(m.canonical(plan)), m.sha(transfer["content"].encode())])
                phase = "transfer" if failure == "destination" else "execute"
                receipt = bundle / ("transport-" + phase + ".json")
                value = json.loads(receipt.read_bytes())
                if failure == "destination":
                    value["effect"]["dest"] = "/unapproved/payload.json"
                elif failure == "bootstrap":
                    value["effect"]["argv"][4] = "raise SystemExit('unapproved bootstrap')"
                elif failure == "argv":
                    value["effect"]["argv"][0] = "/unapproved/python"
                elif failure == "digest":
                    value["effect"]["argv"][-1] = "0" * 64
                elif failure == "late-source":
                    (bundle / "litellm-deployment.py").write_text("unapproved code")
                save(receipt, value)
                with self.assertRaises(SystemExit):
                    m.validate_bundle(bundle, phase=phase, view="arguments", known_hosts=root / "known-hosts",
                                      transport=settings, overrides=["litellm_workspace"] if failure == "override" else [])
                self.assertFalse(fake.recreated)

    def test_dispatcher_protects_bound_result_locally_and_retains_unknown_delivery(self):
        for failure in (None, "symlink", "hardlink", "mode", "size", "binding", "null", "list", "output", "directory", "transport"):
            with self.subTest(failure=failure), prepared_apply() as (m, root, raw, plan, fake):
                launcher = root / "ansible-playbook"
                launcher.write_text("#!" + sys.executable + "\n")
                output = root / "operator-result.json"
                secret = root / "untouched-fixture"
                secret.write_text("untouched")
                secret.chmod(0o640)
                runs = []
                def transport(command, **kwargs):
                    if str(launcher) not in command:
                        return source_git(command, **kwargs)
                    values = json.loads(Path(command[command.index("--extra-vars") + 1][1:]).read_bytes())
                    self.assertEqual(set(values), {"litellm_bundle"})
                    bundle = Path(values["litellm_bundle"])
                    runs.append(bundle)
                    result = bundle / "incoming/result.json"
                    value = {"status": "applied", "plan_sha256": "wrong" if failure == "binding" else plan["plan_sha256"]}
                    if failure == "null":
                        value = None
                    elif failure == "list":
                        value = []
                    if failure == "symlink":
                        result.symlink_to(secret)
                    elif failure == "hardlink":
                        os.link(secret, result)
                    else:
                        save(result, value)
                        result.chmod(0o666 if failure == "mode" else 0o644)
                        if failure == "size":
                            with result.open("wb") as stream:
                                stream.truncate(m.MAX_FILE_BYTES + 1)
                    if failure == "output":
                        output.unlink()
                        output.symlink_to(secret)
                    elif failure == "directory":
                        (bundle / "incoming").rename(bundle / "retained-incoming")
                        (bundle / "incoming").symlink_to(root)
                    return subprocess.CompletedProcess(command, 1 if failure == "transport" else 0, b"", b"")
                with patch("subprocess.run", side_effect=transport), patch("shutil.which", return_value=str(launcher)):
                    if failure:
                        with self.assertRaisesRegex(SystemExit, "host may have completed and released ownership"):
                            m.dispatch("apply", plan, m.approval_for("apply", plan), root / "known-hosts", output)
                    else:
                        m.dispatch("apply", plan, m.approval_for("apply", plan), root / "known-hosts", output)
                self.assertEqual(secret.read_text(), "untouched")
                self.assertEqual(secret.stat().st_mode & 0o777, 0o640)
                self.assertEqual(len(runs), 1)
                delivery = json.loads((runs[0] / "transport-result.json").read_bytes())
                self.assertEqual(delivery["status"], "unknown" if failure else "delivered")
                if not failure:
                    self.assertEqual(json.loads(output.read_bytes())["plan_sha256"], plan["plan_sha256"])
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                    self.assertEqual((runs[0] / "incoming/result.json").stat().st_mode & 0o777, 0o600)
                elif failure != "output":
                    self.assertEqual(output.read_bytes(), b"")

    @unittest.skipUnless(os.environ.get("LITELLM_TEST_ANSIBLE") == "1", "explicit inert local Ansible test approval required")
    def test_ansible_start_at_each_remote_task_cannot_skip_admission(self):
        interpreter = "/Users/pauldiloreto/.local/share/uv/tools/ansible-core/bin/python"
        executable = "/Users/pauldiloreto/.local/bin/ansible-playbook"
        legacy_tasks = ("Allocate an exclusive protected transport workspace",
                 "Transfer the exact approved envelope and source bundle without secret materialization",
                 "Run the guarded one-shot transaction with all native checks in one process",
                 "Return only the bounded non-secret result", "list-hosts", "empty-facts", "transport")
        tasks = ("workspace", "argv", "output", "source")
        if os.environ.get("LITELLM_TEST_ANSIBLE_CASE"):
            tasks = tuple(task for task in (*legacy_tasks, *tasks) if task == os.environ["LITELLM_TEST_ANSIBLE_CASE"])
            self.assertTrue(tasks, "unknown native case")
        for task in tasks:
            with self.subTest(task=task), workspace() as directory:
                root = Path(directory)
                plugins = root / "plugins"
                plugins.mkdir(mode=0o700)
                marker = root / "remote-action-attempted"
                plugin = plugins / "review_inert.py"
                plugin.write_text('''from pathlib import Path
from ansible.plugins.connection import ConnectionBase
from ansible.errors import AnsibleConnectionFailure
class Connection(ConnectionBase):
    transport = 'review_inert'
    has_pipelining = True
    def refuse(self, *args, **kwargs):
        Path(MARKER).touch()
        raise AnsibleConnectionFailure('inert remote-action sentinel; no transport executed')
    _connect = refuse
    exec_command = refuse
    put_file = refuse
    fetch_file = refuse
    def close(self):
        pass
'''.replace("MARKER", repr(str(marker))))
                for path in (root / "bundle", root / "remote", root / "tmp"):
                    path.mkdir(mode=0o700)
                save(root / "bundle/envelope.json", {"operation": "invalid", "document": {}, "approval": {}})
                (root / "known-hosts").write_text("inert fixture; not host trust\n")
                (root / "inventory.yml").write_text("all:\n  children:\n    docker_host:\n      hosts:\n        docker-host-production: {}\n")
                (root / "ansible.cfg").write_text("[defaults]\nroles_path = " + str(ROOT / "ansible/roles") +
                    "\nconnection_plugins = " + str(plugins) + "\nretry_files_enabled = False\n" +
                    "host_key_checking = True\nauto_install_module_deps = False\n")
                settings = {"ansible_connection": "review_inert", "ansible_host": "invalid.example",
                            "ansible_user": "ansible-deploy", "ansible_python_interpreter": "/usr/bin/python3",
                            "ansible_become": True, "ansible_become_method": "sudo", "ansible_ssh_common_args": "",
                            "litellm_bundle": str(root / "bundle")}
                if task in ("workspace", "argv", "output", "source"):
                    settings["litellm_" + task] = str(root / "unapproved-effect")
                if task in ("transport", "workspace", "argv", "output", "source"):
                    m = load()
                    now = int(time.time())
                    request = {"format": m.FORMAT, "operation": "capture", "target": "docker-host/VM100/docker-compose/litellm",
                               "nonce": "a" * 32, "created_at": now, "expires_at": now + 1800,
                               "source": "synthetic-not-live", "artifact_sha256": "synthetic-not-live",
                               "known_hosts_sha256": m.sha((root / "known-hosts").read_bytes())}
                    approval = m.approval_for("capture", request)
                    save(root / "bundle/envelope.json", {"operation": "capture", "document": request, "approval": approval})
                    save(root / ("litellm-" + m.sha(m.canonical(request)) + ".attempt.json"), approval)
                    inventory_settings = {key: settings.pop(key) for key in ("ansible_host", "ansible_user",
                        "ansible_python_interpreter", "ansible_become", "ansible_become_method", "ansible_ssh_common_args")}
                    save(root / "inventory.yml", {"all": {"children": {"docker_host": {
                        "hosts": {"docker-host-production": inventory_settings}}}}})
                save(root / "vars.json", settings)
                env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8",
                       "ANSIBLE_CONFIG": str(root / "ansible.cfg"), "ANSIBLE_LOCAL_TEMP": str(root / "tmp"),
                       "ANSIBLE_REMOTE_TEMP": str(root / "remote"), "PYTHONNOUSERSITE": "1",
                       "HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS": str(root / "known-hosts")}
                playbook = ROOT / "ansible/playbooks/deploy-litellm.yml"
                selection = ["--start-at-task", {
                    "transport": legacy_tasks[0], "workspace": legacy_tasks[0], "source": legacy_tasks[1],
                    "argv": legacy_tasks[2], "output": legacy_tasks[3]}.get(task, task)]
                if task == "list-hosts":
                    selection = ["--list-hosts"]
                elif task == "empty-facts":
                    selection = []
                    playbook = root / "empty-facts.yml"
                    playbook.write_text("- hosts: docker-host-production\n  gather_facts: true\n" +
                                        "  vars:\n    ansible_facts_modules: []\n  tasks: []\n")
                command = [interpreter, "-I", "-B", executable, "-i", str(root / "inventory.yml"),
                           "--extra-vars", "@" + str(root / "vars.json"), *selection, str(playbook)]
                self.assertEqual(settings["ansible_connection"], "review_inert")
                self.assertTrue(all(not p.is_symlink() for p in [root, *root.rglob("*")]))
                m = load()
                hashes = {str(p.relative_to(root)): m.sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}
                for name in ("ansible/playbooks/deploy-litellm.yml", "ansible/roles/litellm_deploy/tasks/main.yml",
                             "scripts/litellm-deployment.py"):
                    hashes[name] = m.sha((ROOT / name).read_bytes())
                result = REAL_RUN(command, env=env, cwd=root, capture_output=True, text=True, timeout=30)
                save(root / "native-selection-result.json", {"command": command, "env": env, "hashes": hashes,
                    "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                    "remote_action_attempted": marker.exists()})
                if task == "empty-facts":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Gathering Facts", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    receipts = list((root / "bundle").glob("admission-rejected-*.json"))
                    self.assertTrue(receipts, result.stdout + result.stderr)
                    for receipt in receipts:
                        self.assertEqual(json.loads(receipt.read_bytes()), {
                            "status": "rejected", "phase": "target", "workspace": str(root / "bundle"),
                            "envelope_sha256": hashes["bundle/envelope.json"],
                            "reason": "effect path/argv override is forbidden" if task in ("workspace", "argv", "output", "source") else
                                      "effective Ansible transport differs" if task == "transport" else "prepared bundle approval differs"})
                    self.assertNotIn("Gathering Facts", result.stdout)
                self.assertFalse(marker.exists())

    def test_operator_command_output_is_bounded_while_os_streams(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel), workspace() as directory:
                m, root = load(), Path(directory)
                known = root / "known-hosts"
                known.write_text("test trust")
                written = 0
                def overflowing(command, **kwargs):
                    nonlocal written
                    try:
                        for _ in range(512):
                            written += os.write(kwargs[channel], b"x" * 65536)
                    except BrokenPipeError:
                        pass
                    return subprocess.CompletedProcess(command, 1, None, None)
                with patch("subprocess.run", side_effect=overflowing), self.assertRaisesRegex(SystemExit, "output byte limit"):
                    m.main(["request", "--known-hosts", str(known), "--output", str(root / "request.json")])
                self.assertLess(written, 18 * 1024 * 1024)
                self.assertFalse((root / "request.json").exists())

    def test_ansible_python_entrypoints_reject_ambient_startup_imports(self):
        with workspace() as directory:
            root = Path(directory)
            marker = root / "ambient-imported"
            (root / "sitecustomize.py").write_text("from pathlib import Path; Path(" + repr(str(marker)) + ").touch()\n")
            user_site = root / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
            user_site.mkdir(parents=True)
            user_marker = root / "user-pth-imported"
            (user_site / "ambient.pth").write_text("import pathlib; pathlib.Path(" + repr(str(user_marker)) + ").touch()\n")
            env = dict(os.environ, PYTHONPATH=str(root), PYTHONUSERBASE=str(root), HOME=str(root))
            for name in ("ansible/roles/litellm_deploy/tasks/main.yml",):
                text = (ROOT / name).read_text()
                flags = re.findall(r"^\s+- (-[IBS]+)$", text, re.M)
                if "'validate-bundle'" in text:
                    flags = re.findall(r"'(-[IBS]+)'", text)
                result = REAL_RUN([sys.executable, *flags, str(ROOT / "scripts/litellm-deployment.py"), "--help"],
                                  env=env, cwd=root, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(marker.exists(), name)
                self.assertFalse(user_marker.exists(), name)
                self.assertIn("-I", flags)

    def test_actual_operator_launcher_isolates_python_before_ansible_import(self):
        with prepared_apply() as (m, root, bundle, plan, fake):
            home = root / "operator-home"
            home.mkdir(mode=0o700)
            marker = home / "ambient-imported"
            env = {"HOME": str(home), "PATH": os.defpath}
            site = REAL_RUN([sys.executable, "-I", "-B", "-c", "import site; print(site.getusersitepackages())"],
                            env=env, capture_output=True, text=True, check=True).stdout.strip()
            user_site = Path(site)
            self.assertTrue(user_site.is_relative_to(home))
            user_site.mkdir(parents=True)
            poison = "import pathlib; pathlib.Path(" + repr(str(marker)) + ").touch()\n"
            (user_site / "ambient.pth").write_text(poison)
            (user_site / "sitecustomize.py").write_text(poison)
            launcher = root / "ansible-playbook"
            launcher.write_text("#!" + sys.executable + "\n" + '''import json, pathlib, sys
values = json.loads(pathlib.Path(sys.argv[sys.argv.index('--extra-vars') + 1][1:]).read_bytes())
bundle = pathlib.Path(values['litellm_bundle'])
plan = json.loads((bundle / 'envelope.json').read_bytes())['document']
output = bundle / 'incoming/result.json'
output.write_text(json.dumps({'status': 'applied', 'plan_sha256': plan['plan_sha256'], 'isolated': sys.flags.isolated, 'no_user_site': sys.flags.no_user_site}))
output.chmod(0o600)
''')
            launcher.chmod(0o700)
            output = root / "launcher-result.json"
            def run(command, **kwargs):
                return REAL_RUN(command, **kwargs) if str(launcher) in command else source_git(command, **kwargs)
            with patch("subprocess.run", side_effect=run), patch("shutil.which", return_value=str(launcher)), \
                    patch("pathlib.Path.home", return_value=home):
                m.dispatch("apply", plan, m.approval_for("apply", plan), root / "known-hosts", output)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(output.read_bytes()), {"status": "applied", "plan_sha256": plan["plan_sha256"], "isolated": 1, "no_user_site": 1})

    def test_tampered_stale_wrong_host_and_unapproved_plans_never_dispatch(self):
        with prepared_apply() as (m, root, bundle, plan, fake):
            for failure in ("hash", "expired", "host", "effect", "approval", "source"):
                with self.subTest(failure=failure):
                    wrong = copy.deepcopy(plan)
                    if failure == "expired":
                        wrong["request"]["created_at"] -= 3600
                        wrong["request"]["expires_at"] -= 3600
                    elif failure == "host":
                        wrong["before"]["host"]["hostname"] = "other-host"
                    elif failure == "effect":
                        wrong["effects"]["recreate"] = ["other"]
                    elif failure == "source":
                        wrong["request"]["source"] = "b" * 40
                    wrong.pop("plan_sha256")
                    wrong["plan_sha256"] = "bad" if failure == "hash" else m.sha(m.canonical(wrong))
                    path = root / "wrong-plan.json"
                    save(path, wrong)
                    approval = root / "wrong-approval.json"
                    save(approval, {} if failure == "approval" else m.approval_for("apply", wrong))
                    with self.assertRaises(SystemExit):
                        m.main(["apply", "--plan", str(path), "--approval-file", str(approval),
                                "--known-hosts", str(root / "known-hosts"), "--output", str(root / "refused.json")])
            self.assertFalse(fake.recreated)


class PayloadExecutionTests(unittest.TestCase):
    def test_preexec_authenticates_and_executes_the_same_main_and_helper_buffers(self):
        import inspect
        import hashlib
        import builtins
        for failure in (None, "race", "main", "helper", "digest", "duplicate-key", "duplicate-file", "path", "mode", "size", "symlink"):
            with self.subTest(failure=failure), workspace() as directory:
                m, root = load(), Path(directory)
                remote = root / "remote"
                remote.mkdir(mode=0o700)
                marker = root / "approved-executed"
                script_path = remote / "input/litellm-deployment.py"
                main = ("import importlib.util, sys\nfrom pathlib import Path\n__file__ = " + repr(str(script_path)) + "\n" +
                        "def require(ok, reason):\n    if not ok: raise SystemExit(reason)\n" + inspect.getsource(m.helper) +
                        "module = helper('compose-artifact')\n" +
                        "assert module.VALUE == 'verified-helper' and module.__spec__.name == 'compose_artifact'\n" +
                        "Path(" + repr(str(marker)) + ").write_text(module.VALUE)\n").encode()
                files = {name: b"VALUE = 'verified-helper'\n" for name in m.COLLECTORS}
                files["compose-artifact.py"] = (b"from dataclasses import dataclass\n@dataclass\nclass Record:\n"
                                                b"    value: str = 'verified-helper'\nVALUE = Record().value\n")
                files["litellm-deployment.py"] = main
                files["home-lab.yml"] = b"synthetic-not-live-contract"
                request = {"collector": {name: m.sha(files[name]) for name in m.COLLECTORS},
                           "contract_sha256": m.sha(files["home-lab.yml"])}
                envelope = {"operation": "capture", "document": request, "approval": {"synthetic": True}}
                files["envelope.json"] = m.canonical(envelope)
                document_sha = m.sha(m.canonical(request))
                payload = {"format": m.FORMAT, "document_sha256": document_sha,
                           "files": [{"path": name, "mode": 0o600, "data": base64.b64encode(raw).decode()}
                                     for name, raw in files.items()]}
                sealed = base64.b64encode(m.canonical(payload))
                expected_sha = m.sha(sealed)
                if failure in ("main", "helper"):
                    name = "litellm-deployment.py" if failure == "main" else "compose-artifact.py"
                    next(e for e in payload["files"] if e["path"] == name)["data"] = base64.b64encode(b"raise AssertionError('unapproved execution')").decode()
                elif failure == "duplicate-file":
                    payload["files"].append(payload["files"][0])
                elif failure == "path":
                    payload["files"][0]["path"] = "../escape.py"
                elif failure == "mode":
                    payload["files"][0]["mode"] = 0o777
                if failure in ("main", "helper", "duplicate-file", "path", "mode"):
                    sealed = base64.b64encode(m.canonical(payload))
                    if failure not in ("main", "helper"):
                        expected_sha = m.sha(sealed)
                elif failure == "duplicate-key":
                    sealed = base64.b64encode(b'{"format":"one","format":"two"}')
                    expected_sha = m.sha(sealed)
                elif failure == "digest":
                    expected_sha = "0" * 64
                elif failure == "size":
                    sealed = b"x" * (m.PAYLOAD_LIMIT + 1)
                    expected_sha = m.sha(sealed)
                payload_path = remote / "payload.json"
                payload_path.write_bytes(sealed)
                payload_path.chmod(0o600)
                if failure == "symlink":
                    payload_path.rename(remote / "linked-input")
                    payload_path.symlink_to(remote / "linked-input")
                virtual = "/var/lib/docker-compose/.litellm-" + document_sha
                real_open, real_sha, real_compile = os.open, hashlib.sha256, builtins.compile
                def open_fixture(path, *args, **kwargs):
                    if str(path) == virtual:
                        path = remote
                    if Path(path).is_absolute():
                        self.assertTrue(Path(path).is_relative_to(root), path)
                    return real_open(path, *args, **kwargs)
                def hash_fixture(raw=b"", *args, **kwargs):
                    value = real_sha(raw, *args, **kwargs)
                    if failure == "race" and raw == sealed:
                        payload_path.write_bytes(b"changed after authenticated descriptor read")
                    return value
                def compile_fixture(raw, filename, *args, **kwargs):
                    if filename == virtual + "/input/litellm-deployment.py":
                        self.assertEqual(raw, main)
                        (remote / "input/litellm-deployment.py").write_text("raise AssertionError('mutable main executed')")
                        (remote / "input/compose-artifact.py").write_text("raise AssertionError('mutable helper executed')")
                    return real_compile(raw, filename, *args, **kwargs)
                namespace = {}
                with patch("os.open", side_effect=open_fixture), patch("hashlib.sha256", side_effect=hash_fixture), \
                        patch("builtins.compile", side_effect=compile_fixture), patch.object(sys, "argv", ["preexec", document_sha, expected_sha]), \
                        patch.dict("sys.modules"):
                    if failure not in (None, "race"):
                        with self.assertRaises((SystemExit, OSError)):
                            exec(m.PREEXEC, namespace)
                    else:
                        exec(m.PREEXEC, namespace)
                if failure in (None, "race"):
                    self.assertEqual(marker.read_text(), "verified-helper")
                    self.assertIn("mutable main", script_path.read_text())
                else:
                    self.assertFalse(marker.exists())
                    self.assertFalse((remote / "input").exists())


class HostTransactionTests(unittest.TestCase):
    def test_host_network_hostname_is_declaration_backed_and_other_identity_retained(self):
        for failure in (None, "hostname", "declaration", "other-service"):
            with self.subTest(failure=failure), prepared_apply(host_network=True) as (m, root, bundle, plan, fake):
                old = m.manifest(root / "srv/docker-compose/current")
                if failure == "hostname":
                    fake.host_hostname = "wrong-host"
                elif failure == "declaration":
                    fake.model["services"]["other"].pop("network_mode")
                elif failure == "other-service":
                    fake.other_drift = True
                if failure:
                    with self.assertRaises(SystemExit):
                        m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                    if failure != "other-service":
                        self.assertEqual(m.manifest(root / "srv/docker-compose/current"), old)
                        self.assertFalse(fake.recreated)
                else:
                    result = m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                    self.assertEqual(result["status"], "applied")
                    self.assertEqual(result["state"]["containers"]["other"], plan["before"]["containers"]["other"])

    def test_previous_image_lock_is_complete_and_bound_before_publication(self):
        for failure in ("missing", "wrong-id", "wrong-reference", "previous-declaration", "previous-env"):
            with self.subTest(failure=failure), workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                    patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
                m, root = load(), Path(directory)
                bundle, request = host_fixture(m, root)
                fake = DockerFixture(root, m)
                current = m.manifest(root / "srv/docker-compose/current")
                previous = m.manifest(root / "srv/docker-compose/previous")
                path = root / "var/lib/docker-compose/previous-images.json"
                lock = json.loads(path.read_bytes())
                if failure == "missing":
                    lock["images"].pop()
                elif failure == "wrong-id":
                    lock["images"][1]["image_id"] = "sha256:unrelated-available"
                elif failure == "wrong-reference":
                    lock["images"][1]["reference"] = "sha256:unrelated-available"
                elif failure == "previous-declaration":
                    fake.previous_model["services"]["other"]["image"] = "sha256:different-previous"
                else:
                    (root / "etc/docker-compose/previous.env").write_text("CHANGED=synthetic\n")
                save(path, lock)
                retained = path.read_bytes()
                with self.assertRaisesRegex(SystemExit, "previous.*(identity|service set) differs"):
                    m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                self.assertFalse(fake.recreated)
                self.assertEqual(m.manifest(root / "srv/docker-compose/current"), current)
                self.assertEqual(m.manifest(root / "srv/docker-compose/previous"), previous)
                self.assertEqual(path.read_bytes(), retained)
                self.assertFalse(list((root / "srv/docker-compose").glob(".litellm-*")))

    def test_previous_digest_binding_does_not_require_moved_mutable_tag(self):
        with workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
            m, root = load(), Path(directory)
            bundle, request = host_fixture(m, root)
            fake = DockerFixture(root, m)
            digest = "example.invalid/other@sha256:" + "a" * 64
            fake.previous_model["services"]["other"]["image"] = "example.invalid/other:old@sha256:" + "a" * 64
            fake.repo_digests = {"sha256:other": [digest]}
            path = root / "var/lib/docker-compose/previous-images.json"
            lock = json.loads(path.read_bytes())
            lock["images"][1]["reference"] = "example.invalid/other:old"
            save(path, lock)
            result = m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
            self.assertEqual(result["status"], "captured")
            self.assertFalse(any("example.invalid/other:old" in call for call in fake.docker_calls))

    def test_host_transaction_requires_transferred_admission_before_native_actions(self):
        with workspace() as directory, patch("subprocess.run", side_effect=source_git):
            m, root = load(), Path(directory)
            bundle, request = host_fixture(m, root)
            m._VERIFIED_ENVELOPE_SHA256 = None
            with self.assertRaisesRegex(SystemExit, "pre-execution authenticated payload"):
                m.host_transaction(bundle, root=root, run=lambda *a, **kw: self.fail("unadmitted native action"))

    def test_stopped_docker_refuses_before_socket_activation_or_owner_publication(self):
        m = load()
        with workspace() as directory, patch("subprocess.run", side_effect=source_git):
            root = Path(directory)
            known = root / "known-hosts"
            known.write_text("test trust")
            request_file = root / "request.json"
            m.main(["request", "--known-hosts", str(known), "--output", str(request_file)])
            request = json.loads(request_file.read_bytes())
            bundle = root / "bundle"
            bundle.mkdir(mode=0o700)
            for name in request["collector"]:
                (bundle / name).write_bytes((ROOT / "scripts" / name).read_bytes())
            save(bundle / "envelope.json", {"operation": "capture", "document": request,
                 "approval": m.approval_for("capture", request)})
            fixture_receipts(m, bundle, "capture", request)
            calls = []
            def stopped(command, **kwargs):
                calls.append(command)
                self.assertEqual(command[0], "/usr/bin/systemctl")
                return subprocess.CompletedProcess(command, 0, "ActiveState=inactive\nSubState=dead\nMainPID=0\n", "")
            with self.assertRaisesRegex(SystemExit, "Docker must already be running"):
                m.host_transaction(bundle, root=root, run=stopped)
            self.assertEqual(len(calls), 1)
            self.assertFalse((root / "var/lib/iac-ansible-production.lock").exists())

    def test_held_production_owner_refuses_without_docker_or_replacement(self):
        m = load()
        with workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
            root = Path(directory)
            bundle, request = host_fixture(m, root)
            owner = root / "var/lib/iac-ansible-production.lock"
            owner.mkdir(mode=0o700)
            (owner / "owner").write_text("foreign-owner\n")
            fake = DockerFixture(root, m)
            with self.assertRaisesRegex(SystemExit, "production ownership"):
                m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
            self.assertEqual(fake.docker_calls, [])
            self.assertEqual((owner / "owner").read_text(), "foreign-owner\n")

    def test_capture_offline_plan_apply_recreates_only_litellm_and_retains_both_generations(self):
        m = load()
        with workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
            root = Path(directory)
            bundle, request = host_fixture(m, root)
            fake = DockerFixture(root, m)
            captured = m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
            self.assertEqual(captured["status"], "captured")
            plan_path = root / "plan.json"
            m.main(["plan", "--capture", str(bundle / "result.json"), "--output", str(plan_path)])
            plan = json.loads(plan_path.read_bytes())
            previous = m.manifest(root / "srv/docker-compose/previous")
            active = m.manifest(root / "srv/docker-compose/current")
            apply_bundle = root / "apply-bundle"
            shutil.copytree(bundle, apply_bundle, ignore=shutil.ignore_patterns("result.json", "envelope.json", "docker-cli-config"))
            m.helper("compose-artifact").copy_artifact(ROOT, apply_bundle / "artifact", sorted(request["artifact"]))
            save(apply_bundle / "envelope.json", {"operation": "apply", "document": plan,
                                                 "approval": m.approval_for("apply", plan)})
            fixture_receipts(m, apply_bundle, "apply", plan)
            result = m.host_transaction(apply_bundle, root=root, run=fake.run, sleep=lambda _: None)
            self.assertEqual(result["status"], "applied")
            self.assertEqual(m.manifest(root / "srv/docker-compose/previous"), previous)
            self.assertEqual(m.manifest(Path(result["recovery"]) / "current"), active)
            self.assertEqual(m.manifest(root / "srv/docker-compose/current"), (request["artifact"], request["artifact_sha256"]))
            self.assertEqual(result["state"]["containers"]["other"], captured["state"]["containers"]["other"])
            mutations = [c for c in fake.docker_calls if "up" in c and "--dry-run" not in c]
            self.assertEqual(len(mutations), 1)
            self.assertEqual(mutations[0][-len(m.UP):], m.UP)
            self.assertFalse((root / "var/lib/iac-ansible-production.lock").exists())
            self.assertTrue((Path(result["recovery"]) / "previous.env").is_file())

    def test_failed_adoption_retains_ownership_recovery_and_never_retries(self):
        for failure in ("liveness", "other-service", "no-recreation", "wrong-loaded", "tokens", "before-env", "candidate"):
            with self.subTest(failure=failure), prepared_apply() as (m, root, bundle, plan, fake):
                old = m.manifest(root / "srv/docker-compose/current")
                previous = m.manifest(root / "srv/docker-compose/previous")
                if failure == "liveness":
                    fake.fail_liveness = True
                elif failure == "other-service":
                    fake.other_drift = True
                elif failure == "no-recreation":
                    fake.no_new_identity = True
                elif failure == "wrong-loaded":
                    fake.wrong_loaded = True
                elif failure == "tokens":
                    fake.token_change = True
                elif failure == "before-env":
                    (root / "etc/docker-compose/production.env").write_text("changed-synthetic-env\n")
                else:
                    (bundle / "artifact/services/apps.yml").write_text("unexpected image change\n")
                with self.assertRaises(SystemExit):
                    m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                mutations = [c for c in fake.docker_calls if "up" in c and "--dry-run" not in c]
                self.assertEqual(len(mutations), 0 if failure in ("before-env", "candidate") else 1)
                self.assertEqual(m.manifest(root / "srv/docker-compose/previous"), previous)
                if failure != "candidate":
                    self.assertTrue((root / "var/lib/iac-ansible-production.lock/owner").is_file())
                if mutations:
                    recovery = root / ("srv/docker-compose/.litellm-" + plan["plan_sha256"])
                    self.assertEqual(m.manifest(recovery / "current"), old)
                    self.assertTrue((recovery / "production.env").is_file())
                else:
                    self.assertEqual(m.manifest(root / "srv/docker-compose/current"), old)
                # Reentry cannot adopt foreign/retained ownership or reuse its durable attempt.
                with self.assertRaises((SystemExit, FileExistsError)):
                    m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                self.assertEqual(len([c for c in fake.docker_calls if "up" in c and "--dry-run" not in c]), len(mutations))

    def test_capture_refuses_bounded_file_tree_and_command_overflows(self):
        for failure in ("artifact-file", "recovery-file", "token-depth", "token-total", "command-output"):
            with self.subTest(failure=failure), workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                    patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
                m, root = load(), Path(directory)
                bundle, request = host_fixture(m, root)
                fake = DockerFixture(root, m)
                if failure in ("artifact-file", "recovery-file"):
                    path = root / ("srv/docker-compose/current/" + m.CONFIG if failure == "artifact-file" else
                                   "etc/docker-compose/production.env")
                    with path.open("wb") as stream:
                        stream.truncate(8 * 1024 * 1024 + 1)
                elif failure == "token-depth":
                    (root / "srv/home-lab-state/litellm-data" / Path(*(["deep"] * 17))).mkdir(parents=True)
                elif failure == "token-total":
                    for index in range(17):
                        with (root / "srv/home-lab-state/litellm-data" / str(index)).open("wb") as stream:
                            stream.truncate(1024 * 1024)
                else:
                    fake.output_overflow = True
                with self.assertRaisesRegex(SystemExit, "limit"):
                    m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                self.assertFalse(fake.recreated)
                self.assertFalse((root / "var/lib/iac-ansible-production.lock").exists())

    def test_capture_stops_enumeration_before_consuming_unbounded_trees(self):
        for target, limit in (("srv/home-lab-state/litellm-data", 1000), ("srv/docker-compose/current", 4096)):
            with self.subTest(target=target), workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                    patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
                m, root = load(), Path(directory)
                bundle, request = host_fixture(m, root)
                fake = DockerFixture(root, m)
                tree = root / target
                for index in range(limit + 2):
                    (tree / str(index)).touch()
                scanned = 0
                real_scandir = os.scandir
                class LimitedScan:
                    def __init__(self):
                        self.stream = real_scandir(tree)
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        self.stream.close()
                    def __iter__(self):
                        return self
                    def __next__(self):
                        nonlocal scanned
                        scanned += 1
                        if scanned > limit + 1:
                            raise AssertionError("eager traversal consumed entries beyond refusal boundary")
                        return next(self.stream)
                def scandir(path):
                    return LimitedScan() if Path(path) == tree else real_scandir(path)
                with patch("os.scandir", side_effect=scandir), self.assertRaisesRegex(SystemExit, "entry limit"):
                    m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                self.assertGreater(scanned, 0)
                self.assertLessEqual(scanned, limit + 1)
                self.assertFalse(fake.recreated)

    def test_existing_tmpfs_secret_and_image_volume_mounts_admit_and_refuse_drift(self):
        for failure in (None, "tmpfs-size", "secret-source", "volume-source", "hostname"):
            with self.subTest(failure=failure), workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                    patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
                m, root = load(), Path(directory)
                bundle, request = host_fixture(m, root)
                fake = DockerFixture(root, m)
                fake.mount_examples = True
                fake.mount_drift = failure
                fake.model["services"]["other"].update({
                    "hostname": "explicit-other",
                    "volumes": [{"type": "tmpfs", "target": "/cache/transcodes", "tmpfs": {"size": 17179869184}}],
                    "secrets": [{"source": "nextcloud_mysql_password", "target": "nextcloud_mysql_password"}]})
                fake.model["secrets"] = {"nextcloud_mysql_password": {"file": "/etc/docker-compose/credentials/nextcloud-mysql-password"}}
                if failure:
                    with self.assertRaises(SystemExit):
                        m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                else:
                    captured = m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                    self.assertEqual(captured["status"], "captured")
                self.assertFalse(fake.recreated)

    def test_unknown_dry_run_action_cannot_hide_unrelated_recreation(self):
        with workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
            m, root = load(), Path(directory)
            bundle, request = host_fixture(m, root)
            fake = DockerFixture(root, m)
            fake.extra_action = "Container other Recreating\n"
            with self.assertRaisesRegex(SystemExit, "dry run proposes"):
                m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
            self.assertFalse(fake.recreated)

    def test_capture_refuses_environment_image_service_and_backup_conflicts(self):
        import fcntl
        for failure in ("environment", "image", "service", "backup"):
            with self.subTest(failure=failure), workspace() as directory, patch("subprocess.run", side_effect=source_git), \
                    patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
                m, root = load(), Path(directory)
                bundle, request = host_fixture(m, root)
                fake = DockerFixture(root, m)
                fake.environment_drift = failure == "environment"
                fake.image_drift = failure == "image"
                fake.service_drift = failure == "service"
                with (root / "run/lock/home-lab-backup.lock").open() as lock:
                    if failure == "backup":
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(SystemExit):
                        m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
                self.assertFalse(fake.recreated)
                self.assertFalse((root / "var/lib/iac-ansible-production.lock").exists())


@contextmanager
def prepared_apply(host_network=False):
    with workspace() as directory, patch("subprocess.run", side_effect=source_git), \
            patch.dict("sys.modules", {"yaml": SimpleNamespace(safe_load=fixture_yaml)}), \
            patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())):
        m, root = load(), Path(directory)
        bundle, request = host_fixture(m, root)
        fake = DockerFixture(root, m)
        if host_network:
            fake.model["services"]["other"]["network_mode"] = "host"
            fake.host_network = True
        m.host_transaction(bundle, root=root, run=fake.run, sleep=lambda _: None)
        plan_path = root / "plan.json"
        m.main(["plan", "--capture", str(bundle / "result.json"), "--output", str(plan_path)])
        plan = json.loads(plan_path.read_bytes())
        apply_bundle = root / "apply-bundle"
        shutil.copytree(bundle, apply_bundle, ignore=shutil.ignore_patterns("result.json", "envelope.json", "docker-cli-config"))
        m.helper("compose-artifact").copy_artifact(ROOT, apply_bundle / "artifact", sorted(request["artifact"]))
        save(apply_bundle / "envelope.json", {"operation": "apply", "document": plan,
                                             "approval": m.approval_for("apply", plan)})
        fixture_receipts(m, apply_bundle, "apply", plan)
        yield m, root, apply_bundle, plan, fake


def fixture_yaml(raw):
    # PyYAML is an external native prerequisite, substituted here, not qualified by this fixture.
    if b"model_list:" in raw:
        return {"model_list": [{"model_name": "synthetic", "litellm_params": {"model": "chatgpt/synthetic"}}],
                "general_settings": {"master_key": "os.environ/LITELLM_MASTER_KEY"},
                "litellm_settings": {"check_provider_endpoint": True,
                                     "callbacks": ["custom_callbacks.service_tier_passthrough"]}}
    return CONTRACT


def transport_fixture(known_hosts):
    return {"host": "docker-host", "user": "ansible-deploy", "connection": "ssh", "port": 22,
        "ssh_executable": "/usr/bin/ssh", "ssh_args": "-o ControlMaster=no -o ControlPath=none",
        "ssh_common_args": "-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes "
            "-o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o UserKnownHostsFile=" + str(known_hosts) +
            " -o IdentityAgent=none -o IdentityFile=none -o IdentitiesOnly=yes -o PreferredAuthentications=none"
            " -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
            " -o GSSAPIAuthentication=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -o ConnectTimeout=10"
            " -o ServerAliveInterval=15 -o ServerAliveCountMax=2 -o RequestTTY=no",
        "ssh_extra_args": "", "sftp_extra_args": "", "scp_extra_args": "", "private_key_file": "",
        "password": "", "retries": 0, "host_key_checking": True, "ssh_host_key_checking": True,
        "become": True, "become_method": "sudo", "become_user": "root", "become_exe": "/usr/bin/sudo",
        "become_flags": "-H -S -n", "python_interpreter": "/usr/bin/python3", "transfer_method": "piped",
        "shell_type": "sh", "shell_executable": "/bin/sh", "use_tty": False,
        "pipelining": True, "ssh_pipelining": True, "facts_modules": [], "check_mode": False,
        "inventory_hostname": "docker-host-production",
        "legacy": {"host": "docker-host", "user": "ansible-deploy", "port": 22, "key": "",
                   "password": "", "become_password": "", "become_pass": "", "sudo_exe": "/usr/bin/sudo",
                   "sudo_flags": "-H -S -n", "sudo_user": "root", "sudo_pass": ""}}


CONTRACT = {"vm_100": {"host_name": "docker-host"}, "proxmox": {"vm": {"state_disk": {
    "mountpoint": "/srv/home-lab-state", "filesystem": "ext4",
    "filesystem_uuid": "d4a19647-7879-4079-9fc9-b3e79711b449"}}}}


def controller_fixture(m, root, raw, plan):
    bundle = root / "controller-bundle"
    bundle.mkdir(mode=0o700)
    for name in (*m.COLLECTORS, "home-lab.yml"):
        shutil.copyfile(raw / name, bundle / name)
        (bundle / name).chmod(0o600)
    m.write_private(bundle / "envelope.json", {"operation": "apply", "document": plan, "approval": m.approval_for("apply", plan)})
    shutil.copytree(raw / "artifact", bundle / "artifact")
    (bundle / "incoming").mkdir(mode=0o700)
    m.write_private(bundle / "variables.json", {"litellm_bundle": str(bundle)})
    return bundle


def fixture_receipts(m, bundle, operation, document):
    # Host-only seam substitutes pre-execution authentication, never live approval evidence.
    m._VERIFIED_ENVELOPE_SHA256 = m.sha((bundle / "envelope.json").read_bytes())


def host_fixture(m, root):
    known = root / "known-hosts"
    known.write_text("synthetic independently established trust")
    request_path = root / "request.json"
    m.main(["request", "--known-hosts", str(known), "--output", str(request_path)])
    request = json.loads(request_path.read_bytes())
    bundle = root / "bundle"
    bundle.mkdir(mode=0o700)
    for name in request["collector"]:
        shutil.copyfile(ROOT / "scripts" / name, bundle / name)
    shutil.copyfile(ROOT / "infrastructure/contract/home-lab.yml", bundle / "home-lab.yml")
    save(bundle / "envelope.json", {"operation": "capture", "document": request,
         "approval": m.approval_for("capture", request)})
    fixture_receipts(m, bundle, "capture", request)
    for path in ("run/lock/home-lab-backup.lock", "etc/hostname", "etc/machine-id", "proc/sys/kernel/random/boot_id"):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text("docker-host\n" if path == "etc/hostname" else "synthetic\n")
        target.chmod(0o660 if path.endswith("backup.lock") else 0o600)
    (root / "var/lib/docker-compose").mkdir(parents=True, mode=0o700)
    (root / "srv/home-lab-state/litellm-data").mkdir(parents=True, mode=0o700)
    for name in ("current", "previous"):
        target = root / "srv/docker-compose" / name
        m.helper("compose-artifact").copy_artifact(ROOT, target, sorted(request["artifact"]))
        (target / m.CONFIG).write_text("old-model-config\n")
    _, old_hash = m.manifest(root / "srv/docker-compose/current")
    image_id = next(i["image_id"] for i in request["image_lock"]["images"] if i["service"] == "litellm")
    for name, mode in m.RECOVERY_FILES.items():
        target = root / name.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if name.endswith(".env"):
            target.write_text("UNCHANGED=synthetic-not-secret\n")
        elif name == m.OVERRIDE:
            target.write_text(json.dumps({"services": {"litellm": {"image": image_id}, "other": {"image": "sha256:other"}}}))
        elif name.endswith("images.json"):
            target.write_text(json.dumps({"schema": 1, "images": [{"service": "litellm", "image_id": image_id, "reference": image_id},
                                                                  {"service": "other", "image_id": "sha256:other", "reference": "sha256:other"}]}))
        else:
            target.write_text(old_hash + "\n")
        target.chmod(mode)
    return bundle, request


class DockerFixture:
    """OS/Docker test double at subprocess boundary; no host-shaped live receipt export."""
    def __init__(self, root, module):
        self.root, self.m = root, module
        self.docker_calls = []
        self.recreated = False
        self.fail_liveness = False
        self.other_drift = False
        self.environment_drift = False
        self.image_drift = False
        self.service_drift = False
        self.extra_action = ""
        self.no_new_identity = False
        self.wrong_loaded = False
        self.token_change = False
        self.mount_examples = False
        self.mount_drift = None
        self.output_overflow = False
        self.host_network = False
        self.host_hostname = "docker-host"
        self.repo_digests = {}
        lock = json.loads((ROOT / "infrastructure/debian/production-image-lock.json").read_bytes())
        self.image_id = next(i["image_id"] for i in lock["images"] if i["service"] == "litellm")
        self.mounts = [{"type": "bind", "source": "/srv/docker-compose/current/services/data/litellm/config.yaml",
                        "target": "/app/config.yaml", "read_only": True},
                       {"type": "bind", "source": "/srv/docker-compose/current/services/data/litellm/custom_callbacks.py",
                        "target": "/app/custom_callbacks.py", "read_only": True},
                       {"type": "bind", "source": "/srv/home-lab-state/litellm-data", "target": "/data", "read_only": False}]
        self.command = ["--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "4000"]
        self.model = {"name": "docker-compose", "services": {
            "litellm": {"image": self.image_id, "command": self.command, "volumes": self.mounts},
            "other": {"image": "sha256:other"}}, "networks": {}}
        self.previous_model = copy.deepcopy(self.model)

    def rows(self):
        result = []
        for name, service in self.model["services"].items():
            new = self.recreated and not self.no_new_identity and (name == "litellm" or self.other_drift)
            mounts = self.mounts if name == "litellm" else []
            container_id = (("2" if new else "1") if name == "litellm" else ("4" if new else "3")) * 64
            result.append({"Id": container_id, "Image": "sha256:wrong" if self.image_drift else service["image"],
                "Config": {"Image": service["image"], "Hostname": service.get("hostname", self.host_hostname if self.host_network and name == "other" else container_id[:12]),
                           "Domainname": "", "Cmd": service.get("command"), "Entrypoint": None,
                           "Env": ["DRIFT=true"] if self.environment_drift else [],
                           "User": None, "WorkingDir": None,
                           "Labels": {"com.docker.compose.service": name, "com.docker.compose.config-hash": "hash-" + name}},
                "State": {"Running": True, "Pid": 200 if new else 100, "StartedAt": "new" if new else "old"},
                "RestartCount": 0, "HostConfig": {"NetworkMode": "host"} if self.host_network and name == "other" else {}, "NetworkSettings": {"Networks": {}},
                "Mounts": [{"Source": x["source"], "Destination": x["target"], "Type": "bind", "RW": not x["read_only"]} for x in mounts]})
        if self.mount_examples:
            row = result[1]
            row["HostConfig"]["Mounts"] = [{"Type": "tmpfs", "Target": "/cache/transcodes",
                "TmpfsOptions": {"SizeBytes": 1 if self.mount_drift == "tmpfs-size" else 17179869184}}]
            volume = "a" * 64
            row["Mounts"] = [
                {"Type": "tmpfs", "Source": "", "Destination": "/cache/transcodes", "RW": True},
                {"Type": "bind", "Source": "/wrong" if self.mount_drift == "secret-source" else
                 "/etc/docker-compose/credentials/nextcloud-mysql-password",
                 "Destination": "/run/secrets/nextcloud_mysql_password", "RW": False},
                {"Type": "volume", "Name": volume, "Driver": "local", "RW": True, "Destination": "/run/user/wolf",
                 "Source": "/wrong" if self.mount_drift == "volume-source" else "/var/lib/docker/volumes/" + volume + "/_data"}]
            if self.mount_drift == "hostname":
                row["Config"]["Hostname"] = "wrong-explicit"
        return result[:1] if self.service_drift else result

    def run(self, command, **kwargs):
        output = ""
        if command[0] == "/usr/bin/systemctl":
            if "list-jobs" in command:
                output = "" if "--no-legend" in command else "No jobs running.\n"
            else:
                output = "MainPID=12\nSubState=running\nActiveState=active\n"
            if self.output_overflow:
                output += " " * (16 * 1024 * 1024 + 1)
        elif command[0] == "/usr/bin/findmnt":
            output = json.dumps({"filesystems": [{"target": "/srv/home-lab-state", "source": "/dev/test", "fstype": "ext4",
                 "uuid": CONTRACT["proxmox"]["vm"]["state_disk"]["filesystem_uuid"], "options": "rw,noatime"}]})
        elif command[0] == "/usr/bin/docker":
            self.docker_calls.append(command)
            assert command[1:4] == ["--host", "unix:///var/run/docker.sock", "--config"], command
            assert Path(command[4]).is_dir() and not list(Path(command[4]).iterdir()), command
            assert kwargs["env"]["HOME"] == "/" and not any(k.startswith("DOCKER_") for k in kwargs["env"])
            args = command[5:]
            if args[0] == "compose":
                if "--dry-run" in args:
                    assert args == ["compose", "--dry-run", "--ansi", "never", "--project-name", "docker-compose",
                        "--project-directory", str(self.root / "srv/docker-compose/current"),
                        "--env-file", str(self.root / "etc/docker-compose/production.env"),
                        "--file", str(self.root / "srv/docker-compose/current/docker-compose.yml"),
                        "--file", str(self.root / "var/lib/home-lab/production-image-override.json"),
                        "up", "--detach", "--no-build", "--pull", "never", "--no-deps", "--force-recreate", "litellm"], args
                    output = "Container litellm Recreated\nContainer litellm Started\n" + self.extra_action
                elif "--hash" in args:
                    output = "litellm hash-litellm\nother hash-other\n"
                elif "config" in args:
                    if str(self.root / "srv/docker-compose/previous") in args:
                        assert args == ["compose", "--ansi", "never", "--project-name", "docker-compose",
                            "--project-directory", str(self.root / "srv/docker-compose/previous"),
                            "--env-file", str(self.root / "etc/docker-compose/previous.env"),
                            "--file", str(self.root / "srv/docker-compose/previous/docker-compose.yml"),
                            "config", "--format", "json"], args
                        previous = copy.deepcopy(self.previous_model)
                        if (self.root / "etc/docker-compose/previous.env").read_text().startswith("CHANGED="):
                            previous["services"]["other"]["image"] = "sha256:env-changed-previous"
                        output = json.dumps(previous)
                    else:
                        output = json.dumps(self.model)
                elif "up" in args:
                    if args[-len(self.m.UP):] != self.m.UP:
                        raise AssertionError("unconfined mutation " + repr(args))
                    self.recreated = True
                    if self.token_change:
                        (self.root / "srv/home-lab-state/litellm-data/token.json").write_text("synthetic changed token")
                else:
                    raise AssertionError(command)
            elif args[0] == "ps":
                output = "litellm-old\nother-old\n"
            elif args[0] == "inspect":
                output = json.dumps(self.rows())
            elif args[:2] == ["image", "inspect"]:
                image_config = {"Env": []}
                if self.mount_examples and args[2] == "sha256:other":
                    image_config["Volumes"] = {"/run/user/wolf": {}}
                output = json.dumps([{"Id": args[2], "Config": image_config, "RepoDigests": self.repo_digests.get(args[2], [])}])
            elif args[:2] == ["volume", "inspect"]:
                output = json.dumps([{"Name": "a" * 64, "Driver": "local", "Scope": "local",
                    "Mountpoint": "/var/lib/docker/volumes/" + "a" * 64 + "/_data", "Options": None}])
            elif args[0] == "exec":
                assert args[3:] == ["python", "-I", "-B", "-"], args
                if self.fail_liveness and self.recreated:
                    return subprocess.CompletedProcess(command, 65, "", "suppressed")
                files = self.root / "srv/docker-compose/current/services/data/litellm"
                output = json.dumps({"config_sha256": "old" if self.wrong_loaded and self.recreated else self.m.sha((files / "config.yaml").read_bytes()),
                    "callback_sha256": self.m.sha((files / "custom_callbacks.py").read_bytes()),
                    "server_pid": 1, "server_start_ticks": "200" if self.recreated else "100",
                    "argv_sha256": "argv", "environment_sha256": "env", "version": "1.94.0", "liveness": True})
            else:
                raise AssertionError(command)
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, output, "")


if __name__ == "__main__":
    unittest.main()
