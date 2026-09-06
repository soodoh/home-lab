#!/usr/bin/env python3
"""Offline capability fixtures; Linux/root filesystem cases run in a child chroot."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "infrastructure/maintenance/host"


def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(HOST / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


observer = load("maintenance-read-only-observer")
transport = load("maintenance-plan-transport")
ARGS = ["observe", "a" * 64, "b" * 40, "c" * 64]


def fixture(host="debian", proposal=None):
    proposal = proposal or {"version": 2, "host": host, "metadata_refresh_performed": False}
    sources = {
        "producer": (HOST / "maintenance-read-only-observer").read_bytes(),
        "transport": (HOST / "maintenance-plan-transport").read_bytes(),
        "package": ("def observe(host):\n    return " + repr(proposal) + "\n").encode(),
        "machine": b"0123456789abcdef0123456789abcdef\n",
    }
    policy = {"version": 1, "host": host, "source_commit": ARGS[2], "contract_sha256": ARGS[3]}
    for source, field in (("producer", "producer_sha256"), ("package", "package_producer_sha256"),
                          ("transport", "transport_sha256"), ("machine", "machine_id_sha256")):
        policy[field] = observer.digest(sources[source])
    sources["policy"] = observer.canonical(policy)
    return sources


class CapabilityTests(unittest.TestCase):
    def test_real_alarm_at_spawn_return_cleans_up_and_restores_handler(self):
        launch = subprocess.Popen
        children = []
        original = observer.signal.signal(observer.signal.SIGALRM, observer.deadline)

        def interrupted_spawn(*args, **kwargs):
            child = launch(*args, **kwargs)
            children.append(child)
            # Actual signal at the boundary before Popen's reference reaches
            # the caller. The old implementation leaked this child.
            os.kill(os.getpid(), observer.signal.SIGALRM)
            return child

        try:
            with patch.object(observer.subprocess, "Popen", side_effect=interrupted_spawn), self.assertRaises(observer.Refusal):
                observer.bounded_process([sys.executable, "-I", "-c", "import time; time.sleep(10)"], timeout=5)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
            self.assertIs(observer.signal.getsignal(observer.signal.SIGALRM), observer.deadline)
            with patch.object(observer.subprocess, "Popen", side_effect=OSError("synthetic spawn failure")), self.assertRaises(OSError):
                observer.bounded_process(["/never-executed"])
            self.assertIs(observer.signal.getsignal(observer.signal.SIGALRM), observer.deadline)
        finally:
            observer.signal.signal(observer.signal.SIGALRM, original)
            for child in children:
                if child.returncode is None:
                    os.killpg(child.pid, observer.signal.SIGKILL)
                    child.wait(timeout=2)
                child.stdout.close(); child.stderr.close()

    def test_real_streaming_command_capture_and_cleanup(self):
        launch = subprocess.Popen
        children = []

        def tracked(*args, **kwargs):
            child = launch(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(observer, "MAX_BYTES", 4096), patch.object(observer.subprocess, "Popen", side_effect=tracked):
            result = observer.bounded_process([sys.executable, "-I", "-c",
                "import os; os.write(1,b'o'*2048); os.write(2,b'e'*2048)"], timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"o"*2048, b"e"*2048))
            for stdout, stderr in ((10000000, 0), (0, 10000000), (3000, 3000)):
                program = f"import os,time; os.write(1,b'o'*{stdout}); os.write(2,b'e'*{stderr}); time.sleep(10)"
                started = time.monotonic()
                with self.subTest(stdout=stdout, stderr=stderr), self.assertRaises(observer.Refusal):
                    observer.bounded_process([sys.executable, "-I", "-c", program], timeout=5)
                self.assertLess(time.monotonic() - started, 5)
                self.assertIsNotNone(children[-1].returncode)
            with self.assertRaises((observer.Refusal, subprocess.TimeoutExpired)):
                observer.bounded_process([sys.executable, "-I", "-c", "import time; time.sleep(10)"], timeout=0.1)
            with patch.object(observer.selectors.DefaultSelector, "select", side_effect=observer.Refusal("synthetic outer deadline")), self.assertRaises(observer.Refusal):
                observer.bounded_process([sys.executable, "-I", "-c", "import os,time; os.write(1,b'x'); time.sleep(10)"], timeout=5)
        for child in children:
            self.assertIsNotNone(child.returncode)
            self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_pinned_package_commands_use_streaming_runner(self):
        sources = fixture()
        sources["package"] = ("def run(*args): raise AssertionError('standalone capture must not run')\n"
            "def observe(host):\n"
            "    run(['/fixed/package-command'], 30)\n"
            "    return {'version':2,'host':host,'metadata_refresh_performed':False}\n").encode()
        policy = json.loads(sources["policy"])
        policy["package_producer_sha256"] = observer.digest(sources["package"])
        sources["policy"] = observer.canonical(policy)
        with patch.object(observer, "bounded_process") as command:
            self.invoke(sources)
        command.assert_called_once_with(["/fixed/package-command"], 30, env={**observer.ENV, "DEBIAN_FRONTEND": "noninteractive"})
    def test_exact_transport_and_no_shell_escape(self):
        command = " ".join(ARGS)
        expected = ["/usr/bin/sudo", "-n", "--", transport.OBSERVER, *ARGS]
        self.assertEqual(transport.arguments(["-c", command], ""), expected)
        hostile = [command + tail for tail in ("\n", ";id", " && id", " ", "\x00", "\t")]
        hostile += [" " + command, command.replace("observe ", "observe  "), "sh", "-c id",
                    command.replace("a" * 64, "A" * 64), "observe $(id)"]
        for value in hostile:
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport.arguments(["-c", value], "")
        for argv, original in (([], ""), ([command], ""), (["-c", command, "id"], ""),
                               (["-c", command], "id")):
            with self.assertRaises(ValueError):
                transport.arguments(argv, original)

    def test_request_has_no_path_code_or_operation_input(self):
        self.assertEqual(observer.request(ARGS), ARGS[1:])
        for args in ([], ARGS + ["/tmp/policy"], ["apply", *ARGS[1:]],
                     ["observe", "a" * 65, *ARGS[2:]], ["observe", ARGS[1], "b" * 39, ARGS[3]],
                     ["observe", ARGS[1], ARGS[2], "c" * 64 + "\n"]):
            with self.assertRaises(observer.Refusal):
                observer.request(args)

    def test_policy_binds_all_installed_sources_and_host(self):
        sources = fixture()
        self.assertEqual(observer.installed(sources, *ARGS[2:])["host"], "debian")
        for key in sources:
            wrong = dict(sources)
            wrong[key] += b"changed"
            with self.subTest(key=key), self.assertRaises((observer.Refusal, ValueError)):
                observer.installed(wrong, *ARGS[2:])
        for key, value in (("version", True), ("host", "vm9900"), ("source_commit", "d" * 40),
                           ("contract_sha256", "d" * 64), ("extra", True)):
            wrong = dict(sources)
            policy = json.loads(wrong["policy"])
            policy[key] = value
            wrong["policy"] = observer.canonical(policy)
            with self.subTest(key=key), self.assertRaises(observer.Refusal):
                observer.installed(wrong, *ARGS[2:])
        for raw in (b'{"version":1,"version":1}', b'{"version":NaN}', b"[]", b"null"):
            wrong = dict(sources, policy=raw)
            with self.assertRaises(observer.Refusal):
                observer.installed(wrong, *ARGS[2:])

    def invoke(self, sources, reads=None):
        fixed = {observer.PATHS[key]: value for key, value in sources.items()}
        with patch.object(observer, "read_trusted", side_effect=reads or fixed.__getitem__), \
                patch.object(observer, "lock_observation", side_effect=[["backup"], ["operation"]]), \
                patch.object(observer, "reboot_observation", return_value={"required": None, "backup_proven": False}):
            return observer.observe(ARGS)

    def test_both_hosts_preserve_challenge_and_never_authorize(self):
        for host in ("debian", "proxmox"):
            sources = fixture(host)
            result = self.invoke(sources)
            self.assertEqual(result["format"], "home-lab-maintenance-observation-v1")
            self.assertEqual(result["host"], host)
            self.assertEqual([result[k] for k in ("nonce", "source_commit", "contract_sha256")], ARGS[1:])
            self.assertEqual(result["producer_sha256"], observer.digest(sources["producer"]))
            self.assertEqual(result["package_sha256"], observer.digest(sources["package"]))
            self.assertEqual(result["transport_sha256"], observer.digest(sources["transport"]))
            self.assertEqual(result["active_locks"], ["backup", "operation"])
            self.assertIsNone(result["reboot"]["required"])
            for field in ("authorized", "automatic_apply", "automatic_reboot", "automatic_retry_allowed"):
                self.assertIs(result[field], False)

    def test_changed_dependency_during_observation_refuses(self):
        sources = fixture()
        sequence = list(sources[k] for k in observer.PATHS)
        for key in observer.PATHS:
            again = [sources[k] + (b"changed" if k == key else b"") for k in observer.PATHS]
            with self.subTest(key=key), self.assertRaises(observer.Refusal):
                self.invoke(sources, reads=sequence + again)

    def test_wrong_package_host_version_or_refresh_refuses(self):
        proposal = {"version": 2, "host": "debian", "metadata_refresh_performed": False}
        for key, value in (("version", True), ("version", 1), ("host", "proxmox"),
                           ("metadata_refresh_performed", True), ("metadata_refresh_performed", 0)):
            wrong = dict(proposal)
            wrong[key] = value
            with self.assertRaises(observer.Refusal):
                self.invoke(fixture(proposal=wrong))

    def locks(self, stdout, returncode=0, stderr=b""):
        result = SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)
        with patch.object(observer, "bounded_process", return_value=result) as command, \
                patch.object(observer.os, "lstat", side_effect=FileNotFoundError):
            value = observer.lock_observation()
            self.assertIn("--notruncate", command.call_args.args[0])
            self.assertEqual(command.call_args.kwargs["env"], observer.ENV)
            return value

    def test_lock_output_strict_and_retained_mutex_not_presence_lock(self):
        self.assertEqual(self.locks(b""), [])
        self.assertEqual(self.locks(b'{"locks":[]}'), [])
        self.assertEqual(self.locks(b'{"locks":[{"path":"/var/lib/home-lab/reconciliation/operation.lock"}]}'), ["operation"])
        self.assertNotIn("/var/lib/home-lab/reconciliation/operation.lock", observer.RETAINED)
        for raw in (b"{}", b"[]", b'{"locks":null}', b'{"locks":[{}]}',
                    b'{"locks":[{"path":12}]}', b'{"locks":[{"path":null}]}',
                    b'{"locks":[{"path":"unknown"}]}', b'{"locks":[{"path":"/run/lock/unrecognized.lock"}]}',
                    b'{"locks":[],"locks":[]}'):
            with self.assertRaises(observer.Refusal):
                self.locks(raw)
        for code, error in ((1, b""), (0, b"warning")):
            with self.assertRaises(observer.Refusal):
                self.locks(b"", code, error)
        with self.assertRaises(observer.Refusal):
            self.locks(b" " * (observer.MAX_BYTES + 1))

    def test_retained_apply_record_blocks_without_a_descriptor_holder(self):
        retained = "/var/lib/home-lab/reconciliation/apply.lock"
        mutex = "/var/lib/home-lab/reconciliation/operation.lock"
        result = SimpleNamespace(stdout=b'{"locks":[]}', stderr=b"", returncode=0)
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "record"
            actual_lstat = os.lstat

            def observed_lstat(path):
                if path == retained:
                    return actual_lstat(record)
                if path == mutex:
                    raise AssertionError("descriptor mutex must not be a presence lock")
                raise FileNotFoundError(path)

            for kind in ("absent", "regular", "dangling-symlink", "fifo"):
                if kind == "regular":
                    record.write_bytes(b"retained exact reboot owner\n")
                elif kind == "dangling-symlink":
                    record.symlink_to("missing-target")
                elif kind == "fifo":
                    os.mkfifo(record)
                with patch.object(observer, "bounded_process", return_value=result), \
                        patch.object(observer.os, "lstat", side_effect=observed_lstat):
                    self.assertEqual(observer.lock_observation(), [] if kind == "absent" else ["apply-owner"], kind)
                if kind != "absent":
                    if kind == "regular":
                        self.assertEqual(record.read_bytes(), b"retained exact reboot owner\n")
                    record.unlink()

    def test_reboot_absence_or_unsafe_is_unknown_not_false(self):
        for error in (FileNotFoundError(), PermissionError(), observer.Refusal()):
            with patch.object(observer, "read_trusted", side_effect=error):
                self.assertEqual(observer.reboot_observation(), {"required": None, "backup_proven": False})
        with patch.object(observer, "read_trusted", return_value=b"reboot required\n"):
            self.assertEqual(observer.reboot_observation(), {"required": True, "backup_proven": False})

    def test_deadline_and_cli_failure_do_not_disclose_inputs(self):
        with self.assertRaises(observer.Refusal):
            observer.deadline(None, None)
        for filename in ("maintenance-read-only-observer", "maintenance-plan-transport"):
            result = subprocess.run([sys.executable, "-I", str(HOST / filename), "secret-test-sentinel"],
                                    capture_output=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"secret-test-sentinel", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "requires Linux root child chroot")
    def test_native_descriptor_reads(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-read-fixture-") as root:
            trusted = Path(root) / "trusted"
            trusted.mkdir(mode=0o755)
            (trusted / "file").write_bytes(b"fixture\n")
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--native-child", root],
                                    capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b"native-filesystem-fixtures=passed", result.stdout)


def native_child(root):
    # No host filesystem changes: only this subprocess enters the disposable root.
    os.chroot(root)
    os.chdir("/")
    path = "/trusted/file"
    assert observer.read_trusted(path) == b"fixture\n"

    def refused(candidate):
        try:
            observer.read_trusted(candidate)
        except (observer.Refusal, OSError):
            return
        raise AssertionError("unsafe filesystem entry accepted")

    os.symlink("file", "/trusted/link")
    refused("/trusted/link")
    os.symlink("trusted", "/ancestor")
    refused("/ancestor/file")
    os.mkfifo("/trusted/fifo")
    refused("/trusted/fifo")
    os.link(path, "/trusted/hardlink")
    refused(path)
    os.unlink("/trusted/hardlink")
    os.chmod(path, 0o666)
    refused(path)
    os.chmod(path, 0o644)
    os.chown(path, 1, 0)
    refused(path)
    os.chown(path, 0, 0)
    os.chmod("/trusted", 0o777)
    refused(path)
    os.chmod("/trusted", 0o755)
    with patch.object(observer.os, "read", return_value=b""):
        refused(path)
    actual_read = os.read

    def raced_read(fd, size):
        raw = actual_read(fd, size)
        os.chmod(path, 0o600)
        return raw

    with patch.object(observer.os, "read", side_effect=raced_read):
        refused(path)
    print("native-filesystem-fixtures=passed", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--native-child":
        native_child(sys.argv[2])
    else:
        unittest.main()
