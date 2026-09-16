#!/usr/bin/env python3
"""Fixture-only tests for guarded Proxmox activation and rollback."""

from __future__ import annotations

import base64
import copy
import datetime as dt
from contextlib import ExitStack, redirect_stderr
import hashlib
import hmac
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
sys.path.insert(0, str(NIX / "proxmox"))
import planner
import apply as guarded_apply
import prepare as private_prepare

bundle_spec = importlib.util.spec_from_file_location("proxmox_bundle_apply_tests", NIX / "proxmox/bundle.py")
if bundle_spec is None or bundle_spec.loader is None:
    raise RuntimeError("unable to load bundle builder")
bundle = importlib.util.module_from_spec(bundle_spec)
bundle_spec.loader.exec_module(bundle)


class ProxmoxNixRetirementBoundaryTests(unittest.TestCase):
    """Offline retirement limits, not evidence of installed or recovered sessions."""

    def test_current_freeze_blocks_prepare_and_apply_before_retained_session_access(self) -> None:
        projection = json.loads((NIX / "proxmox/projection.json").read_bytes())
        self.assertIs(projection["nixMutationFrozen"], True)
        args = SimpleNamespace(repo_root=str(ROOT), plan_sha="a" * 64, approve_plan_sha="a" * 64)
        # Do not execute bundle verification: it invokes the rendered observer.
        # In particular, no real .reconcile inputs or retained sessions are read.
        effects = (
            (guarded_apply, "load_secure_canonical"), (guarded_apply, "controller_lock"),
            (guarded_apply, "send_session"), (private_prepare, "send"),
            (private_prepare, "write_exclusive"), (planner, "open_live_output_directory"),
            (subprocess, "run"),
        )
        for entrypoint in (guarded_apply.apply, private_prepare.prepare):
            with self.subTest(entrypoint=entrypoint.__name__), ExitStack() as stack:
                inputs = stack.enter_context(patch.object(
                    planner, "bundle_inputs", return_value=({}, projection, {}, {})))
                guards = [stack.enter_context(patch.object(
                    module, name, side_effect=AssertionError(f"unexpected effect: {name}")))
                    for module, name in effects]
                with self.assertRaisesRegex(ValueError, "frozen"):
                    entrypoint(args, Path("fixed"), Path("fixed.sha"), Path("source"))
                inputs.assert_called_once()
                for guard in guards:
                    guard.assert_not_called()

    def test_no_standalone_session_recovery_cli(self) -> None:
        for command in ("status", "rollback"):
            with self.subTest(command=command), patch.object(
                    sys, "argv", ["proxmox-host", command, "--repo-root", str(ROOT)]), \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                planner.parse_args()
            self.assertEqual(error.exception.code, 64)

    def test_every_allowlisted_nix_file_remains_source_bound(self) -> None:
        # Copy only known source files; never traverse operational artifacts or
        # execute helpers. Missing files and byte substitutions must fail closed.
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "nix"
            for relative in planner.APPROVED_SOURCE_FILES:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((NIX / relative).read_bytes())
            planner.sanitized_source_binding(source, NIX)
            for relative in sorted(planner.APPROVED_SOURCE_FILES):
                target = source / relative
                original = target.read_bytes()
                with self.subTest(file=relative, change="missing"):
                    target.unlink()
                    with self.assertRaisesRegex(ValueError, "exact allowlist"):
                        planner.sanitized_source_binding(source, NIX)
                with self.subTest(file=relative, change="substituted"):
                    target.write_bytes(original + b"\n")
                    with self.assertRaisesRegex(ValueError, "source binding failed"):
                        planner.sanitized_source_binding(source, NIX)
                target.write_bytes(original)
            planner.sanitized_source_binding(source, NIX)


# Retained observer -> preparer dependency regression. No installed helper runs.
LIBEXEC = "/usr/local/libexec/home-lab/"
ACTIVATOR = LIBEXEC + "proxmox-activator"
PREPARER = LIBEXEC + "proxmox-private-preparer"
OBSERVER = LIBEXEC + "proxmox-observer"
RUNTIME = "/var/lib/home-lab/reconciliation/"
OBSERVATION_HELPER_HASHES = {
    "proxmox-observer": "edb7ff95e6b8bfbfaa0227a07c521c2fe26e1f53e92b29d21d67ea17c4f3553f",
    "proxmox-private-preparer": "7d667609e11f4b66be75b45c5c04176fc4c6712fdc72e1f6254d220eab494b75",
}


def observation_canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class ObservationFixtureOS:
    """Map absolute helper paths to a temporary tree; never expose host paths."""
    def __init__(self, root):
        self.root, self.fds, self.reads, self.output = root, {}, [], []

    def mapped(self, path, dir_fd=None):
        virtual = str(path)
        if not virtual.startswith("/"):
            virtual = str(Path(self.fds[dir_fd]) / virtual)
        if ".." in Path(virtual).parts:
            raise AssertionError("fixture traversal")
        self.reads.append(virtual)
        if virtual == ACTIVATOR:
            raise AssertionError("observation touched the activator")
        return virtual, self.root / virtual.lstrip("/")

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        virtual, real = self.mapped(path, dir_fd)
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            if virtual != RUNTIME + "operation.lock":
                raise AssertionError("unexpected fixture write")
        fd = os.open(real, flags, mode)
        self.fds[fd] = virtual
        return fd

    def close(self, fd):
        os.close(fd)
        self.fds.pop(fd, None)

    @staticmethod
    def as_root(info):
        # Model root UID/GID only; preserve real mode, type, links and fingerprints.
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**{**fields, "st_uid": 0, "st_gid": 0})

    def fstat(self, fd):
        assert fd in self.fds
        return self.as_root(os.fstat(fd))

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        _, real = self.mapped(path, dir_fd)
        return self.as_root(os.stat(real, follow_symlinks=follow_symlinks))

    def read(self, fd, size):
        assert fd in self.fds
        return os.read(fd, size)

    def write(self, fd, raw):
        assert fd == 1, "only canonical fixture stdout may be written"
        self.output.append(raw)
        return len(raw)

    def __getattr__(self, name):
        if name.startswith("O_"):
            return getattr(os, name)
        raise AssertionError("unmodelled OS effect: " + name)


class ProxmoxObservationWithoutActivatorTests(unittest.TestCase):
    """Real rendered protected-observation path; simulated host/HTTP/root metadata."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fs = ObservationFixtureOS(self.root)
        fs = self.fs

        class FixturePath(type(Path())):
            def lstat(self):
                return fs.stat(str(self), follow_symlinks=False)

            def read_bytes(self):
                _, real = fs.mapped(str(self))
                return real.read_bytes()

        projection = json.loads((NIX / "proxmox/projection.json").read_bytes())
        self.modules = {}
        for name, expected in OBSERVATION_HELPER_HASHES.items():
            raw = bundle.expected_helper_content(name, projection)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected,
                             "reassess the inspected installed generation before updating this test")
            self.put(LIBEXEC + name, raw, 0o755)
            module = {"__name__": "fixture_" + name, "__file__": LIBEXEC + name, "Path": FixturePath}
            exec(compile(raw, name, "exec"), module)
            module.update(Path=FixturePath, os=self.fs)
            self.modules[name] = module
        self.observer = self.modules["proxmox-observer"]
        self.preparer = self.modules["proxmox-private-preparer"]
        # Rebind constants created at template import to virtual fixture Paths.
        for name in ("ROOT", "PROTECTED", "PROTECTED_MAC", "KEY", "INSTALL", "OPERATION_LOCK", "APPLY_LOCK", "ANSIBLE_LOCK"):
            self.preparer[name] = FixturePath(str(self.preparer[name]))
        self.preparer["pwd"] = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=0, pw_gid=0))
        self.calls = []
        self.dispatches = 0
        self.http_status = 200
        fake_subprocess = SimpleNamespace(run=self.command, DEVNULL=subprocess.DEVNULL,
                                          TimeoutExpired=subprocess.TimeoutExpired)
        self.observer["subprocess"] = self.preparer["subprocess"] = fake_subprocess
        self.observer["sys"] = SimpleNamespace(argv=[OBSERVER, "observe"])
        self.preparer["sys"] = SimpleNamespace(argv=[PREPARER, "summary"])
        # Isolate unrelated public observer domains; do not stub observe(),
        # protected_summaries(), run/run_result, main(), summaries(), or readers.
        for name in ("file_record", "fragment_record", "artifact_record", "audit_record"):
            self.observer[name] = lambda item: ({"target": item["target"]}, True)
        self.observer["unexpected_regular_count"] = lambda *args: 0
        self.observer["public_summaries"] = lambda: [self.observer["summary"]()] * 7
        for name in ("accounts", "packages", "services", "timezone"):
            self.observer[name] = lambda: self.observer["records_domain"](None)
        self.observer["host"] = lambda: {"fixture": True}
        self.key = b"synthetic-session-key-" * 2
        self.members = [f"/dev/disk/by-id/synthetic-member-{i:02d}" for i in range(12)]
        self.state = {
            "format": "home-lab-proxmox-protected-inputs-v1",
            "access": {
                "planKeys": ["ssh-ed25519 " + base64.b64encode(b"A" * 32).decode()],
                "applyKeys": ["ssh-ed25519 " + base64.b64encode(b"B" * 32).decode()],
                "firewallKeys": ["ssh-ed25519 " + base64.b64encode(b"C" * 32).decode()],
                "planTokenIdentity": "root@pam!tofu-plan", "applyTokenIdentity": "root@pam!tofu-apply",
                "planToken": "root@pam!tofu-plan=synthetic-plan-token",
                "applyToken": "root@pam!tofu-apply=synthetic-apply-token",
            },
            "hardware": {"gamesDiskIdentity": "/dev/disk/by-id/synthetic-games", "poolGuid": "123456789",
                         "poolMembers": self.members, "usbMappings": [
                             {"mapping": "zigbee-cp210x", "port": "1-2", "serial": "synthetic-usb-a"},
                             {"mapping": "zwave-cp210x", "port": "1-3", "serial": "synthetic-usb-b"}]},
        }
        self.put(RUNTIME + "session.key", self.key)
        self.put(RUNTIME + "operation.lock", b"")
        for principal in ("plan", "apply"):
            self.put(f"/root/.config/home-lab/proxmox-{principal}-token.env",
                     ("PROXMOX_VE_API_TOKEN=" + self.state["access"][principal + "Token"] + "\n").encode())
        self.write_state()
        # No install manifest is supplied either: reading it must fail, not be mocked.
        self.http = patch("urllib.request.urlopen", side_effect=self.request)
        self.http.start()
        self.addCleanup(self.http.stop)

    def put(self, path, raw, mode=0o600):
        real = self.root / path.lstrip("/")
        real.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        real.write_bytes(raw)
        real.chmod(mode)

    def write_state(self):
        raw = observation_canonical(self.state)
        self.put(RUNTIME + "protected-inputs.json", raw)
        self.put(RUNTIME + "protected-inputs.mac", hmac.new(self.key, raw, hashlib.sha256).hexdigest().encode() + b"\n")

    def request(self, request, **kwargs):
        self.assertEqual(request.full_url, "https://127.0.0.1:8006/api2/json/version")
        self.assertIn(request.get_header("Authorization"), ["PVEAPIToken=" + self.state["access"][p + "Token"] for p in ("plan", "apply")])
        status = self.http_status

        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, maximum): return b"{}"
        response = Response()
        response.status = status
        return response

    def command(self, args, **kwargs):
        args = tuple(args)
        self.calls.append(args)
        if args == (PREPARER, "summary"):
            self.dispatches += 1
            saved = self.fs.output
            self.fs.output = []
            try:
                code = self.preparer["main"]()
                return subprocess.CompletedProcess(args, code, b"".join(self.fs.output), b"")
            except ValueError:
                return subprocess.CompletedProcess(args, 1, b"", b"fixture preparer refused")
            finally:
                self.fs.output = saved
        if args[:3] == ("/usr/bin/pvesh", "get", "/access/acl"):
            raw = observation_canonical([{"path": path, "propagate": 1, "roleid": role, "ugid": "root@pam!tofu-" + principal}
                             for principal, path, role in (("apply", "/", "HomeLabTofuApply"),
                                 ("plan", "/", "HomeLabTofuPlan"), ("plan", "/vms/100", "HomeLabTofuPlanDiskInspect"),
                                 ("plan", "/vms/9900", "HomeLabTofuPlanDiskInspect"))])
        elif args in [("/usr/bin/pvesh", "get", f"/access/users/root@pam/token/tofu-{p}", "--output-format", "json") for p in ("plan", "apply")]:
            raw = b'{"privsep":1}\n'
        elif args in [("/usr/bin/pvesh", "get", "/cluster/mapping/usb/" + m, "--output-format", "json") for m in ("zigbee-cp210x", "zwave-cp210x")]:
            raw = observation_canonical({"map": [{"node": "proxmox", "path": "1-2" if args[2].endswith("zigbee-cp210x") else "1-3"}]})
        elif args == ("/usr/sbin/qm", "config", "100"):
            raw = b"scsi1: /dev/disk/by-id/synthetic-games,backup=0\n"
        elif args == ("/usr/sbin/zpool", "get", "-H", "-o", "value", "guid", "storage"):
            raw = b"123456789\n"
        elif args == ("/usr/sbin/zpool", "status", "-P", "storage"):
            raw = ("\n".join(line for i in range(6) for line in
                   (f"  mirror-{i} ONLINE", f"    {self.members[2*i]} ONLINE", f"    {self.members[2*i+1]} ONLINE")) + "\n").encode()
        elif args == ("/usr/bin/udevadm", "info", "--export-db"):
            raw = b"P: /devices/usb1/1-2\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=synthetic-usb-a\n\nP: /devices/usb1/1-3\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=synthetic-usb-b\n"
        else:
            raise AssertionError("unmodelled command; no real subprocess is allowed")
        return subprocess.CompletedProcess(args, 0, raw, b"")

    def observe(self):
        self.fs.output = []
        # A leaked real subprocess/network path must never silently reach the host.
        with patch("subprocess.run", side_effect=AssertionError("real subprocess forbidden")):
            self.assertEqual(self.observer["main"](), 0)
        self.assertFalse(self.fs.fds, "all real temporary descriptors must be released")
        self.assertNotIn(ACTIVATOR, self.fs.reads)
        raw = b"".join(self.fs.output)
        for private in (b"synthetic-", self.key, self.state["hardware"]["poolGuid"].encode()):
            self.assertNotIn(private, raw)
        value = json.loads(raw)
        self.assertEqual(raw, observation_canonical(value))
        return {name: value["domains"][name] for name in ("protectedAccess", "protectedHardware")}

    def test_actual_summary_path_is_identical_with_activator_absent(self):
        self.put(ACTIVATOR, b"synthetic activator must never be opened", 0o755)
        before = self.observe()
        (self.root / ACTIVATOR.lstrip("/")).unlink()
        self.fs.reads.clear()
        after = self.observe()
        self.assertEqual(before, after)
        self.assertEqual(after, {name: {"expectedCount": 3, "observedCount": 3, "matches": True, "status": "complete"}
                                 for name in ("protectedAccess", "protectedHardware")})
        self.assertEqual(self.dispatches, 2)
        for name in ("protected-inputs.json", "protected-inputs.mac", "session.key", "operation.lock"):
            self.assertIn(RUNTIME + name, self.fs.reads)
        self.assertNotIn(RUNTIME + "install-manifest.json", self.fs.reads)
        self.assertFalse((self.root / ACTIVATOR.lstrip("/")).exists())
        self.assertTrue(self.calls)

    def test_missing_key_and_bad_mac_still_fail_closed(self):
        for defect in ("key", "mac"):
            with self.subTest(defect=defect):
                self.put(RUNTIME + "session.key", self.key)
                self.write_state()
                if defect == "key": (self.root / (RUNTIME + "session.key").lstrip("/")).unlink()
                else: self.put(RUNTIME + "protected-inputs.mac", b"0" * 64 + b"\n")
                self.assertTrue(all(x["status"] == "unavailable" for x in self.observe().values()))

    def test_preparer_hash_and_mode_are_still_checked_before_dispatch(self):
        p = self.root / PREPARER.lstrip("/")
        original = p.read_bytes()
        for defect in ("bytes", "mode"):
            with self.subTest(defect=defect):
                self.put(PREPARER, original + (b"\n" if defect == "bytes" else b""), 0o644 if defect == "mode" else 0o755)
                self.assertTrue(all(x["status"] == "unavailable" for x in self.observe().values()))
                self.assertEqual(self.dispatches, 0)

    def test_hardware_token_and_retained_owner_guards_are_not_bypassed(self):
        self.state["hardware"]["poolGuid"] = "987654321"
        self.write_state()
        self.assertFalse(self.observe()["protectedHardware"]["matches"])
        self.state["hardware"]["poolGuid"] = "123456789"
        self.write_state()
        self.http_status = 403
        self.assertFalse(self.observe()["protectedAccess"]["matches"])
        self.http_status = 200
        self.put("/var/lib/iac-ansible-production.lock", b"synthetic owner")
        self.assertTrue(all(x["status"] == "unavailable" for x in self.observe().values()))


class ProxmoxNixApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.projection = json.loads((NIX / "proxmox/projection.json").read_bytes())
        cls.projection["nixMutationFrozen"] = False
        next(item for item in cls.projection["planningPolicy"]["domains"] if item["domain"] == "managed-artifacts")["automatic"] = True
        cls.manifest = json.loads((NIX / "proxmox/package-manifest.json").read_bytes())
        cls.before_observation = json.loads((NIX / "proxmox/fixture-observation.json").read_bytes())
        cls.before_observation["domains"]["protectedAccess"] = {"expectedCount": 6, "matches": True, "observedCount": 6, "status": "complete"}
        cls.before_observation["domains"]["protectedHardware"] = {"expectedCount": 3, "matches": True, "observedCount": 3, "status": "complete"}
        projected_account_names = {account["name"] for kind in ("service", "human") for account in cls.projection["accounts"][kind]}
        cls.before_observation["domains"]["accounts"]["records"] = [
            record for record in cls.before_observation["domains"]["accounts"]["records"]
            if record["name"] in projected_account_names
        ]
        for record in cls.before_observation["domains"]["accounts"]["records"]:
            if record["name"] == "tofu-apply":
                record["shell"] = "/usr/local/libexec/home-lab/proxmox-apply-transport"
                record["expectedGroupsMatch"] = True
        observed_names = {record["name"] for record in cls.before_observation["domains"]["accounts"]["records"]}
        for account in cls.projection["accounts"]["service"]:
            if account["name"] not in observed_names:
                cls.before_observation["domains"]["accounts"]["records"].append({
                    "commentMatches": True, "exists": True, "expectedGroupsMatch": True,
                    "home": account["home"], "name": account["name"], "passwordLocked": True,
                    "primaryGroupMatches": True, "shell": account["shell"],
                })
        cls.before_observation["domains"]["accounts"]["records"].sort(key=lambda record: record["name"])
        cls.before_observation["domains"]["auditAbsence"]["records"] = [
            {"count": 0, "target": absence["path"], "type": absence["absence"]}
            for absence in cls.projection["auditAbsence"]
        ]
        managed_records = cls.before_observation["domains"]["managedFiles"]["records"]
        projected_managed_targets = {managed["path"] for managed in cls.projection["managedFiles"]}
        managed_records[:] = [record for record in managed_records if record["target"] in projected_managed_targets]
        managed_targets = {record["target"] for record in managed_records}
        for managed in cls.projection["managedFiles"]:
            if managed["path"] not in managed_targets:
                managed_records.append({"contentMatches": True, "groupMatches": True, "mode": managed["mode"],
                                        "ownerMatches": True, "target": managed["path"], "type": "file"})
        managed_records.sort(key=lambda record: record["target"])
        cls.bindings = {
            "activationEnvelopeSchemaSha256": "7" * 64, "activatorSha256": "8" * 64,
            "bundleContentSha256": "1" * 64, "bundleFormat": planner.BUNDLE_FORMAT,
            "flakeLockSha256": "2" * 64, "gitCommit": "3" * 40, "gitTree": "4" * 40,
            "observerProtocol": 4, "observerSha256": cls.before_observation["observerSha256"],
            "packageManifestSha256": "6" * 64, "planSchemaSha256": "9" * 64,
            "privatePreconditionsSchemaSha256": "a" * 64, "privatePreparationRequestSchemaSha256": "b" * 64,
            "privatePreparerSha256": "c" * 64, "projectionSha256": "5" * 64,
        }
        cls.metadata = {
            "activationEnvelopeSchemaSha256": cls.bindings["activationEnvelopeSchemaSha256"],
            "helperSha256": {"proxmox-activator": cls.bindings["activatorSha256"],
                             "proxmox-observer": cls.bindings["observerSha256"],
                             "proxmox-private-preparer": cls.bindings["privatePreparerSha256"]},
            "privatePreconditionsSchemaSha256": cls.bindings["privatePreconditionsSchemaSha256"],
            "privatePreparationRequestSchemaSha256": cls.bindings["privatePreparationRequestSchemaSha256"],
        }
        plan_start = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.plan = planner.build_plan(cls.bindings, cls.projection, cls.manifest, cls.before_observation,
                                      planner.format_time(plan_start), planner.format_time(plan_start + dt.timedelta(seconds=1)), False)
        if cls.plan["status"] != "ready" or len(cls.plan["actions"]) != 1:
            raise RuntimeError(f"apply fixture must be a one-action ready plan: {json.dumps({'status': cls.plan['status'], 'blockers': cls.plan['blockers'], 'findings': cls.plan['findings'], 'actions': cls.plan['actions']}, sort_keys=True)}")
        cls.after_observation = copy.deepcopy(cls.before_observation)
        action = cls.plan["actions"][0]
        records = cls.after_observation["domains"]["managedArtifacts"]["records"]
        record = next(value for value in records if value["target"] == action["target"]["path"])
        record.update({key: value for key, value in action["after"].items() if key != "state"})
        rendered = bundle.expected_helper_content("proxmox-activator", cls.projection)
        cls.activator = {"__name__": "fixed_activator_test", "__file__": "/tmp/fixed-proxmox-activator"}
        exec(compile(rendered, "fixed-proxmox-activator", "exec"), cls.activator)

    def sidecar(self, now: dt.datetime | None = None) -> dict:
        now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        expires = now + dt.timedelta(seconds=60)
        return {
            "actionManifestSha256": planner.digest(self.plan["actions"]),
            "attestations": {
                "protectedAccess": {"expectedCount": 5, "keyedAttestation": "b" * 64, "matches": True},
                "protectedHardware": {"expectedCount": 3, "keyedAttestation": "c" * 64, "matches": True},
            },
            "bindings": {
                "activationEnvelopeSchemaSha256": self.bindings["activationEnvelopeSchemaSha256"],
                "activatorSha256": self.bindings["activatorSha256"],
                "bundleContentSha256": self.bindings["bundleContentSha256"],
                "flakeLockSha256": self.bindings["flakeLockSha256"],
                "gitCommit": self.bindings["gitCommit"], "gitTree": self.bindings["gitTree"],
                "observerSha256": self.bindings["observerSha256"],
                "packageManifestSha256": self.bindings["packageManifestSha256"],
                "planSchemaSha256": self.bindings["planSchemaSha256"],
                "privatePreconditionsSchemaSha256": self.bindings["privatePreconditionsSchemaSha256"],
                "privatePreparationRequestSchemaSha256": self.bindings["privatePreparationRequestSchemaSha256"],
                "privatePreparerSha256": self.bindings["privatePreparerSha256"],
                "projectionSha256": self.bindings["projectionSha256"],
            },
            "challenge": "challenge_0123456789", "createdAt": planner.format_time(now),
            "format": "home-lab-proxmox-private-preconditions-v1",
            "hostSession": {"id": "session_01234567890", "sidecarMac": "d" * 64},
            "operatorGates": {"backupsConfirmed": False, "consoleConfirmed": False,
                              "lanRollbackConfirmed": False, "noConcurrentMutationConfirmed": True},
            "packageSession": None, "planSha256": self.plan["planSha256"],
            "validUntil": planner.format_time(expires),
        }

    def write_inputs(self, root: Path, sidecar: dict | None = None) -> None:
        plans = root / ".reconcile/plans"
        plans.mkdir(parents=True, mode=0o700)
        (root / ".reconcile").chmod(0o700)
        plans.chmod(0o700)
        plan_path = plans / f"{self.plan['planSha256']}.json"
        private_path = plans / f"{self.plan['planSha256']}.private.json"
        plan_path.write_bytes(planner.canonical_json(self.plan))
        private_path.write_bytes(planner.canonical_json(sidecar or self.sidecar()))
        plan_path.chmod(0o600)
        private_path.chmod(0o600)

    def boot_mutation_catalog(self) -> dict:
        projection = copy.deepcopy(self.projection)
        boot_paths = {"/etc/modprobe.d/zfs.conf", "/etc/modules-load.d/home-lab-vfio.conf"}
        for policy in projection["planningPolicy"]["managedFilePolicies"]:
            if policy["path"] in boot_paths:
                policy["automatic"] = True
        next(item for item in projection["planningPolicy"]["domains"]
             if item["domain"] == "managed-fragments")["automatic"] = True
        return bundle.activation_specification(projection, "0" * 64, False)["catalog"]

    def test_private_sidecar_bindings_expiry_gates_and_package_shape(self) -> None:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        guarded_apply.validate_private(self.sidecar(now), self.plan, self.metadata, now)
        cases = []
        wrong = self.sidecar(now); wrong["bindings"]["activatorSha256"] = "e" * 64; cases.append(wrong)
        expired = self.sidecar(now); expired["validUntil"] = planner.format_time(now - dt.timedelta(seconds=1)); cases.append(expired)
        gate = self.sidecar(now); gate["operatorGates"]["noConcurrentMutationConfirmed"] = False; cases.append(gate)
        unknown = self.sidecar(now); unknown["command"] = "id"; cases.append(unknown)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                guarded_apply.validate_private(value, self.plan, self.metadata, now)
        represented = self.sidecar(now)
        represented["packageSession"] = {"completeInstalledMapSha256": "e" * 64,
                                         "handle": "package_012345678", "keyedSimulationAttestation": "f" * 64,
                                         "validUntil": represented["validUntil"]}
        guarded_apply.validate_private(represented, self.plan, self.metadata, now)

    def test_exact_hash_approval_is_mandatory_before_bundle_or_transport(self) -> None:
        args = SimpleNamespace(repo_root=str(ROOT), plan_sha="a" * 64, approve_plan_sha="b" * 64)
        with patch.object(planner, "bundle_inputs") as inputs, patch.object(guarded_apply, "send_session") as transport, \
                self.assertRaisesRegex(ValueError, "approval"):
            guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
        inputs.assert_not_called()
        transport.assert_not_called()

    def test_complete_sidecar_mac_covers_all_private_fields_and_protected_macs_remain_independent(self) -> None:
        sidecar = self.sidecar()
        sidecar["bindings"].update(self.activator["SPEC"]["expectedBindings"])
        key = b"k" * 32
        host_id = sidecar["hostSession"]["id"]
        for name in ("protectedAccess", "protectedHardware"):
            record = sidecar["attestations"][name]
            message = {"challenge": sidecar["challenge"], "expectedCount": record["expectedCount"],
                       "hostSessionId": host_id, "matches": True, "planSha256": sidecar["planSha256"], "type": name}
            record["keyedAttestation"] = self.activator["hmac"].new(
                key, self.activator["canonical"](message), self.activator["hashlib"].sha256).hexdigest()
        def sign(value):
            value["hostSession"]["sidecarMac"] = self.activator["hmac"].new(
                key, self.activator["canonical"](self.activator["sidecar_signing_projection"](value)),
                self.activator["hashlib"].sha256).hexdigest()
        sign(sidecar)
        old_key = self.activator["load_key"]
        try:
            self.activator["load_key"] = lambda: key
            self.activator["validate_private"](sidecar, self.plan["planSha256"], self.bindings["activatorSha256"],
                                                 planner.digest(self.plan["actions"]))
            mutations = (
                lambda value: value["operatorGates"].update({"backupsConfirmed": True}),
                lambda value: value["bindings"].update({"bundleContentSha256": "e" * 64}),
                lambda value: value.update({"validUntil": planner.format_time(planner.parse_time(value["validUntil"]) + dt.timedelta(seconds=1))}),
                lambda value: value.update({"actionManifestSha256": "f" * 64}),
                lambda value: value.update({"packageSession": {"completeInstalledMapSha256": "1" * 64,
                    "handle": "package_012345678", "keyedSimulationAttestation": "2" * 64, "validUntil": value["validUntil"]}}),
            )
            for mutation in mutations:
                changed = copy.deepcopy(sidecar); mutation(changed)
                recomputed = self.activator["hmac"].new(key, self.activator["canonical"](
                    self.activator["sidecar_signing_projection"](changed)), self.activator["hashlib"].sha256).hexdigest()
                self.assertNotEqual(changed["hostSession"]["sidecarMac"], recomputed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    self.activator["validate_private"](changed, self.plan["planSha256"], self.bindings["activatorSha256"],
                                                         planner.digest(self.plan["actions"]))
            protected = copy.deepcopy(sidecar)
            protected["attestations"]["protectedAccess"]["keyedAttestation"] = "0" * 64
            sign(protected)
            with self.assertRaisesRegex(ValueError, "protected keyed"):
                self.activator["validate_private"](protected, self.plan["planSha256"], self.bindings["activatorSha256"],
                                                     planner.digest(self.plan["actions"]))
        finally:
            self.activator["load_key"] = old_key

    def test_plan_and_sidecar_require_mode_0600_real_single_link_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.write_inputs(root)
            plan_path = root / ".reconcile/plans" / f"{self.plan['planSha256']}.json"
            guarded_apply.load_secure_canonical(plan_path, "plan", 1024 * 1024)
            plan_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode-0600"):
                guarded_apply.load_secure_canonical(plan_path, "plan", 1024 * 1024)
            private_path = root / ".reconcile/plans" / f"{self.plan['planSha256']}.private.json"
            private_path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "mode-0600"):
                guarded_apply.load_secure_canonical(private_path, "private preconditions", 256 * 1024)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            plan_path = root / ".reconcile/plans" / f"{self.plan['planSha256']}.json"
            other = root / "other"; plan_path.rename(other); plan_path.symlink_to(other)
            with self.assertRaises(OSError):
                guarded_apply.load_secure_canonical(plan_path, "plan", 1024 * 1024)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            plan_path = root / ".reconcile/plans" / f"{self.plan['planSha256']}.json"
            os.link(plan_path, root / "hardlink")
            with self.assertRaisesRegex(ValueError, "single-link"):
                guarded_apply.load_secure_canonical(plan_path, "plan", 1024 * 1024)

    def test_controller_lock_contention_prevents_transport_and_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / ".reconcile").mkdir(mode=0o700)
            first = guarded_apply.controller_lock(root, {"operation": "test"})
            try:
                with patch.object(guarded_apply, "send_session") as transport, self.assertRaisesRegex(ValueError, "already held"):
                    guarded_apply.controller_lock(root, {"operation": "second"})
                transport.assert_not_called()
            finally:
                guarded_apply.release_controller_lock(first)
            self.assertTrue((root / ".reconcile/controller-apply.lock").is_file())

    def test_nested_controller_lock_validates_inherited_descriptor_or_token(self) -> None:
        protocol = guarded_apply.controller_lock_protocol
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            token = "e" * 64
            commit = "a" * 40
            outer = protocol.acquire(root, protocol.outer_owner(commit, "steady", token, os.getpid()))
            environment = {protocol.TOKEN_ENV: token, protocol.FD_ENV: str(outer.lock_fd)}
            try:
                with patch.dict(os.environ, environment, clear=False):
                    nested = guarded_apply.controller_lock(
                        root, {"gitCommit": commit, "operation": "nested-test"}
                    )
                    self.assertFalse(nested.owned)
                    guarded_apply.release_controller_lock(nested)
                with patch.dict(
                    os.environ,
                    {protocol.TOKEN_ENV: token, protocol.FD_ENV: "999999"},
                    clear=False,
                ):
                    nested = guarded_apply.controller_lock(
                        root, {"gitCommit": commit, "operation": "token-fallback-test"}
                    )
                    self.assertFalse(nested.owned)
                    guarded_apply.release_controller_lock(nested)
                with patch.dict(
                    os.environ,
                    {protocol.TOKEN_ENV: "f" * 64, protocol.FD_ENV: str(outer.lock_fd)},
                    clear=False,
                ), self.assertRaisesRegex(ValueError, "ownership metadata"):
                    guarded_apply.controller_lock(
                        root, {"gitCommit": commit, "operation": "forged-test"}
                    )
            finally:
                protocol.release(outer)
            with patch.dict(
                os.environ,
                {protocol.TOKEN_ENV: token, protocol.FD_ENV: "999999"},
                clear=False,
            ), self.assertRaisesRegex(ValueError, "not held"):
                guarded_apply.controller_lock(
                    root, {"gitCommit": commit, "operation": "stale-test"}
                )

    def test_host_lock_contention_retention_and_free_space_fail_before_session_mutation(self) -> None:
        private = self.sidecar()
        envelope = {"actions": self.plan["actions"], "bindings": {"activatorSha256": "8" * 64, "bundleContentSha256": "1" * 64,
                                  "gitCommit": "3" * 40, "gitTree": "4" * 40},
                    "hostSessionId": private["hostSession"]["id"], "operation": "begin",
                    "planSha256": self.plan["planSha256"], "privatePreconditions": private,
                    "protocol": 4, "startedAt": private["createdAt"]}
        namespace = self.activator
        substitutions = {"validate_private": lambda *args: private, "self_sha256": lambda: "8" * 64,
                         "read_journal": lambda plan: (_ for _ in ()).throw(FileNotFoundError()),
                         "lstat_fixed": lambda path: (_ for _ in ()).throw(FileNotFoundError()),
                         "read_lock": lambda: (_ for _ in ()).throw(FileNotFoundError()),
                         "cleanup_unowned_incomplete_generations": lambda: None,
                         "challenge_was_used": lambda challenge: False}
        with patch.dict(namespace, substitutions), \
                patch.dict(namespace, {"retained_generations": lambda: ["a" * 64] * namespace["MAX_RETAINED_SESSIONS"]}), \
                patch.object(namespace["shutil"], "disk_usage", return_value=SimpleNamespace(free=namespace["MIN_FREE_BYTES"] + 1)):
            with self.assertRaisesRegex(ValueError, "retention"):
                namespace["begin"](envelope)
        with patch.dict(namespace, {**substitutions, "retained_generations": lambda: []}), \
                patch.object(namespace["shutil"], "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(ValueError, "free-space"):
                namespace["begin"](envelope)
        contended = {"planSha256": "f" * 64}
        with patch.dict(namespace, {**substitutions, "read_lock": lambda: contended}):
            with self.assertRaisesRegex(ValueError, "ownership lock"):
                namespace["begin"](envelope)
        source = (NIX / "proxmox/activator-template.py").read_text(encoding="utf-8")
        self.assertIn("fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", source)

    def test_fixed_transport_has_no_path_target_command_or_forwarding_inputs(self) -> None:
        self.assertEqual(guarded_apply.SSH_APPLY_COMMAND[-2:], (
            "tofu-apply@192.168.0.123", "sudo -n -- /usr/local/libexec/home-lab/proxmox-activator session"))
        self.assertEqual(guarded_apply.SSH_APPLY_COMMAND[1:3], ("-F", "/dev/null"))
        self.assertIn(str(Path.home() / ".ssh/home-lab-proxmox-apply"), guarded_apply.SSH_APPLY_COMMAND)
        for option in ("IdentitiesOnly=yes", "BatchMode=yes",
                       "ClearAllForwardings=yes", "PermitLocalCommand=no", "RequestTTY=no",
                       "StrictHostKeyChecking=yes", "UpdateHostKeys=no"):
            self.assertIn(option, guarded_apply.SSH_APPLY_COMMAND)
        self.assertFalse(any(value.startswith("ProxyCommand=") for value in guarded_apply.SSH_APPLY_COMMAND))
        old = list(sys.argv)
        try:
            for rejected in (("--plan", "/tmp/x"), ("--target", "root@other"), ("--helper", "/tmp/x")):
                sys.argv = ["proxmox-host", "apply", "--repo-root", str(ROOT), "--plan-sha", "a" * 64,
                            "--approve-plan-sha", "a" * 64, *rejected]
                with self.assertRaises(SystemExit) as error:
                    planner.parse_args()
                self.assertEqual(error.exception.code, 64)
        finally:
            sys.argv = old

    def test_apply_orders_controller_then_host_reobserve_action_verify_commit(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            events = []
            responses = iter([
                {"hostSessionId": "session_01234567890", "operation": "status", "planSha256": self.plan["planSha256"], "status": "failed"},
                {"actionManifestSha256": planner.digest(self.plan["actions"]), "hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "status": "begun"},
                {"actionId": self.plan["actions"][0]["id"], "hostSessionId": "session_01234567890", "sequence": 1, "status": "applied"},
                {"hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "status": "committed"},
            ])
            def send(envelope):
                self.assertTrue((root / ".reconcile/controller-apply.lock").exists())
                events.append(envelope["operation"])
                return next(responses)
            observations = iter([self.before_observation, self.after_observation, self.after_observation])
            def observe(_):
                events.append("observe")
                return next(observations)
            args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
            with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                    patch.object(guarded_apply, "send_session", side_effect=send), \
                    patch.object(planner, "live_observation", side_effect=observe):
                result = guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
            self.assertEqual(events, ["status", "begin", "observe", "action", "observe", "observe", "commit"])
            self.assertIn("rebootRequired=false", result)
            self.assertTrue((root / ".reconcile/controller-apply.lock").is_file())

    def test_reobserved_precondition_mismatch_rolls_back_without_action_or_replan(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            changed = copy.deepcopy(self.before_observation)
            changed["domains"]["managedArtifacts"]["records"][0]["contentMatches"] = False
            operations = []
            def send(envelope):
                operations.append(envelope["operation"])
                if envelope["operation"] == "begin":
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "status": "begun"}
                if envelope["operation"] == "status":
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "b" * 64,
                            "capturedActionIds": [], "completedActionIds": [],
                            "hostSessionId": "session_01234567890", "nextSequence": 1, "pendingTransition": None,
                            "planSha256": self.plan["planSha256"], "state": "begun", "status": "session-status"}
                return {"hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "restoredActionIds": [], "status": "recovered"}
            args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
            with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                    patch.object(guarded_apply, "send_session", side_effect=send), \
                    patch.object(planner, "live_observation", return_value=changed), \
                    patch.object(planner, "build_plan") as replan, self.assertRaisesRegex(ValueError, "refusing to replan"):
                guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
            self.assertEqual(operations, ["status", "begin", "status", "rollback"])
            replan.assert_not_called()

    def test_action_or_postcondition_failure_requests_host_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            operations = []
            def send(envelope):
                operations.append(envelope["operation"])
                if envelope["operation"] == "begin":
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "status": "begun"}
                if envelope["operation"] == "action":
                    return {"hostSessionId": "session_01234567890", "operation": "action", "planSha256": self.plan["planSha256"], "status": "failed"}
                if envelope["operation"] == "status":
                    if operations.count("status") == 1:
                        return {"hostSessionId": "session_01234567890", "operation": "status",
                                "planSha256": self.plan["planSha256"], "status": "failed"}
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "b" * 64,
                            "capturedActionIds": [self.plan["actions"][0]["id"]], "completedActionIds": [],
                            "hostSessionId": "session_01234567890", "nextSequence": 1, "pendingTransition": {
                                "actionId": self.plan["actions"][0]["id"], "operation": "action", "requestSha256": "f" * 64,
                                "sequence": 1, "stage": "prepared"}, "planSha256": self.plan["planSha256"],
                            "state": "failed", "status": "session-status"}
                return {"hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"],
                        "restoredActionIds": [self.plan["actions"][0]["id"]], "status": "recovered"}
            args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
            with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                    patch.object(guarded_apply, "send_session", side_effect=send), \
                    patch.object(planner, "live_observation", return_value=self.before_observation), \
                    self.assertRaisesRegex(ValueError, "status confirms action failure"):
                guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
            self.assertEqual(operations, ["status", "begin", "action", "status", "status", "rollback"])

    def test_ambiguous_transport_uses_status_and_never_starts_concurrent_rollback(self) -> None:
        action = self.plan["actions"][0]
        envelope = {"action": action, "hostSessionId": "session_01234567890", "operation": "action",
                    "planSha256": self.plan["planSha256"], "protocol": 4}
        expected = {"actionId": action["id"], "hostSessionId": "session_01234567890",
                    "sequence": 1, "status": "applied"}
        proved = {"actionManifestSha256": planner.digest(self.plan["actions"]), "capturedActionIds": [action["id"]],
                  "completedActionIds": [action["id"]], "hostSessionId": "session_01234567890", "nextSequence": 2,
                  "planSha256": self.plan["planSha256"], "state": "applying", "status": "session-status"}
        with patch.object(guarded_apply, "send_session", side_effect=[guarded_apply.AmbiguousTransportError("lost"), proved]):
            self.assertEqual(guarded_apply.send_transition(envelope, expected, planner.digest(self.plan["actions"])), expected)
        commit_envelope = {"hostSessionId": "session_01234567890", "operation": "commit",
                           "planSha256": self.plan["planSha256"], "protocol": 4,
                           "verifiedActionIds": [action["id"]]}
        committed = dict(proved, state="released-committed")
        expected_commit = {"hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"], "status": "committed"}
        with patch.object(guarded_apply, "send_session", side_effect=[guarded_apply.AmbiguousTransportError("lost"), committed]):
            self.assertEqual(guarded_apply.send_transition(commit_envelope, expected_commit,
                                                            planner.digest(self.plan["actions"])), expected_commit)
        interrupted_release = {"hostSessionId": "session_01234567890", "operation": "commit",
                               "planSha256": self.plan["planSha256"], "status": "failed"}
        with patch.object(guarded_apply, "send_session", side_effect=[interrupted_release, committed]):
            self.assertEqual(guarded_apply.send_transition(commit_envelope, expected_commit,
                                                            planner.digest(self.plan["actions"])), expected_commit)
        busy = {"hostSessionId": "session_01234567890", "operation": "status",
                "planSha256": self.plan["planSha256"], "status": "busy"}
        with patch.object(guarded_apply, "send_session", side_effect=[guarded_apply.AmbiguousTransportError("lost"), busy]), \
                self.assertRaisesRegex(guarded_apply.AmbiguousSessionError, "rollback not started"):
            guarded_apply.send_transition(envelope, expected, planner.digest(self.plan["actions"]))

    def test_controller_reports_combined_primary_and_rollback_failure(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.write_inputs(root)
            action = self.plan["actions"][0]
            status_calls = 0
            def send(envelope):
                nonlocal status_calls
                if envelope["operation"] == "begin":
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "hostSessionId": "session_01234567890",
                            "planSha256": self.plan["planSha256"], "status": "begun"}
                if envelope["operation"] == "action":
                    return {"hostSessionId": "session_01234567890", "operation": "action",
                            "planSha256": self.plan["planSha256"], "status": "failed"}
                if envelope["operation"] == "status":
                    status_calls += 1
                    if status_calls == 1:
                        return {"hostSessionId": "session_01234567890", "operation": "status",
                                "planSha256": self.plan["planSha256"], "status": "failed"}
                    return {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "b" * 64,
                            "capturedActionIds": [action["id"]], "completedActionIds": [], "hostSessionId": "session_01234567890", "nextSequence": 1,
                            "pendingTransition": {"actionId": action["id"], "operation": "action", "requestSha256": "f" * 64,
                                                  "sequence": 1, "stage": "prepared"},
                            "planSha256": self.plan["planSha256"], "state": "failed", "status": "session-status"}
                return {"hostSessionId": "session_01234567890", "operation": "rollback",
                        "planSha256": self.plan["planSha256"], "status": "failed"}
            args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
            with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                    patch.object(guarded_apply, "send_session", side_effect=send), \
                    patch.object(planner, "live_observation", return_value=self.before_observation), \
                    self.assertRaisesRegex(ValueError, "apply failed.*rollback failed"):
                guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))

    def test_activator_rejects_arbitrary_fields_paths_kinds_content_api_tofu_and_packages(self) -> None:
        action = copy.deepcopy(self.plan["actions"][0])
        self.activator["catalog_item"](action)
        mutations = (
            lambda value: value.update({"command": "id"}),
            lambda value: value["target"].update({"path": "/tmp/arbitrary"}),
            lambda value: value.update({"kind": "reconcile-service"}),
            lambda value: value["after"].update({"content": "caller bytes"}),
            lambda value: value.update({"domain": "pve-access"}),
            lambda value: value.update({"domain": "opentofu"}),
            lambda value: value.update({"domain": "packages"}),
        )
        for mutation in mutations:
            changed = copy.deepcopy(action); mutation(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.activator["catalog_item"](changed)

    def test_complete_ordered_action_manifest_is_hash_bound_and_each_transition_matches_it(self) -> None:
        original = copy.deepcopy(self.plan["actions"][0])
        artifact_policy = next(item for item in self.projection["planningPolicy"]["domains"] if item["domain"] == "managed-artifacts")
        desired_artifacts = planner.desired_records(self.projection, self.manifest)["managed-artifacts"]
        original_order = self.activator["SPEC"]["catalogOrder"].index(
            self.activator["catalog_key"](original["domain"], original["target"])
        )
        desired = next(item for item in desired_artifacts if self.activator["SPEC"]["catalogOrder"].index(
            self.activator["catalog_key"]("managed-artifacts", {"path": item["target"], "type": "artifact"})
        ) > original_order)
        observed = dict(desired, contentMatches=False)
        second = planner.plan_action("managed-artifacts", observed, desired, artifact_policy)
        second["sequence"] = 2
        second["dependsOn"] = [original["id"]]
        actions = [original, second]
        digest_value = self.activator["validate_action_manifest"](actions)
        self.assertEqual(digest_value, planner.digest(actions))
        self.assertNotEqual(digest_value, planner.digest([original]))
        old_journal = self.activator["read_journal"]
        old_manifest = self.activator["read_manifest"]
        old_lock = self.activator["require_lock"]
        try:
            self.activator["read_journal"] = lambda plan: {"completed": [], "nextSequence": 1, "state": "begun"}
            self.activator["read_manifest"] = lambda plan: {"actions": [original], "entries": [],
                                                               "actionManifestSha256": planner.digest([original])}
            self.activator["require_lock"] = lambda envelope: {}
            envelope = {"action": second, "hostSessionId": "session_01234567890", "operation": "action",
                        "planSha256": self.plan["planSha256"], "protocol": 4}
            with self.assertRaisesRegex(ValueError, "exact retained plan manifest"):
                self.activator["action_session"](envelope)
        finally:
            self.activator["read_journal"] = old_journal
            self.activator["read_manifest"] = old_manifest
            self.activator["require_lock"] = old_lock

    def test_action_order_dependencies_and_watchdog_gates_are_closed(self) -> None:
        action = copy.deepcopy(self.plan["actions"][0])
        changed = copy.deepcopy(action); changed["sequence"] = 2; changed["dependsOn"] = []
        with self.assertRaisesRegex(ValueError, "dependencies"):
            self.activator["catalog_item"](changed)
        key = self.activator["catalog_key"](action["domain"], action["target"])
        original = copy.deepcopy(self.activator["SPEC"]["catalog"][key])
        try:
            guarded = copy.deepcopy(action); guarded["watchdogRequired"] = True
            self.activator["SPEC"]["catalog"][key]["action"]["watchdogRequired"] = True
            with self.assertRaisesRegex(ValueError, "watchdog"):
                self.activator["catalog_item"](guarded)
        finally:
            self.activator["SPEC"]["catalog"][key] = original

    def test_safe_dispatch_derives_content_and_commands_only_from_catalog(self) -> None:
        catalog = self.boot_mutation_catalog()
        file_item = next(item for item in catalog.values() if item["domain"] == "managed-files")
        captured = []
        commands = []
        old_replace = self.activator["replace_fixed"]
        old_run = self.activator["run_native"]
        try:
            self.activator["replace_fixed"] = lambda *args: captured.append(args)
            self.activator["run_native"] = lambda argv, accepted=(0,): commands.append(argv) or b""
            self.activator["mutate_item"](file_item)
            self.assertEqual(captured[0][1], base64.b64decode(file_item["contentBase64"]))
            native_items = [item for item in catalog.values() if item.get("nativeOperation")]
            for native_item in native_items:
                self.activator["run_post_write"](native_item)
            self.assertIn(("/usr/sbin/update-grub",), commands)
            self.assertIn(("/usr/sbin/update-initramfs", "-u", "-k", "all"), commands)
            self.assertFalse(any("reboot" in part for command in commands for part in command))
        finally:
            self.activator["replace_fixed"] = old_replace
            self.activator["run_native"] = old_run

    def test_transferred_timezone_has_no_nix_activation_or_rollback_surface(self) -> None:
        observation = copy.deepcopy(self.after_observation)
        observation["domains"]["timezone"]["records"][0]["timezone"] = "Etc/UTC"
        start = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        plan = planner.build_plan(self.bindings, self.projection, self.manifest, observation,
                                  planner.format_time(start), planner.format_time(start + dt.timedelta(seconds=1)), False)
        self.assertEqual([action for action in plan["actions"] if action["domain"] == "timezone"], [])
        self.assertNotIn("timezone_state", self.activator)
        self.assertNotIn("set_timezone", self.activator)
        self.assertFalse(any(item["domain"] == "timezone" for item in self.activator["SPEC"]["catalog"].values()))

    def test_rollback_is_reverse_verified_and_failure_retains_lock(self) -> None:
        keys = list(self.activator["SPEC"]["catalog"])[0:2]
        entries = [{"actionId": "1" * 64, "identity": keys[0], "sequence": 1},
                   {"actionId": "2" * 64, "identity": keys[1], "sequence": 2}]
        actions = [{"id": "1" * 64}, {"id": "2" * 64}]
        manifest = {"actionManifestSha256": "f" * 64, "actions": actions, "entries": entries}
        ownership = {"activatorSha256": "8" * 64, "hostSessionId": "session_01234567890", "planSha256": "a" * 64}
        journal = {"actionManifestSha256": "f" * 64, "completed": [], "hostSessionId": ownership["hostSessionId"],
                   "nextSequence": 3, "ownership": ownership, "pendingTransition": None,
                   "planSha256": ownership["planSha256"], "state": "failed", "terminalResult": None}
        envelope = {"hostSessionId": ownership["hostSessionId"], "operation": "rollback",
                    "planSha256": ownership["planSha256"], "protocol": 4}
        restored, released = [], []
        substitutions = {"require_lock": lambda value: ownership, "read_manifest": lambda plan: manifest,
                         "read_journal": lambda plan: copy.deepcopy(journal),
                         "save_journal": lambda plan, value: journal.update(copy.deepcopy(value)),
                         "release_fixed_lock": lambda path: released.append(path), "retain_diagnostic": lambda *args: None,
                         "restore_entry": lambda entry, item: restored.append(entry["actionId"]) or True,
                         "validate_session_consistency": lambda current, saved: None}
        with patch.dict(self.activator, substitutions):
            result = self.activator["rollback"](envelope)
        self.assertEqual(restored, ["2" * 64, "1" * 64])
        self.assertEqual(result["restoredActionIds"], restored)
        self.assertEqual(journal["state"], "released-recovered")
        self.assertEqual(released, [self.activator["LOCK_PATH"]])
        journal.update({"completed": [], "pendingTransition": None, "state": "failed", "terminalResult": None})
        with patch.dict(self.activator, {**substitutions,
                                         "restore_entry": lambda entry, item: False}):
            with self.assertRaisesRegex(ValueError, "ownership lock retained"):
                self.activator["rollback"](envelope)
        self.assertEqual(journal["state"], "rollback-failed")
        self.assertEqual(released, [self.activator["LOCK_PATH"]])

    def test_capture_capacity_symlink_and_begin_retention_free_space_fail_closed(self) -> None:
        action = copy.deepcopy(self.plan["actions"][0])
        item = copy.deepcopy(next(value for value in self.boot_mutation_catalog().values() if value["domain"] == "managed-files"))
        old_limit = self.activator["MAX_ROLLBACK_RAW_BYTES"]
        old_manifest = self.activator["read_manifest"]
        old_inspect = self.activator["inspect_fixed"]
        try:
            self.activator["MAX_ROLLBACK_RAW_BYTES"] = 4
            self.activator["read_manifest"] = lambda plan: {"entries": [{"identity": "other", "original": {"contentBase64": base64.b64encode(b"1234").decode()}, "targetType": "path"}]}
            self.activator["inspect_fixed"] = lambda path: (SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600,
                                                                               st_dev=1, st_ino=2, st_size=1, st_nlink=1,
                                                                               st_mtime_ns=1, st_ctime_ns=1), b"x", None)
            with self.assertRaisesRegex(ValueError, "capacity"):
                self.activator["capture_once"]("a" * 64, action, item)
        finally:
            self.activator["MAX_ROLLBACK_RAW_BYTES"] = old_limit
            self.activator["read_manifest"] = old_manifest
            self.activator["inspect_fixed"] = old_inspect
        old_manifest = self.activator["read_manifest"]
        old_inspect = self.activator["inspect_fixed"]
        try:
            self.activator["read_manifest"] = lambda plan: {"entries": []}
            self.activator["inspect_fixed"] = lambda path: (SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_dev=1, st_ino=2,
                                                                              st_uid=0, st_gid=0, st_size=9, st_nlink=1,
                                                                              st_mtime_ns=1, st_ctime_ns=1),
                                                               None, "../escape")
            with self.assertRaisesRegex(ValueError, "unsafe symlink"):
                self.activator["capture_once"]("a" * 64, action, item)
        finally:
            self.activator["read_manifest"] = old_manifest
            self.activator["inspect_fixed"] = old_inspect
        source = (NIX / "proxmox/activator-template.py").read_text(encoding="utf-8")
        self.assertIn("os.O_NOFOLLOW", source)

    def test_pre_replace_inode_revalidation_rejects_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "target"
            target.write_text("one", encoding="utf-8")
            fd = os.open(root, os.O_RDONLY)
            try:
                info = os.stat("target", dir_fd=fd, follow_symlinks=False)
                original = self.activator["stable_fingerprint"](info)
                replacement = root / "replacement"
                replacement.write_text("two", encoding="utf-8")
                replacement.replace(target)
                with self.assertRaisesRegex(ValueError, "changed between capture"):
                    self.activator["revalidate_identity"](fd, "target", original)
            finally:
                os.close(fd)

    def test_descriptor_flock_is_live_only_and_close_recovers_after_process_loss(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            real_fstat = os.fstat
            def root_fstat(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0, st_nlink=info.st_nlink)
            def open_mutex_parent(_path):
                return os.open(root, os.O_RDONLY), "operation.lock"
            with patch.dict(self.activator, {"open_fixed_parent": open_mutex_parent}), \
                    patch.object(self.activator["os"], "fstat", side_effect=root_fstat):
                first = self.activator["acquire_operation"]()
                self.assertIsInstance(first, int)
                self.assertIsNone(self.activator["acquire_operation"]())
                os.close(first)
                recovered = self.activator["acquire_operation"]()
                self.assertIsInstance(recovered, int)
                os.close(recovered)
            self.assertTrue((root / "operation.lock").is_file())

    def test_terminal_release_pending_is_status_recoverable_and_never_prematurely_proven(self) -> None:
        ownership = {"activatorSha256": "8" * 64, "bundleContentSha256": "1" * 64, "gitCommit": "3" * 40,
                     "gitTree": "4" * 40, "hostSessionId": "session_01234567890", "operation": "proxmox-guarded-apply",
                     "planSha256": "a" * 64, "startedAt": "2026-01-01T00:00:00Z"}
        journal = {"actionManifestSha256": "1" * 64, "completed": [], "hostSessionId": ownership["hostSessionId"],
                   "nextSequence": 1, "ownership": ownership, "pendingTransition": None,
                   "planSha256": ownership["planSha256"], "state": "applying", "terminalResult": None}
        result = {"hostSessionId": journal["hostSessionId"], "planSha256": journal["planSha256"], "status": "committed"}
        saved = []
        with patch.dict(self.activator, {"save_journal": lambda plan, value: saved.append(copy.deepcopy(value)),
                                         "release_fixed_lock": lambda path: (_ for _ in ()).throw(OSError("fsync interrupted"))}):
            with self.assertRaises(OSError):
                self.activator["terminal_release"](journal, "committed", result)
        self.assertEqual(journal["state"], "committed-release-pending")
        status = {"status": "session-status", "hostSessionId": journal["hostSessionId"],
                  "planSha256": journal["planSha256"], "actionManifestSha256": journal["actionManifestSha256"],
                  "capturedActionIds": [], "completedActionIds": [], "nextSequence": 1, "pendingTransition": None,
                  "state": journal["state"]}
        envelope = {"hostSessionId": journal["hostSessionId"], "operation": "commit",
                    "planSha256": journal["planSha256"], "protocol": 4, "verifiedActionIds": []}
        self.assertFalse(guarded_apply.status_proves(status, envelope, journal["actionManifestSha256"]))
        released = []
        matching_lock = ownership
        with patch.dict(self.activator, {"read_lock": lambda: matching_lock,
                                         "release_fixed_lock": lambda path: released.append(path),
                                         "self_sha256": lambda: "8" * 64,
                                         "save_journal": lambda plan, value: saved.append(copy.deepcopy(value))}):
            reconciled = self.activator["reconcile_terminal_release"](journal)
        self.assertEqual(released, [self.activator["LOCK_PATH"]])
        self.assertEqual(reconciled["state"], "released-committed")
        status["state"] = reconciled["state"]
        self.assertTrue(guarded_apply.status_proves(status, envelope, journal["actionManifestSha256"]))

    def test_release_unlink_fsync_window_reconciles_from_lock_absence(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            lock = root / "apply.lock"
            lock.write_text("locked", encoding="utf-8")
            def open_lock_parent(_path):
                return os.open(root, os.O_RDONLY), "apply.lock"
            with patch.dict(self.activator, {"open_fixed_parent": open_lock_parent}), \
                    patch.object(self.activator["os"], "fsync", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    self.activator["release_fixed_lock"](lock)
            self.assertFalse(lock.exists())
            journal = {"hostSessionId": "session_01234567890", "ownership": {"hostSessionId": "session_01234567890"},
                       "planSha256": "a" * 64, "state": "recovered-release-pending"}
            with patch.dict(self.activator, {"read_lock": lambda: (_ for _ in ()).throw(FileNotFoundError()),
                                             "save_journal": lambda plan, value: None}):
                self.assertEqual(self.activator["reconcile_terminal_release"](journal)["state"], "released-recovered")

    def test_partial_begin_setup_invokes_cleanup_only_for_new_session(self) -> None:
        sidecar = self.sidecar()
        envelope = {"actions": self.plan["actions"], "bindings": {"activatorSha256": "8" * 64,
                    "bundleContentSha256": "1" * 64, "gitCommit": "3" * 40, "gitTree": "4" * 40},
                    "hostSessionId": sidecar["hostSession"]["id"], "operation": "begin",
                    "planSha256": self.plan["planSha256"], "privatePreconditions": sidecar,
                    "protocol": 4, "startedAt": sidecar["createdAt"]}
        with tempfile.TemporaryDirectory() as name:
            session = Path(name) / self.plan["planSha256"]
            cleaned = []
            substitutions = {"validate_envelope_shape": lambda value: "begin", "validate_action_manifest": lambda value: "f" * 64,
                "validate_private": lambda *args: sidecar, "self_sha256": lambda: "8" * 64,
                "read_journal": lambda plan: (_ for _ in ()).throw(FileNotFoundError()),
                "read_lock": lambda: (_ for _ in ()).throw(FileNotFoundError()),
                "lstat_fixed": lambda path: (_ for _ in ()).throw(FileNotFoundError()),
                "retained_generations": lambda: [], "cleanup_unowned_incomplete_generations": lambda: None,
                "challenge_was_used": lambda challenge: False, "session_paths": lambda plan: (session, session / "manifest.json"),
                "validate_manifest": lambda *args: None, "validate_journal": lambda *args: None,
                "write_exclusive_fixed": lambda *args: None, "cleanup_new_session": lambda plan: cleaned.append(plan)}
            with patch.dict(self.activator, substitutions), \
                    patch.object(self.activator["shutil"], "disk_usage", return_value=SimpleNamespace(free=self.activator["MIN_FREE_BYTES"] + 1)), \
                    patch.object(self.activator["os"], "chown", side_effect=OSError("setup interrupted")), \
                    self.assertRaisesRegex(OSError, "setup interrupted"):
                self.activator["begin"](envelope)
            self.assertEqual(cleaned, [self.plan["planSha256"]])
            self.assertTrue(session.is_dir())

    def test_incomplete_begin_cleanup_is_nofollow_and_rejects_unknown_entries(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            rollback = Path(name) / "rollback"
            rollback.mkdir(mode=0o700)
            plan_sha = "a" * 64
            session = rollback / plan_sha
            session.mkdir(mode=0o700)
            (session / "manifest.json").write_text("x", encoding="utf-8"); (session / "manifest.json").chmod(0o600)
            (session / ".state-1").write_text("x", encoding="utf-8"); (session / ".state-1").chmod(0o600)
            real_fstat, real_stat = os.fstat, os.stat
            def root_info(info):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0, st_nlink=info.st_nlink)
            def open_rollback_parent(_path):
                return os.open(rollback, os.O_RDONLY), plan_sha
            with patch.dict(self.activator, {"open_fixed_parent": open_rollback_parent}), \
                    patch.object(self.activator["os"], "fstat", side_effect=lambda fd: root_info(real_fstat(fd))), \
                    patch.object(self.activator["os"], "stat", side_effect=lambda *args, **kwargs: root_info(real_stat(*args, **kwargs))):
                self.activator["cleanup_new_session"](plan_sha)
            self.assertFalse(session.exists())
            session.mkdir(mode=0o700)
            (session / "unexpected").write_text("x", encoding="utf-8"); (session / "unexpected").chmod(0o600)
            with patch.dict(self.activator, {"open_fixed_parent": open_rollback_parent}), \
                    patch.object(self.activator["os"], "fstat", side_effect=lambda fd: root_info(real_fstat(fd))), \
                    patch.object(self.activator["os"], "stat", side_effect=lambda *args, **kwargs: root_info(real_stat(*args, **kwargs))), \
                    self.assertRaisesRegex(ValueError, "unknown entry"):
                self.activator["cleanup_new_session"](plan_sha)
            self.assertTrue((session / "unexpected").exists())

    def test_same_inode_metadata_and_read_mutation_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "target"
            target.write_bytes(b"content")
            parent = os.open(name, os.O_RDONLY)
            try:
                original = self.activator["stable_fingerprint"](os.stat(target, follow_symlinks=False))
                target.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "changed between capture"):
                    self.activator["revalidate_identity"](parent, target.name, original)
            finally:
                os.close(parent)
            target.chmod(0o644)
            real_read = os.read
            changed = False
            def mutating_read(fd, size):
                nonlocal changed
                data = real_read(fd, size)
                if data and not changed:
                    changed = True
                    target.chmod(0o600)
                return data
            with patch.dict(self.activator, {"open_fixed_parent": lambda path: (os.open(path.parent, os.O_RDONLY), path.name)}), \
                    patch.object(self.activator["os"], "read", side_effect=mutating_read), \
                    self.assertRaisesRegex(ValueError, "changed during no-follow inspection"):
                self.activator["inspect_fixed"](target)

    def test_symlink_pre_post_lstat_detects_same_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            link = Path(name) / "link"
            link.symlink_to("one")
            real_readlink = os.readlink
            changed = False
            def replacing_readlink(*args, **kwargs):
                nonlocal changed
                value = real_readlink(*args, **kwargs)
                if not changed:
                    changed = True
                    link.unlink(); link.symlink_to("two")
                return value
            with patch.dict(self.activator, {"open_fixed_parent": lambda path: (os.open(path.parent, os.O_RDONLY), path.name)}), \
                    patch.object(self.activator["os"], "readlink", side_effect=replacing_readlink), \
                    self.assertRaisesRegex(ValueError, "symlink changed"):
                self.activator["inspect_fixed"](link)

    def test_package_refresh_and_reboot_execution_are_unrepresentable(self) -> None:
        source = (NIX / "proxmox/activator-template.py").read_text(encoding="utf-8")
        self.assertNotIn("apt-get", source)
        self.assertNotIn("apt update", source)
        self.assertNotIn("systemctl\", \"reboot", source)
        self.assertNotIn("/sbin/reboot", source)
        catalog_domains = {item["domain"] for item in self.activator["SPEC"]["catalog"].values()}
        self.assertEqual(catalog_domains, {"managed-artifacts"})
        service_names = {item["name"] for item in self.activator["SPEC"]["catalog"].values() if item["domain"] == "services"}
        self.assertEqual(service_names, set())

    def test_strict_schemas_and_manual_handlers_reject_comprehensive_malformed_documents(self) -> None:
        sidecar = self.sidecar()
        common = {"hostSessionId": sidecar["hostSession"]["id"], "planSha256": self.plan["planSha256"], "protocol": 4}
        envelopes = [
            {"actions": self.plan["actions"], "bindings": {"activatorSha256": self.bindings["activatorSha256"],
                "bundleContentSha256": self.bindings["bundleContentSha256"], "gitCommit": self.bindings["gitCommit"],
                "gitTree": self.bindings["gitTree"]}, **common, "operation": "begin", "privatePreconditions": sidecar,
                "startedAt": sidecar["createdAt"]},
            {**common, "operation": "action", "action": self.plan["actions"][0]},
            {**common, "operation": "rollback"},
            {**common, "operation": "commit", "verifiedActionIds": [self.plan["actions"][0]["id"]]},
            {**common, "operation": "status"},
        ]
        invalid_private = []
        for mutate in (
            lambda value: value.update(callerCommand="id"),
            lambda value: value.pop("challenge"),
            lambda value: value["attestations"]["protectedAccess"].update(expectedCount="5"),
            lambda value: value.update(challenge="bad value"),
        ):
            value = copy.deepcopy(sidecar); mutate(value); invalid_private.append(value)
        required = {"begin": "startedAt", "action": "action", "rollback": "planSha256",
                    "commit": "verifiedActionIds", "status": "hostSessionId"}
        invalid_envelopes = []
        bad_referenced_actions = []
        for envelope in envelopes:
            operation = envelope["operation"]
            variants = []
            unknown = copy.deepcopy(envelope); unknown["callerCommand"] = "id"; variants.append(unknown)
            missing = copy.deepcopy(envelope); missing.pop(required[operation]); variants.append(missing)
            wrong_type = copy.deepcopy(envelope); wrong_type["protocol"] = "3"; variants.append(wrong_type)
            bad_pattern = copy.deepcopy(envelope); bad_pattern["hostSessionId"] = "bad value"; variants.append(bad_pattern)
            if operation in {"begin", "action"}:
                bad_action = copy.deepcopy(envelope)
                action = bad_action["actions"][0] if operation == "begin" else bad_action["action"]
                action["target"] = {"path": "/tmp/caller-selected", "type": "file"}
                bad_referenced_actions.append(bad_action)
            invalid_envelopes.extend(variants)
        with tempfile.TemporaryDirectory() as name:
            docs = Path(name) / "documents.json"
            docs.write_text(json.dumps({"validPrivate": sidecar, "validEnvelopes": envelopes,
                                        "invalidPrivate": invalid_private, "invalidEnvelopes": invalid_envelopes,
                                        "schemaValidButUncataloged": bad_referenced_actions}), encoding="utf-8")
            result = subprocess.run(("node", "-e", r'''
const fs=require('fs'); const Ajv=require('ajv/dist/2020'); const root=process.argv[1];
const docs=JSON.parse(fs.readFileSync(process.argv[2])); const ajv=new Ajv({strict:true,allErrors:true});
const plan=JSON.parse(fs.readFileSync(root+'/plan.schema.json')); const priv=JSON.parse(fs.readFileSync(root+'/private-preconditions.schema.json'));
ajv.addSchema(plan); ajv.addSchema(priv); const envelope=ajv.compile(JSON.parse(fs.readFileSync(root+'/activation-envelope.schema.json')));
const privateValidate=ajv.getSchema('private-preconditions.schema.json');
if (!privateValidate(docs.validPrivate)) throw new Error(JSON.stringify(privateValidate.errors));
for (const value of docs.validEnvelopes) if (!envelope(value)) throw new Error(JSON.stringify(envelope.errors));
for (const value of docs.invalidPrivate) if (privateValidate(value)) throw new Error('malformed private accepted');
for (const value of docs.invalidEnvelopes) if (envelope(value)) throw new Error('malformed envelope accepted');
for (const value of docs.schemaValidButUncataloged) if (!envelope(value)) throw new Error('structurally valid uncataloged action rejected by schema');
console.log('strict schema comprehensive validation passed');
''', str(NIX / "proxmox"), str(docs)), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        now = planner.parse_time(sidecar["createdAt"])
        guarded_apply.validate_private(sidecar, self.plan, self.metadata, now)
        for value in invalid_private:
            with self.subTest(private=value), self.assertRaises(Exception):
                guarded_apply.validate_private(value, self.plan, self.metadata, now)
        for envelope in envelopes:
            self.activator["validate_envelope_shape"](envelope)
        for envelope in invalid_envelopes + bad_referenced_actions:
            with self.subTest(envelope=envelope), self.assertRaises(Exception):
                self.activator["validate_envelope_shape"](envelope)

    def test_initializing_journal_precedes_ownership_and_is_exactly_reconciled(self) -> None:
        plan_sha = "a" * 64
        ownership = {"activatorSha256": "8" * 64, "bundleContentSha256": "1" * 64, "gitCommit": "3" * 40,
                     "gitTree": "4" * 40, "hostSessionId": "session_01234567890", "operation": "proxmox-guarded-apply",
                     "planSha256": plan_sha, "startedAt": "2026-01-01T00:00:00Z"}
        journal = {"actionManifestSha256": "f" * 64, "challenge": "challenge_0123456789", "completed": [],
                   "format": "home-lab-proxmox-session-journal-v2", "hostSessionId": ownership["hostSessionId"],
                   "nextSequence": 1, "ownership": ownership,
                   "pendingTransition": {"operation": "begin", "requestSha256": "e" * 64},
                   "planSha256": plan_sha, "state": "initializing", "terminalResult": None}
        events = []
        with patch.dict(self.activator, {"self_sha256": lambda: "8" * 64,
                                         "read_lock": lambda: (_ for _ in ()).throw(FileNotFoundError()),
                                         "write_exclusive_fixed": lambda path, content: events.append(("lock", path)),
                                         "save_journal": lambda plan, value: events.append(("journal", value["state"]))}):
            reconciled = self.activator["reconcile_initializing"](journal)
        self.assertEqual(events, [("lock", self.activator["LOCK_PATH"]), ("journal", "begun")])
        self.assertEqual(reconciled["state"], "begun")
        self.assertIsNone(reconciled["pendingTransition"])
        self.assertEqual(reconciled["completed"][0]["requestSha256"], "e" * 64)
        cleaned = []
        with patch.dict(self.activator, {"read_lock": lambda: (_ for _ in ()).throw(FileNotFoundError()),
                                         "retained_generations": lambda: [plan_sha, "b" * 64],
                                         "read_journal": lambda value: (_ for _ in ()).throw(FileNotFoundError()),
                                         "cleanup_new_session": lambda value: cleaned.append(value)}):
            self.activator["cleanup_unowned_incomplete_generations"]()
        self.assertEqual(cleaned, [plan_sha, "b" * 64])

    def test_action_fault_boundaries_resume_exactly_and_never_replan(self) -> None:
        class Crash(BaseException):
            pass
        envelope = {"action": copy.deepcopy(self.plan["actions"][0]), "hostSessionId": "session_01234567890",
                    "operation": "action", "planSha256": "a" * 64, "protocol": 4}
        for fault in ("pending", "capture", "mutate", "completion"):
            with self.subTest(fault=fault):
                action = envelope["action"]
                manifest = {"actionManifestSha256": planner.digest([action]), "actions": [action], "entries": []}
                holder = {"actionManifestSha256": manifest["actionManifestSha256"], "completed": [],
                          "hostSessionId": envelope["hostSessionId"], "nextSequence": 1, "ownership": {},
                          "pendingTransition": None, "planSha256": envelope["planSha256"], "state": "begun",
                          "terminalResult": None}
                current = [copy.deepcopy(action["before"])]
                save_calls = [0]
                capture_calls = [0]
                mutate_calls = [0]
                def save(_plan, value):
                    save_calls[0] += 1
                    saved = copy.deepcopy(value)
                    holder.clear(); holder.update(saved)
                    if (fault == "pending" and save_calls[0] == 1) or (fault == "completion" and save_calls[0] == 4):
                        raise Crash()
                def capture(_plan, saved_action, _item):
                    capture_calls[0] += 1
                    manifest["entries"].append({"actionId": saved_action["id"], "capturedFingerprint": None})
                    if fault == "capture" and capture_calls[0] == 1:
                        raise Crash()
                    return None, copy.deepcopy(saved_action["before"])
                def mutate(_item, _identity):
                    mutate_calls[0] += 1
                    current[0] = copy.deepcopy(action["after"])
                    if fault == "mutate" and mutate_calls[0] == 1:
                        raise Crash()
                substitutions = {"read_journal": lambda plan: copy.deepcopy(holder), "read_manifest": lambda plan: manifest,
                                 "save_journal": save, "require_lock": lambda value: {},
                                 "observe_item": lambda item: copy.deepcopy(current[0]), "capture_once": capture,
                                 "mutate_item": mutate, "retain_diagnostic": lambda *args: None,
                                 "validate_session_consistency": lambda journal, saved: None}
                with patch.dict(self.activator, substitutions):
                    with self.assertRaises(Crash):
                        self.activator["action_session"](envelope)
                    if holder["state"] in {"action-pending", "action-retryable"}:
                        self.activator["resume_pending_action"](holder, manifest, envelope, False)
                    result = self.activator["action_session"](envelope)
                self.assertEqual(result["status"], "applied")
                self.assertEqual(holder["state"], "applying")
                self.assertEqual(holder["nextSequence"], 2)
                self.assertEqual([item["actionId"] for item in holder["completed"]], [action["id"]])

    def test_rollback_progress_is_durable_and_exact_retry_is_idempotent(self) -> None:
        class Crash(BaseException):
            pass
        keys = list(self.activator["SPEC"]["catalog"])[0:2]
        entries = [{"actionId": "1" * 64, "identity": keys[0], "sequence": 1},
                   {"actionId": "2" * 64, "identity": keys[1], "sequence": 2}]
        manifest = {"actionManifestSha256": "f" * 64, "actions": [{"id": "1" * 64}, {"id": "2" * 64}],
                    "entries": entries}
        envelope = {"hostSessionId": "session_01234567890", "operation": "rollback",
                    "planSha256": "a" * 64, "protocol": 4}
        for failed_progress_write in (2, 3):
            with self.subTest(write=failed_progress_write):
                holder = {"actionManifestSha256": "f" * 64, "completed": [], "hostSessionId": envelope["hostSessionId"],
                          "nextSequence": 3, "ownership": {}, "pendingTransition": None,
                          "planSha256": envelope["planSha256"], "state": "failed", "terminalResult": None}
                writes = [0]
                restore_counts = {}
                def save(_plan, value):
                    writes[0] += 1
                    if writes[0] == failed_progress_write:
                        raise Crash()
                    holder.clear(); holder.update(copy.deepcopy(value))
                def restore(entry, _item):
                    restore_counts[entry["actionId"]] = restore_counts.get(entry["actionId"], 0) + 1
                    return True
                substitutions = {"read_journal": lambda plan: copy.deepcopy(holder), "read_manifest": lambda plan: manifest,
                                 "save_journal": save, "require_lock": lambda value: {}, "restore_entry": restore,
                                 "retain_diagnostic": lambda *args: None, "release_fixed_lock": lambda path: None,
                                 "validate_session_consistency": lambda journal, saved: None}
                with patch.dict(self.activator, substitutions):
                    with self.assertRaises(Crash):
                        self.activator["rollback"](envelope)
                    result = self.activator["rollback"](envelope)
                self.assertEqual(result["restoredActionIds"], ["2" * 64, "1" * 64])
                self.assertEqual(holder["state"], "released-recovered")
                repeated = "2" * 64 if failed_progress_write == 2 else "1" * 64
                self.assertEqual(restore_counts[repeated], 2)

    def test_action_history_is_never_returned_or_proven_after_rollback(self) -> None:
        action = self.plan["actions"][0]
        envelope = {"action": action, "hostSessionId": "session_01234567890", "operation": "action",
                    "planSha256": "a" * 64, "protocol": 4}
        result = {"actionId": action["id"], "hostSessionId": envelope["hostSessionId"],
                  "sequence": action["sequence"], "status": "applied"}
        for state in ("rollback-in-progress", "rollback-failed", "recovered-release-pending", "released-recovered",
                      "committed-release-pending", "released-committed"):
            journal = {"completed": [{"actionId": action["id"], "operation": "action",
                                      "requestSha256": self.activator["request_digest"](envelope), "result": result}],
                       "state": state}
            self.assertIsNone(self.activator["completed_retry"](journal, envelope), state)
            status = {"actionManifestSha256": "f" * 64, "completedActionIds": [action["id"]],
                      "hostSessionId": envelope["hostSessionId"], "nextSequence": 2,
                      "planSha256": envelope["planSha256"], "state": state, "status": "session-status"}
            self.assertFalse(guarded_apply.status_proves(status, envelope, "f" * 64), state)

    def test_controller_retries_only_exact_proven_pending_action_or_rollback_once(self) -> None:
        action = self.plan["actions"][0]
        action_envelope = {"action": action, "hostSessionId": "session_01234567890", "operation": "action",
                           "planSha256": "a" * 64, "protocol": 4}
        action_expected = {"actionId": action["id"], "hostSessionId": action_envelope["hostSessionId"],
                           "sequence": action["sequence"], "status": "applied"}
        pending = {"actionId": action["id"], "operation": "action", "requestSha256": planner.digest(action_envelope),
                   "sequence": action["sequence"], "stage": "prepared"}
        action_status = {"actionManifestSha256": "f" * 64, "completedActionIds": [],
                         "hostSessionId": action_envelope["hostSessionId"], "nextSequence": 1,
                         "pendingTransition": pending, "planSha256": action_envelope["planSha256"],
                         "state": "action-retryable", "status": "session-status"}
        calls = []
        def action_send(value):
            calls.append(value["operation"])
            if len(calls) == 1:
                raise guarded_apply.AmbiguousTransportError("lost")
            return action_status if value["operation"] == "status" else action_expected
        with patch.object(guarded_apply, "send_session", side_effect=action_send):
            self.assertEqual(guarded_apply.send_transition(action_envelope, action_expected, "f" * 64), action_expected)
        self.assertEqual(calls, ["action", "status", "action"])
        rollback_envelope = {"hostSessionId": action_envelope["hostSessionId"], "operation": "rollback",
                             "planSha256": action_envelope["planSha256"], "protocol": 4}
        rollback_expected = {"hostSessionId": action_envelope["hostSessionId"], "planSha256": action_envelope["planSha256"],
                             "restoredActionIds": [action["id"]], "status": "recovered"}
        rollback_status = dict(action_status, state="rollback-in-progress",
                               pendingTransition={"operation": "rollback", "remainingActionIds": [action["id"]],
                                                  "requestSha256": planner.digest(rollback_envelope), "restoredActionIds": []})
        responses = [guarded_apply.AmbiguousTransportError("lost"), rollback_status, rollback_expected]
        with patch.object(guarded_apply, "send_session", side_effect=responses) as transport:
            self.assertEqual(guarded_apply.send_transition(rollback_envelope, rollback_expected, "f" * 64), rollback_expected)
        self.assertEqual(transport.call_count, 3)

    def test_internal_state_documents_are_closed_and_consistent(self) -> None:
        action = self.plan["actions"][0]
        manifest = {"actionManifestSha256": planner.digest([action]), "actions": [action], "entries": [],
                    "format": "home-lab-proxmox-rollback-v2", "planSha256": "a" * 64}
        ownership = {"activatorSha256": "8" * 64, "bundleContentSha256": "1" * 64, "gitCommit": "3" * 40,
                     "gitTree": "4" * 40, "hostSessionId": "session_01234567890", "operation": "proxmox-guarded-apply",
                     "planSha256": "a" * 64, "startedAt": "2026-01-01T00:00:00Z"}
        journal = {"actionManifestSha256": manifest["actionManifestSha256"], "challenge": "challenge_0123456789",
                   "completed": [], "format": "home-lab-proxmox-session-journal-v2",
                   "hostSessionId": ownership["hostSessionId"], "nextSequence": 1, "ownership": ownership,
                   "pendingTransition": {"operation": "begin", "requestSha256": "e" * 64},
                   "planSha256": ownership["planSha256"], "state": "initializing", "terminalResult": None}
        with patch.dict(self.activator, {"self_sha256": lambda: "8" * 64}):
            self.activator["validate_manifest"](manifest, manifest["planSha256"])
            self.activator["validate_journal"](journal, journal["planSha256"])
            for mutation in (
                lambda value: value.update({"unknown": True}),
                lambda value: value.update({"state": "applying"}),
                lambda value: value["pendingTransition"].update({"path": "/tmp/forbidden"}),
            ):
                invalid = copy.deepcopy(journal); mutation(invalid)
                with self.assertRaises(ValueError):
                    self.activator["validate_journal"](invalid, invalid["planSha256"])

    def test_controller_flock_recovers_after_killed_holder_and_overwrites_stale_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / ".reconcile").mkdir(mode=0o700)
            code = """import sys,time
from pathlib import Path
sys.path.insert(0, sys.argv[2])
import apply
held=apply.controller_lock(Path(sys.argv[1]), {'operation':'killed-holder'})
print('ready', flush=True)
time.sleep(60)
"""
            child = subprocess.Popen((sys.executable, "-c", code, str(root), str(NIX / "proxmox")),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with self.assertRaisesRegex(ValueError, "already held"):
                    guarded_apply.controller_lock(root, {"operation": "contender"})
                child.kill(); child.wait(timeout=5)
                recovered = guarded_apply.controller_lock(root, {"operation": "recovered"})
                guarded_apply.release_controller_lock(recovered)
                lock = root / ".reconcile/controller-apply.lock"
                self.assertTrue(lock.is_file())
                self.assertEqual(json.loads(lock.read_bytes()), {"operation": "recovered"})
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=5)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()

    def test_apply_preflight_recovers_active_and_expired_sessions_without_new_mutation(self) -> None:
        active = {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "b" * 64,
                  "capturedActionIds": [self.plan["actions"][0]["id"]], "completedActionIds": [],
                  "hostSessionId": "session_01234567890", "nextSequence": 1,
                  "pendingTransition": {"actionId": self.plan["actions"][0]["id"], "operation": "action",
                                        "requestSha256": "f" * 64, "sequence": 1, "stage": "prepared"},
                  "planSha256": self.plan["planSha256"], "state": "failed", "status": "session-status"}
        recovered = {"hostSessionId": "session_01234567890", "planSha256": self.plan["planSha256"],
                     "restoredActionIds": [self.plan["actions"][0]["id"]], "status": "recovered"}
        for expired in (False, True):
            with self.subTest(expired=expired), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                sidecar = self.sidecar()
                if expired:
                    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
                    sidecar["createdAt"] = planner.format_time(now - dt.timedelta(seconds=120))
                    sidecar["validUntil"] = planner.format_time(now - dt.timedelta(seconds=60))
                self.write_inputs(root, sidecar)
                operations = []
                def send(envelope):
                    operations.append(envelope)
                    return active if envelope["operation"] == "status" else recovered
                args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
                with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                        patch.object(guarded_apply, "send_session", side_effect=send), \
                        patch.object(planner, "live_observation") as observe:
                    result = guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
                self.assertIn("status=recovered", result)
                self.assertEqual([value["operation"] for value in operations], ["status", "rollback"])
                observe.assert_not_called()
                if expired:
                    with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                            patch.object(guarded_apply, "send_session", return_value={"hostSessionId": "session_01234567890",
                                "operation": "status", "planSha256": self.plan["planSha256"], "status": "failed"}), \
                            self.assertRaisesRegex(ValueError, "expired.*no retained session"):
                        guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))

    def test_apply_preflight_handles_released_terminal_sessions(self) -> None:
        base = {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "b" * 64,
                "capturedActionIds": [self.plan["actions"][0]["id"]], "hostSessionId": "session_01234567890",
                "pendingTransition": None, "planSha256": self.plan["planSha256"], "status": "session-status"}
        cases = (
            (dict(base, completedActionIds=[self.plan["actions"][0]["id"]], nextSequence=2,
                  state="released-committed"), "already-applied", 1),
            (dict(base, completedActionIds=[], nextSequence=1, state="released-recovered"), "already-recovered", 0),
        )
        for host_status, expected, observations in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as name:
                root = Path(name); self.write_inputs(root)
                args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
                with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                        patch.object(guarded_apply, "send_session", return_value=host_status), \
                        patch.object(planner, "live_observation", return_value=self.after_observation) as observe:
                    result = guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
                self.assertIn("status=" + expected, result)
                self.assertEqual(observe.call_count, observations)

    def test_deterministic_begin_uses_authenticated_sidecar_creation_time(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); sidecar = self.sidecar(); self.write_inputs(root, sidecar)
            seen = []
            responses = iter([
                {"actionManifestSha256": planner.digest(self.plan["actions"]), "beginRequestSha256": "0" * 64,
                 "capturedActionIds": [], "completedActionIds": [], "hostSessionId": sidecar["hostSession"]["id"],
                 "nextSequence": 1, "pendingTransition": None, "planSha256": self.plan["planSha256"], "state": "begun",
                 "status": "session-status"},
                {"actionManifestSha256": planner.digest(self.plan["actions"]), "hostSessionId": sidecar["hostSession"]["id"],
                 "planSha256": self.plan["planSha256"], "status": "begun"},
            ])
            def send(envelope):
                if envelope["operation"] == "begin":
                    seen.append(envelope["startedAt"])
                response = next(responses)
                if envelope["operation"] == "status":
                    return response
                return response
            args = SimpleNamespace(repo_root=str(root), plan_sha=self.plan["planSha256"], approve_plan_sha=self.plan["planSha256"])
            with patch.object(planner, "bundle_inputs", return_value=(self.bindings, self.projection, self.manifest, self.metadata)), \
                    patch.object(guarded_apply, "send_session", side_effect=send), \
                    patch.object(planner, "live_observation", side_effect=ValueError("stop after deterministic begin")), \
                    self.assertRaises(ValueError):
                guarded_apply.apply(args, Path("fixed"), Path("fixed.sha"), Path("source"))
            self.assertEqual(seen, [sidecar["createdAt"]])


    def test_host_binds_begin_time_and_status_to_exact_authenticated_request(self) -> None:
        sidecar = self.sidecar()
        envelope = {"actions": self.plan["actions"], "bindings": {
            "activatorSha256": self.bindings["activatorSha256"],
            "bundleContentSha256": self.bindings["bundleContentSha256"],
            "gitCommit": self.bindings["gitCommit"], "gitTree": self.bindings["gitTree"]},
            "hostSessionId": sidecar["hostSession"]["id"], "operation": "begin",
            "planSha256": self.plan["planSha256"], "privatePreconditions": sidecar,
            "protocol": 4, "startedAt": sidecar["createdAt"]}
        action_manifest_sha = planner.digest(self.plan["actions"])
        begin_result = {"actionManifestSha256": action_manifest_sha,
                        "hostSessionId": sidecar["hostSession"]["id"],
                        "planSha256": self.plan["planSha256"], "status": "begun"}
        ownership = {"activatorSha256": self.bindings["activatorSha256"],
                     "bundleContentSha256": self.bindings["bundleContentSha256"],
                     "gitCommit": self.bindings["gitCommit"], "gitTree": self.bindings["gitTree"],
                     "hostSessionId": sidecar["hostSession"]["id"], "operation": "proxmox-guarded-apply",
                     "planSha256": self.plan["planSha256"], "startedAt": sidecar["createdAt"]}
        manifest = {"actionManifestSha256": action_manifest_sha, "actions": self.plan["actions"], "entries": [],
                    "format": "home-lab-proxmox-rollback-v2", "planSha256": self.plan["planSha256"]}
        journal = {"actionManifestSha256": action_manifest_sha, "challenge": sidecar["challenge"],
                   "completed": [{"actionId": None, "operation": "begin",
                                   "requestSha256": planner.digest(envelope), "result": begin_result}],
                   "format": "home-lab-proxmox-session-journal-v2",
                   "hostSessionId": sidecar["hostSession"]["id"], "nextSequence": 1,
                   "ownership": ownership, "pendingTransition": None, "planSha256": self.plan["planSha256"],
                   "state": "begun", "terminalResult": None}
        self.activator["validate_manifest"](manifest, self.plan["planSha256"])
        self.activator["validate_journal"](journal, self.plan["planSha256"])
        status = self.activator["status_result"](journal, manifest)
        self.assertEqual(guarded_apply.validate_host_status(status, self.plan, sidecar["hostSession"]["id"]), status)
        self.assertTrue(guarded_apply.status_proves(status, envelope, planner.digest(self.plan["actions"])))
        status["beginRequestSha256"] = "0" * 64
        self.assertFalse(guarded_apply.status_proves(status, envelope, planner.digest(self.plan["actions"])))
        status["beginRequestSha256"] = "bad"
        with self.assertRaises(guarded_apply.AmbiguousSessionError):
            guarded_apply.validate_host_status(status, self.plan, sidecar["hostSession"]["id"])
        status.pop("beginRequestSha256")
        with self.assertRaises(ValueError):
            guarded_apply.validate_host_status(status, self.plan, sidecar["hostSession"]["id"])
        changed = copy.deepcopy(envelope)
        changed["startedAt"] = "2026-08-11T00:00:01Z"
        with patch.dict(self.activator, {
            "validate_private": lambda *args: sidecar,
            "self_sha256": lambda: self.bindings["activatorSha256"],
        }), self.assertRaisesRegex(ValueError, "timestamp differs"):
            self.activator["begin"](changed)

    def test_terminal_consistency_rejects_premature_commit_and_malformed_results(self) -> None:
        action = self.plan["actions"][0]
        manifest = {"actionManifestSha256": planner.digest([action]), "actions": [action],
                    "entries": [{"actionId": action["id"]}], "format": "home-lab-proxmox-rollback-v2",
                    "planSha256": self.plan["planSha256"]}
        host = "session_01234567890"
        begin_result = {"actionManifestSha256": manifest["actionManifestSha256"], "hostSessionId": host,
                        "planSha256": self.plan["planSha256"], "status": "begun"}
        action_result = {"actionId": action["id"], "hostSessionId": host, "sequence": 1, "status": "applied"}
        terminal = {"hostSessionId": host, "planSha256": self.plan["planSha256"], "status": "committed"}
        journal = {"actionManifestSha256": manifest["actionManifestSha256"], "completed": [
            {"actionId": None, "operation": "begin", "requestSha256": "1" * 64, "result": begin_result},
            {"actionId": action["id"], "operation": "action", "requestSha256": "2" * 64, "result": action_result},
            {"actionId": None, "operation": "commit", "requestSha256": "3" * 64, "result": terminal}],
            "hostSessionId": host, "nextSequence": 2, "pendingTransition": None,
            "planSha256": self.plan["planSha256"], "state": "released-committed", "terminalResult": terminal}
        self.activator["validate_session_consistency"](journal, manifest)
        malformed = []
        value = copy.deepcopy(journal); value["completed"].pop(1); value["nextSequence"] = 1; value_manifest = copy.deepcopy(manifest); value_manifest["entries"] = []; malformed.append((value, value_manifest))
        value = copy.deepcopy(journal); value["terminalResult"]["status"] = "recovered"; malformed.append((value, manifest))
        value = copy.deepcopy(journal); value["completed"][-1]["result"]["status"] = "recovered"; malformed.append((value, manifest))
        for value, saved in malformed:
            with self.assertRaises(ValueError):
                self.activator["validate_session_consistency"](value, saved)

    def test_serialized_manifest_capacity_is_identical_for_write_and_read_bounds(self) -> None:
        manifest = {"actionManifestSha256": planner.digest(self.plan["actions"]), "actions": self.plan["actions"],
                    "entries": [], "format": "home-lab-proxmox-rollback-v2", "planSha256": self.plan["planSha256"]}
        size = len(self.activator["canonical"](manifest))
        with patch.dict(self.activator, {"MAX_MANIFEST_BYTES": size,
                                         "replace_canonical_root_file": lambda path, value: None}):
            self.activator["save_manifest"](self.plan["planSha256"], manifest)
        with patch.dict(self.activator, {"MAX_MANIFEST_BYTES": size - 1,
                                         "replace_canonical_root_file": lambda path, value: None}), \
                self.assertRaisesRegex(ValueError, "serialized rollback manifest capacity"):
            self.activator["save_manifest"](self.plan["planSha256"], manifest)
        source = (NIX / "proxmox/activator-template.py").read_text(encoding="utf-8")
        self.assertIn("read_canonical_root_file(path, MAX_MANIFEST_BYTES", source)
        self.assertLess(self.activator["MAX_ROLLBACK_RAW_BYTES"] * 4 // 3, self.activator["MAX_MANIFEST_BYTES"])

    def test_schemas_are_closed_and_bootstrap_required_is_explicit(self) -> None:
        for name in ("private-preconditions.schema.json", "activation-envelope.schema.json"):
            schema = json.loads((NIX / "proxmox" / name).read_bytes())
            if "additionalProperties" in schema:
                self.assertFalse(schema["additionalProperties"])
        source = (NIX / "proxmox/activator-template.py").read_text(encoding="utf-8")
        self.assertIn("bootstrap-required: protected session key is unavailable", source)
        failed = __import__("subprocess").CompletedProcess(guarded_apply.SSH_APPLY_COMMAND, 255, b"", b"redacted")
        envelope = {"hostSessionId": "session_01234567890", "operation": "begin", "planSha256": "a" * 64, "protocol": 4}
        with patch.object(guarded_apply.subprocess, "run", return_value=failed), self.assertRaisesRegex(ValueError, "bootstrap-required"):
            guarded_apply.send_transition(envelope, {}, "b" * 64, bootstrap=True)


if __name__ == "__main__":
    unittest.main()
