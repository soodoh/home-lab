#!/usr/bin/env python3
"""Unit tests for the guarded Proxmox VFIO recovery helper."""

from __future__ import annotations

import importlib.util
import contextlib
import fcntl
import io
import os
import signal
import subprocess
import types
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "infrastructure/host-lifecycle/proxmox/vfio-recover.py"
SPEC = importlib.util.spec_from_file_location("vfio_recover", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load VFIO recovery module")
VFIO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VFIO
SPEC.loader.exec_module(VFIO)


class FakeBackend:
    def __init__(self) -> None:
        self.members = ("0000:03:00.0",)
        self.identities = {
            "0000:03:00.0": ("1002", "744c"),
        }
        self.drivers = {bdf: "vfio-pci" for bdf in self.members}
        self.node_exists = True
        self.operations: list[tuple[str, str]] = []
        self.fail_binds: dict[str, int] = {}

    def group_members(self, group: int) -> tuple[str, ...]:
        return self.members if group == 14 else ()

    def identity(self, bdf: str) -> tuple[str | None, str | None]:
        return self.identities.get(bdf, (None, None))

    def driver(self, bdf: str) -> str | None:
        return self.drivers.get(bdf)

    def device_node_exists(self, group: int) -> bool:
        return group == 14 and self.node_exists

    def unbind(self, bdf: str) -> None:
        self.operations.append(("unbind", bdf))
        self.drivers[bdf] = None

    def bind(self, bdf: str) -> None:
        self.operations.append(("bind", bdf))
        failures = self.fail_binds.get(bdf, 0)
        if failures:
            self.fail_binds[bdf] = failures - 1
            raise OSError("injected bind failure")
        self.drivers[bdf] = "vfio-pci"


POLICY = VFIO.Policy(
    vmid=100,
    iommu_group=14,
    confirmation="recover-vm-100-vfio-group-14",
    lock_path=Path("/run/lock/home-lab-vfio-recovery.lock"),
    devices=(
        VFIO.DevicePolicy(bdf="0000:03:00.0", vendor="1002", device="744c"),
    ),
)


def stopped(_: int) -> str:
    return "stopped"


def no_users(_: int) -> tuple[str, ...]:
    return ()


class VfioRecoveryTests(unittest.TestCase):
    def test_ready_observation_is_read_only(self) -> None:
        backend = FakeBackend()
        result = VFIO.inspect(POLICY, backend, stopped, no_users)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(backend.operations, [])

    def test_running_vm_blocks_recovery(self) -> None:
        backend = FakeBackend()
        result = VFIO.inspect(POLICY, backend, lambda _: "running", no_users)
        self.assertEqual(result["state"], "blocked")
        self.assertIn("VM 100 must be stopped", result["reasons"][0])
        with self.assertRaisesRegex(VFIO.RecoveryError, "prerequisites are blocked"):
            VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, lambda _: "running", no_users)
        self.assertEqual(backend.operations, [])

    def test_identity_group_and_user_mismatches_block(self) -> None:
        backend = FakeBackend()
        backend.identities["0000:03:00.0"] = ("1002", "ffff")
        backend.members = (*backend.members, "0000:04:00.0")
        result = VFIO.inspect(POLICY, backend, stopped, lambda _: ("4321",))
        self.assertEqual(result["state"], "blocked")
        self.assertTrue(any("group membership" in reason for reason in result["reasons"]))
        self.assertTrue(any("PCI identity mismatch" in reason for reason in result["reasons"]))
        self.assertTrue(any("open by a process" in reason for reason in result["reasons"]))

    def test_exact_confirmation_and_operation_order(self) -> None:
        backend = FakeBackend()
        with self.assertRaisesRegex(VFIO.RecoveryError, "confirmation"):
            VFIO.perform_recovery(POLICY, backend, "wrong", stopped, no_users)
        result = VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, stopped, no_users)
        self.assertTrue(result["recovered"])
        self.assertEqual(backend.operations, [
            ("unbind", "0000:03:00.0"),
            ("bind", "0000:03:00.0"),
        ])

    def test_failure_attempts_full_rebind_rollback(self) -> None:
        backend = FakeBackend()
        backend.fail_binds["0000:03:00.0"] = 1
        with self.assertRaisesRegex(VFIO.RecoveryError, "injected bind failure"):
            VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, stopped, no_users)
        self.assertEqual(backend.drivers, {
            "0000:03:00.0": "vfio-pci",
        })

    def test_policy_loader_rejects_extra_fields(self) -> None:
        document = {
            "confirmation": POLICY.confirmation,
            "devices": [
                {"bdf": device.bdf, "device": device.device, "vendor": device.vendor}
                for device in POLICY.devices
            ],
            "iommuGroup": POLICY.iommu_group,
            "lockPath": str(POLICY.lock_path),
            "vmid": POLICY.vmid,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(VFIO.parse_policy(json.loads(path.read_text())), POLICY)
            document["unexpected"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(VFIO.RecoveryError, "unexpected fields"):
                VFIO.parse_policy(json.loads(path.read_text()))


# Reuse only the confined test harness, never another participant at runtime.
PROTOCOL_SPEC = importlib.util.spec_from_file_location(
    "vfio_protocol_fixture", ROOT / "scripts/controller/test-proxmox-capability-protocol.py")
PROTOCOL = importlib.util.module_from_spec(PROTOCOL_SPEC)
PROTOCOL_SPEC.loader.exec_module(PROTOCOL)


class SyntheticBackend:
    def __init__(self):
        self.operations = []
        self.bound = True
        self.fail_bind = False
        self.check = lambda: None

    def group_members(self, group):
        self.check()
        return ("0000:42:00.0",) if group == 77 else ()

    def identity(self, bdf): return ("1234", "5678")
    def driver(self, bdf): return "vfio-pci" if self.bound else None
    def device_node_exists(self, group): return group == 77

    def unbind(self, bdf):
        self.check(); self.operations.append(("unbind", bdf)); self.bound = False

    def bind(self, bdf):
        self.check(); self.operations.append(("bind", bdf))
        if self.fail_bind:
            self.fail_bind = False
            raise OSError("synthetic bind failure")
        self.bound = True


def seed_vfio():
    document = {"vmid": 4242, "iommuGroup": 77, "confirmation": "synthetic-exact-recovery",
                "lockPath": str(VFIO.VFIO_LOCK),
                "devices": [{"bdf": "0000:42:00.0", "vendor": "1234", "device": "5678"}]}
    PROTOCOL.seed(VFIO.POLICY_PATH, json.dumps(document).encode(), 0o440)
    mutexes = [VFIO.OPERATION_LOCK, VFIO.VFIO_LOCK, Path("/run/lock/qemu-server/lock-4242.conf")]
    for path in mutexes: PROTOCOL.seed(path, b"synthetic mutex\n")
    for path in VFIO.RETAINED_OWNERS: path.parent.mkdir(parents=True, exist_ok=True)
    Path("/run/lock").chmod(0o1777)
    return document, mutexes


def isolated_flags(value):
    return types.SimpleNamespace(**({name: getattr(sys.flags, name) for name in dir(sys.flags)
                                    if not name.startswith("_")} | {"isolated": value}))


# argparse lazily imports formatter dependencies; preload before empty chroots.
VFIO.argparse.ArgumentParser().add_subparsers().add_parser("synthetic")


class VfioEntryTests(unittest.TestCase):
    def test_fixed_interpreter_and_advisory_entry(self):
        backend = FakeBackend()
        with patch.object(VFIO.os, "geteuid", return_value=0), \
             patch.object(VFIO.sys, "argv", ["vfio", "recover", "--confirm", POLICY.confirmation]), \
             patch.object(VFIO.sys, "flags", isolated_flags(0)), \
             patch.object(VFIO, "locked_recovery") as recovery:
            with self.assertRaisesRegex(VFIO.RecoveryError, "fixed .* invocation"):
                VFIO.main()
            recovery.assert_not_called()
            with patch.object(VFIO.sys, "flags", isolated_flags(1)), patch.object(VFIO.sys, "executable", "/hostile/python3"):
                with self.assertRaisesRegex(VFIO.RecoveryError, "fixed .* invocation"): VFIO.main()
            recovery.assert_not_called()
        with patch.object(VFIO.os, "geteuid", return_value=0), \
             patch.object(VFIO.sys, "argv", ["vfio", "observe"]), \
             patch.object(VFIO.sys, "flags", isolated_flags(1)), \
             patch.object(VFIO.sys, "executable", "/usr/bin/python3"), \
             patch.object(VFIO, "load_policy", return_value=POLICY), \
             patch.object(VFIO, "RealBackend", return_value=backend), \
             patch.object(VFIO, "inspect", return_value={"state": "ready"}), \
             patch.object(VFIO, "open_fixed") as opened, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(VFIO.main(), 0)
            self.assertTrue(json.loads(out.getvalue())["advisory"])
            opened.assert_not_called()
        self.assertEqual(backend.operations, [])

    def test_isolated_source_import_ignores_python_path_and_environment(self):
        with tempfile.TemporaryDirectory(prefix="vfio-import-fixture-") as directory:
            for name in ("json", "dataclasses", "pathlib", "sitecustomize"):
                (Path(directory) / (name + ".py")).write_text("raise RuntimeError('hostile module substitution')\n")
            environment = {"PATH": directory, "PYTHONPATH": directory, "PYTHONHOME": directory,
                           "PYTHONSTARTUP": str(Path(directory) / "sitecustomize.py"),
                           "PERL5LIB": directory, "PERL5OPT": "-Mhostile"}
            result = subprocess.run([sys.executable, "-I", "-c",
                "import runpy,sys; m=runpy.run_path(sys.argv[1]); assert str(m['QM_PATH']) == '/usr/sbin/qm'; print('isolated-source-only')",
                str(MODULE_PATH)], cwd=directory, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "isolated-source-only\n")


class NativeVfioTests(unittest.TestCase):
    def invoke(self, backend, confirmation="synthetic-exact-recovery"):
        perform = VFIO.perform_recovery
        with patch.object(VFIO, "RealBackend", return_value=backend), \
             patch.object(VFIO, "perform_recovery", side_effect=lambda p, b, c: perform(p, b, c, stopped, no_users)), \
             patch.object(VFIO.sys, "argv", ["vfio", "recover", "--confirm", confirmation]), \
             patch.object(VFIO.sys, "executable", "/usr/bin/python3"), \
             patch.object(VFIO.sys, "flags", isolated_flags(1)), \
             contextlib.redirect_stdout(io.StringIO()):
            return VFIO.main()

    def refused(self, backend, mutexes, confirmation="synthetic-exact-recovery"):
        before = PROTOCOL.descriptor_set()
        with self.assertRaises(VFIO.RecoveryError): self.invoke(backend, confirmation)
        self.assertEqual(backend.operations, [])
        self.assertEqual(before, PROTOCOL.descriptor_set())

    @PROTOCOL.confined
    def test_main_exact_confirmation_policy_order_and_compensation(self):
        document, mutexes = seed_vfio(); backend = SyntheticBackend()
        self.refused(backend, mutexes, "wrong")
        # Publish replacement policy while the shared operation mutex is held.
        real_open = VFIO.open_fixed
        def publish(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            if path == VFIO.OPERATION_LOCK:
                self.assertTrue(PROTOCOL.locked(path))
                document["confirmation"] = "replacement-exact-token"
                PROTOCOL.seed(VFIO.POLICY_PATH, json.dumps(document).encode(), 0o440)
            return fd
        with patch.object(VFIO, "open_fixed", side_effect=publish): self.refused(backend, mutexes)
        backend.check = lambda: self.assertTrue(all(PROTOCOL.locked(p) for p in mutexes))
        backend.fail_bind = True
        before = PROTOCOL.descriptor_set()
        with self.assertRaisesRegex(VFIO.RecoveryError, "synthetic bind failure"):
            self.invoke(backend, "replacement-exact-token")
        self.assertEqual([op for op, _ in backend.operations], ["unbind", "bind", "bind"])
        self.assertTrue(backend.bound)
        self.assertEqual(before, PROTOCOL.descriptor_set())
        for path in mutexes: PROTOCOL.available(path)
        backend.operations.clear()
        self.assertEqual(self.invoke(backend, "replacement-exact-token"), 0)

    @PROTOCOL.confined
    def test_every_mutex_hostile_shape_missing_busy_and_zero_writes(self):
        _, mutexes = seed_vfio(); backend = SyntheticBackend()
        for victim in mutexes:
            original = victim.read_bytes()
            for shape in ("missing", "symlink", "fifo", "directory", "hardlink", "uid", "gid", "mode"):
                with self.subTest(victim=victim, shape=shape):
                    victim.unlink()
                    alias = victim.with_name(victim.name + ".alias")
                    if shape == "symlink": victim.symlink_to("absent-target")
                    elif shape == "fifo": os.mkfifo(victim, 0o600)
                    elif shape == "directory": victim.mkdir()
                    elif shape != "missing":
                        PROTOCOL.seed(victim, original)
                        if shape == "hardlink": os.link(victim, alias)
                        elif shape == "uid": os.chown(victim, 12345, 0)
                        elif shape == "gid": os.chown(victim, 0, 12345)
                        elif shape == "mode": victim.chmod(0o640)
                    before = victim.lstat() if os.path.lexists(victim) else None
                    self.refused(backend, mutexes)
                    if before is None: self.assertFalse(os.path.lexists(victim))
                    else: self.assertEqual(VFIO.fingerprint(before), VFIO.fingerprint(victim.lstat()))
                    if shape == "directory": victim.rmdir()
                    elif os.path.lexists(victim): victim.unlink()
                    if alias.exists(): alias.unlink()
                    PROTOCOL.seed(victim, original)
            ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe()
            pid = os.fork()
            if pid == 0:
                signal.alarm(10); os.close(ready_r); os.close(release_w)
                fd = os.open(victim, os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(ready_w, b"1"); os.read(release_r, 1); os.close(fd); os._exit(0)
            os.close(ready_w); os.close(release_r)
            try:
                self.assertEqual(os.read(ready_r, 1), b"1")
                self.refused(backend, mutexes)
                for path in mutexes:
                    if path != victim: PROTOCOL.available(path)
            finally:
                os.close(ready_r); os.write(release_w, b"1"); os.close(release_w)
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
            for path in mutexes: PROTOCOL.available(path)

    @PROTOCOL.confined
    def test_ancestors_replacement_inspection_errors_and_partial_cleanup(self):
        _, mutexes = seed_vfio(); backend = SyntheticBackend()
        for directory in (Path("/run"), Path("/run/lock"), mutexes[-1].parent,
                          VFIO.OPERATION_LOCK.parent, VFIO.RETAINED_OWNERS[-1].parent):
            mode = directory.stat().st_mode & 0o7777
            for bad_mode in (0o777, 0o1777):
                if directory == Path("/run/lock") and bad_mode == 0o1777: continue
                directory.chmod(bad_mode)
                self.refused(backend, mutexes)
                self.assertEqual(directory.stat().st_mode & 0o7777, bad_mode)
                directory.chmod(mode)
            for uid, gid in ((12345, 0), (0, 12345)):
                os.chown(directory, uid, gid)
                self.refused(backend, mutexes)
                os.chown(directory, 0, 0)
            moved = directory.with_name(directory.name + "-retained")
            directory.rename(moved); directory.symlink_to(moved)
            self.refused(backend, mutexes)
            directory.unlink(); moved.rename(directory)
        native_flock = fcntl.flock
        for victim in mutexes:
            inode = victim.stat().st_ino
            def replace(fd, flags):
                native_flock(fd, flags)
                if os.fstat(fd).st_ino == inode:
                    victim.rename(victim.with_name(victim.name + "-old")); PROTOCOL.seed(victim)
            with patch.object(VFIO.fcntl, "flock", side_effect=replace): self.refused(backend, mutexes)
            PROTOCOL.available(victim.with_name(victim.name + "-old"))
            for path in mutexes: PROTOCOL.available(path)
        # An entire parent replacement is also refused after successful flock.
        victim = mutexes[-1]; inode = victim.stat().st_ino; parent = victim.parent
        def replace_parent(fd, flags):
            native_flock(fd, flags)
            if os.fstat(fd).st_ino == inode:
                parent.rename(parent.with_name("qemu-old")); PROTOCOL.seed(victim)
        with patch.object(VFIO.fcntl, "flock", side_effect=replace_parent): self.refused(backend, mutexes)
        before = PROTOCOL.descriptor_set()
        with patch.object(VFIO, "reject_retained_owners", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.invoke(backend)
        self.assertEqual(before, PROTOCOL.descriptor_set())
        native_stat = os.stat
        def denied(path, *args, **kwargs):
            if path == "active.json": raise PermissionError("synthetic inspection denial")
            return native_stat(path, *args, **kwargs)
        with patch.object(VFIO.os, "stat", side_effect=denied): self.refused(backend, mutexes)

    @PROTOCOL.confined
    def test_policy_replacement_during_read_and_all_partial_acquisition_exceptions(self):
        document, mutexes = seed_vfio(); backend = SyntheticBackend()
        native_read = os.read
        replaced = [False]
        def replace_policy(fd, count):
            raw = native_read(fd, count)
            if not replaced[0] and raw:
                replaced[0] = True
                VFIO.POLICY_PATH.rename(VFIO.POLICY_PATH.with_name("policy-original"))
                PROTOCOL.seed(VFIO.POLICY_PATH, json.dumps(document).encode(), 0o440)
            return raw
        with patch.object(VFIO.os, "read", side_effect=replace_policy): self.refused(backend, mutexes)
        recheck = VFIO.recheck_named
        for victim in [*mutexes, VFIO.POLICY_PATH]:
            for exception in (PermissionError, KeyboardInterrupt):
                def fail_named(path, parent, info):
                    if path == victim: raise exception("synthetic partial failure")
                    return recheck(path, parent, info)
                before = PROTOCOL.descriptor_set()
                with patch.object(VFIO, "recheck_named", side_effect=fail_named):
                    with self.assertRaises(VFIO.RecoveryError if exception is PermissionError else KeyboardInterrupt):
                        self.invoke(backend)
                self.assertEqual(before, PROTOCOL.descriptor_set())
                self.assertEqual(backend.operations, [])
                for path in mutexes: PROTOCOL.available(path)
        # A postcondition failure is still within all descriptors, not a second
        # invocation or automatic retry. Existing same-invocation semantics stay.
        checks = [0]
        def postcondition():
            self.assertTrue(all(PROTOCOL.locked(p) for p in mutexes))
            checks[0] += 1
            if checks[0] == 4: backend.bound = False
        backend.check = postcondition
        with self.assertRaisesRegex(VFIO.RecoveryError, "postconditions failed"): self.invoke(backend)
        for path in mutexes: PROTOCOL.available(path)

    @PROTOCOL.confined
    def test_every_retained_owner_form_without_descriptor_or_token_exemption(self):
        _, mutexes = seed_vfio(); backend = SyntheticBackend()
        for owner in VFIO.RETAINED_OWNERS:
            for shape in ("regular", "empty", "directory", "dangling", "fifo"):
                if shape == "directory": owner.mkdir()
                elif shape == "dangling": owner.symlink_to("absent-owner")
                elif shape == "fifo": os.mkfifo(owner, 0o600)
                else:
                    raw = b"" if shape == "empty" else json.dumps({"boot_id": "synthetic-current", "token": "synthetic-exact-recovery", "sha256": "a" * 64}).encode()
                    PROTOCOL.seed(owner, raw)
                before = VFIO.fingerprint(owner.lstat())
                for path in mutexes: PROTOCOL.available(path)
                native_open = os.open
                def forbid_owner_open(path, *args, **kwargs):
                    if path == owner.name or path == owner:
                        raise AssertionError("owner contents must never be opened")
                    return native_open(path, *args, **kwargs)
                with patch.object(VFIO.os, "open", side_effect=forbid_owner_open):
                    self.refused(backend, mutexes)
                self.assertEqual(before, VFIO.fingerprint(owner.lstat()))
                if shape in ("regular", "empty"): self.assertEqual(owner.read_bytes(), raw)
                if shape == "directory": owner.rmdir()
                else: owner.unlink()
        # Operation must be acquired before any owner inspection or policy read.
        fd = os.open(VFIO.OPERATION_LOCK, os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with patch.object(VFIO, "reject_retained_owners") as owners, patch.object(VFIO, "load_policy") as policy:
                self.refused(backend, mutexes); owners.assert_not_called(); policy.assert_not_called()
        finally: os.close(fd)

    @PROTOCOL.confined
    def test_fixed_policy_and_qm_dependency_substitution(self):
        document, mutexes = seed_vfio(); backend = SyntheticBackend()
        for change in ({"unexpected": True}, {"lockPath": "/run/lock/alternate.lock"},
                       {"lockPath": "/run/lock/./home-lab-vfio-recovery.lock"}):
            PROTOCOL.seed(VFIO.POLICY_PATH, json.dumps(document | change).encode(), 0o440)
            self.refused(backend, mutexes)
        for shape in ("missing", "link", "fifo", "writable", "uid", "gid", "hardlink", "directory"):
            path = VFIO.POLICY_PATH; path.unlink()
            if shape == "link": path.symlink_to("foreign-policy")
            elif shape == "fifo": os.mkfifo(path)
            elif shape == "directory": path.mkdir()
            elif shape != "missing":
                PROTOCOL.seed(path, json.dumps(document).encode(), 0o440)
                if shape == "writable": path.chmod(0o666)
                if shape == "uid": os.chown(path, 12345, 0)
                if shape == "gid": os.chown(path, 0, 12345)
                if shape == "hardlink": os.link(path, path.with_name("policy-alias"))
            self.refused(backend, mutexes)
            if shape == "directory": path.rmdir()
            elif os.path.lexists(path): path.unlink()
            if path.with_name("policy-alias").exists(): path.with_name("policy-alias").unlink()
            PROTOCOL.seed(path, json.dumps(document).encode(), 0o440)
        with self.assertRaises(VFIO.RecoveryError): VFIO.qm_status(4242)
        PROTOCOL.seed(VFIO.QM_PATH, b"synthetic non-executable contents", 0o755)
        with patch.dict(os.environ, {"PATH": "/hostile", "PYTHONPATH": "/hostile", "PYTHONHOME": "/hostile", "PERL5LIB": "/hostile", "PERL5OPT": "-Mhostile", "LD_PRELOAD": "/hostile"}), \
             patch.object(VFIO.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout="status: stopped")) as run:
            self.assertEqual(VFIO.qm_status(4242), "stopped")
            self.assertEqual(run.call_args.args[0], ["/usr/sbin/qm", "status", "4242"])
            self.assertEqual(run.call_args.kwargs["env"], VFIO.NATIVE_ENV)
            self.assertEqual(set(run.call_args.kwargs["env"]), {"PATH", "LC_ALL"})
            self.assertTrue(run.call_args.kwargs["close_fds"])
            def replace_executable(*args, **kwargs):
                VFIO.QM_PATH.rename(VFIO.QM_PATH.with_name("qm-original"))
                PROTOCOL.seed(VFIO.QM_PATH, b"synthetic replacement", 0o755)
                return types.SimpleNamespace(returncode=0, stdout="status: stopped")
            run.side_effect = replace_executable
            with self.assertRaisesRegex(VFIO.RecoveryError, "pathname changed"): VFIO.qm_status(4242)
            run.side_effect = None
            run.reset_mock(); VFIO.QM_PATH.chmod(0o777)
            with self.assertRaises(VFIO.RecoveryError): VFIO.qm_status(4242)
            run.assert_not_called()
            VFIO.QM_PATH.unlink(); VFIO.QM_PATH.symlink_to("qm-substitute")
            with self.assertRaises(VFIO.RecoveryError): VFIO.qm_status(4242)
            run.assert_not_called()

    @PROTOCOL.confined
    def test_child_contention_both_directions_and_retained_publication(self):
        observer = PROTOCOL.NativeProtocolTests().setup_protocol()
        _, mutexes = seed_vfio(); backend = SyntheticBackend()
        deploy = PROTOCOL.module(PROTOCOL.activator_source, "vfio_contending_deploy")
        for participant in (observer, deploy):
            for owner in (VFIO.RETAINED_OWNERS[0], VFIO.RETAINED_OWNERS[1]):
                ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe()
                pid = os.fork()
                if pid == 0:
                    signal.alarm(10)
                    os.close(ready_r); os.close(release_w)
                    held = participant.acquire_locks() if participant is observer else participant.acquire_mutexes([deploy.OPERATION_LOCK])
                    if owner.name.endswith(".lock") and owner == VFIO.RETAINED_OWNERS[0]: owner.mkdir()
                    else: PROTOCOL.seed(owner, b"synthetic retained boot/token/hash")
                    os.write(ready_w, b"1"); os.read(release_r, 1)
                    for fd in held: os.close(fd)
                    os._exit(0)
                os.close(ready_w); os.close(release_r)
                try:
                    self.assertEqual(os.read(ready_r, 1), b"1")
                    self.refused(backend, mutexes)
                finally:
                    os.close(ready_r); os.write(release_w, b"1"); os.close(release_w)
                    self.assertEqual(os.waitpid(pid, 0)[1], 0)
                self.refused(backend, mutexes)
                if owner.is_dir(): owner.rmdir()
                else: owner.unlink()
            # Child recovery holds its descriptors across actual inspection,
            # mutation, compensation and postconditions; parent participants lose.
            ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe()
            pid = os.fork()
            if pid == 0:
                signal.alarm(10); os.close(ready_r); os.close(release_w)
                first = [True]
                def wait_locked():
                    if first[0]:
                        first[0] = False; os.write(ready_w, b"1"); os.read(release_r, 1)
                backend.check = wait_locked
                try: self.invoke(backend)
                except BaseException: os._exit(1)
                os._exit(0)
            os.close(ready_w); os.close(release_r)
            try:
                self.assertEqual(os.read(ready_r, 1), b"1")
                with self.assertRaises(BlockingIOError):
                    participant.acquire_locks() if participant is observer else participant.acquire_mutexes([deploy.OPERATION_LOCK])
            finally:
                os.close(ready_r); os.write(release_w, b"1"); os.close(release_w)
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
            for path in mutexes: PROTOCOL.available(path)


if __name__ == "__main__":
    unittest.main()
