#!/usr/bin/env python3
"""Synthetic hostile filesystem/kernel fixtures; never mount or contact a host."""

import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ansible/roles/debian_lifecycle_guard/files/debian-inactive-path.py"
spec = importlib.util.spec_from_file_location("debian_inactive_path", HELPER)
observer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = observer
spec.loader.exec_module(observer)


class Node:
    def __init__(self, inode, **metadata):
        self.identity = replace(observer.Identity(1, (8, 1), inode,
                                stat.S_IFDIR | 0o755, 0, 0, 2, 4096,
                                (1, 0), (1, 0)), **metadata)
        self.children = {}


class Descriptors:
    """Kernel model: names may change, but open descriptors retain their object."""

    def __init__(self):
        self.top = Node(1)
        self.parent = Node(2)
        self.target = Node(3)
        self.top.children["srv"] = self.parent
        self.parent.children["state"] = self.target
        self.fds = {}
        self.next_fd = 10
        self.enumerated = []
        self.opened = []
        self.events = {}
        self.counts = {}

    def event(self, kind):
        self.counts[kind] = self.counts.get(kind, 0) + 1
        callback = self.events.get((kind, self.counts[kind]))
        if callback:
            callback()

    def acquire(self, node):
        self.next_fd += 1
        self.fds[self.next_fd] = node
        return self.next_fd

    def root(self):
        self.event("root")
        return self.acquire(self.top)

    def child(self, parent, name, readable=False):
        self.event("readable" if readable else "child")
        source = self.fds[parent]
        self.opened.append((source, name, readable))
        node = source if name == "." else source.children.get(name)
        if node is None:
            raise FileNotFoundError(errno.ENOENT, "absent")
        if stat.S_ISLNK(node.identity.mode):
            raise OSError(errno.ELOOP, "symlink forbidden")
        if not stat.S_ISDIR(node.identity.mode):
            raise OSError(errno.ENOTDIR, "not a directory")
        if source.identity.mount != node.identity.mount:
            raise OSError(errno.EXDEV, "mount crossing forbidden")
        return self.acquire(node)

    def identity(self, fd):
        self.event("identity")
        return self.fds[fd].identity

    def empty(self, fd):
        self.event("enumerate")
        node = self.fds[fd]
        self.enumerated.append(node)
        result = not node.children
        self.event("after-enumerate")
        return result

    def close(self, fd):
        del self.fds[fd]


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.fs = Descriptors()

    def observe(self, target="/srv/state"):
        try:
            return observer.observe(target, self.fs)
        finally:
            self.assertEqual(self.fs.fds, {}, "all descriptors must close on every exit")

    def refuse(self, enumerated=False):
        with self.assertRaises((observer.UnsafeObservation, OSError)):
            self.observe()
        if not enumerated:
            self.assertEqual(self.fs.enumerated, [], "unsafe path must never be enumerated")

    def test_empty_directory(self):
        self.assertEqual(self.observe(), {"exists": True, "entry_count": 0})
        self.assertEqual(self.fs.enumerated, [self.fs.target])

    def test_absent_target_and_ancestor(self):
        for owner, name in [(self.fs.parent, "state"), (self.fs.top, "srv")]:
            with self.subTest(name=name):
                old = owner.children.pop(name)
                self.assertEqual(self.observe(), {"exists": False, "entry_count": None})
                self.assertEqual(self.fs.enumerated, [])
                owner.children[name] = old

    def test_noncanonical_paths(self):
        for path in ("/", "", "srv/state", "/srv//state", "//srv/state", "/srv/../state",
                     "/srv/./state", "/srv/state/", "/srv/\x00state"):
            with self.subTest(path=path), self.assertRaises(observer.UnsafeObservation):
                self.observe(path)
        self.assertEqual(self.fs.counts, {})

    def test_symlink_and_dangling_symlink_at_every_component(self):
        for node in (self.fs.parent, self.fs.target):
            for contents in ({}, {"outside": Node(9)}):
                with self.subTest(node=node, contents=contents):
                    old = node.identity
                    node.identity = replace(old, mode=stat.S_IFLNK | 0o777)
                    node.children = contents
                    self.refuse()
                    node.identity = old
            # Restore the valid walk for the target case.
            self.fs.parent.children = {"state": self.fs.target}

    def test_files_and_special_nodes_never_opened_for_reading(self):
        for kind in (stat.S_IFREG, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFBLK, stat.S_IFCHR):
            self.fs.target.identity = replace(self.fs.target.identity, mode=kind | 0o644)
            self.refuse()
        self.assertFalse(any(readable for _, _, readable in self.fs.opened))

    def test_mounts_at_every_component_including_same_device_and_inode_bind(self):
        for node in (self.fs.parent, self.fs.target):
            for device in ((8, 1), (0, 9)):
                with self.subTest(node=node, device=device):
                    old = node.identity
                    node.identity = replace(old, mount=42, device=device)
                    self.refuse()
                    node.identity = old

    def test_untrusted_ancestors_and_target(self):
        for node in (self.fs.top, self.fs.parent, self.fs.target):
            for changes in ({"uid": 1000}, {"gid": 1000}, {"mode": stat.S_IFDIR | 0o775},
                            {"mode": stat.S_IFDIR | 0o777}, {"links": 0}, {"mount": 0},
                            {"inode": 0}):
                with self.subTest(node=node, changes=changes):
                    old = node.identity
                    node.identity = replace(old, **changes)
                    self.refuse()
                    node.identity = old

    def test_all_entries_rejected_without_child_traversal_including_root_owned_token(self):
        for name in ("data", ".hidden", "allow-storage-activation", ".home-lab-mount-ready"):
            for mode in (stat.S_IFREG | 0o600, stat.S_IFDIR | 0o755, stat.S_IFLNK | 0o777):
                with self.subTest(name=name, mode=mode):
                    self.fs.target.children = {name: Node(55, mode=mode)}
                    self.refuse(enumerated=True)
                    self.assertFalse(any(entry == name for _, entry, _ in self.fs.opened))

    def test_observer_errors_are_not_absence_and_never_retried(self):
        for code in (errno.EACCES, errno.EIO, errno.ESTALE, errno.ENOSYS, errno.EINVAL,
                     errno.EAGAIN, errno.EXDEV, errno.ELOOP, errno.ENOTDIR, errno.EINTR):
            with self.subTest(code=code):
                self.fs = Descriptors()
                def fail(code=code):
                    raise OSError(code, "injected")
                self.fs.events[("child", 1)] = fail
                self.refuse()
                self.assertEqual(self.fs.counts["child"], 1)

    def test_rename_or_mount_before_enumeration(self):
        for what in ("ancestor", "target", "root", "bind"):
            with self.subTest(what=what):
                self.fs = Descriptors()
                def swap(what=what):
                    if what == "ancestor":
                        self.fs.top.children["srv"] = Node(4)
                    elif what == "target":
                        self.fs.parent.children["state"] = Node(4)
                    elif what == "root":
                        self.fs.top = Node(4)
                    else:
                        self.fs.parent.children["state"] = Node(3, mount=2)
                self.fs.events[("root", 2)] = swap
                self.refuse()

    def test_mount_or_symlink_racing_initial_open(self):
        for mode, mount in ((stat.S_IFLNK | 0o777, 1), (stat.S_IFDIR | 0o755, 2)):
            self.fs = Descriptors()
            def swap(mode=mode, mount=mount):
                self.fs.parent.children["state"] = Node(3, mode=mode, mount=mount)
            self.fs.events[("child", 2)] = swap
            self.refuse()

    def test_replacement_between_validation_and_readable_open_never_redirects_listing(self):
        for mode, mount in ((stat.S_IFLNK | 0o777, 1), (stat.S_IFDIR | 0o755, 2),
                            (stat.S_IFDIR | 0o755, 1)):
            self.fs = Descriptors()
            original = self.fs.target
            replacement = Node(99, mode=mode, mount=mount)
            def swap(replacement=replacement):
                self.fs.parent.children["state"] = replacement
            self.fs.events[("readable", 1)] = swap
            self.refuse(enumerated=True)
            self.assertEqual(self.fs.enumerated, [original])
            self.assertNotIn(replacement, self.fs.enumerated)

    def test_directory_changed_during_enumeration(self):
        def change():
            self.fs.target.identity = replace(self.fs.target.identity, ctime=(2, 0))
        self.fs.events[("after-enumerate", 1)] = change
        self.refuse(enumerated=True)

    def test_rename_or_mount_after_enumeration(self):
        for mount in (1, 2):
            self.fs = Descriptors()
            def swap(mount=mount):
                self.fs.parent.children["state"] = Node(99, mount=mount)
            self.fs.events[("after-enumerate", 1)] = swap
            self.refuse(enumerated=True)

    def test_missing_path_appears_or_parent_changes(self):
        for change in ("directory", "symlink", "parent"):
            self.fs = Descriptors()
            self.fs.parent.children.clear()
            def appear(change=change):
                if change == "parent":
                    self.fs.parent.identity = replace(self.fs.parent.identity, ctime=(2, 0))
                else:
                    mode = stat.S_IFDIR | 0o755 if change == "directory" else stat.S_IFLNK | 0o777
                    self.fs.parent.children["state"] = Node(9, mode=mode)
            self.fs.events[("root", 2)] = appear
            self.refuse()

    def test_absence_is_revalidated_again_before_success(self):
        self.fs.parent.children.clear()
        def appear():
            self.fs.parent.children["state"] = Node(9)
        self.fs.events[("root", 3)] = appear
        self.refuse()

    def test_ancestor_metadata_drift_after_enumeration(self):
        for node in (self.fs.top, self.fs.parent):
            with self.subTest(node=node):
                def change(node=node):
                    node.identity = replace(node.identity, mode=stat.S_IFDIR | 0o777)
                self.fs.events[("after-enumerate", self.fs.counts.get("after-enumerate", 0) + 1)] = change
                self.refuse(enumerated=True)
                node.identity = replace(node.identity, mode=stat.S_IFDIR | 0o755)

    def test_readable_descriptor_mismatch(self):
        real_child = self.fs.child
        def child(parent, name, readable=False):
            if readable:
                return self.fs.acquire(Node(99))
            return real_child(parent, name, readable)
        with patch.object(self.fs, "child", side_effect=child):
            self.refuse()

    def test_mount_identity_mismatch_even_if_open_backend_misses_crossing(self):
        real_child = self.fs.child
        def child(parent, name, readable=False):
            fd = real_child(parent, name, readable)
            if name == "state":
                self.fs.fds[fd].identity = replace(self.fs.fds[fd].identity, mount=2)
            return fd
        with patch.object(self.fs, "child", side_effect=child):
            self.refuse()

    def test_enumeration_failure_closes_all_descriptors(self):
        def fail():
            raise OSError(errno.EIO, "enumeration failed")
        self.fs.events[("enumerate", 1)] = fail
        self.refuse()


class KernelAbiTests(unittest.TestCase):
    def backend(self):
        # Exercise native wrapper bytes without invoking Linux syscalls on macOS.
        return observer.LinuxDescriptors.__new__(observer.LinuxDescriptors)

    def test_abi_layout(self):
        self.assertEqual(ctypes.sizeof(observer.Statx), 256)
        self.assertEqual(observer.Statx.mnt_id.offset, 144)
        self.assertEqual(ctypes.sizeof(observer.OpenHow), 24)

    def test_openat2_flags_and_single_component_descriptor_arguments(self):
        backend = self.backend()
        calls = []
        class Libc:
            @staticmethod
            def syscall(number, parent, name, pointer, length):
                how = ctypes.cast(pointer, ctypes.POINTER(observer.OpenHow)).contents
                calls.append((number.value, parent.value, name.value, how.flags,
                              how.resolve, length.value))
                return 12
        backend.libc = Libc()
        with patch.object(os, "O_PATH", 0o10000000, create=True):
            self.assertEqual(backend.child(7, "state"), 12)
            backend.child(12, ".", readable=True)
        self.assertEqual(calls[0][:3], (437, 7, b"state"))
        self.assertEqual(calls[1][:3], (437, 12, b"."))
        for call in calls:
            self.assertEqual(call[4:], (0x05, 24))
            self.assertTrue(call[3] & os.O_NOFOLLOW)
            self.assertTrue(call[3] & os.O_DIRECTORY)
            self.assertTrue(call[3] & os.O_CLOEXEC)
        self.assertEqual(calls[0][3], 0o10000000 | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.assertEqual(calls[1][3], os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def test_statx_uses_empty_path_requires_every_requested_field(self):
        backend = self.backend()
        class Libc:
            mask = 0x17FF
            @classmethod
            def statx(cls, fd, path, flags, mask, pointer):
                self.assertEqual((fd, path, flags, mask), (7, b"", 0x1900, 0x17FF))
                value = ctypes.cast(pointer, ctypes.POINTER(observer.Statx)).contents
                value.mask = cls.mask
                value.mnt_id = 88
                return 0
        backend.libc = Libc()
        self.assertEqual(backend.identity(7).mount, 88)
        for bit in [1 << n for n in range(11)] + [0x1000]:
            Libc.mask = 0x17FF & ~bit
            with self.subTest(bit=bit), self.assertRaises(observer.UnsafeObservation):
                backend.identity(7)

    def test_syscall_failures_have_no_fallback(self):
        backend = self.backend()
        class Libc:
            @staticmethod
            def syscall(*args):
                ctypes.set_errno(errno.ENOSYS)
                return -1
            statx = syscall
        backend.libc = Libc()
        with patch.object(os, "O_PATH", 0o10000000, create=True):
            with self.assertRaises(OSError) as error:
                backend.child(7, "state")
            self.assertEqual(error.exception.errno, errno.ENOSYS)
        with self.assertRaises(OSError):
            backend.identity(7)

    def test_unsupported_platform_refused_before_loading_libc(self):
        for system, machine in (("darwin", "x86_64"), ("linux", "aarch64")):
            with patch.object(sys, "platform", system), patch.object(observer.platform, "machine", return_value=machine):
                with patch.object(ctypes, "CDLL") as load, self.assertRaises(observer.UnsafeObservation):
                    observer.LinuxDescriptors()
                load.assert_not_called()

    def test_safe_enumeration_uses_fd_and_never_stats_entries(self):
        class Entry:
            def stat(self, *args, **kwargs):
                raise AssertionError("must not inspect entries")
        class Entries:
            def __enter__(self):
                return iter([Entry()])
            def __exit__(self, *args):
                pass
        with patch.object(os, "scandir", return_value=Entries()) as scan:
            self.assertFalse(observer.LinuxDescriptors.empty(11))
        scan.assert_called_once_with(11)

    def test_cli_no_success_json_on_unknown_or_unsafe(self):
        for error in (OSError(errno.EIO, "unknown"), observer.UnsafeObservation("unsafe")):
            output, errors = io.StringIO(), io.StringIO()
            with patch.object(observer, "observe", side_effect=error), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(observer.main(["/srv/state"]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("refused", errors.getvalue())

    def test_cli_safe_result(self):
        output = io.StringIO()
        with patch.object(observer, "observe", return_value={"exists": True, "entry_count": 0}), contextlib.redirect_stdout(output):
            self.assertEqual(observer.main(["/srv/state"]), 0)
        self.assertEqual(json.loads(output.getvalue()), {"exists": True, "entry_count": 0})

    def test_role_executes_exact_helper_read_only_in_check_mode(self):
        source = (ROOT / "ansible/roles/debian_lifecycle_guard/tasks/main.yml").read_text()
        self.assertIn("lookup('ansible.builtin.file', role_path ~ '/files/debian-inactive-path.py')", source)
        self.assertNotIn("os.path.ismount", source)
        self.assertNotIn("os.lstat", source)
        # No copy/install task: source is sent to the existing command module.
        tasks = json.loads(subprocess.check_output(
            ["node", "-e", "process.stdout.write(JSON.stringify(require('js-yaml').load(require('fs').readFileSync(0, 'utf8'))))"],
            input=source, text=True, cwd=ROOT))
        task = next(task for task in tasks if task["name"].startswith("Inspect inactive protected"))
        self.assertIs(task["changed_when"], False)
        self.assertIs(task["check_mode"], False)
        self.assertNotIn("failed_when", task)
        self.assertEqual(task["when"], "lifecycle_profile in ['inert', 'recovery']")
        self.assertEqual(task["ansible.builtin.command"]["argv"][:2], ["/usr/bin/python3", "-c"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
