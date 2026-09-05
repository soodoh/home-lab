#!/usr/bin/env python3
"""Execute the actual guest cache reader in disposable, root-confined Linux fixtures.

Native tests require Linux root/CAP_SYS_CHROOT (for example, a local container).
They never use the machine's real /var/lib/cloud or contact any guest.
"""
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("cache_reader_host", str(ROOT / "infrastructure/qualification/host/debian-qualification-snippet-transaction"))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)
commands = []
with patch.object(helper, "guest_exec", side_effect=lambda argv: commands.append(argv) or "a" * 64):
    helper.booted_snippet_hash("synthetic")
CODE = commands[0][2]
PAYLOAD = b"#cloud-config\nsynthetic: true\n"


class ReaderWiring(unittest.TestCase):
    def test_exact_embedded_program_and_nonblocking_open(self):
        self.assertEqual(commands[0][:2], ["/usr/bin/python3", "-c"])
        self.assertEqual(commands[0][3:], ["synthetic"])
        compile(CODE, "guest-cache-reader", "exec")
        self.assertIn('os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK', CODE)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "native cache fixtures require a disposable Linux root/chroot environment")
class NativeCacheReader(unittest.TestCase):
    def run_reader(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cloud = root / "var/lib/cloud"
            instance = cloud / "instances/synthetic"
            instance.mkdir(parents=True)
            (cloud / "instance").symlink_to("instances/synthetic")
            source = instance / "user-data.txt"
            source.write_bytes(PAYLOAD)
            source.chmod(0o600)
            if mode == "mode": source.chmod(0o644)
            if mode == "owner": os.chown(source, 1234, 0)
            if mode == "group": os.chown(source, 0, 1234)
            if mode == "hardlink": os.link(source, instance / "alias")
            if mode == "empty": source.write_bytes(b"")
            if mode == "oversize": source.write_bytes(b"x" * 65537)
            if mode == "fifo": source.unlink(); os.mkfifo(source, 0o600)
            if mode == "file-symlink": source.rename(instance / "real"); source.symlink_to("real")
            if mode == "ancestor-symlink":
                (root / "var/lib").rename(root / "var/real-lib")
                (root / "var/lib").symlink_to("real-lib")
            if mode == "writable-parent": instance.chmod(0o777)
            if mode == "wrong-instance": (cloud / "instance").unlink(); (cloud / "instance").symlink_to("instances/wrong")
            # The child starts already confined; the fixture program runs the
            # unmodified embedded source and optional syscall fault injection.
            harness = '''import hashlib,os,signal,stat,sys
signal.alarm(5)
os.chroot(sys.argv[1]);os.chdir("/")
mode=sys.argv[2];code=sys.argv[3];sys.argv=["guest-cache-reader","synthetic"]
read=os.read
cache="/var/lib/cloud/instances/synthetic/user-data.txt"
def injected(fd,size):
 raw=read(fd,size)
 if mode=="short-read":return raw[:-1]
 if mode=="content-race":
  with open(cache,"wb") as out:out.write(b"changed")
 if mode=="mode-race":os.chmod(cache,0o644)
 if mode=="replacement-race":
  os.unlink(cache)
  with open(cache,"wb") as out:out.write(raw)
 return raw
os.read=injected
exec(compile(code,"guest-cache-reader","exec"))
'''
            return subprocess.run([sys.executable, "-c", harness, str(root), mode, CODE], text=True, capture_output=True, timeout=10)

    def test_valid_cache(self):
        result = self.run_reader("valid")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, hashlib.sha256(PAYLOAD).hexdigest() + "\n")

    def test_unsafe_cache_and_interruption_never_emit_hash(self):
        for mode in ("mode", "owner", "group", "hardlink", "empty", "oversize", "fifo", "file-symlink", "ancestor-symlink", "writable-parent", "wrong-instance", "short-read", "content-race", "mode-race", "replacement-race"):
            with self.subTest(mode=mode):
                result = self.run_reader(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(result.returncode, -signal.SIGALRM, "reader hung rather than rejecting unsafe file")
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
