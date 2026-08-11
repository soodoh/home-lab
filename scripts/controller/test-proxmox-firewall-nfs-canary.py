#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"ansible/roles/firewall_nfs_canary/files/proxmox-firewall-nfs-canary.py"
def load():
 spec=importlib.util.spec_from_file_location("nfs_canary",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class NfsTests(unittest.TestCase):
 def setUp(self): self.m=load(); self.temp=tempfile.TemporaryDirectory(); self.m.MOUNTPOINT=Path(self.temp.name)/"mount"
 def tearDown(self): self.temp.cleanup()
 def test_success_uses_fixed_read_only_mount_and_cleans(self):
  calls=[]
  def run(argv,**kwargs): calls.append(tuple(argv)); return SimpleNamespace(returncode=0,stderr=b"",stdout=b"")
  with mock.patch.object(self.m.subprocess,"run",side_effect=run),mock.patch.object(self.m,"mounted",side_effect=[True,True,False]),mock.patch.object(self.m,"fresh_tcp"): self.m.check()
  self.assertIn("ro,nosuid,nodev,noexec,vers=4.2,timeo=5,retrans=1",calls[0]); self.assertEqual(calls[-1][0:2],("/usr/bin/umount","--")); self.assertFalse(self.m.MOUNTPOINT.exists())
 def test_failure_always_cleans_mountpoint(self):
  with mock.patch.object(self.m.subprocess,"run",return_value=SimpleNamespace(returncode=1,stderr=b"failed",stdout=b"")),mock.patch.object(self.m,"mounted",return_value=False),mock.patch.object(self.m,"fresh_tcp"):
   with self.assertRaises(RuntimeError): self.m.check()
  self.assertFalse(self.m.MOUNTPOINT.exists())
 def test_timeout_and_interruption_cleanup(self):
  for error in (self.m.subprocess.TimeoutExpired(("mount",),2),InterruptedError("signal")):
   with mock.patch.object(self.m.subprocess,"run",side_effect=error),mock.patch.object(self.m,"mounted",return_value=False),mock.patch.object(self.m,"fresh_tcp"):
    with self.assertRaises(type(error)): self.m.check()
   self.assertFalse(self.m.MOUNTPOINT.exists())
 def test_fresh_tcp_uses_fixed_new_socket_and_closes_on_timeout(self):
  connection=mock.Mock(); self.m.socket.socket=mock.Mock(return_value=connection); self.m.fresh_tcp()
  self.m.socket.socket.assert_called_once_with(self.m.socket.AF_INET,self.m.socket.SOCK_STREAM); connection.settimeout.assert_called_once_with(2); connection.connect.assert_called_once_with(("192.168.0.123",2049)); connection.close.assert_called_once()
  connection.reset_mock(); connection.connect.side_effect=TimeoutError("timeout")
  with self.assertRaises(TimeoutError): self.m.fresh_tcp()
  connection.close.assert_called_once()
 def test_closed_cli_and_no_caller_inputs(self):
  source=SOURCE.read_text(); self.assertIn('SERVER = "192.168.0.123"',source); self.assertIn("NFS_PORT = 2049",source); self.assertNotIn("shell=True",source)
  with mock.patch.object(self.m.os,"geteuid",return_value=0),mock.patch.object(self.m.sys,"argv",["helper","other"]): self.assertEqual(self.m.main(),64)

if __name__=="__main__": unittest.main()
