#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/proxmox-firewall.py"

def load():
 spec=importlib.util.spec_from_file_location("firewall_controller",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class ControllerTests(unittest.TestCase):
 def setUp(self):
  self.m=load(); self.temp=tempfile.TemporaryDirectory(); root=Path(self.temp.name)
  self.m.LOCK_ROOT=root; self.m.PLAN_DIR=root/"plans"; self.m.CONFIG=root/"config.json"; self.m.KEY=root/"key"; self.m.PROTECTED_UID=os.getuid(); self.m.PROTECTED_GID=os.getgid()
  self.m.KEY.write_bytes(b"c"*32); self.m.KEY.chmod(0o600)
  self.config={"archNfsSshTarget":"ansible-deploy@arch-canary","lanSshTarget":"tofu-apply@lan-canary",
   "lanTlsUrl":"https://lan-canary:8006/api2/json/version","pveCaPem":"-----BEGIN CERTIFICATE-----\nopaque\n-----END CERTIFICATE-----",
   "tailscalePingTarget":"tailnet-canary","tailnetSshTarget":"tofu-apply@tailnet-canary",
   "tailnetTlsUrl":"https://tailnet-canary:8006/api2/json/version"}
  self.m.CONFIG.write_bytes(self.m.canonical(self.config)); self.m.CONFIG.chmod(0o600); self.m.PROTECTED_GID=self.m.CONFIG.stat().st_gid
  self.inspection={"attestation":"a"*64,"challenge":"challenge_0123456789","expiresAt":self.m.format_time(self.m.utcnow()+self.m.dt.timedelta(seconds=300)),
   "format":"home-lab-proxmox-firewall-inspection-v1","helperSha256":self.m.digest(self.m.HELPER_SOURCE.read_bytes()),
   "observedAt":self.m.format_time(self.m.utcnow()),"policySha256":self.m.digest(self.m.load_projection_policy()),
   "state":{"digest":"d"*40,"options":{"enable":False,"policy_in":"ACCEPT","policy_out":"ACCEPT"},"optionState":[],"rules":[]},
   "unitsSha256":self.m.unit_binding()}
 def tearDown(self): self.temp.cleanup()
 def create(self,baseline=None):
  matched={name:True for name in self.m.CHECKS} if baseline is None else baseline
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",return_value=self.inspection),mock.patch.object(self.m,"canaries",return_value=matched):
   result=self.m.make_plan()
  sha=result.rsplit("=",1)[1]; return sha
 def test_controller_lock_is_persistent_and_released_by_descriptor_close(self):
  handle=self.m.controller_lock("a"*40); lock=self.m.LOCK_ROOT/".reconcile/controller-apply.lock"; self.assertTrue(lock.is_file()); self.m.release_controller_lock(handle); self.assertTrue(lock.is_file()); self.assertEqual(json.loads(lock.read_bytes()),{"gitCommit":"a"*40,"operation":"proxmox-firewall-apply"})
 def test_plan_is_exact_private_and_no_protected_values_public(self):
  sha=self.create(); plan=json.loads((self.m.PLAN_DIR/f"{sha}.json").read_bytes()); private=json.loads((self.m.PLAN_DIR/f"{sha}.private.json").read_bytes())
  text=(self.m.PLAN_DIR/f"{sha}.json").read_text()
  for value in self.config.values():
   self.assertNotIn(value,text); self.assertNotIn(self.m.hashlib.sha256(value.encode()).hexdigest(),text)
  self.assertEqual(plan["status"],"ready"); self.assertEqual(plan["configuration"]["canaryCount"],6)
  supplied=private.pop("mac"); self.assertEqual(supplied,self.m.hmac.new(b"c"*32,self.m.canonical(private),self.m.hashlib.sha256).hexdigest())
 def test_errors_and_shareable_artifacts_exclude_protected_values_and_hashes(self):
  sha=self.create(); shareable=(self.m.PLAN_DIR/f"{sha}.json").read_text()+f"status=ready planSha256={sha}"
  failed={name:True for name in self.m.CHECKS}; failed["lanTls"]=False
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"canaries",return_value=failed):
   with self.assertRaises(RuntimeError) as caught: self.m.apply(sha,sha)
  shareable+=str(caught.exception)
  for path in (ROOT/"nix/proxmox/fixture-observation.json",ROOT/"docs/proxmox-firewall-cutover.md",ROOT/"infrastructure/policy/proxmox-firewall-plan.schema.json"):
   shareable+=path.read_text()
  for value in self.config.values():
   self.assertNotIn(value,shareable); self.assertNotIn(self.m.hashlib.sha256(value.encode()).hexdigest(),shareable)
 def test_blocked_direct_baseline_never_ready(self):
  values={name:True for name in self.m.CHECKS}; values["tailscaleDirect"]=False; sha=self.create(values)
  plan=json.loads((self.m.PLAN_DIR/f"{sha}.json").read_bytes()); self.assertEqual(plan["status"],"blocked"); self.assertEqual(plan["blockers"],["tailscaleDirect"])
 def test_apply_consumes_saved_plan_without_replanning_and_rolls_back_on_canary_failure(self):
  sha=self.create(); session="s"*32; calls=[]
  def host(command,request=None):
   calls.append(command)
   if command=="begin": return {"status":"activated","planSha256":sha,"sessionId":session}
   if command=="commit": return {"status":"committed","planSha256":sha,"sessionId":session}
   if command=="rollback": return {"status":"rolled-back","planSha256":sha,"sessionId":session}
   raise AssertionError(command)
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",return_value={name:True for name in self.m.CHECKS}),mock.patch.object(self.m,"make_plan",side_effect=AssertionError("replanned")):
   self.assertIn("status=committed",self.m.apply(sha,sha))
  self.assertEqual(calls,["begin","commit"])
  calls.clear(); failed={name:True for name in self.m.CHECKS}; failed["lanSsh"]=False
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",side_effect=[{name:True for name in self.m.CHECKS},failed]):
   with self.assertRaises(RuntimeError): self.m.apply(sha,sha)
  self.assertEqual(calls,["begin","rollback"])
 def test_fresh_baseline_and_every_canary_failure_rolls_back(self):
  for failed_name in self.m.CHECKS:
   sha=self.create(); calls=[]; session="s"*32
   def host(command,request=None): calls.append(command); return {"status":"activated" if command=="begin" else "rolled-back","planSha256":sha,"sessionId":session}
   failed={name:True for name in self.m.CHECKS}; failed[failed_name]=False
   with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",side_effect=[{name:True for name in self.m.CHECKS},failed]):
    with self.assertRaises(RuntimeError): self.m.apply(sha,sha)
   self.assertEqual(calls,["begin","rollback"])
 def test_malformed_begin_response_uses_status_for_immediate_rollback(self):
  sha=self.create(); session="s"*32; calls=[]
  def host(command,request=None):
   calls.append(command)
   if command=="begin": return {"status":"bad"}
   if command=="status": return {"status":"activated","planSha256":sha,"sessionId":session}
   if command=="rollback": return {"status":"rolled-back","planSha256":sha,"sessionId":session}
   raise AssertionError(command)
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",return_value={name:True for name in self.m.CHECKS}):
   with self.assertRaises(RuntimeError): self.m.apply(sha,sha)
  self.assertEqual(calls,["begin","status","rollback"])
 def test_malformed_commit_response_rolls_back_immediately(self):
  sha=self.create(); session="s"*32; calls=[]
  def host(command,request=None):
   calls.append(command)
   if command=="begin": return {"status":"activated","planSha256":sha,"sessionId":session}
   if command=="commit": return {"status":"activated","planSha256":sha,"sessionId":session}
   if command=="rollback": return {"status":"rolled-back","planSha256":sha,"sessionId":session}
   raise AssertionError(command)
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",return_value={name:True for name in self.m.CHECKS}):
   with self.assertRaises(RuntimeError): self.m.apply(sha,sha)
  self.assertEqual(calls,["begin","commit","rollback"])
 def test_malformed_and_exceptional_canaries_roll_back(self):
  sha=self.create(); calls=[]; session="s"*32
  def host(command,request=None): calls.append(command); return {"status":"activated" if command=="begin" else "rolled-back","planSha256":sha,"sessionId":session}
  for outcome in ({"lanSsh":True},RuntimeError("probe")):
   calls.clear(); effects=[{name:True for name in self.m.CHECKS},outcome]
   with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)),mock.patch.object(self.m,"host",side_effect=host),mock.patch.object(self.m,"canaries",side_effect=effects):
    with self.assertRaises(RuntimeError): self.m.apply(sha,sha)
   self.assertEqual(calls,["begin","rollback"])
 def test_tls_canary_uses_explicit_no_proxy_opener_and_accepts_pve_auth_challenge(self):
  url="https://fixed-sidecar-endpoint:8006/api2/json/version"; opener=mock.Mock(); opener.open.side_effect=self.m.urllib.error.HTTPError(url,401,"authentication required",{},io.BytesIO(b"auth"))
  with mock.patch.dict(os.environ,{"HTTPS_PROXY":"https://untrusted-proxy.invalid:8443","NO_PROXY":""}),mock.patch.object(self.m.ssl,"create_default_context",return_value=mock.Mock()),mock.patch.object(self.m.urllib.request,"build_opener",return_value=opener) as build:
   self.assertTrue(self.m.check_tls(url,"certificate"))
  handlers=build.call_args.args; self.assertEqual(handlers[0].proxies,{}); opener.open.assert_called_once_with(url,timeout=5)
 def test_direct_parser_is_unambiguous(self):
  good=b"pong from pve (100.64.0.1) via 192.0.2.1:41641 in 12ms\n"
  for output,expected in ((good,True),(b"not direct\n",False),(b"pong via DERP(foo)\n",False),(good+b"extra\n",False)):
   with mock.patch.object(self.m,"run",return_value=mock.Mock(stdout=output)),mock.patch.object(self.m.time,"sleep"):
    self.assertEqual(self.m.check_direct("fixed"),expected)
 def test_sidecar_mac_mode_link_and_approval_fail_closed(self):
  sha=self.create(); private=self.m.PLAN_DIR/f"{sha}.private.json"; value=json.loads(private.read_bytes()); value["configuration"]["lanSshTarget"]="changed"; private.write_bytes(self.m.canonical(value)); private.chmod(0o600)
  with mock.patch.object(self.m,"git_identity",return_value=("a"*40,"b"*40)):
   with self.assertRaises(ValueError): self.m.load_plan(sha)
  with self.assertRaises(ValueError): self.m.apply(sha,"0"*64)
  private.unlink(); target=self.m.PLAN_DIR/"target"; target.write_text("x"); private.symlink_to(target)
  with self.assertRaises(ValueError): self.m.secure_read(private,0o600)
 def test_cli_and_fixed_canary_catalogue(self):
  self.assertEqual(set(self.m.CHECKS),{"archNfs","lanSsh","lanTls","tailscaleDirect","tailnetSsh","tailnetTls"})
  source=SOURCE.read_text(); self.assertNotIn("shell=True",source); self.assertNotIn("--host",source); self.assertNotIn("--path",source); self.assertEqual(self.m.PVE_SSH_TARGET,"firewall-apply@proxmox"); self.assertEqual(self.m.KNOWN_HOSTS, str(Path.home()/".ssh/known_hosts")); self.assertNotIn("tofu-apply@proxmox",source); self.assertIn("StrictHostKeyChecking=yes",source); self.assertIn("UpdateHostKeys=no",source)
  for arguments in (("plan","--host","other"),("apply","--plan-sha","a"*64),("rollback","--session-id","bad","extra")):
   result=subprocess.run((sys.executable,SOURCE,*arguments),capture_output=True); self.assertEqual(result.returncode,2)

if __name__=="__main__": unittest.main()
