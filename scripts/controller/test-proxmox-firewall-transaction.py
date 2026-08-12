#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py"


def load():
    loader=importlib.machinery.SourceFileLoader("firewall_host",str(SOURCE)); spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec); loader.exec_module(module); return module


class FakeRunner:
    def __init__(self):
        self.options={"enable":0,"policy_in":"ACCEPT","policy_out":"ACCEPT"}; self.rules=[]; self.serial=0; self.commands=[]; self.timer=True; self.services=True
    def _digest(self): return f"{self.serial:040x}"
    def _rules_digest(self): return f"{1000000+self.serial:040x}"
    def run(self,argv,attempts=2,timeout=5,accepted=(0,),allow_stderr=False):
        self.commands.append(tuple(argv))
        if argv[:4]==("/usr/bin/pvesh","get","/cluster/firewall/options","--output-format"):
            return json.dumps({**self.options,"digest":self._digest()}).encode()
        if argv[:4]==("/usr/bin/pvesh","get","/cluster/firewall/rules","--output-format"):
            values=[]
            for pos,rule in enumerate(self.rules):
                values.append({"action":rule["action"],"digest":self._rules_digest(),"dport":rule["destination_port"],"enable":1,"ipversion":4,"log":rule["log"],"pos":pos,
                               "proto":rule["protocol"],"source":rule["source"],"type":rule["direction"]})
            return json.dumps(values).encode()
        if argv[:3]==("/usr/bin/pvesh","set","/cluster/firewall/options"):
            fields=dict(zip(argv[3::2],argv[4::2])); assert fields["--digest"]==self._digest()
            self.options={**self.options,"enable":int(fields["--enable"]),"policy_in":fields["--policy_in"],"policy_out":fields["--policy_out"]}; self.serial+=1; return b""
        if argv[:3]==("/usr/bin/pvesh","create","/cluster/firewall/rules"):
            fields=dict(zip(argv[3::2],argv[4::2])); assert fields["--digest"]==(self._rules_digest() if self.rules else self._digest())
            self.rules.append({"action":fields["--action"],"destination_port":int(fields["--dport"]),"direction":fields["--type"],
                               "log":fields["--log"],"protocol":fields["--proto"],"source":fields["--source"]}); self.serial+=1; return b""
        if argv[:2]==("/usr/bin/pvesh","delete"):
            fields=dict(zip(argv[3::2],argv[4::2])); assert fields["--digest"]==self._rules_digest(); self.rules.pop(int(argv[2].rsplit("/",1)[1])); self.serial+=1; return b""
        if argv[:2] in (("/usr/bin/loginctl","terminate-user"),("/usr/bin/pkill","--signal")): return b""
        if argv[:2]==("/usr/bin/pgrep","--uid"): return b""
        if argv[:2]==("/usr/bin/systemctl","restart"):
            self.timer=True; return b""
        if argv[:2]==("/usr/bin/systemctl","stop"):
            self.timer=False; return b""
        if argv[:2]==("/usr/bin/systemctl","show"): return b"123456\n"
        if argv[:2]==("/usr/bin/systemctl","is-active"):
            if argv[2].endswith("timer"): return b"active\n" if self.timer else b"inactive\n"
            if self.services: return b"active\n"
            raise RuntimeError("inactive")
        if argv==("/usr/sbin/pve-firewall","status"):
            return b"Status: enabled/running\n" if self.options["enable"] else b"Status: disabled/running\n"
        raise AssertionError(argv)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.m=load(); self.temp=tempfile.TemporaryDirectory(); root=Path(self.temp.name)
        self.m.EXPECTED_UID=os.getuid(); self.m.EXPECTED_GID=os.getgid()
        self.m.RUNTIME=root/"runtime"; self.m.KEY=self.m.RUNTIME/"attestation.key"; self.m.JOURNAL=self.m.RUNTIME/"journal.json"; self.m.AUTHORIZATION=self.m.RUNTIME/"authorization.json"; self.m.ACCESS_SNAPSHOT=self.m.RUNTIME/"access.json"; self.m.TOFU_KEYS=root/"tofu-authorized-keys"
        self.m.MUTEX=root/"operation.lock"; self.m.OWNER_LOCK=root/"owner.lock"; self.m.NIX_LOCK=root/"nix.lock"
        self.m.HELPER=root/"helper"; self.m.BOOT_HELPER=root/"boot-helper"; self.m.TRANSPORT=root/"transport"; self.m.SYSTEMD=root/"systemd"; self.m.POLICY=root/"policy.json"; self.m.RUNTIME.mkdir(mode=0o700); self.m.SYSTEMD.mkdir()
        self.m.HELPER.write_bytes(SOURCE.read_bytes()); self.m.HELPER.chmod(0o755); self.m.BOOT_HELPER.write_text("boot"); self.m.BOOT_HELPER.chmod(0o755); self.m.TRANSPORT.write_text("transport"); self.m.TRANSPORT.chmod(0o755); self.m.KEY.write_bytes(b"k"*32); self.m.KEY.chmod(0o600)
        for name in ("home-lab-proxmox-firewall-backend-stop.service","home-lab-proxmox-firewall-config-recovery.service","home-lab-proxmox-firewall-post-recovery.service","home-lab-proxmox-firewall-rollback.service","home-lab-proxmox-firewall-rollback.timer"):
            (self.m.SYSTEMD/name).write_text(name); (self.m.SYSTEMD/name).chmod(0o644)
        for service in ("pve-firewall.service","proxmox-firewall.service"):
            directory=self.m.SYSTEMD/(service+".d"); directory.mkdir(); (directory/"50-home-lab-firewall-recovery.conf").write_text("dropin"); (directory/"50-home-lab-firewall-recovery.conf").chmod(0o644)
        projection=json.loads((ROOT/"nix/proxmox/projection.json").read_bytes()); self.policy=projection["apiIntent"]["pveFirewall"]
        self.m.POLICY.write_bytes(self.m.canonical(self.policy)); self.m.POLICY.chmod(0o644)
        self.m.EXPECTED_UID=self.m.POLICY.stat().st_uid; self.m.EXPECTED_GID=self.m.POLICY.stat().st_gid; self.m.require_isolated_access=lambda:None; self.runner=FakeRunner()
    def tearDown(self): self.temp.cleanup()
    def plan(self):
        inspected=self.m.inspection(self.runner); now=self.m.utcnow(); value={"bindings":{"controllerSha256":"c"*64,"helperSha256":self.m.self_hash(),"policySha256":self.m.digest(self.policy),"planSchemaSha256":"a"*64,"privateSchemaSha256":"d"*64,"requestSchemaSha256":"e"*64,"unitsSha256":self.m.installed_units_hash()},
            "blockers":[],"configuration":{"canaryCount":6,"id":"x"*32},"createdAt":self.m.format_time(now),
            "expiresAt":min(self.m.format_time(now+self.m.dt.timedelta(seconds=300)),inspected["expiresAt"]),"format":self.m.FORMAT_PLAN,"git":{"commit":"a"*40,"tree":"b"*40},
            "inspection":inspected,"mutations":list(self.m.FIXED_MUTATIONS),"status":"ready","version":1}
        value["planSha256"]=self.m.digest(value)
        self.m.atomic_json(self.m.AUTHORIZATION,{"expiresAt":value["expiresAt"],"format":self.m.FORMAT_AUTHORIZATION,"planSha256":value["planSha256"],"sessionId":None,"state":"authorized"})
        return value
    def test_normalization_rejects_missing_duplicate_disabled_extra(self):
        base={"action":"ACCEPT","dport":"22","enable":1,"log":"nolog","pos":0,"proto":"tcp","source":"192.0.2.0/24","type":"IN"}
        self.assertIsNotNone(self.m.normalize_rule(base)); self.assertEqual(self.m.normalize_rule({**base,"type":"in"})["direction"],"IN")
        self.assertIsNotNone(self.m.normalize_rule({**base,"digest":"d"*40,"ipversion":4}))
        for changed in ({**base,"enable":0},{**base,"comment":"unexpected"},{**base,"digest":"d"*64},{**base,"ipversion":6},{**base,"dport":"bad"},{**base,"type":"OUT"}): self.assertIsNone(self.m.normalize_rule(changed))
        self.runner.rules=[self.m.normalize_rule(base),self.m.normalize_rule(base)]
        with self.assertRaises(ValueError): self.m.observe(self.runner)
    def test_backend_readiness_is_bounded_and_retries_lag(self):
        with mock.patch.object(self.m,"backend_matches",side_effect=[False,False,True]) as check, mock.patch.object(self.m.time,"sleep") as sleep:
            self.assertTrue(self.m.wait_backend(self.runner,True)); self.assertEqual(check.call_count,3); self.assertEqual(sleep.call_count,2)
        with mock.patch.object(self.m,"backend_matches",return_value=False) as check, mock.patch.object(self.m.time,"sleep") as sleep:
            self.assertFalse(self.m.wait_backend(self.runner,True,attempts=3)); self.assertEqual(check.call_count,3); self.assertEqual(sleep.call_count,2)
    def test_local_single_use_authorization_rejects_replay_and_recovers_consumed_crash(self):
        plan=self.plan(); self.m.AUTHORIZATION.unlink()
        request={"approvePlanSha":plan["planSha256"],"format":self.m.FORMAT_AUTHORIZE,"gate":self.m.AUTHORIZE_GATE,"plan":plan}
        self.assertEqual(self.m.authorize(request,self.runner)["status"],"authorized")
        with self.assertRaises(ValueError): self.m.authorize(request,self.runner)
        self.m.consume_authorization(plan,"s"*32); self.m.create_owner("s"*32)
        self.assertEqual(self.m.authorize(request,self.runner)["status"],"authorized"); self.assertFalse(self.m.OWNER_LOCK.exists())
        changed=dict(request); changed["approvePlanSha"]="0"*64
        with self.assertRaises(ValueError): self.m.authorize(changed,self.runner)
    def test_future_or_inspection_exceeding_plan_is_rejected(self):
        plan=self.plan(); future=self.m.utcnow()+self.m.dt.timedelta(days=1); plan["createdAt"]=self.m.format_time(future); plan["expiresAt"]=self.m.format_time(future+self.m.dt.timedelta(seconds=60)); plan["planSha256"]=self.m.digest({k:v for k,v in plan.items() if k!="planSha256"})
        with self.assertRaises(ValueError): self.m.validate_plan(plan)
        plan=self.plan(); plan["expiresAt"]=self.m.format_time(self.m.parse_time(plan["inspection"]["expiresAt"])+self.m.dt.timedelta(seconds=1)); plan["planSha256"]=self.m.digest({k:v for k,v in plan.items() if k!="planSha256"})
        with self.assertRaises(ValueError): self.m.validate_plan(plan)
    def test_external_digest_drift_is_rejected_before_first_mutation(self):
        plan=self.plan(); self.runner.serial+=1
        with self.assertRaises(ValueError): self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        self.assertFalse(any(command[:2]==("/usr/bin/pvesh","set") for command in self.runner.commands))
    def test_begin_enable_last_commit_and_release(self):
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        self.assertEqual(result["status"],"activated")
        enables=[cmd for cmd in self.runner.commands if cmd[:3]==("/usr/bin/pvesh","set","/cluster/firewall/options")]
        self.assertEqual([cmd[cmd.index("--enable")+1] for cmd in enables],["0","1"])
        request={"canaries":{name:True for name in ("archNfs","lanSsh","lanTls","tailscaleDirect","tailnetSsh","tailnetTls")},
                 "configurationId":plan["configuration"]["id"],"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]}
        with mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(result["deadline"])-self.m.dt.timedelta(seconds=200)):
            committed=self.m.commit(request,self.runner)
        self.assertEqual(committed["status"],"committed"); self.assertFalse(self.m.OWNER_LOCK.exists()); self.assertTrue(self.runner.timer)
    def test_rollback_order_and_release_pending_resume(self):
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); before=len(self.runner.commands)
        rolled=self.m.rollback({"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]},self.runner)
        self.assertEqual(rolled["status"],"rolled-back"); commands=self.runner.commands[before:]
        option_values=[cmd[cmd.index("--enable")+1] for cmd in commands if cmd[:3]==("/usr/bin/pvesh","set","/cluster/firewall/options")]
        self.assertEqual(option_values[0],"0"); self.assertEqual(option_values[-1],"0")
        journal=self.m.load_json(self.m.JOURNAL); journal["state"]="commit-release-pending"; journal["decision"]="commit"; self.m.atomic_json(self.m.JOURNAL,journal); self.m.create_owner(journal["sessionId"]); self.runner.timer=True
        self.runner.options={"enable":1,"policy_in":"DROP","policy_out":"ACCEPT"}; self.runner.rules=list(self.policy["rules"])
        resumed=self.m.rollback(None,self.runner,mode="ordinary"); self.assertEqual(resumed["status"],"committed"); self.assertFalse(self.m.OWNER_LOCK.exists())
    def test_lock_collision_and_metadata_attacks(self):
        self.m.NIX_LOCK.write_text("x")
        with self.assertRaises(ValueError): self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":self.plan()},self.runner)
        self.m.NIX_LOCK.unlink(); self.m.KEY.unlink(); self.m.KEY.symlink_to(self.m.HELPER)
        with self.assertRaises(ValueError): self.m.secure_key()
        self.m.KEY.unlink(); self.m.KEY.write_bytes(b"k"*32); self.m.KEY.chmod(0o600); os.link(self.m.KEY,self.m.RUNTIME/"key-link")
        with self.assertRaises(ValueError): self.m.secure_key()
        (self.m.RUNTIME/"key-link").unlink()
        attacked=self.m.RUNTIME/"attacked"; attacked.write_bytes(b"x"*32); attacked.chmod(0o644)
        with self.assertRaises(ValueError): self.m.secure_file(attacked,0o600,16)
        attacked.chmod(0o600)
        with self.assertRaises(ValueError): self.m.secure_file(attacked,0o600,16)
        uid,gid=self.m.EXPECTED_UID,self.m.EXPECTED_GID
        self.m.EXPECTED_UID=uid+1
        with self.assertRaises(ValueError): self.m.secure_key()
        self.m.EXPECTED_UID=uid; self.m.EXPECTED_GID=gid+1
        with self.assertRaises(ValueError): self.m.secure_key()
        self.m.EXPECTED_GID=gid
        self.m.OWNER_LOCK.mkdir(); self.m.release_owner("s"*32); self.assertFalse(self.m.OWNER_LOCK.exists())
        self.m.create_owner("s"*32); (self.m.OWNER_LOCK/"owner").unlink(); self.m.release_owner("s"*32); self.assertFalse(self.m.OWNER_LOCK.exists())
    def test_crash_boundaries_are_recovered_by_timer(self):
        class Crash(BaseException): pass
        for boundary in ("defaults-staged","staged","activated"):
            for phase in ("before","after"):
                with self.subTest(boundary=boundary,phase=phase):
                    for path in (self.m.JOURNAL,self.m.OWNER_LOCK/"owner",self.m.OWNER_LOCK):
                        try: path.unlink() if path.is_file() else path.rmdir()
                        except FileNotFoundError: pass
                    self.runner=FakeRunner(); plan=self.plan(); original=self.m.write_state
                    def crash_boundary(journal,state):
                        if state==boundary and phase=="before": raise Crash()
                        original(journal,state)
                        if state==boundary and phase=="after": raise Crash()
                    with mock.patch.object(self.m,"write_state",side_effect=crash_boundary):
                        with self.assertRaises(Crash): self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
                    self.assertEqual(self.m.rollback(None,self.runner,mode="ordinary")["status"],"rolled-back")
                    self.assertFalse(self.m.OWNER_LOCK.exists())
    def test_every_release_checkpoint_reconciles_idempotently(self):
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); base=self.m.load_journal()
        for state in sorted(self.m.RELEASE_COMMIT-{"boot-commit-config-verified"}):
            journal=dict(base); journal.update(state=state,decision="commit"); self.m.atomic_json(self.m.JOURNAL,journal)
            if not self.m.OWNER_LOCK.exists(): self.m.create_owner(journal["sessionId"])
            self.m.atomic_json(self.m.AUTHORIZATION,{"expiresAt":plan["expiresAt"],"format":self.m.FORMAT_AUTHORIZATION,"planSha256":plan["planSha256"],"sessionId":journal["sessionId"],"state":"consumed"}); self.runner.timer=True
            self.assertEqual(self.m.rollback(None,self.runner)["status"],"committed")
        self.runner.options={"enable":0,"policy_in":"ACCEPT","policy_out":"ACCEPT"}; self.runner.rules=[]; self.runner.serial+=1
        for state in sorted(self.m.RELEASE_ROLLBACK-{"boot-config-restored"}):
            journal=dict(base); journal.update(state=state,decision="rollback",checkpoint=None); self.m.atomic_json(self.m.JOURNAL,journal)
            if not self.m.OWNER_LOCK.exists(): self.m.create_owner(journal["sessionId"])
            self.m.atomic_json(self.m.AUTHORIZATION,{"expiresAt":plan["expiresAt"],"format":self.m.FORMAT_AUTHORIZATION,"planSha256":plan["planSha256"],"sessionId":journal["sessionId"],"state":"consumed"}); self.runner.timer=True
            self.assertEqual(self.m.rollback(None,self.runner)["status"],"rolled-back")
    def test_crash_after_every_commit_and_rollback_journal_boundary_recovers(self):
        class Crash(BaseException): pass
        commit_states=("commit-release-pending","commit-lock-released","committed")
        for boundary in commit_states:
            for phase in ("before","after"):
                with self.subTest(commit=boundary,phase=phase):
                    self.runner=FakeRunner(); plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); request={"canaries":{name:True for name in ("archNfs","lanSsh","lanTls","tailscaleDirect","tailnetSsh","tailnetTls")},"configurationId":plan["configuration"]["id"],"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]}; original=self.m.write_state
                    def crash(journal,state):
                        if state==boundary and phase=="before": raise Crash()
                        original(journal,state)
                        if state==boundary and phase=="after": raise Crash()
                    with mock.patch.object(self.m,"write_state",side_effect=crash),mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(result["deadline"])-self.m.dt.timedelta(seconds=200)):
                        with self.assertRaises(Crash): self.m.commit(request,self.runner)
                    expected="rolled-back" if boundary=="commit-release-pending" and phase=="before" else "committed"
                    self.assertEqual(self.m.rollback(None,self.runner)["status"],expected)
        rollback_states=("rollback-started","rollback-verified","rollback-release-pending","rollback-lock-released","rolled-back")
        for boundary in rollback_states:
            for phase in ("before","after"):
                with self.subTest(rollback=boundary,phase=phase):
                    self.runner=FakeRunner(); plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); original=self.m.write_state
                    def crash(journal,state):
                        if state==boundary and phase=="before": raise Crash()
                        original(journal,state)
                        if state==boundary and phase=="after": raise Crash()
                    with mock.patch.object(self.m,"write_state",side_effect=crash):
                        with self.assertRaises(Crash): self.m.rollback(None,self.runner)
                    self.assertEqual(self.m.rollback(None,self.runner)["status"],"rolled-back")
    def test_crash_after_every_rule_create_delete_and_enable_recovers(self):
        class Crash(BaseException): pass
        for operation,ordinal in [("create",number) for number in range(1,7)]+[("delete",number) for number in range(1,7)]+[("enable",1),("enable",2)]:
            for phase in ("before","after"):
                with self.subTest(operation=operation,ordinal=ordinal,phase=phase):
                    self.runner=FakeRunner(); plan=self.plan(); original=self.m.pvesh; counts={"create":0,"delete":0,"enable":0}
                    def crash(runner,*arguments):
                        kind="create" if arguments[:2]==("create","/cluster/firewall/rules") else "delete" if arguments and arguments[0]=="delete" else "enable" if arguments[:2]==("set","/cluster/firewall/options") else "other"
                        if kind in counts:
                            counts[kind]+=1
                            if kind==operation and counts[kind]==ordinal and phase=="before": raise Crash()
                        original(runner,*arguments)
                        if kind==operation and counts[kind]==ordinal and phase=="after": raise Crash()
                    with mock.patch.object(self.m,"pvesh",side_effect=crash):
                        if operation=="delete":
                            self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
                            with self.assertRaises(Crash): self.m.rollback(None,self.runner)
                        else:
                            with self.assertRaises(Crash): self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
                    self.assertEqual(self.m.rollback(None,self.runner)["status"],"rolled-back")
    def test_commit_release_crash_resumes_commit_not_rollback(self):
        class Crash(BaseException): pass
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        request={"canaries":{name:True for name in ("archNfs","lanSsh","lanTls","tailscaleDirect","tailnetSsh","tailnetTls")},
                 "configurationId":plan["configuration"]["id"],"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]}
        original=self.m.write_state
        def crash_after(journal,state):
            original(journal,state)
            if state=="commit-release-pending": raise Crash()
        with mock.patch.object(self.m,"write_state",side_effect=crash_after),mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(result["deadline"])-self.m.dt.timedelta(seconds=200)):
            with self.assertRaises(Crash): self.m.commit(request,self.runner)
        self.assertEqual(self.m.rollback(None,self.runner,mode="ordinary")["status"],"committed")
    def test_boot_preserves_durable_commit_intent_across_transient_failure(self):
        plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); journal=self.m.load_journal(); journal["decision"]="commit"; journal["state"]="commit-release-pending"; self.m.atomic_json(self.m.JOURNAL,journal)
        self.runner.services=False
        with mock.patch.object(self.m,"desired_matches",return_value=False):
            with self.assertRaises(RuntimeError): self.m.rollback(None,self.runner,mode="boot-config")
        self.assertEqual(self.m.load_journal()["decision"],"commit"); self.assertEqual(self.m.load_journal()["state"],"boot-recovery-active")
        self.assertEqual(self.m.rollback(None,self.runner,mode="boot-config")["status"],"boot-commit-config-verified")
        self.runner.services=True; self.assertEqual(self.m.rollback(None,self.runner,mode="boot-post")["status"],"committed")
    def test_timer_delivery_requires_current_token_and_deadline(self):
        plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); journal=self.m.load_journal()
        with self.assertRaises(BlockingIOError): self.m.rollback(None,self.runner,mode="timer")
        journal["timerToken"]="999"; self.m.atomic_json(self.m.JOURNAL,journal)
        with mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(journal["deadline"])+self.m.dt.timedelta(seconds=1)):
            with self.assertRaises(BlockingIOError): self.m.rollback(None,self.runner,mode="timer")
        journal["timerToken"]="123456"; self.m.atomic_json(self.m.JOURNAL,journal)
        with mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(journal["deadline"])+self.m.dt.timedelta(seconds=1)):
            self.assertEqual(self.m.rollback(None,self.runner,mode="timer")["status"],"rolled-back")
    def test_delayed_commit_is_rejected_and_timer_can_rollback(self):
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        request={"canaries":{name:True for name in ("archNfs","lanSsh","lanTls","tailscaleDirect","tailnetSsh","tailnetTls")},
                 "configurationId":plan["configuration"]["id"],"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]}
        with mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(result["deadline"])-self.m.dt.timedelta(seconds=119)):
            with self.assertRaises(ValueError): self.m.commit(request,self.runner)
        self.assertEqual(self.m.load_journal()["state"],"activated")
        self.assertEqual(self.m.rollback(None,self.runner,mode="ordinary")["status"],"rolled-back")
        journal=self.m.load_journal(); journal["timerToken"]="999"; self.m.atomic_json(self.m.JOURNAL,journal); self.runner.timer=True
        self.assertEqual(self.m.rollback(None,self.runner,mode="timer")["status"],"rolled-back"); self.assertTrue(self.runner.timer)
    def test_rollback_checkpoint_crashes_resume_each_operation_class(self):
        class Crash(BaseException): pass
        for target in ("disable","remove-candidate","restore-options"):
            with self.subTest(target=target):
                plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); original=self.m.checkpointed
                def crash(journal,label,current,expected,operation):
                    result=original(journal,label,current,expected,operation)
                    if label==target: raise Crash()
                    return result
                with mock.patch.object(self.m,"checkpointed",side_effect=crash):
                    with self.assertRaises(Crash): self.m.rollback(None,self.runner)
                self.assertEqual(self.m.load_journal()["checkpoint"]["phase"],"after")
                self.assertEqual(self.m.rollback(None,self.runner)["status"],"rolled-back")
                self.runner=FakeRunner()
    def test_timeout_records_retry_and_exact_retry_recovers(self):
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        original=self.runner.run; failed=False
        def fail_once(argv,attempts=2,timeout=5):
            nonlocal failed
            if not failed and argv[:2]==("/usr/bin/pvesh","get"):
                failed=True; raise RuntimeError("timeout")
            return original(argv,attempts,timeout)
        with mock.patch.object(self.runner,"run",side_effect=fail_once):
            with self.assertRaises(RuntimeError): self.m.rollback({"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]},self.runner)
        self.assertEqual(self.m.load_json(self.m.JOURNAL)["state"],"rollback-retry-pending")
        self.assertEqual(self.m.rollback({"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]},self.runner)["status"],"rolled-back")
    def test_boot_two_phase_and_mutex_collision(self):
        plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        held=self.m.acquire(self.m.MUTEX)
        try:
            with self.assertRaises(BlockingIOError): self.m.rollback(None,self.runner,mode="ordinary")
        finally: os.close(held)
        self.runner.services=False
        with self.assertRaises(RuntimeError): self.m.rollback(None,self.runner,mode="ordinary")
        self.assertNotIn(self.m.load_journal()["state"],self.m.BOOT_OWNED); self.assertTrue(self.m.OWNER_LOCK.exists())
        self.runner.services=True
        self.assertEqual(self.m.rollback(None,self.runner,mode="ordinary")["status"],"rolled-back")
        plan=self.plan(); self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); self.runner.services=False
        phase=self.m.rollback(None,self.runner,mode="boot-config"); self.assertEqual(phase["status"],"boot-config-restored")
        journal=self.m.load_journal(); journal["timerToken"]="999"; self.m.atomic_json(self.m.JOURNAL,journal)
        with self.assertRaises(BlockingIOError): self.m.rollback(None,self.runner,mode="timer")
        with self.assertRaises(RuntimeError): self.m.rollback(None,self.runner,mode="boot-post")
        self.assertEqual(self.m.load_journal()["state"],"boot-config-restored"); self.assertTrue(self.m.OWNER_LOCK.exists())
        self.runner.services=True
        self.assertEqual(self.m.rollback(None,self.runner,mode="boot-post")["status"],"rolled-back")
    def test_order_independent_match_and_rollback_preserves_non_candidate(self):
        state={"options":{"enable":True,"policy_in":"DROP","policy_out":"ACCEPT"},"rules":list(reversed(self.policy["rules"]))}
        self.assertTrue(self.m.desired_matches(state,self.policy,True,{"enable":False,"policy_in":"ACCEPT","policy_out":"ACCEPT"}))
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner)
        extra={"action":"ACCEPT","destination_port":9999,"direction":"IN","log":"nolog","protocol":"tcp","source":"198.51.100.1/32"}; self.runner.rules.append(extra); self.runner.serial+=1
        with self.assertRaises(RuntimeError): self.m.rollback({"format":self.m.FORMAT_RESULT,"planSha256":plan["planSha256"],"sessionId":result["sessionId"]},self.runner)
        self.assertIn(extra,self.runner.rules); self.assertTrue(self.m.OWNER_LOCK.exists())
    def test_release_revalidates_snapshot_and_status_ignores_foreign_ansible_lock(self):
        self.m.OWNER_LOCK.mkdir(mode=0o700); owner=self.m.OWNER_LOCK/"owner"; owner.write_text("controller=ansible\noperation=proxmox-site\nstarted=now\n"); owner.chmod(0o600)
        self.assertEqual(self.m.status(self.runner)["status"],"idle")
        self.runner.timer=False; self.assertEqual(self.m.status(self.runner)["status"],"orphaned"); self.runner.timer=True
        owner.unlink(); self.m.OWNER_LOCK.rmdir(); self.m.create_owner("s"*32); self.assertEqual(self.m.status(self.runner)["status"],"orphaned"); self.m.release_owner("s"*32)
        plan=self.plan(); result=self.m.begin({"format":self.m.FORMAT_BEGIN,"plan":plan},self.runner); journal=self.m.load_journal()
        self.m.rollback_config(journal,self.runner); self.runner.options["policy_in"]="DROP"; self.runner.serial+=1
        with self.assertRaises(RuntimeError): self.m.finish_rollback(journal,self.runner)
        self.assertTrue(self.m.OWNER_LOCK.exists())
    def test_real_sigkill_after_prepared_journal_before_first_mutation_uses_timer(self):
        plan=self.plan(); plan_file=Path(self.temp.name)/"plan-prepared.json"; plan_file.write_bytes(self.m.canonical(plan)); assignments={name:str(getattr(self.m,name)) for name in ("RUNTIME","KEY","JOURNAL","AUTHORIZATION","MUTEX","OWNER_LOCK","NIX_LOCK","HELPER","BOOT_HELPER","TRANSPORT","SYSTEMD","POLICY")}
        code=f'''import importlib.machinery,importlib.util,json,os,signal
l=importlib.machinery.SourceFileLoader("h",{str(SOURCE)!r});s=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);l.exec_module(m)
paths={assignments!r}
for n,p in paths.items():setattr(m,n,m.Path(p))
m.EXPECTED_UID=m.POLICY.stat().st_uid;m.EXPECTED_GID=m.POLICY.stat().st_gid;m.require_isolated_access=lambda:None
class R:
 deadline=None
 def run(self,a,attempts=2,timeout=5,accepted=(0,),allow_stderr=False):
  if a[:4]==('/usr/bin/pvesh','get','/cluster/firewall/options','--output-format'):return json.dumps({{'enable':0,'policy_in':'ACCEPT','policy_out':'ACCEPT','digest':'0'*40}}).encode()
  if a[:4]==('/usr/bin/pvesh','get','/cluster/firewall/rules','--output-format'):return b'[]'
  if a[:2]==('/usr/bin/systemctl','is-active'):return b'active\\n'
  if a[:2]==('/usr/bin/systemctl','show'):return b'123456\\n'
  raise RuntimeError(a)
original=m.load_policy;calls=[0]
def crash():
 calls[0]+=1
 if calls[0]==2:os.kill(os.getpid(),signal.SIGKILL)
 return original()
m.load_policy=crash
plan=json.load(open({str(plan_file)!r}));m.begin({{'format':m.FORMAT_BEGIN,'plan':plan}},R())
'''
        child=subprocess.run((os.environ.get("PYTHON","python3"),"-c",code)); self.assertEqual(child.returncode,-9); journal=self.m.load_journal(); self.assertEqual(journal["state"],"prepared"); self.assertEqual(journal["timerToken"],"123456")
        with mock.patch.object(self.m,"utcnow",return_value=self.m.parse_time(journal["deadline"])+self.m.dt.timedelta(seconds=1)):
            self.assertEqual(self.m.rollback(None,self.runner,mode="timer")["status"],"rolled-back")
    def test_real_transaction_subprocess_sigkill_after_first_mutation_recovers(self):
        plan=self.plan(); plan_file=Path(self.temp.name)/"plan.json"; plan_file.write_bytes(self.m.canonical(plan)); assignments={name:str(getattr(self.m,name)) for name in ("RUNTIME","KEY","JOURNAL","AUTHORIZATION","MUTEX","OWNER_LOCK","NIX_LOCK","HELPER","BOOT_HELPER","TRANSPORT","SYSTEMD","POLICY")}
        code=f'''import importlib.machinery,importlib.util,json,os,signal
l=importlib.machinery.SourceFileLoader("h",{str(SOURCE)!r});s=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);l.exec_module(m)
paths={assignments!r}
for n,p in paths.items():setattr(m,n,m.Path(p))
m.EXPECTED_UID=m.POLICY.stat().st_uid;m.EXPECTED_GID=m.POLICY.stat().st_gid;m.require_isolated_access=lambda:None
class R:
 deadline=None
 def __init__(self):self.serial=0
 def run(self,a,attempts=2,timeout=5,accepted=(0,),allow_stderr=False):
  if a[:4]==('/usr/bin/pvesh','get','/cluster/firewall/options','--output-format'):return json.dumps({{'enable':0,'policy_in':'DROP' if self.serial else 'ACCEPT','policy_out':'ACCEPT','digest':f'{{self.serial:040x}}'}}).encode()
  if a[:4]==('/usr/bin/pvesh','get','/cluster/firewall/rules','--output-format'):return b'[]'
  if a[:3]==('/usr/bin/pvesh','set','/cluster/firewall/options'):self.serial+=1;return b''
  if a[:2]==('/usr/bin/systemctl','is-active'):return b'active\\n'
  if a[:2]==('/usr/bin/systemctl','show'):return b'123456\\n'
  raise RuntimeError(a)
original=m.write_state
def crash(j,state):
 original(j,state)
 if state=='defaults-staged':os.kill(os.getpid(),signal.SIGKILL)
m.write_state=crash
plan=json.load(open({str(plan_file)!r}));m.begin({{'format':m.FORMAT_BEGIN,'plan':plan}},R())
'''
        child=subprocess.run((os.environ.get("PYTHON","python3"),"-c",code)); self.assertEqual(child.returncode,-9); self.assertEqual(self.m.load_journal()["state"],"defaults-staged")
        self.runner.options={"enable":0,"policy_in":"DROP","policy_out":"ACCEPT"}; self.runner.serial=1
        self.assertEqual(self.m.rollback(None,self.runner)["status"],"rolled-back")
    def test_real_subprocess_sigkill_preserves_atomic_journal_and_releases_mutex(self):
        target=Path(self.temp.name)/"kill-journal.json"; lock=Path(self.temp.name)/"kill.lock"; ready=Path(self.temp.name)/"ready"
        code=f'''import importlib.machinery,importlib.util,os,time\nl=importlib.machinery.SourceFileLoader("h",{str(SOURCE)!r});s=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);l.exec_module(m)\nm.EXPECTED_UID=os.getuid();m.EXPECTED_GID=m.Path({str(Path(self.temp.name))!r}).stat().st_gid;fd=m.acquire(m.Path({str(lock)!r}));m.atomic_json(m.Path({str(target)!r}),{{"state":"durable"}});m.Path({str(ready)!r}).write_text("ready");i=0\nwhile True:\n m.atomic_json(m.Path({str(target)!r}),{{"sequence":i}});i+=1\n'''
        child=subprocess.Popen((os.environ.get("PYTHON","python3"),"-c",code))
        for _ in range(100):
            if ready.exists(): break
            time.sleep(.01)
        self.assertTrue(ready.exists())
        with self.assertRaises(BlockingIOError): self.m.acquire(lock)
        child.kill(); child.wait(timeout=5)
        value=json.loads(target.read_bytes()); self.assertEqual(target.read_bytes(),self.m.canonical(value))
        fd=self.m.acquire(lock); os.close(fd)
    def test_isolate_restore_is_exact_and_crash_idempotent(self):
        keys=b"ssh-ed25519 opaque\n"; self.m.TOFU_KEYS.write_bytes(keys); self.m.TOFU_KEYS.chmod(0o600); shell=["/bin/bash"]
        runner=self.runner; original=runner.run
        def run(argv,attempts=2,timeout=5,accepted=(0,),allow_stderr=False):
            if argv[:2]==("/usr/sbin/usermod","--shell"): shell[0]=argv[2]; return b""
            return original(argv,attempts,timeout,accepted,allow_stderr)
        runner.run=run
        request={"format":"home-lab-proxmox-firewall-access-v1","gate":self.m.ISOLATE_GATE}
        with mock.patch.object(self.m.pwd,"getpwnam",side_effect=lambda name:mock.Mock(pw_shell=shell[0])):
            self.assertEqual(self.m.isolate_access(request,runner)["status"],"tofu-apply-isolated"); self.assertFalse(self.m.TOFU_KEYS.exists())
            self.assertTrue(any(cmd[:2]==("/usr/bin/loginctl","terminate-user") for cmd in runner.commands)); self.assertTrue(any(cmd[:2]==("/usr/bin/pkill","--signal") for cmd in runner.commands)); self.assertTrue(any(cmd[:2]==("/usr/bin/pgrep","--uid") for cmd in runner.commands))
            self.assertEqual(self.m.isolate_access(request,runner)["status"],"tofu-apply-isolated")
            plan=self.plan(); journal={"checkpoint":None,"configurationId":plan["configuration"]["id"],"deadline":plan["expiresAt"],"decision":"rollback","format":self.m.FORMAT_JOURNAL,"planSha256":plan["planSha256"],"sessionId":"s"*32,"snapshot":plan["inspection"]["state"],"state":"rolled-back","timerToken":"123456","updatedAt":plan["createdAt"]}; self.m.atomic_json(self.m.JOURNAL,journal)
            restore={"format":"home-lab-proxmox-firewall-access-v1","gate":self.m.RESTORE_GATE}
            self.m.TOFU_KEYS.write_bytes(b"partial"); self.m.TOFU_KEYS.chmod(0o600); pending=self.m.TOFU_KEYS.parent/("."+self.m.TOFU_KEYS.name+".firewall-restore"); pending.write_bytes(b"interrupted")
            self.assertEqual(self.m.restore_access(restore,runner)["status"],"tofu-apply-restored")
            self.assertEqual(self.m.TOFU_KEYS.read_bytes(),keys); self.assertFalse(pending.exists())
            self.m.JOURNAL.unlink(); self.assertEqual(self.m.isolate_access(request,runner)["status"],"tofu-apply-isolated")
            plan=self.plan(); expired=self.m.load_json(self.m.AUTHORIZATION); expired["expiresAt"]=self.m.format_time(self.m.utcnow()-self.m.dt.timedelta(seconds=1)); self.m.atomic_json(self.m.AUTHORIZATION,expired)
            authorize={"approvePlanSha":plan["planSha256"],"format":self.m.FORMAT_AUTHORIZE,"gate":self.m.AUTHORIZE_GATE,"plan":plan}
            self.assertEqual(self.m.authorize(authorize,runner)["status"],"authorized")
            self.assertEqual(self.m.restore_access(restore,runner)["status"],"tofu-apply-restored")
        self.assertEqual(self.m.TOFU_KEYS.read_bytes(),keys); self.assertEqual(shell[0],"/bin/bash"); self.assertFalse(self.m.ACCESS_SNAPSHOT.exists())
    def test_console_requires_linux_vt_and_transport_excludes_privileged_local_commands(self):
        record="1 (helper) R 0 0 0 1 0 0"
        with mock.patch.object(self.m.os,"open",return_value=9),mock.patch.object(self.m.Path,"read_text",return_value=record),mock.patch.object(self.m.os,"major",return_value=136),mock.patch.object(self.m.os,"minor",return_value=1),mock.patch.object(self.m.os,"close"):
            with self.assertRaises(ValueError): self.m.local_console()
        with mock.patch.object(self.m.os,"open",return_value=9),mock.patch.object(self.m.Path,"read_text",return_value=record),mock.patch.object(self.m.os,"major",return_value=4),mock.patch.object(self.m.os,"minor",return_value=2),mock.patch.object(self.m.os,"close"): self.m.local_console()
        transport_path=ROOT/"infrastructure/proxmox-firewall/host/proxmox-firewall-transport"; transport=transport_path.read_text()
        for forbidden in ("authorize","isolate-tofu-apply","restore-tofu-apply","boot-config-recover","boot-post-recover"): self.assertNotIn(forbidden,transport)
        for arguments in ((),("-c","inspect"),("-c","/bin/sh")):
            self.assertEqual(subprocess.run((transport_path,*arguments),capture_output=True,env={**os.environ,"SSH_ORIGINAL_COMMAND":"inspect"}).returncode,64)
        forced=subprocess.run((transport_path,"-c","/usr/local/libexec/home-lab/proxmox-firewall-transport"),capture_output=True,env={**os.environ,"SSH_ORIGINAL_COMMAND":"inspect"})
        self.assertNotEqual(forced.returncode,64)
    def test_real_runner_enforces_attempt_and_aggregate_deadlines(self):
        runner=self.m.Runner(); command=("/usr/bin/pvesh","get","/cluster/firewall/options")
        failed=mock.Mock(returncode=1,stderr=b"",stdout=b"")
        with mock.patch.object(self.m.subprocess,"run",return_value=failed) as invoked,mock.patch.object(self.m.time,"sleep") as slept:
            with self.assertRaises(RuntimeError): runner.run(command)
        self.assertEqual(invoked.call_count,2); slept.assert_called_once_with(1)
        runner.deadline=self.m.time.monotonic()-1
        with mock.patch.object(self.m.subprocess,"run") as invoked:
            with self.assertRaises(RuntimeError): runner.run(command)
        invoked.assert_not_called()
    def test_source_has_closed_catalogue_and_no_pve_filesystem_access(self):
        source=SOURCE.read_text(); self.assertNotIn("/etc/pve",source); self.assertNotIn("shell=True",source)
        self.assertEqual(set(self.m.FIXED_MUTATIONS),{"disable","set-default-policies","remove-before-rules","create-reviewed-rules","verify-staged","enable","verify-activated"})
        with mock.patch.object(self.m.os,"geteuid",return_value=0),mock.patch.object(self.m.sys,"argv",["helper","unknown"]): self.assertEqual(self.m.main(),64)

if __name__=="__main__": unittest.main()
