#!/usr/bin/env python3
import datetime as dt, hashlib, importlib.machinery, importlib.util, json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
EXECUTOR=ROOT/"infrastructure/maintenance/host/debian-package-transaction"
TRANSPORT=ROOT/"infrastructure/maintenance/host/debian-package-apply-transport"
loader=importlib.machinery.SourceFileLoader("debian_package_transaction",str(EXECUTOR)); spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)

def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def fixture():
    change={"action":"upgrade","candidate_version":"2","name":"fixture","origin":"Debian:13","policy_sha256":"a"*64,"previous_version":"1","security":False}
    value={"format":"home-lab-package-transaction-final-v1","version":1,"host":"debian","lifecycle":"production","base_commit":"1"*40,"generated_at":"2026-09-03T10:00:00Z","expires_at":"2026-09-03T10:30:00Z","lane":"no-restart-safe","automatic_apply":False,"automatic_reboot":False,"actionable":True,"authorized":False,
      "bindings":{"candidate_transaction_sha256":"1"*64,"review_sha256":"2"*64,"changes_sha256":"3"*64,"contract_sha256":"4"*64,"inventory_sha256":"5"*64,"host_key_fingerprint":"SHA256:"+"A"*43,"installed_package_set_sha256":"6"*64,"apt_sources_sha256":"7"*64,"apt_keyrings_sha256":"8"*64,"apt_configuration_sha256":"9"*64,"proposal_sha256":"b"*64},
      "transaction":{"changes":[change],"exact_install_specs":["fixture=2"],"additions":[],"download_bytes":1,"disk_delta_bytes":1,"affected_services":[],"protected_services":[],"needrestart_assessment":"no-protected-restart","reboot_required":False,"reboot_reasons":[],"safety_classification":"no-restart-safe"},"blockers":["separate-exact-authorization-required"]}
    value["bindings"]["changes_sha256"]=hashlib.sha256(canonical(value["transaction"]["changes"])).hexdigest(); value["final_sha256"]=hashlib.sha256(canonical(value)).hexdigest(); return value

def observation(plan):
    return {"version":2,"host":"debian","installed_status_sha256":"6"*64,"apt_state_hashes":{"sources_sha256":"7"*64,"keyrings_sha256":"8"*64,"configuration_sha256":"9"*64},"proposal_sha256":"b"*64,"changes":plan["transaction"]["changes"],"apt_tree_safe":True,"size_parse_complete":True,"holds":[],"kept_back":[],"active_lifecycle_locks":[str(module.LOCK)]}

class FakeBackend:
    def __init__(self, observed): self.observed=observed; self.applied=[]
    def observe(self): return self.observed
    def apply(self,specs): self.applied.append(specs)

class Tests(unittest.TestCase):
    def test_exact_validation_and_hostile_drift(self):
        plan=fixture(); raw=canonical(plan); digest=hashlib.sha256(raw).hexdigest(); now=dt.datetime.fromisoformat("2026-09-03T10:05:00+00:00")
        module.validate_plan(plan,raw,digest,now); module.validate_live(plan,observation(plan))
        altered=json.loads(json.dumps(plan)); altered["authorized"]=True
        with self.assertRaisesRegex(RuntimeError,"final hash|authority"): module.validate_plan(altered,canonical(altered),hashlib.sha256(canonical(altered)).hexdigest(),now)
        drift=observation(plan); drift["apt_state_hashes"]["sources_sha256"]="0"*64
        with self.assertRaisesRegex(RuntimeError,"live precondition"): module.validate_live(plan,drift)
        locks=observation(plan); locks["active_lifecycle_locks"].append("/var/lib/dpkg/lock")
        with self.assertRaisesRegex(RuntimeError,"live precondition"): module.validate_live(plan,locks)
        widened=json.loads(json.dumps(plan)); widened["unexpected"]=False; widened["final_sha256"]=hashlib.sha256(canonical({key:value for key,value in widened.items() if key!="final_sha256"})).hexdigest()
        with self.assertRaisesRegex(RuntimeError,"fields differ"): module.validate_plan(widened,canonical(widened),hashlib.sha256(canonical(widened)).hexdigest(),now)
        changed=json.loads(json.dumps(plan)); changed["bindings"]["changes_sha256"]="0"*64; changed["final_sha256"]=hashlib.sha256(canonical({key:value for key,value in changed.items() if key!="final_sha256"})).hexdigest()
        with self.assertRaisesRegex(RuntimeError,"shape differs"): module.validate_plan(changed,canonical(changed),hashlib.sha256(canonical(changed)).hexdigest(),now)
    def test_fake_backend_commit_and_failed_journal(self):
        plan=fixture(); raw=canonical(plan); digest=hashlib.sha256(raw).hexdigest(); backend=FakeBackend(observation(plan))
        with tempfile.TemporaryDirectory() as temp:
            old=(module.install_plan,module.JOURNAL_ROOT,module.save)
            records=[]; module.install_plan=lambda _:plan; module.JOURNAL_ROOT=Path(temp); module.save=lambda path,value,exclusive=False: records.append(json.loads(json.dumps(value)))
            try:
                result=module.apply(digest,backend); self.assertEqual(result["status"],"committed"); self.assertEqual(backend.applied,[["fixture=2"]]); self.assertFalse(result["automatic_reboot"])
                failing=FakeBackend(observation(plan)); failing.apply=lambda specs: (_ for _ in ()).throw(RuntimeError("fixture")); records.clear()
                with self.assertRaises(RuntimeError): module.apply(digest,failing)
                self.assertEqual(records[-1]["status"],"failed-manual-recovery-required")
            finally: module.install_plan,module.JOURNAL_ROOT,module.save=old
    def test_transport_grammar(self):
        digest="a"*64
        environment={k:v for k,v in os.environ.items() if k!="SSH_ORIGINAL_COMMAND"}
        valid=subprocess.run((TRANSPORT,"-c",f"inspect package {digest}"),env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode
        self.assertNotEqual(valid,64)
        for command in ("inspect package a;id",f"inspect package {digest} extra","/bin/sh",""):
            self.assertEqual(subprocess.run((TRANSPORT,"-c",command),env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode,64)
    def test_sources_are_bounded(self):
        source=EXECUTOR.read_text(); transport=TRANSPORT.read_text(); controller=(ROOT/"scripts/controller/debian-package-activation.py").read_text()
        for required in ("--no-remove","--download-only","--no-download","failed-manual-recovery-required","os.O_NOFOLLOW","os.fsync","automatic_reboot"):
            self.assertIn(required,source)
        self.assertNotIn("systemctl\", \"reboot",source); self.assertNotIn("NOPASSWD: ALL",transport+controller)
        for option in ("BatchMode=yes","StrictHostKeyChecking=yes","UpdateHostKeys=no","IdentitiesOnly=yes","RequestTTY=no"):
            self.assertIn(option,controller)
if __name__=="__main__": unittest.main()
