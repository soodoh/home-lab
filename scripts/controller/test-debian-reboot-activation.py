#!/usr/bin/env python3
import importlib.machinery,importlib.util,tempfile,unittest,json,hashlib,datetime as dt
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; EXECUTOR=ROOT/"infrastructure/maintenance/host/debian-reboot-transaction"; CONTROLLER=ROOT/"scripts/controller/debian-reboot-activation.py"
loader=importlib.machinery.SourceFileLoader("debian_reboot",str(EXECUTOR)); spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)
def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
class Tests(unittest.TestCase):
 def test_activation_validation_refuses_authority_drift(self):
  value={"format":"home-lab-debian-reboot-activation-v1","host":"debian","commit":"1"*40,"created_at":"2026-09-03T10:00:00Z","expires_at":"2026-09-03T10:30:00Z","maintenance_plan_sha256":"2"*64,"expected":{"boot_id":"1","current_kernel":"old","target_kernel":"new"},"evidence_sha256":"3"*64,"pending_package_transaction_sha256":"4"*64,"backup":{"accepted_path":"/fixture/accepted.json","accepted_sha256":"5"*64,"max_age_seconds":86400},"window":{"timezone":"America/Los_Angeles","weekday":5,"start_hour":1,"max_duration_seconds":3600,"backup_buffer_seconds":10800},"conflict_locks":[],"inactive_backup_units":[],"workload_order":["compose-drain","host-reboot","host-audit"],"postchecks":["kernel","mounts","docker","compose","restic-timers","tailscale","production-audit"],"executor_sha256":hashlib.sha256(EXECUTOR.read_bytes()).hexdigest(),"automatic_reboot":False,"authorized":False}
  value["activation_sha256"]=hashlib.sha256(canonical(value)).hexdigest(); raw=canonical(value); digest=hashlib.sha256(raw).hexdigest(); module.validate(value,raw,digest,allow_expired=True)
  altered=json.loads(json.dumps(value)); altered["authorized"]=True
  with self.assertRaisesRegex(RuntimeError,"differs"): module.validate(altered,canonical(altered),hashlib.sha256(canonical(altered)).hexdigest(),allow_expired=True)
 def test_sources_encode_single_reboot_and_manual_failure(self):
  source=EXECUTOR.read_text(); controller=CONTROLLER.read_text()
  for required in ('"compose-drained"','"rebooting"','"failed-postboot-manual-recovery-required"','"host-health-passed-awaiting-controller-audit"','"committed"','home-lab-restic-daily.timer','os.O_NOFOLLOW','os.fsync'):
   self.assertIn(required,source)
  self.assertEqual(source.count('("/usr/bin/systemctl","reboot")'),1)
  for required in ("DEBIAN_REBOOT_PREPARE_CONFIRMED","DEBIAN_REBOOT_APPLY_CONFIRMED","BatchMode=yes","StrictHostKeyChecking=yes","UpdateHostKeys=no","IdentitiesOnly=yes","RequestTTY=no","postboot production audit failed; journal remains for manual recovery"):
   self.assertIn(required,controller)
  self.assertNotIn("automatic_reboot\":True",source+controller)
if __name__=="__main__": unittest.main()
