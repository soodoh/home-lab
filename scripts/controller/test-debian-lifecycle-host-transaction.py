#!/usr/bin/env python3
"""Executable rollback and no-retry tests for the fixed Debian host executor."""
import fcntl,importlib.machinery,importlib.util,json,os,subprocess,tempfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction"; loader=importlib.machinery.SourceFileLoader("host_transaction",str(SOURCE)); spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)
def result(stdout="",returncode=0): return subprocess.CompletedProcess([],returncode,stdout,"")
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); token=root/"token"; marker=root/"marker.json"; identity=root/"identity"; artifact=root/"compose.yml"; image=root/"images.yml"; environment=root/"production.env"; restic=root/"restic.json"
 storage_sha="1"*64; token.write_text(f"plan_sha256={storage_sha}\n"); before=module.canonical({"source_commit":"a"*40,"state":"recovery","updated_at":"2026-09-04T00:00:00Z","version":1}); marker.write_bytes(before)
 for path,content in ((identity,b"identity"),(artifact,b"artifact"),(image,b"images"),(environment,b"env")): path.write_bytes(content)
 restic.write_bytes(module.canonical({"commit":"a"*40,"format":"home-lab-restic-recovery-activation-receipt-v1","producer_sha256":"f"*64,"repository_id":"1"*64,"restore_manifest_sha256":"2"*64,"snapshot_id":"3"*64,"snapshot_manifest_sha256":"4"*64,"status":"verified","target":"debian","tree_sha256":"5"*64,"version":1}))
 module.STORAGE_TOKEN=token; module.LIFECYCLE_MARKER=marker; module.require_regular=lambda *args,**kwargs:None; module.require_root_regular=lambda *args,**kwargs:None; module.read_root_regular=lambda path,*args,**kwargs:Path(path).read_bytes(); module.safe_directory=lambda path:Path(path); module.verify_mount=lambda *args,**kwargs:None; original_fchown=module.os.fchown; module.os.fchown=lambda *args:None
 active=set(); commands=[]; fail_start=False
 def fake(argv,check=True,**kwargs):
  commands.append(tuple(argv))
  if "age-keygen" in argv[0]: return result("age1recipient\n")
  if argv[:3]==["/usr/bin/tailscale","status","--json"]: return result(json.dumps({"BackendState":"Running","Self":{"HostName":"docker-host","Tags":["tag:docker-host"]}}))
  if argv[:3]==["/usr/bin/systemctl","show","unit.service"]: return result("dep.mount\n")
  if argv[:2]==["/usr/bin/systemctl","start"]:
   active.add(argv[2])
   if fail_start: raise InterruptedError("injected partial start")
   return result()
  if argv[:2]==["/usr/bin/systemctl","stop"]: active.discard(argv[2]); return result()
  if argv[:3]==["/usr/bin/systemctl","is-active","--quiet"]: return result(returncode=0 if argv[3] in active else 3)
  return result()
 module.run=fake; calls=0
 def fail_first_marker_sync(path):
  global calls
  if Path(path)==marker and calls==0: calls+=1; raise OSError("injected marker fsync failure")
 module.fsync_parent=fail_first_marker_sync
 params={"mounts":[],"storage_plan_sha256":storage_sha,"identity_recipient":"age1recipient","tailscale_hostname":"docker-host","tailscale_tags":["tag:docker-host"],"systemd_dependencies":{"unit.service":["dep.mount"]},"lifecycle_marker_sha256":module.sha(before),"compose_artifact_path":str(artifact),"compose_artifact_sha256":module.sha(artifact.read_bytes()),"compose_image_lock_path":str(image),"compose_image_lock_sha256":module.sha(image.read_bytes()),"compose_command":["/usr/bin/docker","compose"],"root_environment_path":str(environment),"root_environment_sha256":module.sha(environment.read_bytes()),"restic_recovery_receipt_path":str(restic),"restic_recovery_receipt_sha256":module.sha(restic.read_bytes())}
 plan={"base_commit":"a"*40,"bindings":{"authority_producer_sha256":"f"*64},"request":{"parameters":params},"precondition":{"identity":{"path":str(identity)}}}
 try: module.production(plan,"b"*64)
 except OSError as error: assert "injected" in str(error)
 else: raise AssertionError("marker publication failure unexpectedly succeeded")
 assert marker.read_bytes()==before and active==set() and ("/usr/bin/systemctl","stop","unit.service") in commands
 marker.write_bytes(before); commands.clear(); fail_start=True
 try: module.production(plan,"c"*64)
 except InterruptedError as error: assert "partial start" in str(error)
 else: raise AssertionError("partial unit start unexpectedly succeeded")
 assert marker.read_bytes()==before and active==set() and ("/usr/bin/systemctl","stop","unit.service") in commands
 module.os.fchown=original_fchown
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); journal_root=root/"journals"; module.STATE_JOURNAL_ROOT=journal_root; module.safe_directory=lambda path:Path(path); module.device=lambda *args:("/dev/fake",1)
 original_lstat=module.os.lstat; original_fchown=module.os.fchown
 def fake_lstat(path):
  value=original_lstat(path)
  if Path(path)==journal_root: return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0)
  return value
 module.os.lstat=fake_lstat; module.os.fchown=lambda *args:None
 module.run=lambda argv,**kwargs: (_ for _ in ()).throw(InterruptedError("injected mkfs interruption")) if argv[0]=="/usr/sbin/mkfs.ext4" else result()
 params={"force":False,"path":"/dev/disk/by-id/state","serial":"serial","size_bytes":1,"filesystem_uuid":"11111111-1111-4111-8111-111111111111","tofu_receipt_sha256":"c"*64}; plan={"request":{"parameters":params}}
 try: module.state_disk(plan,"d"*64)
 except InterruptedError: pass
 else: raise AssertionError("interrupted mkfs unexpectedly succeeded")
 journal=journal_root/("d"*64)/"journal.json"; assert json.loads(journal.read_bytes())["status"]=="started"
 try: module.state_disk(plan,"d"*64)
 except SystemExit as error: assert "automatic retry forbidden" in str(error)
 else: raise AssertionError("partial state-disk transaction was retryable")
 module.os.lstat=original_lstat; module.os.fchown=original_fchown
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 module.RUNTIME_DIR=Path(raw); original_fchown=module.os.fchown; module.os.fchown=lambda *args:None; calls=[]; secret=b"tskey-auth-test"; plan={"request":{"parameters":{"auth_key_sha256":module.sha(secret),"hostname":"docker-host","tags":["tag:docker-host"],"expected_dns_suffix":"example.ts.net"}}}
 def fake_tailscale(argv,check=True,**kwargs):
  calls.append(tuple(argv))
  if argv[:2]==["/usr/bin/tailscale","up"]: raise InterruptedError("injected enrollment interruption")
  if argv[:2]==["/usr/bin/tailscale","status"]: return result(json.dumps({"BackendState":"Stopped"}))
  return result()
 module.run=fake_tailscale
 try: module.tailscale(plan,secret)
 except InterruptedError: pass
 else: raise AssertionError("interrupted Tailscale enrollment unexpectedly succeeded")
 assert ("/usr/bin/tailscale","down") in calls and not list(Path(raw).iterdir())
 module.os.fchown=original_fchown
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 path=Path(raw)/"persistent.lock"; path.write_bytes(b""); path.chmod(0o600); original_fstat=module.os.fstat
 def root_fstat(fd):
  value=original_fstat(fd); return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0,st_nlink=value.st_nlink)
 module.os.fstat=root_fstat; assert module.flock_active(path) is False; descriptor=os.open(path,os.O_RDWR); fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB); assert module.flock_active(path) is True; os.close(descriptor); module.os.fstat=original_fstat
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); module.QUALIFICATION_ROOT=root/"canaries"; original_fchown=module.os.fchown; original_safe=module.safe_directory; original_run=module.run; module.os.fchown=lambda *args:None; module.safe_directory=lambda path:Path(path); digest="e"*64; params={"receipt_root":str(module.QUALIFICATION_ROOT),"inactive_units":list(module.QUALIFICATION_UNITS)}; plan={"profile":"inert","request":{"parameters":params}}
 module.run=lambda *args,**kwargs:result(returncode=0)
 try: module.qualification(plan,digest)
 except SystemExit as error: assert "production unit is active" in str(error)
 else: raise AssertionError("active production unit passed qualification")
 assert not module.QUALIFICATION_ROOT.exists()
 def unknown_unit(argv,**kwargs): return result("loaded\n",0) if "show" in argv else result(returncode=4)
 module.run=unknown_unit
 try: module.qualification(plan,digest)
 except SystemExit as error: assert "absence is unverifiable" in str(error)
 else: raise AssertionError("unknown production unit passed qualification")
 assert not module.QUALIFICATION_ROOT.exists()
 def absent_unit(argv,**kwargs): return result("not-found\n",0) if "show" in argv else result(returncode=4)
 module.run=absent_unit; module.qualification(plan,digest); receipt=json.loads((module.QUALIFICATION_ROOT/f"{digest}.json").read_bytes()); assert receipt["plan_sha256"]==digest and receipt["profile"]=="inert" and set(receipt["unit_states"].values())=={"absent"}; module.os.fchown=original_fchown; module.safe_directory=original_safe; module.run=original_run
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); machine=root/"machine-id"; machine.write_bytes(b"machine\n"); module.LIFECYCLE_MARKER=root/"missing"/"lifecycle-state.json"; original_run=module.run; original_uname=module.os.uname; original_path=module.Path; original_lstat=module.os.lstat
 def root_directory_lstat(path):
  value=original_lstat(path)
  return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0) if module.stat.S_ISDIR(value.st_mode) else value
 module.run=lambda *args,**kwargs:result("256 SHA256:test root (ED25519)\n"); module.os.uname=lambda:SimpleNamespace(nodename="debian-lifecycle-qualification"); module.os.lstat=root_directory_lstat; module.Path=lambda value:machine if value=="/etc/machine-id" else original_path(value); host={"hostname":"debian-lifecycle-qualification","machine_id_sha256":module.sha(machine.read_bytes()),"host_key_fingerprint":"SHA256:test"}; module.verify_target({"operation":"qualification-canary","profile":"inert","precondition":{"host":host}}); module.QUALIFICATION_ROOT=root/"missing"/"canaries"; original_fchown=module.os.fchown; module.os.fchown=lambda *args:None; module.run=lambda *args,**kwargs:result(returncode=3); digest="a"*64; module.qualification({"profile":"inert","request":{"parameters":{"receipt_root":str(module.QUALIFICATION_ROOT),"inactive_units":list(module.QUALIFICATION_UNITS)}}},digest); assert (module.QUALIFICATION_ROOT/f"{digest}.json").is_file(); module.run=original_run; module.os.uname=original_uname; module.os.lstat=original_lstat; module.os.fchown=original_fchown; module.Path=original_path
print("debian_lifecycle_host_transaction=verified rollback=true no_retry=true interruption=true locks=true qualification=true marker_absence=true")
