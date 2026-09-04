#!/usr/bin/env python3
"""Verify fixed OpenTofu and age recovery receipt producers."""
import importlib.util,json,os,subprocess,tempfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-lifecycle-authority-receipts.py"; spec=importlib.util.spec_from_file_location("authority_receipts",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
def write(path,value):
 raw=(module.canonical_bytes(value)+b"\n") if isinstance(value,dict) else value; path.write_bytes(raw); path.chmod(0o600); return path
def completed(stdout="",stderr="",returncode=0): return subprocess.CompletedProcess([],returncode,stdout,stderr)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); output=root/"out"; output.mkdir(mode=0o700); device={"path":"/dev/disk/by-id/scsi-state","serial":"QUAL-NIXOS-128G","size_bytes":137438953472,"uuid":"d4a19647-7879-4079-9fc9-b3e79711b449","fstype":"ext4","surviving":True}; address="proxmox_virtual_environment_vm.debian"
 request=write(root/"request.json",{"devices":[device],"format":"home-lab-opentofu-debian-disk-receipt-request-v1","kind":"state-disk","resource_address":address,"vmid":100}); saved=write(root/"saved.tfplan",b"binary-plan"); after={"vm_id":100,"node_name":"proxmox","name":"docker-host","disk":[{"serial":device["serial"],"size":128}],"started":True,"on_boot":True,"protection":True}; state_value={"values":{"root_module":{"resources":[{"address":address,"values":after}]}}}; state=write(root/"state.json",state_value); plan_value={"resource_changes":[{"address":address,"change":{"actions":["update"],"before":{**after,"disk":[]},"after":after,"after_unknown":{}}}]}
 original_run=module.subprocess.run; original_commit=module.commit; module.commit=lambda expected=None:"a"*40; module.subprocess.run=lambda argv,**kwargs:completed(json.dumps(plan_value)) if argv[:3]==["tofu","show","-json"] else original_run(argv,**kwargs)
 module.opentofu(SimpleNamespace(request=request,saved_plan=saved,state_json=state,output=output)); receipt_path=next(output.glob("*.json")); receipt=json.loads(receipt_path.read_bytes()); assert receipt["blank_required"] is True and receipt["plan_sha256"]==module.sha(saved.read_bytes()) and receipt["state_sha256"]==module.sha(state.read_bytes())
 unrelated={"resource_changes":[{"address":address,"change":{"actions":["update"],"before":{**after,"disk":[]},"after":{**after,"memory":8192},"after_unknown":{}}}]}; module.subprocess.run=lambda argv,**kwargs:completed(json.dumps(unrelated)) if argv[:3]==["tofu","show","-json"] else original_run(argv,**kwargs)
 try: module.opentofu(SimpleNamespace(request=request,saved_plan=saved,state_json=state,output=output))
 except SystemExit as error: assert "unrelated" in str(error)
 else: raise AssertionError("unrelated OpenTofu VM update accepted")
 module.subprocess.run=lambda argv,**kwargs:completed(json.dumps(plan_value)) if argv[:3]==["tofu","show","-json"] else original_run(argv,**kwargs)
 wrong=dict(state_value); wrong["values"]={"root_module":{"resources":[{"address":address,"values":{"vm_id":100,"disk":[{"serial":"wrong","size":128}]}}]}}; write(state,wrong)
 try: module.opentofu(SimpleNamespace(request=request,saved_plan=saved,state_json=state,output=output))
 except SystemExit as error: assert "serial" in str(error)
 else: raise AssertionError("wrong OpenTofu state disk accepted")
 module.subprocess.run=original_run; module.commit=original_commit
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); output=root/"out"; output.mkdir(mode=0o700); identity=write(root/"identity",b"AGE-SECRET-KEY-TEST\n"); bundle=write(root/"bundle.age",b"encrypted"); recipient="age1"+"q"*58
 original_run=module.subprocess.run; original_commit=module.commit; module.commit=lambda expected=None:"a"*40
 def fake(argv,**kwargs):
  if argv[0]=="age-keygen": return completed(recipient+"\n")
  if argv[0]=="age": return completed()
  return original_run(argv,**kwargs)
 module.subprocess.run=fake; module.age(SimpleNamespace(identity=identity,recovery_bundle=bundle,recipient=recipient,output=output,age="age",age_keygen="age-keygen")); receipt=json.loads(next(output.glob("*.json")).read_bytes()); assert receipt["identity_sha256"]==module.sha(identity.read_bytes()) and receipt["recovery_bundle_sha256"]==module.sha(bundle.read_bytes()) and receipt["bundle_plaintext_sha256"]==module.sha(b"")
 module.subprocess.run=original_run; module.commit=original_commit
with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
 root=Path(raw); snapshot_out=root/"snapshot-out"; restore_out=root/"restore-out"; receipt_out=root/"receipt-out"; staging=root/"staging"
 for path in (snapshot_out,restore_out,receipt_out,staging): path.mkdir(mode=0o700)
 repository_id="1"*64; snapshot_id="2"*64; original_run=module.subprocess.run; original_commit=module.commit; module.commit=lambda expected=None:"a"*40
 def fake_restic(argv,**kwargs):
  if "cat" in argv: return completed(json.dumps({"id":repository_id}))
  if "snapshots" in argv: return completed(json.dumps([{"id":snapshot_id}]))
  if "restore" in argv: (staging/"restored.txt").write_text("verified\n"); return completed()
  if "check" in argv: return completed()
  return original_run(argv,**kwargs)
 module.subprocess.run=fake_restic; module.restic_snapshot(SimpleNamespace(restic="restic",repository="repo",repository_id=repository_id,snapshot_id=snapshot_id,output=snapshot_out)); snapshot=next(snapshot_out.glob("*.json")); module.restic_restore(SimpleNamespace(restic="restic",repository="repo",snapshot_manifest=snapshot,staging_root=staging,output=restore_out)); restore=next(restore_out.glob("*.json")); module.restic_receipt(SimpleNamespace(snapshot_manifest=snapshot,restore_manifest=restore,output=receipt_out)); receipt=json.loads(next(receipt_out.glob("*.json")).read_bytes()); assert receipt["snapshot_manifest_sha256"]==module.sha(snapshot.read_bytes()) and receipt["restore_manifest_sha256"]==module.sha(restore.read_bytes()); module.subprocess.run=original_run; module.commit=original_commit
print("debian_lifecycle_authority_receipts=verified opentofu_bytes=true age_full_read=true restic_bytes=true")
