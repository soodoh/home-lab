#!/usr/bin/env python3
"""Hostile fixture tests for guarded Debian lifecycle transactions."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl, importlib.util, json, os
from pathlib import Path
import stat, tempfile

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("transactions",ROOT/"scripts/controller/debian-lifecycle-transactions.py")
module=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(module)
COMMIT="a"*40
NOW=datetime(2026,9,4,12,0,tzinfo=timezone.utc)
TEST_POLICY={"transaction":{"storage_activation_path":"/etc/home-lab/allow-storage-activation","age_identity_path":"/etc/home-lab/age/keys.txt","qualification_canary_hostname":"debian-lifecycle-qualification","qualification_canary_inventory_host":"debian-lifecycle-qualification","qualification_canary_receipt_root":"/var/lib/home-lab/debian-lifecycle-qualification-canaries","compose_command":["/usr/bin/docker","compose"],"compose_artifact_path":"/etc/home-lab/compose.yml","compose_image_lock_path":"/etc/home-lab/images.json","root_environment_path":"/etc/home-lab/compose.env","production_units":["docker-compose.service"]},"hostname":"docker-host","tag":"tag:docker-host","state":{"mountpoint":"/srv/home-lab-state","filesystem_uuid":"11111111-1111-4111-8111-111111111111","filesystem":"ext4","mount_options":["defaults"],"serial":"replacement-serial","size_gb":2},"storage":{"games":{"mountpoint":"/mnt/games","filesystem_uuid":"31602ce7-0054-498a-9f24-f51ca491e7b3","filesystem":"ext4","options":["noatime"]}},"protected_mounts":["/srv/home-lab-state"]}
actual_policy=module.contract_policy(); assert actual_policy["transaction"]["age_identity_path"]=="/etc/sops/age/keys.txt" and actual_policy["state"]["serial"]=="QUAL-NIXOS-128G"
module.contract_policy=lambda:TEST_POLICY

def canonical(value): return module.canonical_bytes(value)+b"\n"
def write(path,value,mode=0o600): path.write_bytes(canonical(value) if isinstance(value,dict) else value); os.chmod(path,mode)
def expect(label,needle,call):
    try: call()
    except SystemExit as error:
        if needle not in str(error): raise AssertionError(f"{label}: {error}")
    else: raise AssertionError(f"{label}: unexpectedly succeeded")

def base(profile="recovery"):
    return {"format":"home-lab-debian-lifecycle-observation-v1","target":"debian","profile":profile,"host":{"hostname":"debian-lifecycle-qualification" if profile=="inert" else "docker-host","machine_id_sha256":"f"*64,"host_key_fingerprint":"SHA256:test"},"locks":[],"storage":[],"mounts":[],"identity":{"exists":False},"tailscale":{"backend_state":"Absent"},"production":{},"ssh":{}}

def request(op,profile,params): return {"format":"home-lab-debian-lifecycle-request-v1","operation":op,"profile":profile,"parameters":params}

def evidence_for(op,req,root):
    params=req["parameters"]; values=[]
    if op=="storage-activation": values=[{"authority":"opentofu","commit":"a"*40,"devices":params["devices"],"format":"home-lab-opentofu-storage-attachment-receipt-v1","plan_sha256":"1"*64,"producer_sha256":module.sha(module.AUTHORITY_PRODUCER.read_bytes()),"state_sha256":"2"*64,"status":"applied","target":"debian","version":1,"vmid":100}]
    elif op=="identity-recovery": values=[{"bundle_plaintext_sha256":"4"*64,"commit":"a"*40,"format":"home-lab-age-recovery-receipt-v1","identity_sha256":params["identity_sha256"],"path":params["path"],"producer_sha256":module.sha(module.AUTHORITY_PRODUCER.read_bytes()),"recipient":params["recipient"],"recovery_bundle_sha256":"3"*64,"status":"verified","target":"debian","version":1}]
    elif op=="state-disk-initialization": values=[{"authority":"opentofu","blank_required":True,"commit":"a"*40,"disk":{key:params[key] for key in ("path","serial","size_bytes")},"format":"home-lab-opentofu-state-disk-receipt-v1","plan_sha256":"5"*64,"producer_sha256":module.sha(module.AUTHORITY_PRODUCER.read_bytes()),"state_sha256":"6"*64,"status":"applied","target":"debian","version":1,"vmid":100}]
    elif op=="production-activation": values=[{"commit":"a"*40,"format":"home-lab-restic-recovery-activation-receipt-v1","producer_sha256":module.sha(module.AUTHORITY_PRODUCER.read_bytes()),"repository_id":"7"*64,"restore_manifest_sha256":"8"*64,"snapshot_id":"9"*64,"snapshot_manifest_sha256":"a"*64,"status":"verified","target":"debian","tree_sha256":"b"*64,"version":1}]
    elif op=="ssh-tightening": values=[{"commit":"a"*40,"format":"home-lab-debian-access-cleanup-operation-receipt-v1","kind":kind,"manifest_sha256":"b"*64,"plan_sha256":str(index+1)*64,"producer_sha256":module.sha(module.ACCESS_CLEANUP.read_bytes()),"status":"committed","target":"debian","version":1} for index,kind in enumerate(("legacy-marker-removal","conventional-key-removal","openssh-tightening"))]
    paths=[]
    for index,value in enumerate(values):
        path=root/f"{op}-evidence-{index}.json"; write(path,value); paths.append(path)
    digests=[module.sha(path.read_bytes()) for path in paths]
    if op=="storage-activation": params["attachment_receipt_sha256"]=digests[0]
    elif op=="identity-recovery": params["recovery_receipt_sha256"]=digests[0]
    elif op=="state-disk-initialization": params["tofu_receipt_sha256"]=digests[0]
    elif op=="production-activation": params["restic_recovery_receipt_sha256"]=digests[0]
    elif op=="ssh-tightening":
        by_kind={value["kind"]:digest for value,digest in zip(values,digests)}
        for item in params["access_cleanup_receipts"]: item["sha256"]=by_kind[item["kind"]]
    return paths

def mount(active=False):
    return {"path":"/srv/home-lab-state","source":"/dev/disk/by-id/scsi-state","uuid":"11111111-1111-4111-8111-111111111111","fstype":"ext4","options":["defaults","nofail"],"owner":0,"group":0,"mode":"0755","minimum_free_bytes":1048576,**({"active":active,"symlink":False,"free_bytes":9999999,"same_device":True} if active else {})}

def cases(now):
    o=base("inert"); o["production"]={"active_units":[]}
    yield "qualification-canary",request("qualification-canary","inert",{"receipt_root":"/var/lib/home-lab/debian-lifecycle-qualification-canaries","inactive_units":TEST_POLICY["transaction"]["production_units"]}),o
    device={"path":"/dev/disk/by-id/scsi-state","serial":"state-serial","size_bytes":1073741824,"uuid":"11111111-1111-4111-8111-111111111111","fstype":"ext4","surviving":True}
    observed_device={**device,"stable_path":device["path"],"realpath":"/dev/sdb","block":True,"symlink":True,"signatures":[{"type":"ext4","uuid":device["uuid"]}],"holders":[],"mounts":[],"device_number":"8:16"}
    o=base(); o["storage"]=[observed_device]; o["mounts"]=[mount(False)]
    yield "storage-activation",request("storage-activation","recovery",{"devices":[device],"mounts":[{k:v for k,v in mount().items() if k not in {"active","symlink"}}],"activation_path":"/etc/home-lab/allow-storage-activation","attachment_receipt_sha256":"0"*64}),o
    secret=b"# created: test\nAGE-SECRET-KEY-1TEST\n"; digest=module.sha(secret)
    yield "identity-recovery",request("identity-recovery","recovery",{"path":"/etc/home-lab/age/keys.txt","recipient":"age1testrecipient","identity_sha256":digest,"recovery_receipt_sha256":"1"*64}),base(),secret
    auth=b"tskey-auth-test"; o=base()
    yield "tailscale-enrollment",request("tailscale-enrollment","recovery",{"auth_key_sha256":module.sha(auth),"auth_key_expires_at":module.now_text(now+timedelta(minutes=20)),"one_use":True,"preauthorized":True,"hostname":"docker-host","tags":["tag:docker-host"],"expected_dns_suffix":"example.ts.net"}),o,auth
    o=base(); m=mount(True); o["mounts"]=[m]; o["identity"]={"exists":True,"path":"/etc/home-lab/age/keys.txt","recipient":"age1testrecipient","uid":0,"gid":0,"mode":"0600","regular":True,"symlink":False,"nlink":1}; o["tailscale"]={"backend_state":"Running","hostname":"docker-host","tags":["tag:docker-host"],"node_id":"node-test","addresses":["100.64.0.1"],"run_ssh":False}; o["production"]={"lifecycle_marker_sha256":"a"*64,"compose_artifact_sha256":"2"*64,"compose_image_lock_sha256":"3"*64,"compose_config_valid":True,"restic_recovery_receipt_sha256":"4"*64,"root_environment_protected":True,"root_environment_sha256":"6"*64,"systemd_dependencies":{"docker-compose.service":["srv-home\\x2dlab\\x2dstate.mount"]},"systemd_unit_states":{"docker-compose.service":"inactive"},"storage_plan_sha256":"5"*64,"compose_artifact_path":"/etc/home-lab/compose.yml","compose_image_lock_path":"/etc/home-lab/images.json","restic_recovery_receipt_path":"/etc/home-lab/restic-recovery.json","compose_command":["/usr/bin/docker","compose"],"root_environment_path":"/etc/home-lab/compose.env"}
    pm={k:v for k,v in m.items() if k not in {"active","symlink","free_bytes","same_device"}}
    yield "production-activation",request("production-activation","recovery",{"mounts":[pm],"storage_plan_sha256":"5"*64,"identity_recipient":"age1testrecipient","tailscale_hostname":"docker-host","tailscale_tags":["tag:docker-host"],"systemd_dependencies":o["production"]["systemd_dependencies"],"lifecycle_marker_sha256":"a"*64,"compose_artifact_path":"/etc/home-lab/compose.yml","compose_artifact_sha256":"2"*64,"compose_image_lock_path":"/etc/home-lab/images.json","compose_image_lock_sha256":"3"*64,"compose_command":["/usr/bin/docker","compose"],"root_environment_path":"/etc/home-lab/compose.env","root_environment_sha256":"6"*64,"restic_recovery_receipt_path":"/etc/home-lab/restic-recovery.json","restic_recovery_receipt_sha256":"4"*64}),o
    o=base(); disk={"path":"/dev/disk/by-id/scsi-replacement","serial":"replacement-serial","size_bytes":2147483648,"stable_path":"/dev/disk/by-id/scsi-replacement","realpath":"/dev/sdc","block":True,"symlink":True,"signatures":[],"holders":[],"mounts":[],"device_number":"8:32"}; o["storage"]=[disk]
    yield "state-disk-initialization",request("state-disk-initialization","recovery",{"tofu_receipt_sha256":"6"*64,"path":disk["path"],"serial":disk["serial"],"size_bytes":disk["size_bytes"],"filesystem":"ext4","filesystem_uuid":"11111111-1111-4111-8111-111111111111","force":False}),o
    o=base("production"); o["tailscale"]={"backend_state":"Running","run_ssh":True,"tags":["tag:docker-host"]}; o["ssh"]={"conventional_key_paths_present":[],"pubkey_authentication":"no","permit_root_login":"no","host_key_fingerprint":"SHA256:test"}
    yield "ssh-tightening",request("ssh-tightening","production",{"access_cleanup_receipts":[{"kind":"legacy-marker-removal","sha256":"7"*64},{"kind":"conventional-key-removal","sha256":"8"*64},{"kind":"openssh-tightening","sha256":"9"*64}],"required_tailscale_tag":"tag:docker-host","host_key_fingerprint":"SHA256:test"}),o

def main():
  with tempfile.TemporaryDirectory(dir=ROOT/".local") as raw:
    root=Path(raw).resolve(); output=root/"plans"; output.mkdir(mode=0o700)
    generated={}
    evidence_by_op={}
    for entry in cases(NOW):
      op,req,obs,*secret=entry; evidence=evidence_for(op,req,root); evidence_by_op[op]=evidence
      if op=="production-activation": obs["production"]["restic_recovery_receipt_sha256"]=req["parameters"]["restic_recovery_receipt_sha256"]
      rp=root/f"{op}-request.json"; opath=root/f"{op}-observation.json"; write(rp,req); write(opath,obs)
      plan_path,digest,plan=module.make_plan(op,rp,opath,output,NOW,COMMIT,evidence)
      assert plan["blockers"]==["saved-reviewed-plan-required","separate-exact-authorization-required"] and plan["authorized"] is False and plan["automatic_apply"] is False, (op,plan["blockers"])
      secret_path=None
      if secret:
        secret_path=root/f"{op}.secret"; write(secret_path,secret[0])
      module.verify(op,plan_path,opath,secret_path,NOW,COMMIT,evidence); generated[op]=(req,obs,plan_path,secret_path)
    canary_plan=json.loads(generated["qualification-canary"][2].read_bytes()); assert canary_plan["bindings"]["inventory_sha256"]==module.sha(module.QUALIFICATION_INVENTORY.read_bytes())

    canary_req,canary_obs,_,_=generated["qualification-canary"]; missing=deepcopy(canary_obs); missing["production"]={}; rp=root/"canary-hostile-request.json"; current=root/"canary-hostile-observation.json"; write(rp,canary_req); write(current,missing); expect("missing canary unit observation","qualification canary production observation",lambda:module.make_plan("qualification-canary",rp,current,output,NOW,COMMIT,[]))
    op="state-disk-initialization"; req,obs,_,_=generated[op]
    drift=deepcopy(obs); drift["storage"][0]["serial"]="wrong"; rp=root/"drift-request.json"; current=root/"drift.json"; write(rp,req); write(current,drift)
    _,_,blocked=module.make_plan(op,rp,current,output,NOW,COMMIT,evidence_by_op[op]); assert "replacement-disk-not-exactly-blank" in blocked["blockers"]
    signed=deepcopy(obs); signed["storage"][0]["signatures"]=["old-fs"]; write(current,signed); _,_,blocked=module.make_plan(op,rp,current,output,NOW,COMMIT,evidence_by_op[op]); assert "replacement-disk-not-exactly-blank" in blocked["blockers"]
    forced=deepcopy(req); forced["parameters"]["force"]=True; write(rp,forced); write(current,obs); _,_,blocked=module.make_plan(op,rp,current,output,NOW,COMMIT,evidence_by_op[op]); assert "tofu-approved-force-false-disk-required" in blocked["blockers"]

    req,obs,_,_=generated["storage-activation"]; alias=deepcopy(obs); alias["storage"].append({**alias["storage"][0],"path":"/dev/disk/by-id/scsi-alias","stable_path":"/dev/disk/by-id/scsi-alias"}); req_alias=deepcopy(req); req_alias["parameters"]["devices"].append({**req_alias["parameters"]["devices"][0],"path":"/dev/disk/by-id/scsi-alias"}); write(rp,req_alias); write(current,alias); expect("alias receipt mismatch","storage attachment receipt",lambda:module.make_plan("storage-activation",rp,current,output,NOW,COMMIT,evidence_by_op["storage-activation"]))

    req,obs,_,secret=generated["identity-recovery"]; wrong=root/"wrong.secret"; write(wrong,b"wrong"); expect("wrong identity", "secret hash differs", lambda: module.verify("identity-recovery",generated["identity-recovery"][2],root/"identity-recovery-observation.json",wrong,NOW,COMMIT,evidence_by_op["identity-recovery"]))
    occupied=deepcopy(obs); occupied["identity"]={"exists":True,"recipient":"age1wrong"}; write(current,occupied); write(rp,req); _,_,blocked=module.make_plan("identity-recovery",rp,current,output,NOW,COMMIT,evidence_by_op["identity-recovery"]); assert "identity-target-must-be-absent" in blocked["blockers"]
    forged=root/"forged-recovery.json"; write(forged,{"format":"home-lab-age-recovery-receipt-v1","identity_sha256":req["parameters"]["identity_sha256"],"path":req["parameters"]["path"],"recipient":"age1wrong","target":"debian","version":1}); expect("forged recovery evidence","age recovery receipt",lambda:module.make_plan("identity-recovery",rp,root/"identity-recovery-observation.json",output,NOW,COMMIT,[forged]))
    hard_evidence=root/"hard-evidence.json"; os.link(evidence_by_op["identity-recovery"][0],hard_evidence); expect("hardlink evidence","dedicated regular file",lambda:module.verify("identity-recovery",generated["identity-recovery"][2],root/"identity-recovery-observation.json",secret,NOW,COMMIT,[hard_evidence])); hard_evidence.unlink()

    req,obs,_,_=generated["tailscale-enrollment"]; wrong_node=deepcopy(obs); wrong_node["tailscale"]={"backend_state":"Running","node_id":"wrong"}; write(rp,req); write(current,wrong_node); _,_,blocked=module.make_plan("tailscale-enrollment",rp,current,output,NOW,COMMIT,evidence_by_op["tailscale-enrollment"]); assert "tailscale-already-enrolled" in blocked["blockers"]
    expired=deepcopy(req); expired["parameters"]["auth_key_expires_at"]=module.now_text(NOW-timedelta(seconds=1)); write(rp,expired); write(current,obs); _,_,blocked=module.make_plan("tailscale-enrollment",rp,current,output,NOW,COMMIT,evidence_by_op["tailscale-enrollment"]); assert "fresh-auth-key-required" in blocked["blockers"]

    req,obs,_,_=generated["production-activation"]; wrong_recipient=deepcopy(obs); wrong_recipient["identity"]["recipient"]="age1wrong"; write(rp,req); write(current,wrong_recipient); _,_,blocked=module.make_plan("production-activation",rp,current,output,NOW,COMMIT,evidence_by_op["production-activation"]); assert "production-identity-drift" in blocked["blockers"]
    wrong_node=deepcopy(obs); wrong_node["tailscale"]["node_id"]=""; write(current,wrong_node); _,_,blocked=module.make_plan("production-activation",rp,current,output,NOW,COMMIT,evidence_by_op["production-activation"]); assert "tailscale-post-proof-required" in blocked["blockers"]

    req,obs,plan_path,secret=generated["identity-recovery"]
    expect("stale", "stale", lambda: module.load_plan(plan_path,"identity-recovery",NOW+timedelta(minutes=31),COMMIT))
    hard=root/"hard-plan.json"; os.link(plan_path,hard); expect("hardlink plan","dedicated regular file",lambda: module.load_plan(hard,"identity-recovery",NOW,COMMIT)); hard.unlink()
    sym=root/"symlink-plan.json"; sym.symlink_to(plan_path); expect("symlink plan","dedicated regular file",lambda: module.load_plan(sym,"identity-recovery",NOW,COMMIT))
    hard_secret=root/"hard.secret"; os.link(secret,hard_secret); expect("hardlink secret","dedicated regular file",lambda: module.verify("identity-recovery",plan_path,root/"identity-recovery-observation.json",hard_secret,NOW,COMMIT,evidence_by_op["identity-recovery"])); hard_secret.unlink()
    lock_obs=deepcopy(obs); lock_obs["locks"]=["active-lifecycle-lock"]; write(current,lock_obs); expect("active lock","precondition",lambda: module.verify("identity-recovery",plan_path,current,secret,NOW,COMMIT,evidence_by_op["identity-recovery"]))
    expect("production op inert route","operation and lifecycle execution profile route differs",lambda:module.execution_route("storage-activation","inert")); expect("canary recovery route","operation and lifecycle execution profile route differs",lambda:module.execution_route("qualification-canary","recovery"))
    canary_req,canary_obs,canary_plan,_=generated["qualification-canary"]; canary_digest=module.sha(canary_plan.read_bytes()); os.environ["DEBIAN_LIFECYCLE_TRANSACTION_CONFIRMED"]=module.exact_confirmation(json.loads(canary_plan.read_bytes()),canary_digest); captured=[]; original_controlled=module.run_controlled; module.run_controlled=lambda command: captured.append(command) or 0
    module.apply("qualification-canary",canary_plan,root/"qualification-canary-observation.json",None,NOW,COMMIT,[]); module.run_controlled=original_controlled; os.environ.pop("DEBIAN_LIFECYCLE_TRANSACTION_CONFIRMED",None); assert str(module.QUALIFICATION_INVENTORY) in captured[0] and TEST_POLICY["transaction"]["qualification_canary_inventory_host"] in captured[0]
    os.environ.pop("DEBIAN_LIFECYCLE_TRANSACTION_CONFIRMED",None)
    expect("unauthorized apply","exact confirmation",lambda: module.apply("identity-recovery",plan_path,root/"identity-recovery-observation.json",secret,NOW,COMMIT,evidence_by_op["identity-recovery"]))

    role=(ROOT/"ansible/roles/debian_lifecycle_transaction/tasks/main.yml").read_text(); host=(ROOT/"ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction").read_text()
    assert role.index("Run exactly one host-side lifecycle transaction") < role.index("Release the independent host-side lifecycle transaction lock after success only")
    assert 'run(["/usr/bin/tailscale","down"]' in host and "O_EXCL|os.O_NOFOLLOW" in host and "automatic retry forbidden" in host
    assert "verify_target(plan)" in host and "if result.returncode==0" in host and "os.unlink(HOST_LOCK)" in host and '"source_commit":plan["base_commit"]' in host
    controller=(ROOT/"scripts/controller/debian-lifecycle-transactions.py").read_text(); assert "start_new_session=True" in controller and 'cwd=ROOT / "ansible"' in controller and "os.killpg" in controller and "signal.SIGKILL" in controller
    observed_popen={}
    class FinishedProcess:
      def wait(self,timeout): return 0
    def fake_popen(command,**kwargs): observed_popen.update(kwargs); return FinishedProcess()
    original_popen=module.subprocess.Popen; module.subprocess.Popen=fake_popen; assert module.run_controlled(("noop",))==0; module.subprocess.Popen=original_popen; assert observed_popen["cwd"]==ROOT/"ansible" and observed_popen["start_new_session"] is True
    assert "mkfs.ext4" in host and "params[\"force\"] is not False" in host and "separate-access-cleanup-receipts-required" in (ROOT/"scripts/controller/debian-lifecycle-transactions.py").read_text()
  print("debian lifecycle transaction tests passed hostile_plans=22")
if __name__=="__main__": main()
