#!/usr/bin/env python3
"""Exercise the isolated PVE snippet helper and refusal paths."""
import base64,datetime as dt,fcntl,hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; TRANSPORT=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transport"; CONTROLLER=ROOT/"scripts/controller/debian-qualification-snippet.py"
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def call(env,*args,data=None): return subprocess.run([str(HELPER),*args],input=data,capture_output=True,env=env)
with tempfile.TemporaryDirectory() as directory:
 fixture=Path(directory); snippets=fixture/"var/lib/vz/snippets"; snippets.mkdir(parents=True); snippets.chmod(0o755)
 env={**os.environ,"HOME_LAB_QUALIFICATION_SNIPPET_FIXTURE_ROOT":str(fixture)}
 before=json.loads(call(env,"observe").stdout); assert before["snippet"]=={"exists":False}
 content=b"#cloud-config\nhostname: debian-lifecycle-qualification\n"
 now=dt.datetime.now(dt.timezone.utc)
 plan={"admission_sha256":"a"*64,"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical(before)),"commit":"b"*40,"content_b64":base64.b64encode(content).decode(),"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+dt.timedelta(minutes=10)).isoformat().replace("+00:00","Z"),"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","format":"home-lab-debian-qualification-snippet-plan-v1","guest_ssh_public_key_sha256":"c"*64,"known_hosts_sha256":"d"*64,"mode":"0600","node_name":"pve-qualification","operation":"create-snippet","sha256":sha(content),"size":len(content),"target_id":"isolated-pve-qualification","version":1}
 raw=canonical(plan); digest=sha(raw)
 assert call(env,"apply",digest,"0"*64,data=raw).returncode!=0
 result=call(env,"apply",digest,digest,data=raw); assert result.returncode==0,result.stderr; assert json.loads(result.stdout)["changed"] is True
 after=json.loads(call(env,"observe").stdout); assert after["snippet"]["sha256"]==sha(content) and after["snippet"]["mode"]=="0600"
 plan["before_sha256"]=sha(canonical(after)); raw=canonical(plan); digest=sha(raw); assert json.loads(call(env,"apply",digest,digest,data=raw).stdout)["changed"] is False
 stale=dict(plan,created_at=(now-dt.timedelta(hours=1)).isoformat().replace("+00:00","Z")); raw=canonical(stale); assert b"plan stale" in call(env,"apply",sha(raw),sha(raw),data=raw).stderr
 bad=dict(plan,content_b64=base64.b64encode(b"not-cloud-init").decode()); raw=canonical(bad); assert b"snippet content mismatch" in call(env,"apply",sha(raw),sha(raw),data=raw).stderr
 target=snippets/"home-lab-debian-lifecycle-qualification.yaml"; link=fixture/"linked"; os.link(target,link); assert b"unsafe snippet metadata" in call(env,"observe").stderr; link.unlink()
 lock_path=fixture/"run/lock/home-lab-debian-qualification-snippet.lock"; lock_path.parent.mkdir(parents=True,exist_ok=True); fd=os.open(lock_path,os.O_RDWR|os.O_CREAT,0o600); fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 raw=canonical(plan); digest=sha(raw); assert b"active snippet transaction lock" in call(env,"apply",digest,digest,data=raw).stderr; os.close(fd)
 source=TRANSPORT.read_text()
 for required in ("SSH_ORIGINAL_COMMAND", "sudo -n --", "unsupported qualification snippet command", '"$plan" = "$approval"', '"${#plan}" -eq 64'):
  assert required in source
 helper_source=HELPER.read_text(); controller_source=CONTROLLER.read_text()
 for required in ("os.O_NOFOLLOW", "os.fsync", "os.link", "LOCK_EX|fcntl.LOCK_NB", "plan stale", "snippet precondition drift"):
  assert required in helper_source
 for required in ("StrictHostKeyChecking=yes", "UpdateHostKeys=no", "IdentitiesOnly=yes", "RequestTTY=no", "validate-disposable-pve-target.js", "qualification SSH agent must contain exactly one key", "verify_exact_checkout", "acquire_transfer_lock", "DEBIAN_QUALIFICATION_SNIPPET_CONFIRMED", "expected_content=render(public)", "snippet plan binding mismatch"):
  assert required in controller_source
print("debian_qualification_snippet_transaction=verified create_noop_refusals=true")
