#!/usr/bin/env python3
"""Exercise the isolated PVE snippet helper and refusal paths."""
import base64,contextlib,datetime as dt,fcntl,hashlib,importlib.util,io,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; TRANSPORT=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transport"; CONTROLLER=ROOT/"scripts/controller/debian-qualification-snippet.py"
spec=importlib.util.spec_from_file_location("snippet_controller",CONTROLLER); controller=importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
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
 replacement=b"#cloud-config\nhostname: debian-lifecycle-qualification\nmanage_etc_hosts: true\n"; plan=dict(plan,before_sha256=sha(canonical(after)),content_b64=base64.b64encode(replacement).decode(),operation="replace-snippet",sha256=sha(replacement),size=len(replacement)); raw=canonical(plan); digest=sha(raw); result=call(env,"apply",digest,digest,data=raw); assert result.returncode==0,result.stderr; assert json.loads(result.stdout)["changed"] is True
 after=json.loads(call(env,"observe").stdout); assert after["snippet"]["sha256"]==sha(replacement); rollback_content=b"#cloud-config\nhostname: should-rollback\n"; rollback_plan=dict(plan,before_sha256=sha(canonical(after)),content_b64=base64.b64encode(rollback_content).decode(),operation="replace-snippet",sha256=sha(rollback_content),size=len(rollback_content)); raw=canonical(rollback_plan); digest=sha(raw); injected={**env,"HOME_LAB_QUALIFICATION_SNIPPET_INJECT_REPLACEMENT_FAILURE":"1"}; failed=call(injected,"apply",digest,digest,data=raw); assert failed.returncode!=0 and b"injected replacement" in failed.stderr; after=json.loads(call(env,"observe").stdout); assert after["snippet"]["sha256"]==sha(replacement); plan=dict(plan,before_sha256=sha(canonical(after)),operation="create-snippet"); raw=canonical(plan); digest=sha(raw); assert json.loads(call(env,"apply",digest,digest,data=raw).stdout)["changed"] is False
 stale=dict(plan,created_at=(now-dt.timedelta(hours=1)).isoformat().replace("+00:00","Z")); raw=canonical(stale); assert b"plan stale" in call(env,"apply",sha(raw),sha(raw),data=raw).stderr
 bad=dict(plan,content_b64=base64.b64encode(b"not-cloud-init").decode()); raw=canonical(bad); assert b"snippet content mismatch" in call(env,"apply",sha(raw),sha(raw),data=raw).stderr
 target=snippets/"home-lab-debian-lifecycle-qualification.yaml"; link=fixture/"linked"; os.link(target,link); assert b"unsafe snippet metadata" in call(env,"observe").stderr; link.unlink()
 lock_path=fixture/"run/lock/home-lab-disposable-qualification.lock"; lock_path.parent.mkdir(parents=True,exist_ok=True); fd=os.open(lock_path,os.O_RDWR|os.O_CREAT,0o600); fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 raw=canonical(plan); digest=sha(raw); assert b"active qualification transaction lock" in call(env,"apply",digest,digest,data=raw).stderr; os.close(fd)
 holder=subprocess.Popen([str(HELPER),"hold-lock","a"*64],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
 assert json.loads(holder.stdout.readline())["held"] is True
 assert b"active qualification transaction lock" in call(env,"apply",digest,digest,data=raw).stderr
 holder.stdin.close(); assert holder.wait(timeout=5)==0
 known=fixture/"known_hosts"; known.write_text("proxmox ssh-ed25519 AAAA\n"); known.chmod(0o600)
 ssh=controller.ssh_args({"ssh_username":"qualification-apply","ssh_address":"proxmox"},known,"observe"); effective=subprocess.check_output([ssh[0],"-G",*ssh[1:]],text=True,stderr=subprocess.DEVNULL).lower()
 for setting in ("globalknownhostsfile /dev/null",f"userknownhostsfile {known}".lower(),"identityagent none","identityfile none","identitiesonly yes","preferredauthentications none","pubkeyauthentication false","passwordauthentication no","kbdinteractiveauthentication no"):
  assert setting in effective,setting
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory); known=root/"known_hosts"; known.write_text("proxmox ssh-ed25519 AAAA\n"); known.chmod(0o600); receipt_path=root/"observation.json"; target={"isolation_attestation_sha256":"a"*64,"node_name":"proxmox","target_id":"production-pve-vm9900-qualification"}; public="ssh-ed25519 "+"A"*44+" qualification-test"; content=b"#cloud-config\n"; current={"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","snippet":{"exists":True,"gid":0,"mode":"0600","nlink":1,"sha256":sha(content),"size":len(content),"uid":0}}; receipt={"admission_sha256":"a"*64,"commit":"b"*40,"file_id":current["file_id"],"format":"home-lab-debian-qualification-snippet-observation-receipt-v1","guest_ssh_public_key_sha256":sha(public.encode()),"known_hosts_sha256":sha(known.read_bytes()),"mode":"0600","node_name":"proxmox","observation_sha256":sha(canonical(current)),"sha256":sha(content),"size":len(content),"target_id":target["target_id"],"version":1}; receipt_path.write_bytes(canonical(receipt)); receipt_path.chmod(0o600); args=type("Args",(),{"admission":root/"unused","known_hosts":known,"guest_public_key":root/"unused-key","receipt":receipt_path})(); originals=(controller.validate_target,controller.guest_key,controller.render,controller.remote); controller.validate_target=lambda a,k:target; controller.guest_key=lambda p,t:public; controller.render=lambda p:content; controller.remote=lambda t,k,c:current
 try:
  with contextlib.redirect_stdout(io.StringIO()): controller.verify(args)
  forged=dict(receipt,observation_sha256="0"*64); receipt_path.write_bytes(canonical(forged))
  try: controller.verify(args); raise AssertionError("forged observation accepted")
  except SystemExit as error: assert "observation receipt drift" in str(error)
 finally: controller.validate_target,controller.guest_key,controller.render,controller.remote=originals
 source=TRANSPORT.read_text()
 for required in ("SSH_ORIGINAL_COMMAND", '"$#" -eq 2', '"$1" = -c', "sudo -n --", "hold-lock", "first-boot", "diagnostic", "unsupported qualification snippet command", '"$plan" = "$approval"', '"${#plan}" -eq 64'):
  assert required in source
 helper_source=HELPER.read_text(); controller_source=CONTROLLER.read_text()
 for required in ('return "/var/lib/vz/snippets","/run/lock/home-lab-disposable-qualification.lock"', "os.O_NOFOLLOW", "os.fsync", "os.link", "os.replace", "snippet replacement rollback failed", "def first_boot", "apply_diagnostic", "read_first_boot_diagnostic", "short diagnostic read", "cloud-init", "LOCK_EX|fcntl.LOCK_NB", "plan stale", "snippet precondition drift"):
  assert required in helper_source
 for required in ("StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no", "IdentitiesOnly=yes", "IdentityFile=none", "PreferredAuthentications=none", "PubkeyAuthentication=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "RequestTTY=no", "validate-disposable-pve-target.js", "tailscale-policy", "verify_exact_checkout", "acquire_transfer_lock", "PRODUCTION_PVE_VM9900_SNIPPET_CONFIRMED", "expected_content=render(public)", "replace-snippet", "snippet plan binding mismatch", "observe-receipt", "snippet-observation-receipt-v1", "snippet observation receipt drift"):
  assert required in controller_source
print("debian_qualification_snippet_transaction=verified create_replace_noop_refusals=true")
