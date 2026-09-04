#!/usr/bin/env python3
"""Guarded saved-plan controller for the stopped disposable Debian foundation."""
import argparse,datetime as dt,hashlib,json,os,re,select,shutil,signal,stat,subprocess,tempfile,time
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; TF_ROOT=ROOT/"infrastructure/tofu/debian-lifecycle-qualification"; ADMISSION=ROOT/"scripts/controller/validate-disposable-pve-target.js"; SNIPPET=ROOT/"scripts/controller/debian-qualification-snippet.py"; CONFIRM="CREATE_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900"; EMPTY_SHA=hashlib.sha256(b"").hexdigest()
os.umask(0o077)
def fail(message): raise SystemExit(f"debian_qualification=failed reason={message}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def parse_time(value):
 try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("manifest-time")
 if parsed.tzinfo is None: fail("manifest-time")
 return parsed
def run_json(command,env=None):
 result=subprocess.run(command,capture_output=True,env=env)
 if result.returncode or result.stderr: fail("controlled-command")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError: fail("controlled-json")
 return value
def admission(args):
 value=run_json(["node",str(ADMISSION),"--evidence",str(args.admission),"--known-hosts",str(args.known_hosts)])
 if value.get("admitted") is not True or value.get("snippet_content_enabled") is not True: fail("target-not-admitted")
 return value
def snippet(args):
 value=run_json([str(SNIPPET),"verify","--admission",str(args.admission),"--known-hosts",str(args.known_hosts),"--guest-public-key",str(args.guest_public_key),"--receipt",str(args.snippet_receipt)])
 if value.get("snippet_file_id")!="local:snippets/home-lab-debian-lifecycle-qualification.yaml": fail("snippet-not-verified")
 return value
def credential(kind,target):
 directory=Path(os.environ.get("HOME_LAB_CONTROLLER_CONFIG_DIR",Path.home()/".config/home-lab/controller")); path=directory/f"{kind}-credentials.json"; raw=load_protected_bytes(path,f"production PVE {kind} credentials")
 try: source=json.loads(raw)
 except json.JSONDecodeError: fail("credential-structure")
 token_key="PROXMOX_PLAN_API_TOKEN" if kind=="plan" else "PROXMOX_APPLY_API_TOKEN"; expected=target[f"{kind}_principal"]; token=source.get(token_key,""); ca=source.get("PROXMOX_CA_PEM",""); endpoint=source.get("TF_VAR_proxmox_endpoint","")
 if not isinstance(token,str) or not isinstance(ca,str) or not isinstance(endpoint,str) or len(token)>1024 or len(ca)>65536: fail("credential-structure")
 if endpoint!=target["endpoint"] or sha(ca.encode())!=target["api_ca_sha256"]: fail("credential-binding")
 if not token.startswith(expected+"=") or len(token)<=len(expected)+16: fail("credential-principal")
 return {"api_token":token,"ca_pem":ca,"endpoint":endpoint,"principal":expected,"purpose":kind}
def environment(values,output,ca_path):
 data={"HOME":os.environ["HOME"],"PATH":os.environ["PATH"],"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","SSL_CERT_FILE":str(ca_path),"TF_DATA_DIR":str(output/"tf-data"),"PROXMOX_VE_API_TOKEN":values["api_token"]}
 for key in data:
  if "PRODUCTION" in key or "PROXMOX_PLAN" in key or "PROXMOX_APPLY" in key: fail("unsafe-provider-environment")
 return data
def guest_key(path,target):
 raw=load_protected_bytes(path,"qualification guest public key")
 try: line=raw.decode("ascii").removesuffix("\n")
 except UnicodeDecodeError: fail("guest-key")
 if raw!=line.encode()+b"\n" or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2} qualification-[a-z0-9-]+",line) is None or sha(line.encode())!=target["guest_ssh_public_key_sha256"]: fail("guest-key")
 return line
def revision(expected=None):
 commit=subprocess.run(["git","rev-parse","HEAD"],text=True,capture_output=True,check=True).stdout.strip(); verify_exact_checkout("git",expected or commit,os.environ.copy()); return commit
def state_sha(path): return sha(load_protected_bytes(path,"qualification state")) if path.exists() else EMPTY_SHA
def write_private(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 try:
  with os.fdopen(fd,"wb",closefd=False) as output:
   if output.write(raw)!=len(raw): fail("protected-short-write")
   output.flush(); os.fsync(fd)
 finally: os.close(fd)
def tofu_setup(output,credentials):
 data=output/"tf-data"
 if data.exists():
  item=data.lstat()
  if data.is_symlink() or not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700: fail("tf-data-metadata")
 else: data.mkdir(mode=0o700)
 run=Path(tempfile.mkdtemp(prefix="tofu-run-",dir=output)); os.chmod(run,0o700); ca=run/"ca.pem"; write_private(ca,credentials["ca_pem"].encode())
 env=environment(credentials,output,ca); state=output/"state.tfstate"; init_env=dict(env); init_env.pop("SSL_CERT_FILE")
 result=subprocess.run(["tofu",f"-chdir={TF_ROOT}","init","-reconfigure","-input=false",f"-backend-config=path={state}"],env=init_env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 if result.returncode: shutil.rmtree(run); fail("tofu-init")
 return run,env,state
def variables(target,key):
 return ["-var=enable_qualification=true",f"-var=proxmox_endpoint={target['endpoint']}",f"-var=qualification_ssh_public_key={key}",f"-var=qualification_ssh_public_key_sha256={target['guest_ssh_public_key_sha256']}",f"-var=controller_ipv4={target['controller_ipv4']}",f"-var=qualification_node_name={target['node_name']}",f"-var=qualification_image_datastore_id={target['image_datastore_id']}",f"-var=qualification_disk_datastore_id={target['disk_datastore_id']}",f"-var=qualification_bridge={target['bridge']}",f"-var=qualification_cloud_init_file_id={target['snippet_file_id']}",f"-var=isolation_attestation_sha256={target['isolation_attestation_sha256']}"]
def contract_image():
 script='const fs=require("fs"),yaml=require("js-yaml");const c=yaml.load(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify(c.debian.image))'
 result=subprocess.run(["node","-e",script,str(ROOT/"infrastructure/contract/home-lab.yml")],cwd=ROOT,text=True,capture_output=True)
 if result.returncode or result.stderr: fail("contract-projection")
 try: return json.loads(result.stdout)
 except json.JSONDecodeError: fail("contract-projection")
def inspect_plan(value,target):
 expected={"proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_vm.qualification[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]"}; changes={item.get("address"):item.get("change",{}) for item in value.get("resource_changes",[])}
 if set(changes)!=expected or any(item.get("actions")!=["create"] for item in changes.values()): fail("foundation-actions")
 after={key:item.get("after",{}) for key,item in changes.items()}; vm=after["proxmox_virtual_environment_vm.qualification[0]"]; image=after["proxmox_download_file.qualification_image[0]"]; options=after["proxmox_virtual_environment_firewall_options.qualification[0]"]; rules=after["proxmox_virtual_environment_firewall_rules.qualification[0]"].get("rule",[])
 disks=vm.get("disk",[]); initialization=vm.get("initialization",[]); networks=vm.get("network_device",[])
 if vm.get("vm_id")!=9900 or vm.get("node_name")!=target["node_name"] or vm.get("started") is not False or vm.get("on_boot") is not False or vm.get("protection") is not False or vm.get("reboot_after_update") is not False or vm.get("boot_order")!=["scsi0"] or len(disks)!=1 or disks[0].get("datastore_id")!=target["disk_datastore_id"] or disks[0].get("interface")!="scsi0" or disks[0].get("serial")!="DEB-LIFE-ROOT-32G" or disks[0].get("size")!=32 or len(initialization)!=1 or initialization[0].get("datastore_id")!=target["disk_datastore_id"] or initialization[0].get("user_data_file_id")!=target["snippet_file_id"] or initialization[0].get("upgrade") is not False or initialization[0].get("dns",[{}])[0].get("servers")!=["1.1.1.1","9.9.9.9"] or len(networks)!=1 or networks[0].get("bridge")!=target["bridge"] or networks[0].get("firewall") is not True: fail("foundation-vm")
 contract=contract_image()
 if image.get("datastore_id")!=target["image_datastore_id"] or image.get("node_name")!=target["node_name"] or image.get("url")!=contract["url"] or image.get("checksum")!=contract["sha512"] or image.get("checksum_algorithm")!="sha512" or image.get("overwrite") is not False: fail("foundation-image")
 if options.get("enabled") is not True or options.get("input_policy")!="DROP" or options.get("output_policy")!="DROP" or options.get("dhcp") is not True or options.get("ipfilter") is not False or options.get("macfilter") is not True: fail("foundation-firewall")
 expected_rules=[("in","ACCEPT",None,f"{target['controller_ipv4']}/32","tcp","22",None),("out","ACCEPT",f"{target['controller_ipv4']}/32",None,"tcp","1024:65535","22"),("out","DROP","10.0.0.0/8",None,None,None,None),("out","DROP","172.16.0.0/12",None,None,None,None),("out","DROP","192.168.0.0/16",None,None,None,None),("out","DROP","100.64.0.0/10",None,None,None,None),("out","ACCEPT","0.0.0.0/0",None,None,None,None)]
 observed_rules=[(item.get("type"),item.get("action"),item.get("dest"),item.get("source"),item.get("proto"),item.get("dport"),item.get("sport")) for item in rules]
 if observed_rules!=expected_rules: fail("foundation-firewall-rules")
 return sorted(expected)
def ssh_args(target,args,command): return ["ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no","-o",f"UserKnownHostsFile={args.known_hosts}","-o","IdentitiesOnly=yes","-o","IdentityFile=none","-o","PreferredAuthentications=none","-o","PubkeyAuthentication=no","-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","RequestTTY=no",f'{target["ssh_username"]}@{target["ssh_address"]}',command]
def hold_target(target,args):
 child=subprocess.Popen(ssh_args(target,args,f"hold-lock {target['isolation_attestation_sha256']}"),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 ready,_,_=select.select([child.stdout,child.stderr],[],[],10)
 if not ready or child.stderr in ready: child.kill(); child.wait(); fail("target-lock-timeout")
 try: value=json.loads(child.stdout.readline())
 except json.JSONDecodeError: child.kill(); child.wait(); fail("target-lock-response")
 if child.poll() is not None or value!={"admission_sha256":target["isolation_attestation_sha256"],"format":"home-lab-disposable-qualification-lock-v1","held":True}: child.kill(); child.wait(); fail("target-lock-response")
 return child
def release_target(child):
 child.stdin.close()
 try: code=child.wait(timeout=10)
 except subprocess.TimeoutExpired: child.kill(); child.wait(); fail("target-lock-release")
 if code!=0 or child.stderr.read(): fail("target-lock-release")
def run_locked(command,env,host,failure):
 child=subprocess.Popen(command,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 def terminate():
  if child.poll() is None:
   try: os.killpg(child.pid,signal.SIGTERM)
   except ProcessLookupError: pass
   try: child.wait(timeout=10)
   except subprocess.TimeoutExpired:
    try: os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    child.wait()
 def interrupted(signum,frame):
  del signum,frame
  raise InterruptedError("controller interrupted")
 previous={item:signal.getsignal(item) for item in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
 try:
  for item in previous: signal.signal(item,interrupted)
  while child.poll() is None:
   if host.poll() is not None: fail("target-lock-lost")
   time.sleep(0.2)
  if child.returncode: fail(failure)
 except BaseException:
  terminate()
  raise
 finally:
  terminate()
  for item,handler in previous.items(): signal.signal(item,handler)
def locked_setup(output,credentials,target,args):
 controller=acquire_transfer_lock(output/"lifecycle.lock")
 try: run,env,state=tofu_setup(output,credentials)
 except BaseException: os.close(controller); raise
 try: host=hold_target(target,args)
 except BaseException: shutil.rmtree(run,ignore_errors=True); os.close(controller); raise
 return controller,run,env,state,host
def plan(args):
 output=require_private_root(args.output_dir,()); target=admission(args); verified=snippet(args)
 if any(target.get(key)!=verified.get(key) for key in ("isolation_attestation_sha256","target_id","node_name","endpoint")): fail("snippet-target-binding")
 key=guest_key(args.guest_public_key,target); commit=revision(); credentials=credential("plan",target); controller,run,env,state,host=locked_setup(output,credentials,target,args)
 try:
  fresh=snippet(args)
  if fresh.get("snippet_receipt_sha256")!=verified.get("snippet_receipt_sha256"): fail("snippet-drift")
  if state_sha(state)!=EMPTY_SHA: fail("foundation-state-not-empty")
  binary=run/"foundation.tfplan"; shown=run/"foundation.json"
  run_locked(["tofu",f"-chdir={TF_ROOT}","plan","-input=false","-lock=true",*variables(target,key),"-out",str(binary)],env,host,"tofu-plan")
  with shown.open("wb") as stream:
   result=subprocess.run(["tofu",f"-chdir={TF_ROOT}","show","-json",str(binary)],env=env,stdout=stream,stderr=subprocess.PIPE)
  if result.returncode: fail("tofu-show")
  plan_json=json.loads(shown.read_text()); resources=inspect_plan(plan_json,target); plan_sha=sha(binary.read_bytes()); json_sha=sha(shown.read_bytes()); os.chmod(binary,0o600); os.chmod(shown,0o600)
  final_binary=output/f"{plan_sha}.tfplan"; final_json=output/f"{plan_sha}.plan.json"
  os.link(binary,final_binary,follow_symlinks=False); os.unlink(binary); os.link(shown,final_json,follow_symlinks=False); os.unlink(shown); directory=os.open(output,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
  created=now(); manifest={"actionable":True,"admission_sha256":target["isolation_attestation_sha256"],"api_ca_sha256":target["api_ca_sha256"],"apply_principal":target["apply_principal"],"authorized":False,"automatic_apply":False,"commit":commit,"created_at":created.isoformat().replace("+00:00","Z"),"endpoint":target["endpoint"],"expires_at":(created+dt.timedelta(minutes=20)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-foundation-plan-v1","node_name":target["node_name"],"operation":"create-stopped-foundation","plan_json_sha256":json_sha,"plan_principal":target["plan_principal"],"plan_sha256":plan_sha,"resources":resources,"snippet_receipt_sha256":verified["snippet_receipt_sha256"],"state_sha256":EMPTY_SHA,"target_id":target["target_id"],"version":1,"vmid":9900}
  manifest_sha=sha(canonical_bytes(manifest)+b"\n"); write_json(output,f"{manifest_sha}.manifest.json",manifest); print(json.dumps({"actionable":True,"authorization_sha256":manifest_sha,"authorized":False,"manifest":str(output/f'{manifest_sha}.manifest.json'),"plan_sha256":plan_sha},sort_keys=True))
 finally: release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def apply(args):
 if re.fullmatch(r"[0-9a-f]{64}",args.plan_sha or "") is None or re.fullmatch(r"[0-9a-f]{64}",args.authorization_sha or "") is None or args.approve_plan_sha!=args.plan_sha or args.approve_authorization_sha!=args.authorization_sha or args.confirm!=CONFIRM: fail("exact-authorization-required")
 output=require_private_root(args.output_dir,()); manifest,manifest_raw=load_canonical_object(args.manifest,"qualification foundation manifest")
 required={"actionable","admission_sha256","api_ca_sha256","apply_principal","authorized","automatic_apply","commit","created_at","endpoint","expires_at","format","node_name","operation","plan_json_sha256","plan_principal","plan_sha256","resources","snippet_receipt_sha256","state_sha256","target_id","version","vmid"}
 created=parse_time(manifest.get("created_at","")); expires=parse_time(manifest.get("expires_at",""))
 identities=("admission_sha256","api_ca_sha256","plan_json_sha256","plan_sha256","snippet_receipt_sha256","state_sha256")
 expected_resources=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
 if set(manifest)!=required or any(re.fullmatch(r"[0-9a-f]{64}",manifest.get(key,"") or "") is None for key in identities) or sha(manifest_raw)!=args.authorization_sha or manifest.get("plan_sha256")!=args.plan_sha or manifest.get("format")!="home-lab-debian-qualification-foundation-plan-v1" or manifest.get("version")!=1 or manifest.get("vmid")!=9900 or manifest.get("resources")!=expected_resources or manifest.get("actionable") is not True or manifest.get("authorized") is not False or manifest.get("automatic_apply") is not False or manifest.get("operation")!="create-stopped-foundation" or created>now()+dt.timedelta(seconds=5) or created<now()-dt.timedelta(minutes=20) or expires<=now() or expires-created>dt.timedelta(minutes=20): fail("manifest-binding")
 revision(manifest.get("commit")); target=admission(args); verified=snippet(args)
 if manifest.get("admission_sha256")!=target["isolation_attestation_sha256"] or manifest.get("snippet_receipt_sha256")!=verified["snippet_receipt_sha256"] or manifest.get("target_id")!=target["target_id"] or manifest.get("endpoint")!=target["endpoint"] or manifest.get("node_name")!=target["node_name"] or manifest.get("api_ca_sha256")!=target["api_ca_sha256"] or manifest.get("plan_principal")!=target["plan_principal"] or manifest.get("apply_principal")!=target["apply_principal"]: fail("current-binding")
 credentials=credential("apply",target); binary=output/f"{args.plan_sha}.tfplan"; shown=output/f"{args.plan_sha}.plan.json"
 if sha(load_protected_bytes(binary,"qualification saved plan"))!=args.plan_sha or sha(load_protected_bytes(shown,"qualification plan JSON"))!=manifest.get("plan_json_sha256"): fail("saved-plan-binding")
 inspect_plan(json.loads(load_protected_bytes(shown,"qualification plan JSON")),target); controller,run,env,state,host=locked_setup(output,credentials,target,args)
 try:
  fresh=snippet(args)
  if fresh.get("snippet_receipt_sha256")!=verified.get("snippet_receipt_sha256"): fail("snippet-drift")
  if state_sha(state)!=manifest.get("state_sha256"): fail("state-drift")
  run_locked(["tofu",f"-chdir={TF_ROOT}","apply","-input=false","-lock=true","-auto-approve",str(binary)],env,host,"tofu-apply-no-retry")
  post=run_json(["tofu",f"-chdir={TF_ROOT}","show","-json"],env); resources=post.get("values",{}).get("root_module",{}).get("resources",[])
  addresses={item.get("address") for item in resources}; expected=set(manifest["resources"])
  vm=next((item.get("values",{}) for item in resources if item.get("address")=="proxmox_virtual_environment_vm.qualification[0]"),{})
  if addresses!=expected or vm.get("vm_id")!=9900 or vm.get("started") is not False or vm.get("on_boot") is not False: fail("postcondition")
  receipt={"admission_sha256":target["isolation_attestation_sha256"],"commit":manifest["commit"],"format":"home-lab-debian-qualification-foundation-receipt-v1","operation":"create-stopped-foundation","plan_sha256":args.plan_sha,"resources":sorted(addresses),"snippet_receipt_sha256":verified["snippet_receipt_sha256"],"state_sha256":state_sha(state),"target_id":target["target_id"],"version":1,"vm_started":False,"vmid":9900}
  write_json(output,f"{args.plan_sha}.receipt.json",receipt); print(json.dumps({"receipt":str(output/f'{args.plan_sha}.receipt.json'),"vm_started":False},sort_keys=True))
 finally: release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name)
  for option in ("admission","known-hosts","guest-public-key","snippet-receipt","output-dir"): item.add_argument("--"+option,type=Path,required=True)
  if name=="apply": item.add_argument("--manifest",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--authorization-sha",required=True); item.add_argument("--approve-authorization-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path): setattr(args,key,value.resolve())
 apply(args) if args.command=="apply" else plan(args)
if __name__=="__main__": main()
