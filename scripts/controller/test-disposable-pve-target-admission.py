#!/usr/bin/env python3
"""Hostile-path tests for disposable PVE target admission."""
import copy,datetime as dt,hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
VALIDATOR=ROOT/"scripts/controller/validate-disposable-pve-target.js"
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def run(evidence,known,safe_stop=False): return subprocess.run(["node",str(VALIDATOR),"--evidence",str(evidence),"--known-hosts",str(known),*(["--allow-expired-safe-stop"] if safe_stop else [])],text=True,capture_output=True)
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); key=root/"host-key"
 subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(key)],check=True)
 public=key.with_suffix(".pub").read_text().split()
 known=root/"known_hosts"; known.write_text(f"proxmox {public[0]} {public[1]}\n"); known.chmod(0o600)
 fingerprint=subprocess.check_output(["ssh-keygen","-E","sha256","-lf",str(known)],text=True).split()[1]
 now=dt.datetime.now(dt.timezone.utc)
 value={
  "api_ca_sha256":"e"*64,
  "console":{"kind":"physical","verified":True},
  "credentials":{"apply_principal":"root@pam!tofu-apply","guest_ssh_public_key_sha256":"0"*64,"plan_principal":"root@pam!tofu-plan","production_credentials_absent":False,"separate_principals":True,"ssh_authentication":"tailscale-policy","ssh_principal":"qualification-apply"},
  "endpoint":"https://proxmox:8006/api2/json",
  "expires_at":(now+dt.timedelta(minutes=15)).isoformat().replace("+00:00","Z"),
  "format":"home-lab-disposable-pve-target-admission-v1",
  "host_key":{"algorithm":"ssh-ed25519","fingerprint":fingerprint,"known_hosts_sha256":hashlib.sha256(known.read_bytes()).hexdigest(),"out_of_band_verified":True,"ssh_address":"proxmox"},
  "locks":[],"network":{"bridge":"vmbr0","can_reach_production_pve":False,"can_reach_production_state":False,"can_reach_vm100":False,"controller_ipv4":"198.51.100.12","production_cidrs_denied":["10.0.0.0/8","100.64.0.0/10","172.16.0.0/12","192.168.0.0/16"],"public_package_egress":True},
  "node_name":"proxmox","observed_at":now.isoformat().replace("+00:00","Z"),
  "official_pve":{"package_origin_verified":True,"version":"9.0"},
  "route":"production-pve-disposable-vm",
  "storage":{"disk_datastore_id":"local-lvm","image_datastore_id":"local","production_identifiers_absent":True,"shares_production_storage":True,"snippet_content_enabled":True,"snippet_datastore_id":"local","snippet_directory":"/var/lib/vz/snippets","synthetic_only":True},
  "target_id":"production-pve-vm9900-qualification","version":1,
 }
 evidence=root/"admission.json"; evidence.write_bytes(canonical(value)); evidence.chmod(0o600)
 result=run(evidence,known); assert result.returncode==0,result.stderr
 output=json.loads(result.stdout); assert output["admitted"] is True and output["isolation_attestation_sha256"]==hashlib.sha256(evidence.read_bytes()).hexdigest()
 def refused(name,mutate,expected):
  candidate=copy.deepcopy(value); mutate(candidate); p=root/f"{name}.json"; p.write_bytes(canonical(candidate)); p.chmod(0o600); r=run(p,known); assert r.returncode!=0,name; assert expected in r.stderr,(name,r.stderr)
 refused("wrong-endpoint",lambda x:x.update(endpoint="https://pve-qualification.invalid:8006/api2/json"),"target binding mismatch")
 refused("unshared-storage",lambda x:x["storage"].update(shares_production_storage=False),"schema violation")
 refused("same-principal",lambda x:x["credentials"].update(apply_principal=x["credentials"]["plan_principal"]),"shared-hypervisor route")
 refused("wrong-ssh",lambda x:x["credentials"].update(ssh_principal="ansible-deploy"),"schema violation")
 refused("wrong-ssh-auth",lambda x:x["credentials"].update(ssh_authentication="authorized-key"),"schema violation")
 refused("stale",lambda x:x.update(observed_at=(now-dt.timedelta(hours=1)).isoformat().replace("+00:00","Z")),"stale")
 expired=copy.deepcopy(value); expired["observed_at"]=(now-dt.timedelta(minutes=60)).isoformat().replace("+00:00","Z"); expired["expires_at"]=(now-dt.timedelta(minutes=45)).isoformat().replace("+00:00","Z"); expired_path=root/"expired.json"; expired_path.write_bytes(canonical(expired)); expired_path.chmod(0o600); assert run(expired_path,known).returncode!=0; recovered=run(expired_path,known,True); assert recovered.returncode==0,recovered.stderr; assert json.loads(recovered.stdout)["admission_mode"]=="expired-safe-stop"
 too_old=copy.deepcopy(expired); too_old["observed_at"]=(now-dt.timedelta(hours=6)).isoformat().replace("+00:00","Z"); too_old["expires_at"]=(now-dt.timedelta(hours=5,minutes=45)).isoformat().replace("+00:00","Z"); too_old_path=root/"too-old.json"; too_old_path.write_bytes(canonical(too_old)); too_old_path.chmod(0o600); assert run(too_old_path,known,True).returncode!=0
 noncanonical=root/"noncanonical.json"; noncanonical.write_text(json.dumps(value,indent=2)); noncanonical.chmod(0o600); assert "canonical JSON" in run(noncanonical,known).stderr
 unsafe=root/"unsafe.json"; unsafe.write_bytes(canonical(value)); unsafe.chmod(0o644); assert "unsafe protected artifact metadata" in run(unsafe,known).stderr
 hardlink=root/"hardlink.json"; os.link(evidence,hardlink); assert "unsafe protected artifact metadata" in run(evidence,known).stderr; hardlink.unlink()
 symlink=root/"symlink.json"; symlink.symlink_to(evidence); assert "unsafe protected artifact metadata" in run(symlink,known).stderr
 bad_known=root/"bad-known-hosts"; bad_known.write_text(known.read_text().replace("proxmox","wrong.invalid")); bad_known.chmod(0o600); assert "digest mismatch" in run(evidence,bad_known).stderr
print("disposable_pve_target_admission=verified hostile_paths=12 expired_safe_stop_bounded=true")
