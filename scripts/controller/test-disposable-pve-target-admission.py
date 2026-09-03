#!/usr/bin/env python3
"""Hostile-path tests for disposable PVE target admission."""
import copy,datetime as dt,hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
VALIDATOR=ROOT/"scripts/controller/validate-disposable-pve-target.js"
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def run(evidence,known): return subprocess.run(["node",str(VALIDATOR),"--evidence",str(evidence),"--known-hosts",str(known)],text=True,capture_output=True)
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); key=root/"host-key"
 subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(key)],check=True)
 public=key.with_suffix(".pub").read_text().split()
 known=root/"known_hosts"; known.write_text(f"pve-qualification.invalid {public[0]} {public[1]}\n"); known.chmod(0o600)
 fingerprint=subprocess.check_output(["ssh-keygen","-E","sha256","-lf",str(known)],text=True).split()[1]
 now=dt.datetime.now(dt.timezone.utc)
 value={
  "console":{"kind":"isolated-hypervisor-console","verified":True},
  "credentials":{"apply_principal":"qualification@pve!apply","guest_ssh_public_key_sha256":"0"*64,"plan_principal":"qualification@pve!plan","production_credentials_absent":True,"separate_principals":True,"ssh_agent_key_count":1,"ssh_agent_public_key_sha256":hashlib.sha256(f"{public[0]} {public[1]}".encode()).hexdigest(),"ssh_principal":"qualification-apply"},
  "endpoint":"https://pve-qualification.invalid:8006/api2/json",
  "expires_at":(now+dt.timedelta(minutes=15)).isoformat().replace("+00:00","Z"),
  "format":"home-lab-disposable-pve-target-admission-v1",
  "host_key":{"algorithm":"ssh-ed25519","fingerprint":fingerprint,"known_hosts_sha256":hashlib.sha256(known.read_bytes()).hexdigest(),"out_of_band_verified":True,"ssh_address":"pve-qualification.invalid"},
  "locks":[],"network":{"bridge":"vmbr-qualification","can_reach_production_pve":False,"can_reach_production_state":False,"can_reach_vm100":False,"controller_ipv4":"198.51.100.12","production_cidrs_denied":["10.0.0.0/8","100.64.0.0/10","172.16.0.0/12","192.168.0.0/16"],"public_package_egress":True},
  "node_name":"pve-qualification","observed_at":now.isoformat().replace("+00:00","Z"),
  "official_pve":{"package_origin_verified":True,"version":"9.0"},
  "storage":{"disk_datastore_id":"qualification-lvm","image_datastore_id":"qualification-dir","production_identifiers_absent":True,"shares_production_storage":False,"snippet_content_enabled":True,"snippet_datastore_id":"local","snippet_directory":"/var/lib/vz/snippets","synthetic_only":True},
  "target_id":"isolated-pve-qualification","version":1,
 }
 evidence=root/"admission.json"; evidence.write_bytes(canonical(value)); evidence.chmod(0o600)
 result=run(evidence,known); assert result.returncode==0,result.stderr
 output=json.loads(result.stdout); assert output["admitted"] is True and output["isolation_attestation_sha256"]==hashlib.sha256(evidence.read_bytes()).hexdigest()
 def refused(name,mutate,expected):
  candidate=copy.deepcopy(value); mutate(candidate); p=root/f"{name}.json"; p.write_bytes(canonical(candidate)); p.chmod(0o600); r=run(p,known); assert r.returncode!=0,name; assert expected in r.stderr,(name,r.stderr)
 refused("production-endpoint",lambda x:x.update(endpoint="https://proxmox:8006/api2/json"),"production endpoint")
 refused("shared-storage",lambda x:x["storage"].update(shares_production_storage=True),"schema violation")
 refused("same-principal",lambda x:x["credentials"].update(apply_principal=x["credentials"]["plan_principal"]),"not independent")
 refused("production-ssh",lambda x:x["credentials"].update(ssh_principal="ansible-deploy"),"not independent")
 refused("reused-guest-key",lambda x:x["credentials"].update(guest_ssh_public_key_sha256=x["credentials"]["ssh_agent_public_key_sha256"]),"guest and PVE SSH keys must differ")
 refused("stale",lambda x:x.update(observed_at=(now-dt.timedelta(hours=1)).isoformat().replace("+00:00","Z")),"stale")
 noncanonical=root/"noncanonical.json"; noncanonical.write_text(json.dumps(value,indent=2)); noncanonical.chmod(0o600); assert "canonical JSON" in run(noncanonical,known).stderr
 unsafe=root/"unsafe.json"; unsafe.write_bytes(canonical(value)); unsafe.chmod(0o644); assert "unsafe protected artifact metadata" in run(unsafe,known).stderr
 hardlink=root/"hardlink.json"; os.link(evidence,hardlink); assert "unsafe protected artifact metadata" in run(evidence,known).stderr; hardlink.unlink()
 symlink=root/"symlink.json"; symlink.symlink_to(evidence); assert "unsafe protected artifact metadata" in run(symlink,known).stderr
 bad_known=root/"bad-known-hosts"; bad_known.write_text(known.read_text().replace("pve-qualification.invalid","wrong.invalid")); bad_known.chmod(0o600); assert "digest mismatch" in run(evidence,bad_known).stderr
print("disposable_pve_target_admission=verified hostile_paths=10")
