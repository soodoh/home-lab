#!/usr/bin/env python3
"""Build separate immutable Debian legacy-marker, key, and OpenSSH cleanup plans."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/debian-access-cleanup"
FINGERPRINT = "SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ"
TARGET = "ansible-deploy@docker-host"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("Debian access cleanup planning requires clean pushed HEAD")
    return commit


def observe() -> dict:
    program = r'''
import grp,hashlib,json,os,pwd,stat,subprocess
paths=["/var/lib/home-lab/debian-inert-provisioned","/home/ansible-deploy/.ssh/authorized_keys","/root/.ssh/authorized_keys"]
def metadata(path):
 try: info=os.lstat(path)
 except FileNotFoundError: return {"exists":False}
 value={"exists":True,"uid":info.st_uid,"gid":info.st_gid,"mode":format(stat.S_IMODE(info.st_mode),"04o"),"regular":stat.S_ISREG(info.st_mode),"symlink":stat.S_ISLNK(info.st_mode),"nlink":info.st_nlink,"size":info.st_size}
 if value["regular"] and info.st_size<=65536:
  raw=open(path,"rb").read(); value["sha256"]=hashlib.sha256(raw).hexdigest(); value["nonempty_lines"]=len([line for line in raw.splitlines() if line.strip()])
  fingerprints=[]
  for line in raw.decode("utf-8","strict").splitlines():
   if not line.strip(): continue
   result=subprocess.run(["/usr/bin/ssh-keygen","-lf","-"],input=line+"\n",text=True,capture_output=True)
   if result.returncode: fingerprints.append("unparsed")
   else: fingerprints.append(result.stdout.split()[1])
  value["fingerprints"]=sorted(fingerprints)
 return value
account=pwd.getpwnam("ansible-deploy"); status=subprocess.run(["/usr/bin/passwd","--status","ansible-deploy"],capture_output=True,text=True); fields=status.stdout.split()
sshd=subprocess.run(["/usr/sbin/sshd","-T"],capture_output=True,text=True,check=True)
selected={"allow_users":[],"authorized_keys_file":[],"permit_root_login":None,"pubkey_authentication":None}
for line in sshd.stdout.splitlines():
 key,_,item=line.partition(" ")
 if key=="allowusers": selected["allow_users"].append(item)
 elif key=="authorizedkeysfile": selected["authorized_keys_file"]=item.split()
 elif key=="permitrootlogin": selected["permit_root_login"]=item
 elif key=="pubkeyauthentication": selected["pubkey_authentication"]=item
tailscale=json.loads(subprocess.run(["/usr/bin/tailscale","status","--json"],capture_output=True,text=True,check=True).stdout); prefs=json.loads(subprocess.run(["/usr/bin/tailscale","debug","prefs"],capture_output=True,text=True,check=True).stdout); self_state=tailscale.get("Self") or {}
locks=[path for path in ("/var/lib/iac-ansible-production.lock","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock") if os.path.lexists(path)]
print(json.dumps({"account":{"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist("ansible-deploy",account.pw_gid)),"home":account.pw_dir,"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"},"shell":account.pw_shell},"locks":locks,"paths":{path:metadata(path) for path in paths},"sshd":selected,"tailscale":{"backend_state":tailscale.get("BackendState"),"dns_name":self_state.get("DNSName"),"run_ssh":prefs.get("RunSSH"),"tags":self_state.get("Tags") or [],"want_running":prefs.get("WantRunning")}},sort_keys=True,separators=(",",":")))
'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("Debian access cleanup observation failed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit("Debian lifecycle lock is active")
    tailscale = value.get("tailscale", {})
    if tailscale.get("backend_state") != "Running" or tailscale.get("run_ssh") is not True or tailscale.get("want_running") is not True or "tag:docker-host" not in tailscale.get("tags", []):
        raise SystemExit("Debian Tailscale SSH state differs")
    account = value.get("account", {})
    if account.get("groups") != ["ansible-deploy"] or account.get("password_locked") is not True:
        raise SystemExit("Debian deploy identity differs")
    return value


def plan() -> tuple[Path, str]:
    commit = clean_pushed_commit(); evidence = observe(); now = datetime.now(timezone.utc).replace(microsecond=0)
    created = now.isoformat().replace("+00:00", "Z"); expires = (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z")
    contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes(); inventory_raw = (ROOT / "ansible/inventory/production.yml").read_bytes()
    base = {"format": "home-lab-debian-access-cleanup-plan-v1", "commit": commit, "contract_sha256": sha(contract_raw),
            "inventory_sha256": sha(inventory_raw), "host_key_fingerprint": FINGERPRINT, "created_at": created,
            "expires_at": expires, "host": "debian", "observation_sha256": sha(canonical(evidence)), "authorized": False}
    marker_path = "/var/lib/home-lab/debian-inert-provisioned"; key_paths = ["/home/ansible-deploy/.ssh/authorized_keys", "/root/.ssh/authorized_keys"]
    definitions = [
        ("legacy-marker-removal", {"path": marker_path, "before": evidence["paths"][marker_path], "after": {"exists": False}},
         ["physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
        ("conventional-key-removal", {"paths": {path: {"before": evidence["paths"][path], "after": {"exists": False}} for path in key_paths}},
         ["legacy-marker-removal-required", "physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
        ("openssh-tightening", {"before": evidence["sshd"], "after": {"pubkey_authentication": "no", "permit_root_login": "no"}},
         ["conventional-key-removal-required", "independent-post-key-session-canary-required", "physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
    ]
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700); plans=[]
    for sequence, (kind, action, blockers) in enumerate(definitions, 1):
        value = {**base, "sequence": sequence, "kind": kind, "action": action, "blockers": blockers}
        raw = canonical(value); digest = sha(raw); target = OUTPUT / f"{sequence}-{kind}-{digest}.json"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        plans.append({"sequence": sequence, "kind": kind, "plan_sha256": digest, "path": str(target), "blockers": blockers})
    material = {"format": "home-lab-debian-access-cleanup-manifest-v1", "commit": commit, "created_at": created,
                "expires_at": expires, "host_key_fingerprint": FINGERPRINT, "evidence": evidence, "plans": plans, "authorized": False}
    raw = canonical(material); digest = sha(raw); target = OUTPUT / f"manifest-{digest}.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return target, digest


def attest_recovery(path: Path, method: str) -> None:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or path.name != f"manifest-{digest}.json" or raw != canonical(value):
        raise SystemExit("Debian access cleanup manifest metadata differs")
    if value.get("commit") != clean_pushed_commit() or datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("Debian access cleanup manifest binding or freshness differs")
    if method not in {"localhost", "physical-console"}:
        raise SystemExit("Debian recovery attestation method is invalid")
    expected = f"attest-debian-{method}-recovery-{digest}"
    if os.environ.get("DEBIAN_RECOVERY_ATTESTATION_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    receipt = {"format": "home-lab-debian-access-recovery-attestation-v1", "manifest_sha256": digest,
               "commit": value["commit"], "method": method,
               "attested_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
    receipt_raw = canonical(receipt); receipt_digest = sha(receipt_raw); target = OUTPUT / f"recovery-{receipt_digest}.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(receipt_raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"attestation_sha256": receipt_digest, "method": method, "path": str(target)}, sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); commands.add_parser("plan"); attested=commands.add_parser("attest-recovery"); attested.add_argument("manifest",type=Path); attested.add_argument("--method",choices=("localhost","physical-console"),required=True); args=parser.parse_args()
    if args.command == "plan":
        path,digest=plan(); print(json.dumps({"authorized":False,"manifest_sha256":digest,"path":str(path)},sort_keys=True))
    else: attest_recovery(args.manifest.resolve(), args.method)


if __name__ == "__main__": main()
