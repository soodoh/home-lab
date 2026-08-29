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
import tempfile

from protected_execution import acquire_transfer_lock
ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/debian-access-cleanup"
FINGERPRINT = "SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ"
TARGET = "ansible-deploy@docker-host"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")
LOCK = ROOT / ".local/debian-access-cleanup.lock"


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
    marker_present = evidence["paths"][marker_path].get("exists") is True
    keys_present = any(evidence["paths"][path].get("exists") is True for path in key_paths)
    definitions = [
        ("legacy-marker-removal", {"path": marker_path, "before": evidence["paths"][marker_path], "after": {"exists": False}},
         ([] if marker_present else ["legacy-marker-already-absent"]) + ["physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
        ("conventional-key-removal", {"paths": {path: {"before": evidence["paths"][path], "after": {"exists": False}} for path in key_paths}},
         ([] if not marker_present else ["legacy-marker-removal-required"]) + ["physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
        ("openssh-tightening", {"before": evidence["sshd"], "after": {"pubkey_authentication": "no", "permit_root_login": "no"}},
         ([] if not keys_present else ["conventional-key-removal-required"]) + ["independent-post-key-session-canary-required", "physical-console-attestation-required", "saved-reviewed-plan-required", "separate-authorization-required"]),
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


def load_private(path: Path, label: str) -> tuple[dict, bytes]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value):
        raise SystemExit(f"{label} metadata or canonical content differs")
    return value, raw


def apply_legacy_marker(plan_path: Path, manifest_path: Path, recovery_path: Path) -> None:
    plan_value, plan_raw = load_private(plan_path, "Debian access cleanup plan")
    manifest, manifest_raw = load_private(manifest_path, "Debian access cleanup manifest")
    recovery, _ = load_private(recovery_path, "Debian recovery attestation")
    plan_digest = sha(plan_raw); manifest_digest = sha(manifest_raw)
    if plan_path.name != f"1-legacy-marker-removal-{plan_digest}.json" or manifest_path.name != f"manifest-{manifest_digest}.json":
        raise SystemExit("Debian cleanup artifact filename binding differs")
    if plan_value.get("kind") != "legacy-marker-removal" or plan_value.get("sequence") != 1 or plan_value.get("authorized") is not False or plan_value.get("commit") != clean_pushed_commit() or plan_value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan_value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml"):
        raise SystemExit("Debian legacy marker plan binding differs")
    reference = next((item for item in manifest.get("plans", []) if item.get("plan_sha256") == plan_digest), None)
    if manifest.get("commit") != plan_value["commit"] or reference is None or reference.get("kind") != "legacy-marker-removal":
        raise SystemExit("Debian cleanup manifest does not bind the marker plan")
    if recovery != {"format": "home-lab-debian-access-recovery-attestation-v1", "manifest_sha256": manifest_digest, "commit": manifest["commit"], "method": "localhost", "attested_at": recovery.get("attested_at")}:
        raise SystemExit("Debian localhost recovery receipt differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan_value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("Debian legacy marker plan expired")
    expected = f"apply-debian-legacy-marker-removal-{plan_digest}"
    if os.environ.get("DEBIAN_ACCESS_CLEANUP_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    current = observe(); marker_path = plan_value["action"]["path"]
    if current["paths"].get(marker_path) != plan_value["action"]["before"]:
        raise SystemExit("Debian legacy marker changed after planning")
    extra = {"debian_access_cleanup_plan": plan_value}
    lock_descriptor = acquire_transfer_lock(LOCK)
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=OUTPUT, prefix="legacy-marker-extra-", suffix=".json", delete=False) as handle:
            extra_path = Path(handle.name); os.chmod(extra_path, 0o600); handle.write(canonical(extra)); handle.flush(); os.fsync(handle.fileno())
        try:
            command = ("ansible-playbook", "-i", "inventory/production.yml", "playbooks/apply-debian-access-cleanup.yml", "--limit", "docker-host-production", "--tags", "debian_legacy_marker", "--extra-vars", f"@{extra_path}")
            applied = subprocess.run(command, cwd=ROOT / "ansible", timeout=300)
            if applied.returncode:
                raise SystemExit("Debian legacy marker one-tag apply failed")
        finally:
            extra_path.unlink(missing_ok=True)
    finally:
        os.close(lock_descriptor)
    after = observe()
    if after["paths"].get(marker_path) != {"exists": False}:
        raise SystemExit("Debian legacy marker postcondition differs")
    print(json.dumps({"action": "legacy-marker-removal", "plan_sha256": plan_digest, "status": "applied"}, sort_keys=True))


def apply_conventional_keys(plan_path: Path, manifest_path: Path, recovery_path: Path) -> None:
    plan_value, plan_raw = load_private(plan_path, "Debian conventional key plan")
    manifest, manifest_raw = load_private(manifest_path, "Debian access cleanup manifest")
    recovery, _ = load_private(recovery_path, "Debian recovery attestation")
    plan_digest = sha(plan_raw); manifest_digest = sha(manifest_raw)
    if plan_path.name != f"2-conventional-key-removal-{plan_digest}.json" or manifest_path.name != f"manifest-{manifest_digest}.json":
        raise SystemExit("Debian conventional key artifact filename differs")
    if plan_value.get("kind") != "conventional-key-removal" or plan_value.get("sequence") != 2 or plan_value.get("authorized") is not False or plan_value.get("commit") != clean_pushed_commit() or plan_value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan_value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml"):
        raise SystemExit("Debian conventional key plan binding differs")
    reference = next((item for item in manifest.get("plans", []) if item.get("plan_sha256") == plan_digest), None)
    if manifest.get("commit") != plan_value["commit"] or reference is None or reference.get("kind") != "conventional-key-removal" or "legacy-marker-removal-required" in reference.get("blockers", []):
        raise SystemExit("Debian cleanup manifest does not permit the key plan")
    if recovery != {"format": "home-lab-debian-access-recovery-attestation-v1", "manifest_sha256": manifest_digest, "commit": manifest["commit"], "method": "localhost", "attested_at": recovery.get("attested_at")}:
        raise SystemExit("Debian localhost recovery receipt differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan_value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("Debian conventional key plan expired")
    expected = f"apply-debian-conventional-key-removal-{plan_digest}"
    if os.environ.get("DEBIAN_ACCESS_CLEANUP_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    current = observe(); marker_path = "/var/lib/home-lab/debian-inert-provisioned"
    if current["paths"].get(marker_path) != {"exists": False}:
        raise SystemExit("Debian legacy marker must remain absent")
    for path, action in plan_value["action"]["paths"].items():
        if current["paths"].get(path) != action["before"]:
            raise SystemExit("Debian conventional key changed after planning")

    def invoke(operation: str) -> int:
        extra = {"debian_access_cleanup_plan": plan_value, "debian_access_cleanup_plan_sha256": plan_digest,
                 "debian_access_cleanup_operation": operation}
        with tempfile.NamedTemporaryFile(mode="wb", dir=OUTPUT, prefix=f"keys-{operation}-", suffix=".json", delete=False) as handle:
            extra_path = Path(handle.name); os.chmod(extra_path, 0o600); handle.write(canonical(extra)); handle.flush(); os.fsync(handle.fileno())
        try:
            command = ("ansible-playbook", "-i", "inventory/production.yml", "playbooks/apply-debian-access-cleanup.yml", "--limit", "docker-host-production", "--tags", "debian_conventional_keys", "--extra-vars", f"@{extra_path}")
            return subprocess.run(command, cwd=ROOT / "ansible", timeout=300).returncode
        finally:
            extra_path.unlink(missing_ok=True)

    lock_descriptor = acquire_transfer_lock(LOCK)
    try:
        if invoke("apply"):
            raise SystemExit("Debian conventional key one-tag apply failed")
        try:
            after = observe()
            if any(after["paths"].get(path) != {"exists": False} for path in plan_value["action"]["paths"]):
                raise ValueError("Debian conventional key postcondition differs")
        except (Exception, SystemExit):
            if invoke("rollback"):
                raise SystemExit("Debian conventional key canary failed and rollback failed")
            raise SystemExit("Debian conventional key canary failed; rollback restored exact keys")
    finally:
        os.close(lock_descriptor)
    print(json.dumps({"action": "conventional-key-removal", "plan_sha256": plan_digest, "rollback_retained": True, "status": "applied"}, sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); commands.add_parser("plan"); attested=commands.add_parser("attest-recovery"); attested.add_argument("manifest",type=Path); attested.add_argument("--method",choices=("localhost","physical-console"),required=True); marker=commands.add_parser("apply-legacy-marker"); marker.add_argument("plan",type=Path); marker.add_argument("manifest",type=Path); marker.add_argument("recovery",type=Path); keys=commands.add_parser("apply-conventional-keys"); keys.add_argument("plan",type=Path); keys.add_argument("manifest",type=Path); keys.add_argument("recovery",type=Path); args=parser.parse_args()
    if args.command == "plan":
        path,digest=plan(); print(json.dumps({"authorized":False,"manifest_sha256":digest,"path":str(path)},sort_keys=True))
    elif args.command == "attest-recovery": attest_recovery(args.manifest.resolve(), args.method)
    elif args.command == "apply-legacy-marker": apply_legacy_marker(args.plan.resolve(), args.manifest.resolve(), args.recovery.resolve())
    else: apply_conventional_keys(args.plan.resolve(), args.manifest.resolve(), args.recovery.resolve())


if __name__ == "__main__": main()
