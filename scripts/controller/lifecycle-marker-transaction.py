#!/usr/bin/env python3
"""Plan and apply one immutable production lifecycle marker per host."""

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
PLAN_DIR = ROOT / ".local/lifecycle-marker-plans"
LOCK = ROOT / ".local/lifecycle-marker-transaction.lock"
MARKER = "/var/lib/home-lab/lifecycle-state.json"
HOSTS = {
    "proxmox": {"target": "proxmox@proxmox", "plan_target": "ansible-plan@proxmox", "fingerprint": "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"},
    "debian": {"target": "ansible-deploy@docker-host", "fingerprint": "SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ"},
}
SSH_OPTIONS = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")


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
        raise SystemExit("lifecycle marker transaction requires clean pushed HEAD")
    return commit


def observe(host: str) -> dict:
    locks = ["/var/lib/iac-ansible-production.lock", "/var/lib/home-lab/reconciliation/apply.lock",
             "/var/lib/home-lab/firewall-transaction/active.json", "/var/lock/home-lab-compose.lock"]
    program = r'''
import hashlib,json,os,stat,sys
path=sys.argv[1]; locks=json.loads(sys.argv[2]); result={"exists":False}
try: info=os.lstat(path)
except FileNotFoundError: pass
else:
 result={"exists":True,"uid":info.st_uid,"gid":info.st_gid,"mode":format(stat.S_IMODE(info.st_mode),"04o"),"regular":stat.S_ISREG(info.st_mode),"symlink":stat.S_ISLNK(info.st_mode),"nlink":info.st_nlink}
 if result["regular"] and info.st_size<=4096:
  raw=open(path,"rb").read(); result["sha256"]=hashlib.sha256(raw).hexdigest()
  try: result["value"]=json.loads(raw)
  except json.JSONDecodeError: result["value"]=None
print(json.dumps({"locks":[p for p in locks if os.path.lexists(p)],"marker":result},sort_keys=True,separators=(",",":")))
'''
    command = f"sudo -n -- /usr/bin/python3 - {MARKER!r} {json.dumps(locks)!r}"
    result = subprocess.run((*SSH_OPTIONS, HOSTS[host]["target"], command), input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr:
        raise SystemExit(f"{host} lifecycle marker observation failed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit(f"{host} lifecycle lock is active")
    return value


def fixed_plan_observer() -> dict:
    result = subprocess.run((*SSH_OPTIONS, HOSTS["proxmox"]["plan_target"], "observe"), capture_output=True, timeout=60)
    if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
        raise SystemExit("Proxmox fixed plan observer failed")
    value = json.loads(result.stdout)
    statuses = {name: domain.get("status") for name, domain in value.get("domains", {}).items() if isinstance(domain, dict) and "status" in domain}
    if value.get("format") != "home-lab-proxmox-observation-v1" or value.get("protocol") != 4 or any(status != "complete" for status in statuses.values()):
        raise SystemExit("Proxmox fixed plan observer is incomplete")
    return {"observer_sha256": value.get("observerSha256"), "domain_statuses": statuses, "observation_sha256": sha(result.stdout)}


def save_plan(host: str) -> tuple[Path, str]:
    commit = clean_pushed_commit(); observation = observe(host)
    if observation["marker"] != {"exists": False}:
        raise SystemExit(f"{host} lifecycle marker is not absent")
    plan_observer = fixed_plan_observer() if host == "proxmox" else None
    now = datetime.now(timezone.utc).replace(microsecond=0); created = now.isoformat().replace("+00:00", "Z")
    plan = {"authorized": False, "commit": commit, "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
            "created_at": created, "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
            "format": "home-lab-lifecycle-marker-plan-v1", "host": host, "host_key_fingerprint": HOSTS[host]["fingerprint"],
            "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
            "marker": {"after": {"source_commit": commit, "state": "production", "updated_at": created, "version": 1},
                       "before": {"exists": False}, "path": MARKER}}
    raw = canonical(plan); digest = sha(raw); PLAN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(PLAN_DIR, 0o700)
    path = PLAN_DIR / f"{host}-{digest}.json"; fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    if plan_observer is not None:
        evidence = {"format": "home-lab-lifecycle-marker-plan-evidence-v1", "plan_sha256": digest, "plan_observer": plan_observer}
        evidence_path = PLAN_DIR / f"{host}-{digest}.evidence.json"; fd = os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle: handle.write(canonical(evidence)); handle.flush(); os.fsync(handle.fileno())
    return path, digest


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or path.name != f"{value.get('host')}-{digest}.json" or raw != canonical(value):
        raise SystemExit("lifecycle marker plan metadata or canonical hash differs")
    expected_keys = {"authorized", "commit", "contract_sha256", "created_at", "expires_at", "format", "host", "host_key_fingerprint", "inventory_sha256", "marker"}
    if set(value) != expected_keys or value.get("format") != "home-lab-lifecycle-marker-plan-v1" or value.get("authorized") is not False or value.get("host") not in HOSTS:
        raise SystemExit("lifecycle marker plan envelope differs")
    return value, raw, digest


def exact_marker(plan: dict) -> dict:
    return {"exists": True, "uid": 0, "gid": 0, "mode": "0600", "regular": True, "symlink": False, "nlink": 1,
            "sha256": sha(canonical(plan["marker"]["after"])), "value": plan["marker"]["after"]}


def apply_plan(path: Path) -> None:
    plan, raw, digest = load_plan(path); host = plan["host"]
    if plan["commit"] != clean_pushed_commit() or plan["contract_sha256"] != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan["inventory_sha256"] != file_sha(ROOT / "ansible/inventory/production.yml") or plan["host_key_fingerprint"] != HOSTS[host]["fingerprint"]:
        raise SystemExit("lifecycle marker source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("lifecycle marker plan expired")
    expected = f"apply-{host}-lifecycle-marker-{digest}"
    if os.environ.get("LIFECYCLE_MARKER_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    before = observe(host)
    if before["marker"] != {"exists": False}:
        raise SystemExit("lifecycle marker before-state changed")
    if host == "proxmox":
        evidence_path = path.with_name(f"proxmox-{digest}.evidence.json")
        evidence_info = evidence_path.lstat(); evidence_raw = evidence_path.read_bytes(); evidence = json.loads(evidence_raw)
        if not stat.S_ISREG(evidence_info.st_mode) or stat.S_IMODE(evidence_info.st_mode) != 0o600 or evidence_info.st_uid != os.getuid() or evidence_info.st_nlink != 1 or evidence_raw != canonical(evidence) or evidence.get("format") != "home-lab-lifecycle-marker-plan-evidence-v1" or evidence.get("plan_sha256") != digest or not isinstance(evidence.get("plan_observer"), dict):
            raise SystemExit("Proxmox fixed plan observer evidence differs")
    lock_descriptor = acquire_transfer_lock(LOCK)
    try:
        if host == "proxmox":
            stage = subprocess.run((*SSH_OPTIONS, "ansible-deploy@proxmox", f"stage lifecycle-marker {digest}"), input=raw, capture_output=True, timeout=60)
            if stage.returncode or stage.stderr or stage.stdout != b'{"staged":true}\n': raise SystemExit("Proxmox marker plan staging failed")
            inspect = subprocess.run((*SSH_OPTIONS, "ansible-deploy@proxmox", f"inspect lifecycle-marker {digest}"), capture_output=True, timeout=60)
            if inspect.returncode or inspect.stderr or inspect.stdout != b'{"present":true}\n': raise SystemExit("Proxmox marker plan inspection failed")
            applied = subprocess.run((*SSH_OPTIONS, "ansible-deploy@proxmox", f"apply lifecycle-marker {digest}"), capture_output=True, timeout=120)
            if applied.returncode:
                recovered = observe(host)
                if recovered["marker"] != exact_marker(plan): raise SystemExit("Proxmox marker apply failed without a verifiable committed result")
        else:
            extra = {"lifecycle_marker_plan": plan}
            with tempfile.NamedTemporaryFile(mode="wb", dir=PLAN_DIR, prefix="debian-extra-", suffix=".json", delete=False) as handle:
                extra_path = Path(handle.name); os.chmod(extra_path, 0o600); handle.write(canonical(extra)); handle.flush(); os.fsync(handle.fileno())
            try:
                command = ("ansible-playbook", "-i", "inventory/production.yml", "playbooks/adopt-lifecycle-marker.yml", "--limit", "docker-host-production", "--tags", "lifecycle_marker", "--extra-vars", f"@{extra_path}")
                applied = subprocess.run(command, cwd=ROOT / "ansible", timeout=300)
                if applied.returncode: raise SystemExit("Debian one-tag lifecycle marker apply failed")
            finally: extra_path.unlink(missing_ok=True)
    finally:
        os.close(lock_descriptor)
    after = observe(host)
    if after["marker"] != exact_marker(plan): raise SystemExit("lifecycle marker postcondition differs")
    print(json.dumps({"host": host, "lifecycle_marker": "adopted", "plan_sha256": digest}, sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); planned=commands.add_parser("plan"); planned.add_argument("host",choices=sorted(HOSTS)); applied=commands.add_parser("apply"); applied.add_argument("plan",type=Path); args=parser.parse_args()
    if args.command == "plan":
        path,digest=save_plan(args.host); print(json.dumps({"authorized":False,"host":args.host,"path":str(path),"plan_sha256":digest},sort_keys=True))
    else: apply_plan(args.plan.resolve())


if __name__ == "__main__": main()
