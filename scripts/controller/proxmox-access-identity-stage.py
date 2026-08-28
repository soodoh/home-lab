#!/usr/bin/env python3
"""Save and apply the add-only inert Proxmox access-identity staging transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[2]
PLAN_ROOT = ROOT / ".local/access-identity-plans"
HOST = "proxmox@proxmox"
TARGETS = ("ansible-plan", "ansible-deploy")
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
MAX_AGE = 1800
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha(path: Path) -> str:
    return sha256(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def require_clean_pushed() -> str:
    head = git("rev-parse", "HEAD")
    if head != git("rev-parse", "origin/main"):
        raise SystemExit("access identity staging requires pushed HEAD")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("access identity staging requires a clean worktree")
    return head


def observe() -> dict:
    program = r'''
import json, os, pwd, subprocess
names=("ansible-plan","ansible-deploy")
accounts=[]
for name in names:
    try:
        value=pwd.getpwnam(name)
        status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True,check=False)
        fields=status.stdout.split()
        accounts.append({"name":name,"exists":True,"uid":value.pw_uid,"gid":value.pw_gid,"home":value.pw_dir,"shell":value.pw_shell,"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"}})
    except KeyError:
        accounts.append({"name":name,"exists":False})
paths={}
for name in names:
    for suffix in (".ssh/authorized_keys",".ssh/authorized_keys2"):
        path=f"/home/{name}/{suffix}"
        paths[path]=os.path.lexists(path)
    paths[f"/etc/sudoers.d/{name}"]=os.path.lexists(f"/etc/sudoers.d/{name}")
locks=[path for path in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(path)]
print(json.dumps({"accounts":accounts,"paths":paths,"locks":locks},sort_keys=True,separators=(",",":")))
'''
    result = subprocess.run((*SSH, HOST, "sudo -n -- /usr/bin/python3 -"), cwd=ROOT, input=program,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise SystemExit("access identity observation failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise SystemExit("access identity observation is invalid")
    return value


def validate_absent(observation: dict) -> None:
    if observation.get("locks") != []:
        raise SystemExit("access identity staging blocked by active host lock")
    accounts = observation.get("accounts")
    if not isinstance(accounts, list) or [item.get("name") for item in accounts] != list(TARGETS):
        raise SystemExit("access identity account observation is invalid")
    if any(item.get("exists") is not False for item in accounts):
        raise SystemExit("access identity staging requires both targets to be absent")
    paths = observation.get("paths")
    expected = {f"/home/{name}/{suffix}" for name in TARGETS for suffix in (".ssh/authorized_keys", ".ssh/authorized_keys2")}
    expected |= {f"/etc/sudoers.d/{name}" for name in TARGETS}
    if not isinstance(paths, dict) or set(paths) != expected or any(paths.values()):
        raise SystemExit("access identity staging requires key and sudo paths to be absent")


def build_plan(observation: dict, commit: str, now: datetime) -> dict:
    validate_absent(observation)
    return {
        "format": "home-lab-proxmox-access-identity-stage-v1",
        "commit": commit,
        "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
        "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
        "host_key_fingerprint": FINGERPRINT,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=MAX_AGE)).isoformat().replace("+00:00", "Z"),
        "observation_sha256": sha256(canonical(observation)),
        "actions": [
            {"account": name, "state": "present", "home": f"/home/{name}", "shell": "/usr/sbin/nologin",
             "password_locked": True, "groups": [], "authorized_keys": "absent", "sudo": "absent"}
            for name in TARGETS
        ],
        "authorized": False,
    }


def save_plan(plan: dict) -> tuple[Path, str]:
    raw = canonical(plan)
    digest = sha256(raw)
    PLAN_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PLAN_ROOT, 0o700)
    path = PLAN_ROOT / f"{digest}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return path, digest


def load_plan(path: Path) -> tuple[dict, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise SystemExit("access identity plan metadata differs")
    raw = path.read_bytes()
    digest = sha256(raw)
    if path.name != f"{digest}.json":
        raise SystemExit("access identity plan filename hash differs")
    plan = json.loads(raw)
    if canonical(plan) != raw:
        raise SystemExit("access identity plan is not canonical")
    return plan, digest


def validate_plan(plan: dict, digest: str, now: datetime) -> None:
    expected_keys = {"format", "commit", "contract_sha256", "inventory_sha256", "host_key_fingerprint",
                     "created_at", "expires_at", "observation_sha256", "actions", "authorized"}
    if set(plan) != expected_keys or plan.get("format") != "home-lab-proxmox-access-identity-stage-v1":
        raise SystemExit("access identity plan schema differs")
    if plan.get("commit") != require_clean_pushed() or plan.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml"):
        raise SystemExit("access identity plan source binding differs")
    if plan.get("host_key_fingerprint") != FINGERPRINT or plan.get("authorized") is not False:
        raise SystemExit("access identity plan authority binding differs")
    expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    if now > expires:
        raise SystemExit("access identity plan expired")
    expected_actions = build_plan({"accounts": [{"name": name, "exists": False} for name in TARGETS],
                                   "paths": {**{f"/home/{name}/{suffix}": False for name in TARGETS for suffix in (".ssh/authorized_keys", ".ssh/authorized_keys2")}, **{f"/etc/sudoers.d/{name}": False for name in TARGETS}}, "locks": []}, plan["commit"], now)["actions"]
    if plan.get("actions") != expected_actions:
        raise SystemExit("access identity plan action catalog differs")
    confirmation = f"stage-proxmox-access-identities-{digest}"
    if os.environ.get("PROXMOX_ACCESS_IDENTITY_STAGE_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")


def apply_plan(path: Path) -> None:
    plan, digest = load_plan(path)
    validate_plan(plan, digest, datetime.now(timezone.utc))
    current = observe()
    validate_absent(current)
    if sha256(canonical(current)) != plan["observation_sha256"]:
        raise SystemExit("access identity observation changed since plan")
    remote = r'''set -euo pipefail
names=(ansible-plan ansible-deploy)
created=()
rollback(){ rc=$?; if ((rc)); then for name in "${created[@]}"; do userdel -r "$name" >/dev/null 2>&1 || true; groupdel "$name" >/dev/null 2>&1 || true; done; fi; exit "$rc"; }; trap rollback EXIT
[[ ! -e /var/lib/home-lab/reconciliation/apply.lock && ! -e /var/lib/iac-ansible-production.lock && ! -e /var/lib/home-lab/firewall-transaction/active.json ]]
for name in "${names[@]}"; do
  ! getent passwd "$name" >/dev/null; ! getent group "$name" >/dev/null
  [[ ! -e "/home/$name" && ! -e "/etc/sudoers.d/$name" ]]
  groupadd --system "$name"
  useradd --system --gid "$name" --home-dir "/home/$name" --create-home --shell /usr/sbin/nologin "$name"
  created+=("$name")
  passwd --lock "$name" >/dev/null
  install -d -o "$name" -g "$name" -m 0700 "/home/$name/.ssh"
  [[ ! -e "/home/$name/.ssh/authorized_keys" && ! -e "/home/$name/.ssh/authorized_keys2" ]]
done
trap - EXIT
'''
    result = subprocess.run((*SSH, HOST, "sudo -n -- /bin/bash -s"), input=remote, text=True, timeout=120)
    if result.returncode:
        raise SystemExit("access identity staging transaction failed")
    print(json.dumps({"access_identity_stage": "applied", "plan_sha256": digest}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("plan")
    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("plan", type=Path)
    args = parser.parse_args()
    if args.operation == "plan":
        commit = require_clean_pushed()
        plan = build_plan(observe(), commit, datetime.now(timezone.utc))
        path, digest = save_plan(plan)
        print(json.dumps({"path": str(path), "plan_sha256": digest, "authorized": False}, sort_keys=True))
    else:
        apply_plan(args.plan.resolve())


if __name__ == "__main__":
    main()
