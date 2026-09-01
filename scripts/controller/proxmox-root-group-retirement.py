#!/usr/bin/env python3
"""Build an exact, unauthorized plan for removing stale root supplementary groups."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-root-group-retirement"
TARGET = "proxmox@proxmox"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no")
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TARGET_GROUP = "apex"
RETAINED = (
    "/root/.ssh/authorized_keys", "/etc/pve/priv/authorized_keys", "/root/.config/home-lab/proxmox-plan-token.env",
    "/root/.config/home-lab/proxmox-apply-token.env", "/home/firewall-apply/.ssh/authorized_keys",
    "/etc/sudoers.d/firewall-apply", "/usr/local/libexec/home-lab/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-private-preparer", "/usr/local/libexec/home-lab/proxmox-activator",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/60-home-lab.conf",
)
RETAINED_METADATA = {
    "/root/.ssh/authorized_keys": {"uid": 0, "gid": 0, "mode": "0777", "regular": False, "symlink": True, "nlink": 1, "symlink_target": "/etc/pve/priv/authorized_keys"},
    "/etc/pve/priv/authorized_keys": {"uid": 0, "gid": 33, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/root/.config/home-lab/proxmox-plan-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/root/.config/home-lab/proxmox-apply-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/home/firewall-apply/.ssh/authorized_keys": {"uid": 1003, "gid": 1004, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/etc/sudoers.d/firewall-apply": {"uid": 0, "gid": 0, "mode": "0440", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-firewall-transport": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-private-preparer": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-activator": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config.d/60-home-lab.conf": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "symlink": False, "nlink": 1},
}


def retained_metadata_valid(paths: dict) -> bool:
    if set(paths) != set(RETAINED_METADATA): return False
    return all(paths[path].get("exists") is True and all(paths[path].get(key) == value for key, value in expected.items()) and (not expected["regular"] or isinstance(paths[path].get("sha256"), str)) for path, expected in RETAINED_METADATA.items())


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("root group retirement planning requires clean pushed HEAD")
    return commit


def access_policy(raw: bytes) -> tuple[str, list[str]]:
    text = raw.decode(); section = text.split("      access_cutover:\n", 1)
    if len(section) != 2:
        raise SystemExit("access cutover policy is unavailable")
    body = section[1].split("      domain_handoffs:\n", 1)[0]
    state_match = re.search(r"^        state: (pending|ready|complete)$", body, re.MULTILINE)
    groups_match = re.search(r"^        retire_root_supplementary_groups:\n((?:          - [^\n]+\n)+)", body, re.MULTILINE)
    groups = re.findall(r"^          - ([^\n]+)$", groups_match.group(1), re.MULTILINE) if groups_match else []
    if state_match is None or groups != [TARGET_GROUP]:
        raise SystemExit("root supplementary-group retirement policy differs")
    return state_match.group(1), groups


def observe() -> dict:
    paths = sorted(RETAINED)
    program = f'''import grp,hashlib,json,os,pwd,stat,subprocess\npaths={paths!r}\ndef meta(path):\n try:s=os.lstat(path)\n except FileNotFoundError:return {{"exists":False}}\n value={{"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"directory":stat.S_ISDIR(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"size":s.st_size}}\n if value["regular"]:value["sha256"]=hashlib.sha256(open(path,"rb").read()).hexdigest()\n if value["symlink"]:value["symlink_target"]=os.readlink(path)\n return value\nroot=pwd.getpwnam("root");apex=grp.getgrnam("apex")\nrecords={{}}\nfor path in ("/etc/group","/etc/gshadow"):\n lines=[line for line in open(path).read().splitlines() if line.split(":",1)[0]=="apex"]\n records[path]={{"count":len(lines),"line":lines[0] if len(lines)==1 else None,"sha256":hashlib.sha256((lines[0]+"\\n").encode()).hexdigest() if len(lines)==1 else None}}\nlocks=[]\nfor path in ("/var/lib/iac-ansible-production.lock","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock","/run/lock/home-lab-apt.lock","/run/lock/home-lab-pve-firewall.lock"):\n if os.path.lexists(path):locks.append(path)\ntokens=json.loads(subprocess.run(["/usr/sbin/pveum","user","token","list","root@pam","--output-format","json"],capture_output=True,text=True,check=True).stdout)\nprint(json.dumps({{"apex":{{"exists":True,"gid":apex.gr_gid,"members":sorted(apex.gr_mem)}},"database_records":records,"locks":locks,"paths":{{path:meta(path) for path in paths}},"pve_tokens":sorted([{{"tokenid":item["tokenid"],"privsep":item["privsep"]}} for item in tokens],key=lambda item:item["tokenid"]),"root":{{"exists":True,"gid":root.pw_gid,"home":root.pw_dir,"shell":root.pw_shell,"groups":sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist("root",root.pw_gid))}}}},sort_keys=True,separators=(",",":")))\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("root group retirement observation failed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit("a protected lifecycle lock is active")
    return value

def remove_member(line: str, member: str) -> str:
    fields = line.split(":")
    if len(fields) != 4 or fields[0] != TARGET_GROUP: raise ValueError("apex database record is malformed")
    fields[3] = ",".join(value for value in fields[3].split(",") if value and value != member)
    return ":".join(fields)


def build_plan(commit: str, contract_raw: bytes, observation: dict, now: datetime) -> dict:
    state, groups = access_policy(contract_raw)
    blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if state != "ready": blockers.insert(0, "access-cutover-state-not-ready")
    before = {"root_groups": observation["root"]["groups"], "apex": observation["apex"],
              "database_records": observation["database_records"]}
    if before != {"root_groups": ["apex", "root"], "apex": {"exists": True, "gid": 1000, "members": ["root"]},
                  "database_records": before["database_records"]} or any(item.get("count") != 1 or not item.get("sha256") for item in before["database_records"].values()):
        blockers.insert(0, "root-apex-membership-differs")
    expected_tokens = [{"privsep": 1, "tokenid": "tofu-apply"}, {"privsep": 1, "tokenid": "tofu-plan"}]
    if observation.get("pve_tokens") != expected_tokens:
        blockers.insert(0, "retained-pve-token-set-differs")
    if not retained_metadata_valid(observation.get("paths", {})):
        blockers.insert(0, "retained-access-metadata-differs")
    after_records = {path: {"line": remove_member(item["line"], "root")} for path, item in before["database_records"].items()}
    for item in after_records.values(): item["sha256"] = sha((item["line"] + "\n").encode())
    created = now.replace(microsecond=0); expires = created + timedelta(minutes=30)
    return {"format": "home-lab-proxmox-root-group-retirement-plan-v1", "commit": commit,
            "contract_sha256": sha(contract_raw), "inventory_sha256": sha((ROOT / "ansible/inventory/production.yml").read_bytes()),
            "host_key_fingerprint": FINGERPRINT, "created_at": created.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"), "access_cutover_state": state,
            "target_group": groups[0], "before": before,
            "after": {"root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []},
                      "database_records": after_records},
            "retained_assets_before": {path: observation["paths"][path] for path in RETAINED},
            "retained_pve_tokens": observation["pve_tokens"],
            "explicit_exclusions": {"delete_apex_group": False, "delete_root_account": False, "root_authorized_keys": True,
                                    "openssh_policy": True, "pve_api_tokens": ["tofu-plan", "tofu-apply"],
                                    "firewall_recovery": True, "tofu_ssh_identities": "already-retired"},
            "blockers": blockers, "authorized": False}


def plan() -> None:
    contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()
    value = build_plan(clean_pushed_commit(), contract_raw, observe(), datetime.now(timezone.utc))
    raw = canonical(value); digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    target = OUTPUT / f"root-apex-{digest}.json"; descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"authorized": False, "blockers": value["blockers"], "path": str(target), "plan_sha256": digest}, sort_keys=True))


def complete_proofs(evidence: dict) -> bool:
    proofs = evidence.get("proofs", {})
    return proofs.get("strict_host_key") is True and proofs.get("plan_observer", {}).get("positive") is True and proofs["plan_observer"].get("injection_rejected") is True and proofs.get("deploy_transport", {}).get("positive") is True and proofs["deploy_transport"].get("injection_rejected") is True and proofs.get("firewall_transport", {}).get("positive") is True and proofs["firewall_transport"].get("injection_rejected") is True and proofs.get("human_session", {}).get("positive") is True and proofs.get("tailnet_policy", {}).get("tests_present") is True and proofs["tailnet_policy"].get("live_plan_noop") is True and proofs.get("root_keys", {}).get("complete") is True and proofs.get("console") == {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value) or path.name != f"root-apex-{digest}.json" or value.get("format") != "home-lab-proxmox-root-group-retirement-plan-v1":
        raise SystemExit("root group plan metadata differs")
    contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != sha(contract_raw) or value.get("inventory_sha256") != sha((ROOT / "ansible/inventory/production.yml").read_bytes()) or value.get("host_key_fingerprint") != FINGERPRINT or value.get("access_cutover_state") != "ready" or datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("root group plan binding or freshness differs")
    return value, raw, digest


def load_evidence(path: Path, plan_value: dict) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value) or value.get("format") != "home-lab-proxmox-access-evidence-v1" or value.get("commit") != plan_value["commit"] or value.get("contract_sha256") != plan_value["contract_sha256"] or value.get("inventory_sha256") != plan_value["inventory_sha256"] or value.get("host_key_fingerprint") != FINGERPRINT or not complete_proofs(value) or datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("fresh root group console evidence differs")
    return value, raw, digest


def stage_bundle(plan_path: Path, plan_raw: bytes, evidence_raw: bytes, authorization_raw: bytes, plan_digest: str, evidence_digest: str, authorization_digest: str) -> dict:
    destination = f"/var/lib/home-lab/root-group-retirement/staged/{plan_digest}"
    files = {plan_path.name: plan_raw.hex(), f"evidence-{evidence_digest}.json": evidence_raw.hex(), f"authorization-{authorization_digest}.json": authorization_raw.hex()}
    program = f'''import os,stat\nfiles={files!r};parent="/var/lib/home-lab";destination={destination!r}\ninfo=os.lstat(parent)\nif not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=0:raise SystemExit(64)\nfor path in ("/var/lib/home-lab/root-group-retirement","/var/lib/home-lab/root-group-retirement/staged",destination):\n try:os.mkdir(path,0o700)\n except FileExistsError:pass\n info=os.lstat(path)\n if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=0:raise SystemExit(64)\nfor name,raw_hex in files.items():\n target=os.path.join(destination,name);fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,"wb") as handle:handle.write(bytes.fromhex(raw_hex));handle.flush();os.fsync(handle.fileno())\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("root group authorized bundle staging failed")
    return {"plan": f"{destination}/{plan_path.name}", "evidence": f"{destination}/evidence-{evidence_digest}.json", "authorization": f"{destination}/authorization-{authorization_digest}.json"}


def authorize(plan_path: Path, evidence_path: Path) -> None:
    plan_value, plan_raw, digest = load_plan(plan_path); evidence, evidence_raw, evidence_digest = load_evidence(evidence_path, plan_value)
    requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if plan_value.get("blockers") != requirements: raise SystemExit("root group plan requirements differ")
    expected = f"authorize-proxmox-root-apex-retirement-{digest}-{evidence_digest}"
    if os.environ.get("PROXMOX_ROOT_GROUP_RETIREMENT_AUTHORIZATION_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
    now = datetime.now(timezone.utc).replace(microsecond=0); limit = min(now + timedelta(minutes=10), datetime.fromisoformat(plan_value["expires_at"].replace("Z", "+00:00")), datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")))
    authorization = {"format": "home-lab-proxmox-root-group-retirement-authorization-v1", "authorized": True, "plan_sha256": digest,
                     "console_evidence_sha256": evidence_digest, "commit": plan_value["commit"], "contract_sha256": plan_value["contract_sha256"],
                     "inventory_sha256": plan_value["inventory_sha256"], "host_key_fingerprint": FINGERPRINT,
                     "authorized_at": now.isoformat().replace("+00:00", "Z"), "expires_at": limit.isoformat().replace("+00:00", "Z"),
                     "accepted_requirements": requirements}
    raw = canonical(authorization); authorization_digest = sha(raw); target = OUTPUT / f"authorization-{authorization_digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    staged = stage_bundle(plan_path, plan_raw, evidence_raw, raw, digest, evidence_digest, authorization_digest)
    print(json.dumps({"authorization_sha256": authorization_digest, "expires_at": authorization["expires_at"], "plan_sha256": digest, "staged": staged}, sort_keys=True))


def run_session(target: str, command: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run((*SSH, target, command), text=True, capture_output=True, timeout=120)
    if result.returncode: raise SystemExit(f"root group canary session failed: {target}")
    return result


def canary(plan_path: Path) -> None:
    plan_value, _, digest = load_plan(plan_path); current = observe()
    current_records = {path: {"line": item["line"], "sha256": item["sha256"]} for path, item in current["database_records"].items()}
    current_retained = {path: current["paths"][path] for path in plan_value["retained_assets_before"]}
    if {"root_groups": current["root"]["groups"], "apex": current["apex"]} != {"root_groups": plan_value["after"]["root_groups"], "apex": plan_value["after"]["apex"]} or current_records != plan_value["after"]["database_records"] or not retained_metadata_valid(current_retained) or current_retained != plan_value["retained_assets_before"] or current["pve_tokens"] != plan_value["retained_pve_tokens"]:
        raise SystemExit("root group canary state differs")
    plan_session = run_session("ansible-plan@proxmox", "observe")
    if json.loads(plan_session.stdout).get("format") != "home-lab-proxmox-observation-v1": raise SystemExit("plan canary output differs")
    marker_candidates = sorted((ROOT / ".local/lifecycle-marker-plans").glob("proxmox-*.json")); marker_candidates = [path for path in marker_candidates if not path.name.endswith(".evidence.json")]
    marker = re.fullmatch(r"proxmox-([0-9a-f]{64})\.json", marker_candidates[-1].name).group(1)
    deploy = run_session("ansible-deploy@proxmox", f"inspect lifecycle-marker {marker}")
    if deploy.stdout != '{"present":true}\n': raise SystemExit("deploy canary output differs")
    firewall = run_session("firewall-apply@proxmox", "inspect"); run_session("proxmox@proxmox", "true")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    receipt = {"format": "home-lab-proxmox-root-group-canary-v1", "plan_sha256": digest, "captured_at": now,
               "checks": {"ansible_plan": True, "ansible_deploy": True, "firewall_apply": bool(firewall.stdout), "human_tailscale": True,
                          "root_group_state": True, "retained_assets": True, "pve_tokens": True}}
    raw = canonical(receipt); receipt_digest = sha(raw); local = OUTPUT / f"canary-{receipt_digest}.json"
    descriptor = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    destination = f"/var/lib/home-lab/root-group-retirement/{digest}/candidate-canary.json"
    program = f'''import json,os,stat\nraw=bytes.fromhex({raw.hex()!r});journal={str(Path(destination).parent)!r}\nstate=json.load(open(os.path.join(journal,"state.json")))\nif state.get("status")!="awaiting-canary" or state.get("plan_sha256")!={digest!r}:raise SystemExit(64)\nfd=os.open({destination!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,"wb") as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("root group canary staging failed")
    print(json.dumps({"canary_sha256": receipt_digest, "plan_sha256": digest, "staged_path": destination}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan")
    auth = commands.add_parser("authorize"); auth.add_argument("plan", type=Path); auth.add_argument("evidence", type=Path)
    checked = commands.add_parser("canary"); checked.add_argument("plan", type=Path); args = parser.parse_args()
    if args.command == "plan": plan()
    elif args.command == "authorize": authorize(args.plan.resolve(), args.evidence.resolve())
    else: canary(args.plan.resolve())


if __name__ == "__main__":
    main()
