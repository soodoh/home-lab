#!/usr/bin/env python3
"""Build separate, unauthorized retirement plans for legacy Proxmox tofu SSH identities."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-tofu-identity-retirement"
TARGET = "proxmox@proxmox"
SSH = (
    "ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
    "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no",
)
HOST_KEY_FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
IDENTITIES = ("tofu-plan", "tofu-apply")
HOST_ASSETS = {
    "tofu-plan": (
        "/home/tofu-plan", "/home/tofu-plan/.ssh",
        "/home/tofu-plan/.ssh/authorized_keys", "/etc/sudoers.d/tofu-plan",
    ),
    "tofu-apply": (
        "/home/tofu-apply", "/home/tofu-apply/.ssh",
        "/home/tofu-apply/.ssh/authorized_keys", "/etc/sudoers.d/tofu-apply",
        "/usr/local/libexec/home-lab/proxmox-apply-transport",
    ),
}
RETAINED_HOST_ASSETS = (
    "/root/.config/home-lab/proxmox-plan-token.env",
    "/root/.config/home-lab/proxmox-apply-token.env",
    "/root/.ssh/authorized_keys",
    "/home/firewall-apply/.ssh/authorized_keys",
    "/etc/sudoers.d/firewall-apply",
    "/usr/local/libexec/home-lab/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-private-preparer",
    "/usr/local/libexec/home-lab/proxmox-activator",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("tofu identity retirement planning requires clean pushed HEAD")
    return commit


def access_state(contract_raw: bytes) -> str:
    text = contract_raw.decode()
    section = text.split("      access_cutover:\n", 1)
    if len(section) != 2:
        raise SystemExit("access cutover policy is unavailable")
    match = re.search(r"^        state: (pending|ready|complete)$", section[1].split("      domain_handoffs:\n", 1)[0], re.MULTILINE)
    if not match:
        raise SystemExit("access cutover state is unavailable")
    return match.group(1)


def local_metadata(path: Path) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    value = {
        "exists": True, "uid": info.st_uid, "gid": info.st_gid,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "nlink": info.st_nlink,
        "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode),
        "size": info.st_size,
    }
    if value["regular"]:
        value["sha256"] = sha(path.read_bytes())
    return value


def observe_host() -> dict:
    request = {"identities": list(IDENTITIES), "paths": sorted({*RETAINED_HOST_ASSETS, *sum(HOST_ASSETS.values(), ())})}
    program = r'''
import grp,hashlib,json,os,pwd,stat,subprocess,sys
request=json.load(sys.stdin)
def metadata(path):
 try: info=os.lstat(path)
 except FileNotFoundError: return {"exists":False}
 value={"exists":True,"uid":info.st_uid,"gid":info.st_gid,"mode":format(stat.S_IMODE(info.st_mode),"04o"),"nlink":info.st_nlink,"regular":stat.S_ISREG(info.st_mode),"directory":stat.S_ISDIR(info.st_mode),"symlink":stat.S_ISLNK(info.st_mode),"size":info.st_size}
 if value["regular"]:
  with open(path,"rb") as handle: value["sha256"]=hashlib.sha256(handle.read()).hexdigest()
 if value["directory"]:
  records=[]
  for root,dirs,files in os.walk(path,topdown=True,followlinks=False):
   dirs.sort(); files.sort()
   for name in dirs+files:
    item=os.path.join(root,name); item_info=os.lstat(item); record={"path":os.path.relpath(item,path),"uid":item_info.st_uid,"gid":item_info.st_gid,"mode":format(stat.S_IMODE(item_info.st_mode),"04o"),"regular":stat.S_ISREG(item_info.st_mode),"directory":stat.S_ISDIR(item_info.st_mode),"symlink":stat.S_ISLNK(item_info.st_mode),"size":item_info.st_size}
    if record["regular"]:
     with open(item,"rb") as handle: record["sha256"]=hashlib.sha256(handle.read()).hexdigest()
    records.append(record)
  value["tree_sha256"]=hashlib.sha256((json.dumps(records,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest(); value["tree_entries"]=len(records)
 return value
def account(name):
 try: item=pwd.getpwnam(name)
 except KeyError: return {"exists":False}
 status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True); fields=status.stdout.split()
 pids=subprocess.run(["/usr/bin/pgrep","-u",name],capture_output=True,text=True)
 return {"exists":True,"uid":item.pw_uid,"gid":item.pw_gid,"home":item.pw_dir,"shell":item.pw_shell,"gecos":item.pw_gecos,"groups":sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name,item.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"},"active_pids":sorted(int(value) for value in pids.stdout.split())}
def group(name):
 try: item=grp.getgrnam(name)
 except KeyError: return {"exists":False}
 return {"exists":True,"gid":item.gr_gid,"members":sorted(item.gr_mem)}
locks=[path for path in ("/var/lib/iac-ansible-production.lock","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock","/run/lock/home-lab-apt.lock","/run/lock/home-lab-pve-firewall.lock") if os.path.lexists(path)]
print(json.dumps({"accounts":{name:account(name) for name in request["identities"]},"groups":{name:group(name) for name in request["identities"]},"locks":locks,"paths":{path:metadata(path) for path in request["paths"]}},sort_keys=True,separators=(",",":")))
'''
    command = (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -")
    request_arg = json.dumps(request, sort_keys=True, separators=(",", ":"))
    wrapped = program.replace("request=json.load(sys.stdin)", f"request=json.loads({request_arg!r})")
    result = subprocess.run(command, input=wrapped, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("tofu identity retirement host observation failed closed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit("a protected lifecycle lock is active")
    return value


def build_plans(commit: str, contract_raw: bytes, observation: dict, controller: dict, now: datetime) -> list[dict]:
    state = access_state(contract_raw)
    created = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expires = (now + timedelta(minutes=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    common = {
        "format": "home-lab-proxmox-tofu-identity-retirement-plan-v1", "commit": commit,
        "contract_sha256": sha(contract_raw), "inventory_sha256": sha((ROOT / "ansible/inventory/production.yml").read_bytes()),
        "host_key_fingerprint": HOST_KEY_FINGERPRINT,
        "created_at": created, "expires_at": expires, "access_cutover_state": state,
        "authorized": False,
        "explicit_exclusions": {
            "pve_api_identities": ["root@pam!tofu-plan", "root@pam!tofu-apply"],
            "protected_token_escrows": ["/root/.config/home-lab/proxmox-plan-token.env", "/root/.config/home-lab/proxmox-apply-token.env"],
            "root_authorized_keys": "/root/.ssh/authorized_keys", "firewall_recovery": True,
            "openssh_policy": True, "unrelated_accounts_and_groups": True,
        },
        "retained_host_assets_before": {path: observation["paths"][path] for path in RETAINED_HOST_ASSETS},
    }
    plans = []
    for sequence, identity in enumerate(IDENTITIES, 1):
        blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
        if state != "ready": blockers.insert(0, "access-cutover-state-not-ready")
        if observation["accounts"][identity].get("active_pids"):
            blockers.insert(0, "identity-has-active-processes")
        plans.append({**common, "sequence": sequence, "kind": f"host-{identity}-retirement", "scope": "proxmox-host",
                      "before": {"account": observation["accounts"][identity], "group": observation["groups"][identity],
                                 "assets": {path: observation["paths"][path] for path in HOST_ASSETS[identity]}},
                      "after": {"account": {"exists": False}, "group": {"exists": False},
                                "assets": {path: {"exists": False} for path in HOST_ASSETS[identity]}},
                      "blockers": blockers})
    host_plan_digests = {identity: sha(canonical(plans[index])) for index, identity in enumerate(IDENTITIES)}
    for sequence, identity in enumerate(IDENTITIES, 3):
        paths = controller[identity]
        plans.append({**common, "sequence": sequence, "kind": f"controller-{identity}-credential-retirement", "scope": "controller",
                      "host_retirement_plan_sha256": host_plan_digests[identity],
                      "before": {path: local_metadata(Path(path)) for path in paths},
                      "after": {path: {"exists": False} for path in paths},
                      "blockers": [f"host-{identity}-retirement-receipt-required", "controller-recovery-attestation-required", "separate-authorization-required"]})
    return plans


def save_plans(plans: list[dict]) -> tuple[Path, str]:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    references = []
    for plan in plans:
        raw = canonical(plan); digest = sha(raw)
        target = OUTPUT / f"{plan['sequence']}-{plan['kind']}-{digest}.json"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        references.append({"sequence": plan["sequence"], "kind": plan["kind"], "plan_sha256": digest,
                           "path": str(target), "blockers": plan["blockers"]})
    manifest = {"format": "home-lab-proxmox-tofu-identity-retirement-manifest-v1", "commit": plans[0]["commit"],
                "created_at": plans[0]["created_at"], "expires_at": plans[0]["expires_at"],
                "plans": references, "authorized": False}
    raw = canonical(manifest); digest = sha(raw); target = OUTPUT / f"manifest-{digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    directory = os.open(OUTPUT, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return target, digest


def plan() -> None:
    commit = clean_pushed_commit(); contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()
    observation = observe_host()
    controller = {name: [str(Path.home() / f".ssh/home-lab-proxmox-{name.removeprefix('tofu-')}"),
                         str(Path.home() / f".ssh/home-lab-proxmox-{name.removeprefix('tofu-')}.pub")] for name in IDENTITIES}
    plans = build_plans(commit, contract_raw, observation, controller, datetime.now(timezone.utc))
    target, digest = save_plans(plans)
    print(json.dumps({"authorized": False, "manifest_sha256": digest, "path": str(target),
                      "plans": [{"kind": item["kind"], "blockers": item["blockers"]} for item in plans]}, sort_keys=True))


def run_session(target: str, command: str, expected: int = 0, identity: Path | None = None) -> subprocess.CompletedProcess[str]:
    options = (*SSH, *(('-o', 'IdentitiesOnly=yes', '-i', str(identity)) if identity else ()), target, command)
    result = subprocess.run(options, text=True, capture_output=True, timeout=120)
    if result.returncode != expected:
        raise SystemExit(f"retirement canary session failed closed: {target}")
    return result


def marker_plan_digest() -> str:
    candidates = sorted((ROOT / ".local/lifecycle-marker-plans").glob("proxmox-*.json"))
    candidates = [path for path in candidates if not path.name.endswith(".evidence.json")]
    if not candidates:
        raise SystemExit("saved lifecycle marker plan is unavailable")
    match = re.fullmatch(r"proxmox-([0-9a-f]{64})\.json", candidates[-1].name)
    if match is None:
        raise SystemExit("saved lifecycle marker plan name is invalid")
    return match.group(1)


def load_local_plan(path: Path) -> tuple[dict, bytes, str, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    match = re.fullmatch(r"host-(tofu-plan|tofu-apply)-retirement", value.get("kind", ""))
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value) or match is None or path.name != f"{value.get('sequence')}-{value.get('kind')}-{digest}.json":
        raise SystemExit("local host retirement plan metadata differs")
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != sha((ROOT / "infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256") != sha((ROOT / "ansible/inventory/production.yml").read_bytes()) or value.get("host_key_fingerprint") != HOST_KEY_FINGERPRINT or value.get("access_cutover_state") != "ready":
        raise SystemExit("local host retirement plan source binding is not ready")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("local host retirement plan expired")
    return value, raw, digest, match.group(1)


def stage_canary_receipt(raw: bytes, digest: str) -> str:
    destination = f"/var/lib/home-lab/tofu-identity-retirement/{digest}/candidate-canary.json"
    program = f'''\nimport json,os,stat\nraw=bytes.fromhex({raw.hex()!r})\njournal={str(Path(destination).parent)!r}\ninfo=os.lstat(journal)\nif not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=0:\n raise SystemExit(64)\nstate_path=os.path.join(journal,"state.json")\nstate_info=os.lstat(state_path); state=json.loads(open(state_path,"rb").read())\nif not stat.S_ISREG(state_info.st_mode) or stat.S_IMODE(state_info.st_mode)!=0o600 or state_info.st_uid!=0 or state_info.st_nlink!=1 or state.get("status")!="awaiting-canary" or state.get("plan_sha256")!={digest!r}:\n raise SystemExit(64)\nfd=os.open({destination!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,"wb") as handle:\n handle.write(raw); handle.flush(); os.fsync(handle.fileno())\ndirectory=os.open(journal,os.O_RDONLY)\ntry: os.fsync(directory)\nfinally: os.close(directory)\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("retirement canary receipt staging failed")
    return destination


def canary(plan_path: Path) -> None:
    plan_value, _, digest, identity = load_local_plan(plan_path)
    observation = observe_host()
    expected_after = {"account": observation["accounts"][identity], "group": observation["groups"][identity],
                      "assets": {path: observation["paths"][path] for path in plan_value["after"]["assets"]}}
    if expected_after != plan_value["after"]:
        raise SystemExit("retired identity postcondition differs during canary")
    retained = {path: observation["paths"][path] for path in plan_value["retained_host_assets_before"]}
    if retained != plan_value["retained_host_assets_before"]:
        raise SystemExit("retained assets changed during retirement canary")
    plan_session = run_session("ansible-plan@proxmox", "observe")
    observed = json.loads(plan_session.stdout)
    if observed.get("format") != "home-lab-proxmox-observation-v1":
        raise SystemExit("ansible plan canary output differs")
    marker = marker_plan_digest()
    deploy = run_session("ansible-deploy@proxmox", f"inspect lifecycle-marker {marker}")
    if deploy.stdout != '{"present":true}\n':
        raise SystemExit("ansible deploy canary output differs")
    firewall = run_session("firewall-apply@proxmox", "inspect")
    if not firewall.stdout:
        raise SystemExit("firewall canary output is empty")
    run_session("proxmox@proxmox", "true")
    key = Path.home() / f".ssh/home-lab-proxmox-{identity.removeprefix('tofu-')}"
    run_session(f"{identity}@192.168.0.123", "true", expected=255, identity=key)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    receipt = {"format": "home-lab-proxmox-tofu-retirement-canary-v1", "plan_sha256": digest,
               "identity": identity, "captured_at": now,
               "checks": {"ansible_plan": True, "ansible_deploy": True, "firewall_apply": True,
                          "human_tailscale": True, "retired_identity_rejected": True, "retained_assets_unchanged": True},
               "evidence_sha256": {"ansible_plan": sha(plan_session.stdout.encode()), "ansible_deploy": sha(deploy.stdout.encode()),
                                   "firewall_apply": sha(firewall.stdout.encode()), "host_observation": sha(canonical(observation))}}
    raw = canonical(receipt); receipt_digest = sha(raw); target = OUTPUT / f"canary-{identity}-{receipt_digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    destination = stage_canary_receipt(raw, digest)
    print(json.dumps({"canary_sha256": receipt_digest, "identity": identity, "local_path": str(target),
                      "plan_sha256": digest, "staged_path": destination}, sort_keys=True))

def access_proofs_complete(evidence: dict) -> bool:
    proofs = evidence.get("proofs", {})
    return proofs.get("strict_host_key") is True and \
        proofs.get("plan_observer", {}).get("positive") is True and proofs["plan_observer"].get("injection_rejected") is True and \
        proofs.get("deploy_transport", {}).get("positive") is True and proofs["deploy_transport"].get("injection_rejected") is True and \
        proofs.get("firewall_transport", {}).get("positive") is True and proofs["firewall_transport"].get("injection_rejected") is True and \
        proofs.get("human_session", {}).get("positive") is True and proofs.get("tailnet_policy", {}).get("tests_present") is True and \
        proofs["tailnet_policy"].get("live_plan_noop") is True and proofs.get("root_keys", {}).get("complete") is True and \
        proofs.get("console") == {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}


def load_local_evidence(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value):
        raise SystemExit("local console evidence metadata differs")
    if value.get("format") != "home-lab-proxmox-access-evidence-v1" or not access_proofs_complete(value):
        raise SystemExit("attested physical-console evidence is required")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("physical-console evidence expired")
    return value, raw, digest


def stage_authorized_bundle(plan_path: Path, plan_raw: bytes, evidence_raw: bytes, authorization_raw: bytes,
                            plan_digest: str, evidence_digest: str, authorization_digest: str) -> dict:
    names = {plan_path.name: plan_raw, f"evidence-{evidence_digest}.json": evidence_raw,
             f"authorization-{authorization_digest}.json": authorization_raw}
    destination = f"/var/lib/home-lab/tofu-identity-retirement/staged/{plan_digest}"
    encoded = {name: raw.hex() for name, raw in names.items()}
    program = f'''\nimport os,stat\nfiles={encoded!r}\nparent="/var/lib/home-lab"\ninfo=os.lstat(parent)\nif not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=0:\n raise SystemExit(64)\npaths=["/var/lib/home-lab/tofu-identity-retirement","/var/lib/home-lab/tofu-identity-retirement/staged",{destination!r}]\nfor path in paths:\n try: os.mkdir(path,0o700)\n except FileExistsError: pass\n info=os.lstat(path)\n if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=0:\n  raise SystemExit(64)\nfor name,raw_hex in files.items():\n target=os.path.join({destination!r},name)\n fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,"wb") as handle:\n  handle.write(bytes.fromhex(raw_hex)); handle.flush(); os.fsync(handle.fileno())\nfor path in reversed(paths):\n fd=os.open(path,os.O_RDONLY)\n try: os.fsync(fd)\n finally: os.close(fd)\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("authorized retirement bundle staging failed")
    return {"authorization": f"{destination}/authorization-{authorization_digest}.json",
            "evidence": f"{destination}/evidence-{evidence_digest}.json", "plan": f"{destination}/{plan_path.name}"}


def authorize(plan_path: Path, evidence_path: Path) -> None:
    plan_value, plan_raw, plan_digest, identity = load_local_plan(plan_path)
    evidence, evidence_raw, evidence_digest = load_local_evidence(evidence_path)
    if evidence.get("commit") != plan_value["commit"] or evidence.get("contract_sha256") != plan_value["contract_sha256"] or evidence.get("inventory_sha256") != plan_value["inventory_sha256"] or evidence.get("host_key_fingerprint") != plan_value["host_key_fingerprint"]:
        raise SystemExit("console evidence source binding differs from retirement plan")
    requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if plan_value.get("blockers") != requirements:
        raise SystemExit("retirement plan requirements differ")
    expected = f"authorize-proxmox-{plan_value['kind']}-{plan_digest}-{evidence_digest}"
    if os.environ.get("PROXMOX_TOFU_RETIREMENT_AUTHORIZATION_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    limit = min(now + timedelta(minutes=10), datetime.fromisoformat(plan_value["expires_at"].replace("Z", "+00:00")),
                datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")))
    if limit <= now:
        raise SystemExit("retirement authorization would already be expired")
    authorization = {"format": "home-lab-proxmox-tofu-retirement-authorization-v1", "authorized": True,
                     "plan_sha256": plan_digest, "console_evidence_sha256": evidence_digest,
                     "commit": plan_value["commit"], "contract_sha256": plan_value["contract_sha256"],
                     "inventory_sha256": plan_value["inventory_sha256"], "host_key_fingerprint": plan_value["host_key_fingerprint"],
                     "expires_at": limit.isoformat().replace("+00:00", "Z"),
                     "authorized_at": now.isoformat().replace("+00:00", "Z"), "accepted_requirements": requirements}
    authorization_raw = canonical(authorization); authorization_digest = sha(authorization_raw)
    target = OUTPUT / f"authorization-{identity}-{authorization_digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(authorization_raw); handle.flush(); os.fsync(handle.fileno())
    staged = stage_authorized_bundle(plan_path, plan_raw, evidence_raw, authorization_raw,
                                     plan_digest, evidence_digest, authorization_digest)
    print(json.dumps({"authorization_sha256": authorization_digest, "expires_at": authorization["expires_at"],
                      "identity": identity, "plan_sha256": plan_digest, "staged": staged}, sort_keys=True))


def load_controller_plan(path: Path) -> tuple[dict, bytes, str, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    match = re.fullmatch(r"controller-(tofu-plan|tofu-apply)-credential-retirement", value.get("kind", ""))
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value) or match is None or path.name != f"{value.get('sequence')}-{value.get('kind')}-{digest}.json":
        raise SystemExit("controller credential plan metadata differs")
    if value.get("scope") != "controller" or value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != sha((ROOT / "infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256") != sha((ROOT / "ansible/inventory/production.yml").read_bytes()) or value.get("host_key_fingerprint") != HOST_KEY_FINGERPRINT or value.get("access_cutover_state") != "ready":
        raise SystemExit("controller credential plan source binding is not ready")
    identity = match.group(1); suffix = identity.removeprefix("tofu-")
    expected_paths = {str(Path.home() / f".ssh/home-lab-proxmox-{suffix}"), str(Path.home() / f".ssh/home-lab-proxmox-{suffix}.pub")}
    if set(value.get("before", {})) != expected_paths or set(value.get("after", {})) != expected_paths or any(item != {"exists": False} for item in value["after"].values()):
        raise SystemExit("controller credential path allowlist differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("controller credential plan expired")
    return value, raw, digest, identity


def fetch_host_receipt(host_plan_digest: str) -> tuple[dict, bytes, str, Path]:
    source = f"/var/lib/home-lab/tofu-identity-retirement/{host_plan_digest}/receipt.json"
    result = subprocess.run((*SSH, TARGET, f"sudo -n -- /usr/bin/cat {source}"), capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("committed host retirement receipt is unavailable")
    value = json.loads(result.stdout); raw = result.stdout; digest = sha(raw)
    if raw != canonical(value):
        raise SystemExit("host retirement receipt is not canonical")
    target = OUTPUT / f"host-receipt-{host_plan_digest}-{digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return value, raw, digest, target


def retire_controller_credentials(plan_path: Path) -> None:
    plan_value, _, plan_digest, identity = load_controller_plan(plan_path)
    host_receipt, _, host_receipt_digest, receipt_path = fetch_host_receipt(plan_value["host_retirement_plan_sha256"])
    if host_receipt.get("format") != "home-lab-proxmox-tofu-retirement-host-receipt-v1" or host_receipt.get("status") != "committed" or host_receipt.get("identity") != identity or host_receipt.get("plan_sha256") != plan_value["host_retirement_plan_sha256"]:
        raise SystemExit("host retirement receipt binding differs")
    expected_blockers = [f"host-{identity}-retirement-receipt-required", "controller-recovery-attestation-required", "separate-authorization-required"]
    if plan_value.get("blockers") != expected_blockers:
        raise SystemExit("controller credential retirement requirements differ")
    expected = f"retire-controller-{identity}-credentials-{plan_digest}-{host_receipt_digest}"
    if os.environ.get("PROXMOX_TOFU_RETIREMENT_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock_path = OUTPUT / ".controller-retirement.lock"; lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = {path: local_metadata(Path(path)) for path in plan_value["before"]}
        if current != plan_value["before"]:
            raise SystemExit("controller credentials changed after planning")
        journal = OUTPUT / "controller-journals" / plan_digest
        journal.parent.mkdir(mode=0o700, exist_ok=True); os.chmod(journal.parent, 0o700); journal.mkdir(mode=0o700)
        backup = {path: Path(path).read_bytes().hex() for path in plan_value["before"]}
        backup_raw = canonical({"format": "home-lab-controller-tofu-credential-rollback-v1", "plan_sha256": plan_digest,
                                "host_receipt_sha256": host_receipt_digest, "files": backup})
        backup_path = journal / "rollback.json"; descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(backup_raw); handle.flush(); os.fsync(handle.fileno())
        for directory_path in (journal, journal.parent):
            directory = os.open(directory_path, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        try:
            removed_parents = set()
            for path in plan_value["before"]:
                target = Path(path); target.unlink(); removed_parents.add(target.parent)
            for parent in removed_parents:
                directory = os.open(parent, os.O_RDONLY)
                try: os.fsync(directory)
                finally: os.close(directory)
            after = {path: local_metadata(Path(path)) for path in plan_value["after"]}
            if after != plan_value["after"]:
                raise RuntimeError("controller credential retirement postcondition differs")
        except Exception:
            restored_parents = set()
            for path, raw_hex in backup.items():
                target = Path(path)
                if not target.exists():
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, "wb") as handle:
                        before = plan_value["before"][path]
                        os.fchown(handle.fileno(), before["uid"], before["gid"]); os.fchmod(handle.fileno(), int(before["mode"], 8))
                        handle.write(bytes.fromhex(raw_hex)); handle.flush(); os.fsync(handle.fileno())
                    restored_parents.add(target.parent)
            for parent in restored_parents:
                directory = os.open(parent, os.O_RDONLY)
                try: os.fsync(directory)
                finally: os.close(directory)
            restored = {path: local_metadata(Path(path)) for path in plan_value["before"]}
            if restored != plan_value["before"]:
                raise RuntimeError("controller credential rollback differs")
            raise
        receipt = {"format": "home-lab-controller-tofu-credential-retirement-receipt-v1", "status": "committed",
                   "identity": identity, "plan_sha256": plan_digest, "host_receipt_sha256": host_receipt_digest,
                   "committed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
        receipt_raw = canonical(receipt); result_path = journal / "receipt.json"
        descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(receipt_raw); handle.flush(); os.fsync(handle.fileno())
        directory = os.open(journal, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        os.close(lock)
    print(json.dumps({"host_receipt": str(receipt_path), "identity": identity, "plan_sha256": plan_digest,
                      "receipt": str(result_path), "status": "committed"}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    canary_parser = commands.add_parser("canary"); canary_parser.add_argument("plan", type=Path)
    authorize_parser = commands.add_parser("authorize"); authorize_parser.add_argument("plan", type=Path); authorize_parser.add_argument("evidence", type=Path)
    retire_parser = commands.add_parser("retire-controller"); retire_parser.add_argument("plan", type=Path)
    args = parser.parse_args()
    if args.command == "plan": plan()
    elif args.command == "authorize": authorize(args.plan.resolve(), args.evidence.resolve())
    elif args.command == "retire-controller": retire_controller_credentials(args.plan.resolve())
    else: canary(args.plan.resolve())


if __name__ == "__main__":
    main()
