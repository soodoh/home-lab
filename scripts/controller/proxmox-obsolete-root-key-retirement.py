#!/usr/bin/env python3
"""Plan, authorize, and canary exact obsolete Proxmox root-key retirement."""
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
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
INVENTORY = ROOT / "ansible/inventory/production.yml"
OUTPUT = ROOT / ".local/proxmox-obsolete-root-key-retirement"
TARGET = "proxmox@proxmox"
KEY_PATH = "/etc/pve/priv/authorized_keys"
SYMLINK_PATH = "/root/.ssh/authorized_keys"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TARGET_FINGERPRINTS = [
    "SHA256:/qSECkXxkpCIjTkBwa8XZZdRW2/seScon5uAKGlLC80",
    "SHA256:SNH3GBfBBvbkycl78DbrIjbaC0rJxkvue+KF9qhpXrs",
]
RETAINED_FINGERPRINTS = [
    "SHA256:6RaXU5sJ5bREB69ozsxdAFWVhYvCm9jlPAu7rSOx+dU",
    "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw",
    "SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA",
    "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w",
]
EXPECTED_ATTRIBUTIONS = {
    "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw": "current-proxmox-root-identity",
    "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w": "personal-laptop",
    "SHA256:6RaXU5sJ5bREB69ozsxdAFWVhYvCm9jlPAu7rSOx+dU": "iphone-termius",
    "SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA": "work-laptop",
    TARGET_FINGERPRINTS[0]: "obsolete-proxmox-root-identity",
    TARGET_FINGERPRINTS[1]: "obsolete-proxmox-root-identity",
}
EXPECTED_TOKENS = [{"privsep": 1, "tokenid": "tofu-apply"}, {"privsep": 1, "tokenid": "tofu-plan"}]
RETAINED_METADATA = {
    SYMLINK_PATH: {"uid": 0, "gid": 0, "mode": "0777", "regular": False, "directory": False, "symlink": True, "nlink": 1, "symlink_target": KEY_PATH},
    "/root/.config/home-lab/proxmox-plan-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/root/.config/home-lab/proxmox-apply-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/home/firewall-apply/.ssh/authorized_keys": {"uid": 1003, "gid": 1004, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/etc/sudoers.d/firewall-apply": {"uid": 0, "gid": 0, "mode": "0440", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-firewall-transport": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-private-preparer": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-activator": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "directory": False, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config.d/60-home-lab.conf": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "directory": False, "symlink": False, "nlink": 1},
}
PROTECTED_LOCKS = ["/var/lib/iac-ansible-production.lock", "/var/lock/home-lab-compose.lock", "/run/lock/home-lab-restic-backup.lock", "/run/lock/home-lab-apt.lock", "/run/lock/home-lab-pve-firewall.lock", "/run/lock/home-lab-proxmox-activation.lock", "/run/lock/home-lab-proxmox-root-group-retirement.lock"]
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")
def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("obsolete root-key planning requires clean pushed HEAD")
    return commit


def load_private(path: Path) -> tuple[dict, bytes]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value):
        raise SystemExit("private artifact metadata differs")
    return value, raw


def pve_tokens() -> list[dict]:
    program = 'import json,subprocess\nitems=json.loads(subprocess.run(["/usr/sbin/pveum","user","token","list","root@pam","--output-format","json"],capture_output=True,text=True,check=True).stdout)\nprint(json.dumps(sorted([{"tokenid":item["tokenid"],"privsep":item["privsep"]} for item in items],key=lambda item:item["tokenid"]),sort_keys=True,separators=(",",":")))\n'
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("PVE token observation failed")
    return json.loads(result.stdout)


def contract_policy(raw: bytes) -> tuple[str, dict[str, str]]:
    text = raw.decode(); access = text.split("      access_cutover:\n", 1)
    section = access[1].split("      domain_handoffs:\n", 1)[0] if len(access) == 2 else ""
    state_match = re.search(r"^        state: (pending|ready|complete)$", section, re.MULTILINE)
    key_section = section.split("        root_key_attributions:\n", 1)
    attributions = {}
    if len(key_section) == 2:
        for fingerprint, label in re.findall(r'^          "([^"]+)": ([a-z0-9-]+)$', key_section[1].split("        required_tailnet_users:\n", 1)[0], re.MULTILINE):
            attributions[fingerprint] = label
    if state_match is None: raise SystemExit("access cutover policy is unavailable")
    return state_match.group(1), attributions


def parse_authorized_keys(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8", "strict"); records = []
    for index, line in enumerate(text.splitlines(keepends=True)):
        if not line.strip(): continue
        match = re.search(r"(ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?: [^\r\n]*)?)(?:\r?\n)?$", line)
        if match is None: raise ValueError("root authorized-key line is malformed")
        result = subprocess.run(("ssh-keygen", "-lf", "-"), input=match.group(1) + "\n", text=True, capture_output=True, timeout=15)
        if result.returncode or result.stderr: raise ValueError("root authorized-key fingerprint is unavailable")
        fields = result.stdout.split()
        records.append({"index": index, "line": line, "line_sha256": sha(line.encode()), "fingerprint": fields[1]})
    return records


def retained_metadata_valid(paths: dict) -> bool:
    if set(paths) != set(RETAINED_METADATA): return False
    return all(paths[path].get("exists") is True and all(paths[path].get(key) == value for key, value in expected.items()) and (not expected["regular"] or isinstance(paths[path].get("sha256"), str)) for path, expected in RETAINED_METADATA.items())


def observe() -> dict:
    paths = sorted(set(RETAINED_METADATA) | {KEY_PATH})
    program = f'''import grp,hashlib,json,os,pwd,stat,subprocess\npaths={paths!r}\ndef metadata(path):\n try:s=os.lstat(path)\n except FileNotFoundError:return {{"exists":False}}\n value={{"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"directory":stat.S_ISDIR(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"size":s.st_size}}\n if value["regular"]: value["sha256"]=hashlib.sha256(open(path,"rb").read()).hexdigest()\n if value["symlink"]: value["symlink_target"]=os.readlink(path)\n return value\nraw=open({KEY_PATH!r},"rb").read()\nsshd=subprocess.run(["/usr/sbin/sshd","-T"],capture_output=True,text=True,check=True).stdout\nselected={{"allow_users":[],"authorized_keys_file":[],"permit_root_login":None,"pubkey_authentication":None}}\nfor line in sshd.splitlines():\n key,_,item=line.partition(" ")\n if key=="allowusers": selected["allow_users"].append(item)\n elif key=="authorizedkeysfile": selected["authorized_keys_file"]=item.split()\n elif key=="permitrootlogin": selected["permit_root_login"]=item\n elif key=="pubkeyauthentication": selected["pubkey_authentication"]=item\ndef absent(name):\n try:pwd.getpwnam(name); user=False\n except KeyError:user=True\n try:grp.getgrnam(name); group=False\n except KeyError:group=True\n return user and group and not os.path.lexists("/home/"+name) and not os.path.lexists("/etc/sudoers.d/"+name)\napex=grp.getgrnam("apex")\nprint(json.dumps({{"paths":{{p:metadata(p) for p in paths}},"key_bytes_hex":raw.hex(),"locks":[p for p in {PROTECTED_LOCKS!r} if os.path.exists(p)],"root_groups":sorted(os.getgrouplist("root",pwd.getpwnam("root").pw_gid) and [g.gr_name for g in grp.getgrall() if "root" in g.gr_mem or g.gr_gid==pwd.getpwnam("root").pw_gid]),"apex":{{"exists":True,"gid":apex.gr_gid,"members":sorted(apex.gr_mem)}},"tofu_absent":all(absent(n) for n in ["tofu-plan","tofu-apply"]),"sshd":selected}},sort_keys=True,separators=(",",":")))\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("obsolete root-key observation failed")
    value = json.loads(result.stdout); raw = bytes.fromhex(value.pop("key_bytes_hex"))
    try: value["key_records"] = parse_authorized_keys(raw)
    except ValueError as error: raise SystemExit(str(error)) from error
    value["key_bytes_hex"] = raw.hex(); value["pve_tokens"] = pve_tokens(); return value


def key_snapshot(observation: dict) -> dict:
    raw = bytes.fromhex(observation["key_bytes_hex"]); metadata = observation["paths"][KEY_PATH]
    if metadata.get("sha256") != sha(raw) or metadata.get("size") != len(raw):
        raise SystemExit("root-key bytes and metadata were not captured atomically")
    return {"metadata": metadata, "bytes_hex": raw.hex(), "records": observation["key_records"]}


def after_snapshot(before: dict) -> dict:
    target = set(TARGET_FINGERPRINTS); records = before["records"]
    target_indexes = {item["index"] for item in records if item["fingerprint"] in target}
    lines = bytes.fromhex(before["bytes_hex"]).decode("utf-8", "strict").splitlines(keepends=True)
    raw = "".join(line for index, line in enumerate(lines) if index not in target_indexes).encode()
    parsed = parse_authorized_keys(raw); metadata = {**before["metadata"], "size": len(raw), "sha256": sha(raw)}
    return {"metadata": metadata, "bytes_hex": raw.hex(), "records": parsed}


def build_plan(commit: str, contract_raw: bytes, observation: dict, now: datetime) -> dict:
    state, attributions = contract_policy(contract_raw); findings = []; mutation = False
    if state != "ready": findings.append("access-cutover-state-not-ready")
    if attributions != EXPECTED_ATTRIBUTIONS: findings.append("root-key-attribution-policy-differs")
    if observation.get("locks"): findings.append("protected-lock-active")
    if observation.get("root_groups") != ["root"] or observation.get("apex") != {"exists": True, "gid": 1000, "members": []} or observation.get("tofu_absent") is not True: findings.append("access-retirement-prerequisites-differ")
    target_metadata = observation.get("paths", {}).get(KEY_PATH, {})
    if any(target_metadata.get(key) != value for key, value in {"exists": True, "uid": 0, "gid": 33, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1}.items()): findings.append("root-key-file-metadata-differs")
    if not retained_metadata_valid({path: observation.get("paths", {}).get(path, {}) for path in RETAINED_METADATA}): findings.append("retained-access-metadata-differs")
    if observation.get("pve_tokens") != EXPECTED_TOKENS: findings.append("retained-pve-token-set-differs")
    records = observation.get("key_records", []); fingerprints = [item.get("fingerprint") for item in records]
    if len(fingerprints) != len(set(fingerprints)): findings.append("duplicate-root-key-fingerprint")
    if sorted(fingerprints) == sorted(EXPECTED_ATTRIBUTIONS): mutation = True
    elif sorted(fingerprints) != sorted(RETAINED_FINGERPRINTS): findings.append("root-key-set-differs")
    before = key_snapshot(observation); after = after_snapshot(before) if mutation else before
    actions = [{"kind": "remove-obsolete-root-key-lines", "path": KEY_PATH, "fingerprints": TARGET_FINGERPRINTS}] if mutation and not findings else []
    authorization_blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"] if actions else []
    created = now.replace(microsecond=0)
    return {"format": "home-lab-proxmox-obsolete-root-key-retirement-plan-v1", "commit": commit, "contract_sha256": sha(contract_raw), "inventory_sha256": sha(INVENTORY.read_bytes()), "host_key_fingerprint": FINGERPRINT, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": (created + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"), "access_cutover_state": state, "target_fingerprints": TARGET_FINGERPRINTS, "retained_fingerprints": RETAINED_FINGERPRINTS, "before": before, "after": after, "retained_assets_before": {path: observation["paths"][path] for path in RETAINED_METADATA}, "retained_pve_tokens": observation["pve_tokens"], "retained_sshd_policy": observation["sshd"], "retained_root_group_state": {"root_groups": observation["root_groups"], "apex": observation["apex"]}, "explicit_exclusions": {"delete_key_file_or_symlink": False, "delete_non_target_keys": False, "delete_root_or_apex": False, "pve_api_tokens": ["tofu-plan", "tofu-apply"], "firewall_recovery": True, "openssh_policy": True, "controller_keys": True, "final_conventional_key_absence": "not-authorized"}, "actions": actions, "blockers": findings + authorization_blockers, "findings": findings, "authorized": False}


def write_exclusive(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def plan() -> None:
    contract_raw = CONTRACT.read_bytes(); value = build_plan(clean_pushed_commit(), contract_raw, observe(), datetime.now(timezone.utc)); raw = canonical(value); digest = sha(raw)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700); target = OUTPUT / f"obsolete-root-keys-{digest}.json"; write_exclusive(target, raw)
    print(json.dumps({"authorized": False, "actions": value["actions"], "blockers": value["blockers"], "findings": value["findings"], "path": str(target), "plan_sha256": digest}, sort_keys=True))


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value) or path.name != f"obsolete-root-keys-{digest}.json" or value.get("format") != "home-lab-proxmox-obsolete-root-key-retirement-plan-v1": raise SystemExit("obsolete root-key plan metadata differs")
    contract_raw = CONTRACT.read_bytes()
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != sha(contract_raw) or value.get("inventory_sha256") != sha(INVENTORY.read_bytes()) or value.get("host_key_fingerprint") != FINGERPRINT or contract_policy(contract_raw) != ("ready", EXPECTED_ATTRIBUTIONS) or datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")): raise SystemExit("obsolete root-key plan binding or freshness differs")
    return value, raw, digest


def complete_proofs(evidence: dict) -> bool:
    proofs = evidence.get("proofs", {})
    return proofs.get("strict_host_key") is True and proofs.get("plan_observer", {}).get("positive") is True and proofs["plan_observer"].get("injection_rejected") is True and proofs.get("deploy_transport", {}).get("positive") is True and proofs["deploy_transport"].get("injection_rejected") is True and proofs.get("firewall_transport", {}).get("positive") is True and proofs["firewall_transport"].get("injection_rejected") is True and proofs.get("human_session", {}).get("positive") is True and proofs.get("tailnet_policy", {}).get("tests_present") is True and proofs["tailnet_policy"].get("live_plan_noop") is True and proofs.get("root_keys", {}).get("complete") is True and proofs.get("console") == {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}


def evidence_keys_match(evidence: dict, expected_fingerprints: list[str]) -> bool:
    root_keys = evidence.get("proofs", {}).get("root_keys", {}); records = root_keys.get("records", [])
    fingerprints = [item.get("fingerprint") for item in records]
    return root_keys.get("complete") is True and root_keys.get("unresolved") == [] and root_keys.get("total_count") == len(expected_fingerprints) and root_keys.get("attributed_count") == len(expected_fingerprints) and sorted(fingerprints) == sorted(expected_fingerprints) and len(fingerprints) == len(set(fingerprints))


def stage_bundle(plan_path: Path, plan_raw: bytes, evidence_raw: bytes, authorization_raw: bytes, digest: str, evidence_digest: str, authorization_digest: str) -> dict:
    destination = f"/var/lib/home-lab/obsolete-root-key-retirement/staged/{digest}"; files = {plan_path.name: plan_raw, f"evidence-{evidence_digest}.json": evidence_raw, f"authorization-{authorization_digest}.json": authorization_raw}
    program = "import os,stat\nbase='/var/lib/home-lab'\ndef valid(path,mode):\n s=os.lstat(path)\n return stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and stat.S_IMODE(s.st_mode)==mode and s.st_uid==0 and s.st_gid==0\nif not valid(base,0o750):raise SystemExit(72)\nretirement=os.path.join(base,'obsolete-root-key-retirement');staged=os.path.join(retirement,'staged')\nfor path in (retirement,staged):\n if os.path.lexists(path):\n  if not valid(path,0o700):raise SystemExit(72)\n else:os.mkdir(path,0o700)\nroot=" + repr(destination) + "\nparent=os.path.dirname(root)\nif os.path.lexists(root):raise SystemExit(73)\nos.mkdir(root,0o700)\n"
    for name, raw in files.items():
        program += f"p=os.path.join(root,{name!r});r=bytes.fromhex({raw.hex()!r});fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=os.fdopen(fd,'wb');h.write(r);h.flush();os.fsync(h.fileno());h.close()\n"
    program += "\nfor path in (root,parent,os.path.dirname(parent),base):\n d=os.open(path,os.O_RDONLY);os.fsync(d);os.close(d)\n"
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("obsolete root-key bundle staging failed")
    return {"plan": f"{destination}/{plan_path.name}", "evidence": f"{destination}/evidence-{evidence_digest}.json", "authorization": f"{destination}/authorization-{authorization_digest}.json"}


def authorize(plan_path: Path, evidence_path: Path) -> None:
    value, plan_raw, digest = load_plan(plan_path); evidence, evidence_raw = load_private(evidence_path); evidence_digest = sha(evidence_raw); now = datetime.now(timezone.utc)
    requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if value.get("actions") != [{"kind": "remove-obsolete-root-key-lines", "path": KEY_PATH, "fingerprints": TARGET_FINGERPRINTS}] or value.get("blockers") != requirements or value.get("findings") != []: raise SystemExit("obsolete root-key plan is not authorizable")
    if evidence.get("format") != "home-lab-proxmox-access-evidence-v1" or evidence.get("commit") != value["commit"] or evidence.get("contract_sha256") != value["contract_sha256"] or evidence.get("inventory_sha256") != value["inventory_sha256"] or evidence.get("host_key_fingerprint") != FINGERPRINT or not complete_proofs(evidence) or not evidence_keys_match(evidence, list(EXPECTED_ATTRIBUTIONS)) or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")): raise SystemExit("fresh complete console evidence differs")
    expected = f"authorize-proxmox-obsolete-root-keys-{digest}-{evidence_digest}"
    if os.environ.get("PROXMOX_OBSOLETE_ROOT_KEY_AUTHORIZATION_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
    created = now.replace(microsecond=0); authorization = {"format": "home-lab-proxmox-obsolete-root-key-retirement-authorization-v1", "plan_sha256": digest, "evidence_sha256": evidence_digest, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": min(created + timedelta(minutes=15), datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")), datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))).isoformat().replace("+00:00", "Z"), "confirmation": expected, "authorized": True}
    raw = canonical(authorization); authorization_digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); target = OUTPUT / f"authorization-{authorization_digest}.json"; write_exclusive(target, raw)
    staged = stage_bundle(plan_path, plan_raw, evidence_raw, raw, digest, evidence_digest, authorization_digest)
    print(json.dumps({"authorization_sha256": authorization_digest, "expires_at": authorization["expires_at"], "plan_sha256": digest, "staged": staged}, sort_keys=True))


def run_session(target: str, command: str, options: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
    result = subprocess.run((*SSH, *options, target, command), text=True, capture_output=True, timeout=120)
    if result.returncode: raise SystemExit(f"obsolete root-key canary session failed: {target}")
    return result


def canary(plan_path: Path) -> None:
    value, _, digest = load_plan(plan_path); current = observe(); current_key = key_snapshot(current)
    if current_key != value["after"] or sorted(item["fingerprint"] for item in current_key["records"]) != sorted(RETAINED_FINGERPRINTS): raise SystemExit("obsolete root-key canary state differs")
    retained = {path: current["paths"][path] for path in RETAINED_METADATA}
    if not retained_metadata_valid(retained) or retained != value["retained_assets_before"] or current["pve_tokens"] != EXPECTED_TOKENS or current["sshd"] != value["retained_sshd_policy"] or {"root_groups": current["root_groups"], "apex": current["apex"]} != value["retained_root_group_state"]: raise SystemExit("retained access authority changed")
    plan_session = run_session("ansible-plan@proxmox", "observe")
    if json.loads(plan_session.stdout).get("format") != "home-lab-proxmox-observation-v1": raise SystemExit("plan canary output differs")
    markers = sorted((ROOT / ".local/lifecycle-marker-plans").glob("proxmox-*.json")); markers = [path for path in markers if not path.name.endswith(".evidence.json")]; marker = re.fullmatch(r"proxmox-([0-9a-f]{64})\.json", markers[-1].name).group(1)
    if run_session("ansible-deploy@proxmox", f"inspect lifecycle-marker {marker}").stdout != '{"present":true}\n': raise SystemExit("deploy canary output differs")
    firewall = run_session("firewall-apply@proxmox", "inspect"); run_session("proxmox@proxmox", "true")
    key = Path.home() / ".ssh/home-lab-arch-ansible"; public = subprocess.run(("ssh-keygen", "-y", "-f", str(key)), capture_output=True, check=True).stdout; fingerprint = subprocess.run(("ssh-keygen", "-lf", "-"), input=public, capture_output=True, check=True).stdout.decode().split()[1]
    if fingerprint != "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w": raise SystemExit("retained recovery key fingerprint differs")
    run_session("root@192.168.0.123", "true", ("-o", "HostKeyAlias=proxmox", "-o", "IdentitiesOnly=yes", "-i", str(key)))
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"); receipt = {"format": "home-lab-proxmox-obsolete-root-key-canary-v1", "plan_sha256": digest, "captured_at": now, "checks": {"ansible_plan": True, "ansible_deploy": True, "firewall_apply": bool(firewall.stdout), "human_tailscale": True, "root_lan_recovery": True, "obsolete_keys_absent": True, "retained_keys_exact": True, "retained_assets": True, "pve_tokens": True, "sshd_policy": True}}
    raw = canonical(receipt); receipt_digest = sha(raw); local = OUTPUT / f"canary-{receipt_digest}.json"; write_exclusive(local, raw); destination = f"/var/lib/home-lab/obsolete-root-key-retirement/{digest}/candidate-canary.json"
    program = f'''import json,os\nraw=bytes.fromhex({raw.hex()!r});journal={str(Path(destination).parent)!r}\nstate=json.load(open(os.path.join(journal,"state.json")))\nif state.get("status")!="awaiting-canary" or state.get("plan_sha256")!={digest!r}:raise SystemExit(64)\nfd=os.open({destination!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,"wb") as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("obsolete root-key canary staging failed")
    print(json.dumps({"canary_sha256": receipt_digest, "plan_sha256": digest, "staged_path": destination}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan"); auth = commands.add_parser("authorize"); auth.add_argument("plan", type=Path); auth.add_argument("evidence", type=Path); checked = commands.add_parser("canary"); checked.add_argument("plan", type=Path); args = parser.parse_args()
    if args.command == "plan": plan()
    elif args.command == "authorize": authorize(args.plan.resolve(), args.evidence.resolve())
    else: canary(args.plan.resolve())


if __name__ == "__main__": main()
