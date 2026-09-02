#!/usr/bin/env python3
"""Plan and authorize final OpenSSH tightening on Proxmox."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE_SOURCE = (
    HERE / "proxmox-final-key-retirement.py"
    if (HERE / "proxmox-final-key-retirement.py").exists()
    else ROOT / "scripts/controller/proxmox-final-key-retirement.py"
)
SPEC = importlib.util.spec_from_file_location("final_keys", BASE_SOURCE)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
CONTRACT = B.CONTRACT
INVENTORY = B.INVENTORY
OUTPUT = ROOT / ".local/proxmox-openssh-tightening"
TARGET = B.TARGET
CONFIG = "/etc/ssh/sshd_config.d/60-home-lab.conf"
DESIRED = b"PubkeyAuthentication no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n"
SSH = B.SSH
RETAINED = {path: value for path, value in B.RETAINED.items() if path != CONFIG}


def canonical(v):
    return B.canonical(v)


def sha(v):
    return B.sha(v)


def write_private(p, r):
    return B.write_private(p, r)


def load_private(p):
    return B.load_private(p)


def clean_commit():
    return B.clean_commit()


def desired_policy(raw):
    text = raw.decode()
    parts = text.split("\nproxmox:\n", 1)
    if len(parts) != 2:
        raise SystemExit("OpenSSH steady policy is unavailable")
    section = parts[1]
    required = [
        "    pubkey_authentication: false",
        "    password_authentication: false",
        "    kbd_interactive_authentication: false",
        "    permit_root_login: no",
        "    allow_users: []",
    ]
    if any(x not in section for x in required):
        raise SystemExit("OpenSSH steady policy differs")


def validate_final_key_receipt(value):
    receipts = value.get("receipts")
    if (
        value.get("watchdog_units") != []
        or not isinstance(receipts, list)
        or len(receipts) != 1
    ):
        raise SystemExit("one committed final-key receipt is required")
    item = receipts[0]
    path = Path(item.get("path", ""))
    raw = bytes.fromhex(item.get("receipt_hex", ""))
    state_raw = bytes.fromhex(item.get("state_hex", ""))
    try:
        receipt = json.loads(raw)
        state = json.loads(state_raw)
    except (ValueError, json.JSONDecodeError) as error:
        raise SystemExit("final-key receipt encoding differs") from error
    expected_keys = {
        "status",
        "plan_sha256",
        "mutation_started_at",
        "mutated_at",
        "watchdog_deadline",
        "watchdog_seconds",
        "format",
        "canary_sha256",
        "committed_at",
    }
    plan_sha = receipt.get("plan_sha256")
    if (
        set(receipt) != expected_keys
        or receipt != state
        or raw != canonical(receipt)
        or state_raw != canonical(state)
        or item.get("receipt_sha256") != sha(raw)
        or item.get("state_sha256") != sha(state_raw)
        or receipt.get("format") != "home-lab-proxmox-final-key-retirement-receipt-v1"
        or receipt.get("status") != "committed"
        or receipt.get("watchdog_seconds") != 900
        or not isinstance(plan_sha, str)
        or path
        != Path("/var/lib/home-lab/final-key-retirement") / plan_sha / "receipt.json"
        or any(
            not isinstance(receipt.get(name), str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt[name]) is None
            for name in ("plan_sha256", "canary_sha256")
        )
    ):
        raise SystemExit("committed final-key receipt differs")
    for timestamp in (
        "mutation_started_at",
        "mutated_at",
        "watchdog_deadline",
        "committed_at",
    ):
        try:
            parsed = datetime.fromisoformat(receipt[timestamp].replace("Z", "+00:00"))
        except (TypeError, ValueError) as error:
            raise SystemExit("final-key receipt timestamp differs") from error
        if timestamp != "watchdog_deadline" and parsed > datetime.now(timezone.utc):
            raise SystemExit("final-key receipt timestamp is in the future")
    return {
        "path": str(path),
        "sha256": sha(raw),
        "plan_sha256": plan_sha,
        "committed_at": receipt["committed_at"],
    }


def observe():
    value = B.observe()
    program = r"""import glob,hashlib,json,os,stat
items=[]
for receipt in sorted(glob.glob("/var/lib/home-lab/final-key-retirement/*/receipt.json")):
 state=os.path.join(os.path.dirname(receipt),"state.json")
 def read(path):
  s=os.lstat(path);raw=open(path,"rb").read()
  if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1:raise SystemExit(65)
  return raw
 receipt_raw=read(receipt);state_raw=read(state)
 items.append({"path":receipt,"receipt_hex":receipt_raw.hex(),"receipt_sha256":hashlib.sha256(receipt_raw).hexdigest(),"state_hex":state_raw.hex(),"state_sha256":hashlib.sha256(state_raw).hexdigest()})
print(json.dumps({"receipts":items,"watchdog_units":sorted(glob.glob("/etc/systemd/system/home-lab-final-key-*")),"service_active":os.system("/usr/bin/systemctl is-active --quiet ssh.service")==0,"service_enabled":os.system("/usr/bin/systemctl is-enabled --quiet ssh.service")==0},sort_keys=True,separators=(",",":")))"""
    result = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode or result.stderr:
        raise SystemExit("OpenSSH receipt observation failed")
    value.update(json.loads(result.stdout))
    value["effective"] = {key: value["sshd"][key] for key in final_effective()}
    value["final_key_receipt"] = validate_final_key_receipt(value)
    return value


def final_effective():
    return {
        "allow_users": [],
        "pubkey_authentication": "no",
        "password_authentication": "no",
        "kbd_interactive_authentication": "no",
        "permit_root_login": "no",
    }


def retained(o):
    assets = all(
        all(
            o["paths"][p].get(k) == v
            for k, v in {
                "exists": True,
                "uid": e[0],
                "gid": e[1],
                "mode": e[2],
                "regular": True,
                "symlink": False,
                "nlink": 1,
            }.items()
        )
        for p, e in RETAINED.items()
    )
    return (
        all(o["paths"][p] == {"exists": False} for p in B.AUTHORIZED_KEY_CATALOG)
        and o["service_active"]
        and o["service_enabled"]
        and assets
        and B.retained_content_ok(o["paths"])
        and o["accounts"]
        == {
            **B.RETAINED_ACCOUNTS,
            **{
                name: {
                    "exists": False,
                    "group_exists": False,
                    "home_exists": False,
                    "sudo_exists": False,
                }
                for name in B.RETIRED_ACCOUNTS
            },
        }
        and o["tokens"] == B.TOKENS
        and o["root_groups"] == ["root"]
        and o["apex"] == {"gid": 1000, "members": []}
    )


def build_plan(commit, raw, o, now):
    desired_policy(raw)
    findings = []
    if o["locks"]:
        findings.append("protected-lock-active")
    if not retained(o):
        findings.append("final-key-absence-or-ssh-service-differs")
    before = o["paths"][CONFIG]
    present = all(
        before.get(k) == v
        for k, v in {
            "exists": True,
            "uid": 0,
            "gid": 0,
            "mode": "0644",
            "regular": True,
            "symlink": False,
            "nlink": 1,
        }.items()
    )
    if not present:
        findings.append("OpenSSH-drop-in-metadata-differs")
    after = (
        {
            **before,
            "size": len(DESIRED),
            "sha256": sha(DESIRED),
            "bytes_hex": DESIRED.hex(),
        }
        if present
        else {}
    )
    noop = (
        present
        and bytes.fromhex(before["bytes_hex"]) == DESIRED
        and o["effective"] == final_effective()
    )
    actions = (
        []
        if noop or findings
        else [
            {
                "kind": "tighten-openssh-drop-in",
                "path": CONFIG,
                "reload_service": "ssh.service",
            }
        ]
    )
    created = now.replace(microsecond=0)
    auth = (
        [
            "physical-console-attestation-required",
            "persistent-watchdog-required",
            "separate-authorization-required",
        ]
        if actions
        else []
    )
    return {
        "format": "home-lab-proxmox-openssh-tightening-plan-v1",
        "commit": commit,
        "contract_sha256": sha(raw),
        "inventory_sha256": sha(INVENTORY.read_bytes()),
        "host_key_fingerprint": B.HOST_FP,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(minutes=30))
        .isoformat()
        .replace("+00:00", "Z"),
        "before": {"config": before, "effective": o["effective"]},
        "after": {"config": after, "effective": final_effective()},
        "key_paths": {p: o["paths"][p] for p in B.AUTHORIZED_KEY_CATALOG},
        "final_key_receipt": o["final_key_receipt"],
        "retained_accounts": {
            name: o["accounts"][name] for name in B.RETAINED_ACCOUNTS
        },
        "retired_accounts": {name: o["accounts"][name] for name in B.RETIRED_ACCOUNTS},
        "service_state": {
            "active": o["service_active"],
            "enabled": o["service_enabled"],
        },
        "retained_assets": {p: o["paths"][p] for p in RETAINED},
        "retained_tokens": o["tokens"],
        "root_group_state": {"root_groups": o["root_groups"], "apex": o["apex"]},
        "actions": actions,
        "findings": findings,
        "blockers": findings + auth,
        "authorized": False,
        "explicit_exclusions": [
            "authorized-keys",
            "accounts",
            "groups",
            "sudoers",
            "fixed-transports",
            "pve-api-tokens",
            "host-keys",
            "firewall-policy",
        ],
    }


def plan():
    raw = CONTRACT.read_bytes()
    v = build_plan(clean_commit(), raw, observe(), datetime.now(timezone.utc))
    encoded = canonical(v)
    digest = sha(encoded)
    p = OUTPUT / f"openssh-{digest}.json"
    write_private(p, encoded)
    print(
        json.dumps(
            {
                "plan_sha256": digest,
                "path": str(p),
                "actions": v["actions"],
                "findings": v["findings"],
                "blockers": v["blockers"],
            },
            sort_keys=True,
        )
    )


def load_plan(p):
    v, raw = load_private(p)
    digest = sha(raw)
    contract = CONTRACT.read_bytes()
    desired_policy(contract)
    if (
        p.name != f"openssh-{digest}.json"
        or v.get("format") != "home-lab-proxmox-openssh-tightening-plan-v1"
        or v.get("commit") != clean_commit()
        or v.get("contract_sha256") != sha(contract)
        or v.get("inventory_sha256") != sha(INVENTORY.read_bytes())
        or v.get("host_key_fingerprint") != B.HOST_FP
        or v.get("authorized") is not False
        or datetime.now(timezone.utc)
        > datetime.fromisoformat(v["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("OpenSSH plan binding differs")
    return v, raw, digest


def stage(files, digest):
    base = f"/var/lib/home-lab/openssh-tightening/staged/{digest}"
    program = f"import os\nbase={base!r}\nos.makedirs(base,mode=0o700,exist_ok=False)\n"
    for name, raw in files.items():
        program += f"p=os.path.join(base,{name!r});fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=os.fdopen(fd,'wb');h.write(bytes.fromhex({raw.hex()!r}));h.flush();os.fsync(h.fileno());h.close()\n"
    r = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
    )
    if r.returncode or r.stderr:
        raise SystemExit("OpenSSH bundle staging failed")
    return {n: f"{base}/{n}" for n in files}


def authorize(p, e):
    v, raw, digest = load_plan(p)
    evidence, eraw = load_private(e)
    edigest = sha(eraw)
    now = datetime.now(timezone.utc)
    B.validate_access_evidence(evidence, eraw, v, [])
    req = [
        "physical-console-attestation-required",
        "persistent-watchdog-required",
        "separate-authorization-required",
    ]
    if (
        v["actions"]
        != [
            {
                "kind": "tighten-openssh-drop-in",
                "path": CONFIG,
                "reload_service": "ssh.service",
            }
        ]
        or v["findings"]
        or v["blockers"] != req
        or evidence.get("commit") != v["commit"]
        or evidence.get("contract_sha256") != v["contract_sha256"]
        or evidence.get("inventory_sha256") != v["inventory_sha256"]
        or not B.complete_evidence(evidence)
        or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("fresh complete console evidence differs")
    confirmation = f"authorize-proxmox-openssh-{digest}-{edigest}"
    if os.environ.get("PROXMOX_OPENSSH_AUTHORIZATION_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")
    created = now.replace(microsecond=0)
    auth = {
        "format": "home-lab-proxmox-openssh-tightening-authorization-v1",
        "plan_sha256": digest,
        "evidence_sha256": edigest,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": min(
            created + timedelta(minutes=15),
            datetime.fromisoformat(v["expires_at"].replace("Z", "+00:00")),
            datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")),
        )
        .isoformat()
        .replace("+00:00", "Z"),
        "confirmation": confirmation,
        "authorized": True,
    }
    araw = canonical(auth)
    adigest = sha(araw)
    write_private(OUTPUT / f"authorization-{adigest}.json", araw)
    print(
        json.dumps(
            {
                "plan_sha256": digest,
                "authorization_sha256": adigest,
                "staged": stage(
                    {
                        p.name: raw,
                        f"evidence-{edigest}.json": eraw,
                        f"authorization-{adigest}.json": araw,
                    },
                    digest,
                ),
            },
            sort_keys=True,
        )
    )


def session(target, command, options=(), expect=True, input_data=None):
    r = subprocess.run(
        (*SSH, *options, target, command),
        input=input_data,
        capture_output=True,
        timeout=120,
    )
    if expect and r.returncode:
        raise SystemExit(f"OpenSSH canary failed: {target}")
    if not expect and r.returncode == 0:
        raise SystemExit(f"negative canary passed: {target}")
    return r


def canary(p):
    v, _, digest = load_plan(p)
    o = observe()
    if (
        o["paths"][CONFIG] != v["after"]["config"]
        or o["effective"] != final_effective()
        or not retained(o)
    ):
        raise SystemExit("OpenSSH postcondition differs")
    if (
        json.loads(session("ansible-plan@proxmox", "observe").stdout).get("format")
        != "home-lab-proxmox-observation-v1"
    ):
        raise SystemExit("plan canary differs")
    marker = max(
        x
        for x in (ROOT / ".local/lifecycle-marker-plans").glob("proxmox-*.json")
        if not x.name.endswith(".evidence.json")
    ).stem.split("-", 1)[1]
    session("ansible-deploy@proxmox", f"inspect lifecycle-marker {marker}")
    session("firewall-apply@proxmox", "inspect")
    session("proxmox@proxmox", "true")
    snippet = b"#cloud-config\nhostname: ssh-canary\n"
    sd = sha(snippet)
    session(
        "ansible-deploy@proxmox",
        f"restic-recovery stage-snippet {sd}",
        input_data=snippet,
    )
    session("ansible-deploy@proxmox", f"restic-recovery remove-snippet {sd}")
    key = Path.home() / ".ssh/home-lab-arch-ansible"
    firewall_key = Path.home() / ".ssh/home-lab-proxmox-firewall"
    if B.fingerprint(
        subprocess.run(
            ("ssh-keygen", "-y", "-f", str(key)), capture_output=True, check=True
        ).stdout
    ) != ["SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w"] or B.fingerprint(
        subprocess.run(
            ("ssh-keygen", "-y", "-f", str(firewall_key)),
            capture_output=True,
            check=True,
        ).stdout
    ) != [B.FIREWALL_FP]:
        raise SystemExit("negative-canary controller identity differs")
    opts = ("-o", "HostKeyAlias=proxmox", "-o", "IdentitiesOnly=yes", "-i", str(key))
    firewall_opts = (
        "-o",
        "HostKeyAlias=proxmox",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(firewall_key),
    )
    session("root@192.168.0.123", "true", opts, False)
    session("firewall-apply@192.168.0.123", "inspect", firewall_opts, False)
    checks = {
        "sshd_test": True,
        "effective_policy": True,
        "service_active": True,
        "plan": True,
        "deploy": True,
        "firewall": True,
        "human": True,
        "fixed_restic": True,
        "conventional_root_rejected": True,
        "conventional_firewall_rejected": True,
    }
    receipt = {
        "format": "home-lab-proxmox-openssh-tightening-canary-v1",
        "plan_sha256": digest,
        "captured_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "checks": checks,
    }
    rr = canonical(receipt)
    rd = sha(rr)
    write_private(OUTPUT / f"canary-{rd}.json", rr)
    dest = f"/var/lib/home-lab/openssh-tightening/{digest}/candidate-canary.json"
    program = f"import os\nraw=bytes.fromhex({rr.hex()!r});fd=os.open({dest!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=os.fdopen(fd,'wb');h.write(raw);h.flush();os.fsync(h.fileno());h.close()\n"
    r = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
    )
    if r.returncode or r.stderr:
        raise SystemExit("OpenSSH canary staging failed")
    print(
        json.dumps(
            {"plan_sha256": digest, "canary_sha256": rd, "staged_path": dest},
            sort_keys=True,
        )
    )


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("plan")
    a = sp.add_parser("authorize")
    a.add_argument("plan", type=Path)
    a.add_argument("evidence", type=Path)
    c = sp.add_parser("canary")
    c.add_argument("plan", type=Path)
    x = ap.parse_args()
    if x.cmd == "plan":
        plan()
    elif x.cmd == "authorize":
        authorize(x.plan.resolve(), x.evidence.resolve())
    else:
        canary(x.plan.resolve())


if __name__ == "__main__":
    main()
