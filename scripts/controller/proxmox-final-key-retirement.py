#!/usr/bin/env python3
"""Plan and authorize final conventional-key retirement on Proxmox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
INVENTORY = ROOT / "ansible/inventory/production.yml"
OUTPUT = ROOT / ".local/proxmox-final-key-retirement"
TARGET = "proxmox@proxmox"
HOST_FP = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
ROOT_KEY = "/etc/pve/priv/authorized_keys"
ROOT_LINK = "/root/.ssh/authorized_keys"
FIREWALL_KEY = "/home/firewall-apply/.ssh/authorized_keys"
PATHS = (ROOT_KEY, ROOT_LINK, FIREWALL_KEY)
ACCOUNT_NAMES = (
    "proxmox",
    "firewall-apply",
    "ansible-plan",
    "ansible-deploy",
    "tofu-plan",
    "tofu-apply",
)
AUTHORIZED_KEY_CATALOG = tuple(
    sorted(
        {
            ROOT_KEY,
            "/etc/pve/priv/authorized_keys2",
            "/root/.ssh/authorized_keys",
            "/root/.ssh/authorized_keys2",
            *(
                f"/home/{name}/.ssh/{filename}"
                for name in ACCOUNT_NAMES
                for filename in ("authorized_keys", "authorized_keys2")
            ),
        }
    )
)
ROOT_FPS = sorted(
    [
        "SHA256:6RaXU5sJ5bREB69ozsxdAFWVhYvCm9jlPAu7rSOx+dU",
        "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw",
        "SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA",
        "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w",
    ]
)
FIREWALL_FP = "SHA256:YUQQfpL0WvPdLoxVuQ1ZGDG7aM7941CpKd7RGeCeiQQ"
ACCESS_ATTRIBUTIONS = {
    "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw": "current-proxmox-root-id-rsa",
    "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w": "personal-laptop",
    "SHA256:6RaXU5sJ5bREB69ozsxdAFWVhYvCm9jlPAu7rSOx+dU": "iphone-termius",
    "SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA": "work-laptop",
    "SHA256:/qSECkXxkpCIjTkBwa8XZZdRW2/seScon5uAKGlLC80": "obsolete-proxmox-root-identity",
    "SHA256:SNH3GBfBBvbkycl78DbrIjbaC0rJxkvue+KF9qhpXrs": "obsolete-proxmox-root-identity",
}
TOKENS = [
    {"privsep": 1, "tokenid": "tofu-apply"},
    {"privsep": 1, "tokenid": "tofu-plan"},
]
SSHD_BEFORE = {
    "allow_users": ["root", "tofu-plan", "tofu-apply", "firewall-apply"],
    "authorized_keys_file": [".ssh/authorized_keys", ".ssh/authorized_keys2"],
    "pubkey_authentication": "yes",
    "password_authentication": "no",
    "kbd_interactive_authentication": "no",
    "permit_root_login": "without-password",
}
SSHD_FINAL = {
    "allow_users": [],
    "authorized_keys_file": [".ssh/authorized_keys", ".ssh/authorized_keys2"],
    "pubkey_authentication": "no",
    "password_authentication": "no",
    "kbd_interactive_authentication": "no",
    "permit_root_login": "no",
}
RECOVERY_COMMIT = "e6e4a2f5fd0613e703d36c0a53c95f80c741608c"
RECOVERY_SHA = "82537efde96231435da520e0f0dc472f1808e0c24dad0fef8b7b659c6c2ba1cc"
RECOVERY = ROOT / f".reconcile/restic-recovery-vm/{RECOVERY_COMMIT}/run-evidence.json"
RECOVERY_JOURNAL = RECOVERY.parent / "journal.json"
RECOVERY_JOURNAL_SHA = (
    "6ec32081ddd4283cec6329695daf74670d83ac0fbecd7cb95f437cd81b0a6a15"
)
RECOVERY_MAX_AGE_DAYS = 90
RECOVERY_REPOSITORY_ID = (
    "98d792c009c01e06b8b39aab5112f0392050e9c533d1882e9c0d87727884ea25"
)
RECOVERY_SNAPSHOT_ID = (
    "e0ac47b09716b3a1632a9fce21ada5f53b82980ecce6723fa7a682b9117fc139"
)
RETAINED_ACCOUNTS = {
    "proxmox": {
        "home": "/home/proxmox",
        "shell": "/bin/bash",
        "groups": ["proxmox"],
        "password_locked": True,
    },
    "firewall-apply": {
        "home": "/home/firewall-apply",
        "shell": "/usr/local/libexec/home-lab/proxmox-firewall-transport",
        "groups": ["firewall-apply"],
        "password_locked": True,
    },
    "ansible-plan": {
        "home": "/home/ansible-plan",
        "shell": "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport",
        "groups": ["ansible-plan"],
        "password_locked": True,
    },
    "ansible-deploy": {
        "home": "/home/ansible-deploy",
        "shell": "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport",
        "groups": ["ansible-deploy"],
        "password_locked": True,
    },
}
RETIRED_ACCOUNTS = ("tofu-plan", "tofu-apply")
SUDO_CONTENT = {
    "/etc/sudoers.d/proxmox": "proxmox ALL=(root) NOPASSWD: ALL\n",
    "/etc/sudoers.d/firewall-apply": "firewall-apply ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-firewall-transaction inspect, /usr/local/libexec/home-lab/proxmox-firewall-transaction begin, /usr/local/libexec/home-lab/proxmox-firewall-transaction status, /usr/local/libexec/home-lab/proxmox-firewall-transaction commit, /usr/local/libexec/home-lab/proxmox-firewall-transaction rollback\n",
    "/etc/sudoers.d/ansible-plan": "ansible-plan ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-observer observe\n",
    "/etc/sudoers.d/ansible-deploy": "ansible-deploy ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-ansible-deploy-activator, /usr/local/libexec/home-lab/proxmox-restic-recovery-transport\n",
}
TRANSPORT_SOURCES = {
    "/usr/local/libexec/home-lab/proxmox-firewall-transport": "infrastructure/proxmox-firewall/host/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport": "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport",
    "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport": "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport",
    "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator": "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator",
    "/usr/local/libexec/home-lab/proxmox-restic-recovery-transport": "infrastructure/proxmox-access/host/proxmox-restic-recovery-transport.py",
}
RETAINED = {
    "/etc/sudoers.d/proxmox": (0, 0, "0440"),
    "/etc/sudoers.d/firewall-apply": (0, 0, "0440"),
    "/etc/sudoers.d/ansible-plan": (0, 0, "0440"),
    "/etc/sudoers.d/ansible-deploy": (0, 0, "0440"),
    "/usr/local/libexec/home-lab/proxmox-firewall-transport": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-observer": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-restic-recovery-transport": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-private-preparer": (0, 0, "0755"),
    "/usr/local/libexec/home-lab/proxmox-activator": (0, 0, "0755"),
    "/etc/ssh/sshd_config": (0, 0, "0644"),
    "/etc/ssh/sshd_config.d/60-home-lab.conf": (0, 0, "0644"),
    "/root/.config/home-lab/proxmox-plan-token.env": (0, 0, "0600"),
    "/root/.config/home-lab/proxmox-apply-token.env": (0, 0, "0600"),
}
SHARED_LOCK = "/run/lock/home-lab-proxmox-access-cutover.lock"
LOCKS = [
    "/var/lib/iac-ansible-production.lock",
    "/var/lock/home-lab-compose.lock",
    "/run/lock/home-lab-restic-backup.lock",
    "/run/lock/home-lab-apt.lock",
    "/run/lock/home-lab-pve-firewall.lock",
    "/run/lock/home-lab-proxmox-activation.lock",
]
SSH = (
    "ssh",
    "-F",
    "/dev/null",
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "UpdateHostKeys=no",
    "-o",
    "ClearAllForwardings=yes",
)


def canonical(v):
    return (json.dumps(v, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(v):
    return hashlib.sha256(v).hexdigest()


def git(*a):
    return subprocess.check_output(("git", *a), cwd=ROOT, text=True).strip()


def clean_commit():
    c = git("rev-parse", "HEAD")
    if c != git("rev-parse", "origin/main") or git(
        "status", "--porcelain=v1", "--untracked-files=all"
    ):
        raise SystemExit("final key planning requires clean pushed HEAD")
    return c


def write_private(p, raw):
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(p.parent, 0o700)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as h:
        h.write(raw)
        h.flush()
        os.fsync(h.fileno())


def load_private(p):
    s = p.lstat()
    raw = p.read_bytes()
    v = json.loads(raw)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != os.getuid()
        or s.st_nlink != 1
        or raw != canonical(v)
    ):
        raise SystemExit("private artifact metadata differs")
    return v, raw


def fingerprint(raw):
    text = raw.decode("utf-8", "strict")
    values = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = re.search(r"(ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?: [^\r\n]*)?)$", line)
        if not m:
            raise SystemExit("authorized-key line is malformed")
        r = subprocess.run(
            ("ssh-keygen", "-lf", "-"),
            input=m.group(1) + "\n",
            text=True,
            capture_output=True,
        )
        if r.returncode or r.stderr:
            raise SystemExit("authorized-key fingerprint unavailable")
        values.append(r.stdout.split()[1])
    return sorted(values)


def policy(raw):
    text = raw.decode()
    sec = text.split("      access_cutover:\n", 1)
    if len(sec) != 2:
        raise SystemExit("access policy unavailable")
    sec = sec[1].split("      domain_handoffs:\n", 1)[0]
    state = re.search(r"^        state: (ready|complete)$", sec, re.MULTILINE)
    target = re.search(
        r"^        conventional_keys_target: (absent)$", sec, re.MULTILINE
    )
    recovery_age = re.search(r"^  evidence_max_age_days: 90$", text, re.MULTILINE)
    if not state or not target or recovery_age is None:
        raise SystemExit("final access policy differs")
    return state.group(1)


def validate_recovery_timestamp(completed_epoch, now):
    if not isinstance(completed_epoch, int) or isinstance(completed_epoch, bool):
        raise SystemExit("qualified recovery timestamp differs")
    completed = datetime.fromtimestamp(completed_epoch, timezone.utc)
    age = now - completed
    if age.total_seconds() < 0 or age > timedelta(days=RECOVERY_MAX_AGE_DAYS):
        raise SystemExit("qualified recovery evidence is stale")
    return completed


def recovery_proof(now=None):
    s = RECOVERY.lstat()
    raw = RECOVERY.read_bytes()
    v = json.loads(raw)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != os.getuid()
        or s.st_nlink != 1
        or sha(raw) != RECOVERY_SHA
        or v.get("state") != "restored-verified"
        or v.get("vmid") != 9900
        or v.get("restore", {}).get("state") != "restored-verified"
        or v.get("restore", {}).get("repository_id") != RECOVERY_REPOSITORY_ID
        or v.get("restore", {}).get("snapshot_id") != RECOVERY_SNAPSHOT_ID
    ):
        raise SystemExit("qualified recovery evidence differs")
    journal_info = RECOVERY_JOURNAL.lstat()
    journal_raw = RECOVERY_JOURNAL.read_bytes()
    journal = json.loads(journal_raw)
    if (
        not stat.S_ISREG(journal_info.st_mode)
        or stat.S_IMODE(journal_info.st_mode) != 0o600
        or journal_info.st_uid != os.getuid()
        or journal_info.st_nlink != 1
        or sha(journal_raw) != RECOVERY_JOURNAL_SHA
        or journal_raw != canonical(journal)
        or journal.get("commit") != RECOVERY_COMMIT
        or journal.get("state") != "destroy-applied"
    ):
        raise SystemExit("qualified recovery journal differs")
    completions = [
        item
        for item in journal.get("checkpoints", [])
        if item.get("state") == "run-complete"
    ]
    if len(completions) != 1:
        raise SystemExit("qualified recovery completion timestamp differs")
    completed = validate_recovery_timestamp(
        completions[0].get("time"), now or datetime.now(timezone.utc)
    )
    return {
        "commit": RECOVERY_COMMIT,
        "sha256": RECOVERY_SHA,
        "journal_sha256": RECOVERY_JOURNAL_SHA,
        "completed_at": completed.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "maximum_age_days": RECOVERY_MAX_AGE_DAYS,
        "repository_id": v["restore"]["repository_id"],
        "snapshot_id": v["restore"]["snapshot_id"],
    }


def observe():
    paths = sorted(set(AUTHORIZED_KEY_CATALOG) | set(RETAINED))
    program = f"""import grp,hashlib,json,os,pwd,stat,subprocess
paths={paths!r}
accounts={list(ACCOUNT_NAMES)!r}
def meta(p):
 try:s=os.lstat(p)
 except FileNotFoundError:return {{"exists":False}}
 v={{"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"size":s.st_size}}
 if v["regular"]:
  raw=open(p,"rb").read();v["sha256"]=hashlib.sha256(raw).hexdigest();v["bytes_hex"]=raw.hex()
 if v["symlink"]:v["target"]=os.readlink(p)
 return v
def account(name):
 try:value=pwd.getpwnam(name)
 except KeyError:return {{"exists":False,"group_exists":name in [g.gr_name for g in grp.getgrall()],"home_exists":os.path.lexists("/home/"+name),"sudo_exists":os.path.lexists("/etc/sudoers.d/"+name)}}
 status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True);fields=status.stdout.split()
 return {{"exists":True,"home":value.pw_dir,"shell":value.pw_shell,"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(name,value.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {{"L","LK"}}}}
def sshd():
 out=subprocess.run(["/usr/sbin/sshd","-T"],capture_output=True,text=True,check=True).stdout;v={{"allow_users":[],"authorized_keys_file":[],"pubkey_authentication":None,"password_authentication":None,"kbd_interactive_authentication":None,"permit_root_login":None}};mapping={{"allowusers":"allow_users","authorizedkeysfile":"authorized_keys_file","pubkeyauthentication":"pubkey_authentication","passwordauthentication":"password_authentication","kbdinteractiveauthentication":"kbd_interactive_authentication","permitrootlogin":"permit_root_login"}}
 for line in out.splitlines():
  k,_,x=line.partition(" ");m=mapping.get(k)
  if m:v[m]=x.split() if m in {{"allow_users","authorized_keys_file"}} else x
 return v
items=json.loads(subprocess.run(["/usr/sbin/pveum","user","token","list","root@pam","--output-format","json"],capture_output=True,text=True,check=True).stdout)
root=pwd.getpwnam("root");apex=grp.getgrnam("apex")
print(json.dumps({{"paths":{{p:meta(p) for p in paths}},"accounts":{{name:account(name) for name in accounts}},"sshd":sshd(),"locks":[p for p in {LOCKS!r} if os.path.lexists(p)],"tokens":sorted([{{"tokenid":i["tokenid"],"privsep":i["privsep"]}} for i in items],key=lambda i:i["tokenid"]),"root_groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist("root",root.pw_gid)),"apex":{{"gid":apex.gr_gid,"members":sorted(apex.gr_mem)}}}},sort_keys=True,separators=(",",":")))
"""
    r = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
        timeout=120,
    )
    if r.returncode or r.stderr:
        raise SystemExit("final key observation failed")
    return json.loads(r.stdout)


def expected_present(o):
    p = o["paths"]
    root = p[ROOT_KEY]
    link = p[ROOT_LINK]
    fw = p[FIREWALL_KEY]
    root_ok = (
        all(
            root.get(k) == v
            for k, v in {
                "exists": True,
                "uid": 0,
                "gid": 33,
                "mode": "0600",
                "regular": True,
                "symlink": False,
                "nlink": 1,
            }.items()
        )
        and fingerprint(bytes.fromhex(root["bytes_hex"])) == ROOT_FPS
    )
    link_ok = all(
        link.get(k) == v
        for k, v in {
            "exists": True,
            "uid": 0,
            "gid": 0,
            "mode": "0777",
            "regular": False,
            "symlink": True,
            "nlink": 1,
            "target": ROOT_KEY,
        }.items()
    )
    fw_ok = all(
        fw.get(k) == v
        for k, v in {
            "exists": True,
            "uid": 1003,
            "gid": 1004,
            "mode": "0600",
            "regular": True,
            "symlink": False,
            "nlink": 1,
        }.items()
    ) and fingerprint(bytes.fromhex(fw["bytes_hex"])) == [FIREWALL_FP]
    non_targets_absent = all(
        p[path] == {"exists": False}
        for path in AUTHORIZED_KEY_CATALOG
        if path not in PATHS
    )
    return root_ok and link_ok and fw_ok and non_targets_absent


def retained_content_ok(paths, root=ROOT):
    for path, content in SUDO_CONTENT.items():
        if bytes.fromhex(paths[path].get("bytes_hex", "")) != content.encode():
            return False
    for path, source in TRANSPORT_SOURCES.items():
        if paths[path].get("sha256") != sha((root / source).read_bytes()):
            return False
    return True


def retained_ok(o, allowed_sshd=(SSHD_BEFORE,)):
    return (
        all(
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
        and retained_content_ok(o["paths"])
        and o["accounts"]
        == {
            **RETAINED_ACCOUNTS,
            **{
                name: {
                    "exists": False,
                    "group_exists": False,
                    "home_exists": False,
                    "sudo_exists": False,
                }
                for name in RETIRED_ACCOUNTS
            },
        }
        and o["tokens"] == TOKENS
        and o["sshd"] in allowed_sshd
        and o["root_groups"] == ["root"]
        and o["apex"] == {"gid": 1000, "members": []}
    )


def build_plan(commit, contract_raw, o, now):
    findings = []
    state = policy(contract_raw)
    proof = None
    if o["locks"]:
        findings.append("protected-lock-active")
    present = expected_present(o)
    absent = all(o["paths"][p] == {"exists": False} for p in AUTHORIZED_KEY_CATALOG)
    allowed_sshd = (
        (SSHD_BEFORE,) if present else (SSHD_BEFORE, SSHD_FINAL) if absent else ()
    )
    if not retained_ok(o, allowed_sshd):
        findings.append("retained-access-authority-differs")
    if not present and not absent:
        findings.append("conventional-key-state-differs")
    if present:
        proof = recovery_proof(now)
    actions = (
        [{"kind": "remove-final-conventional-key-paths", "paths": list(PATHS)}]
        if present and not findings
        else []
    )
    created = now.replace(microsecond=0)
    blockers = (
        [
            "physical-console-attestation-required",
            "durable-rollback-required",
            "separate-authorization-required",
        ]
        if actions
        else []
    )
    return {
        "format": "home-lab-proxmox-final-key-retirement-plan-v1",
        "commit": commit,
        "contract_sha256": sha(contract_raw),
        "inventory_sha256": sha(INVENTORY.read_bytes()),
        "host_key_fingerprint": HOST_FP,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(minutes=30))
        .isoformat()
        .replace("+00:00", "Z"),
        "access_cutover_state": state,
        "recovery_evidence": proof,
        "before": {p: o["paths"][p] for p in AUTHORIZED_KEY_CATALOG},
        "after": {p: {"exists": False} for p in AUTHORIZED_KEY_CATALOG},
        "retained_accounts": {name: o["accounts"][name] for name in RETAINED_ACCOUNTS},
        "retired_accounts": {name: o["accounts"][name] for name in RETIRED_ACCOUNTS},
        "retained_assets": {p: o["paths"][p] for p in RETAINED},
        "retained_tokens": TOKENS,
        "retained_sshd_policy": o["sshd"],
        "root_group_state": {
            "root_groups": ["root"],
            "apex": {"gid": 1000, "members": []},
        },
        "actions": actions,
        "findings": findings,
        "blockers": findings + blockers,
        "authorized": False,
        "explicit_exclusions": [
            "accounts",
            "groups",
            "sudoers",
            "fixed-transports",
            "pve-api-tokens",
            "openssh-policy",
            "host-keys",
            "firewall-policy",
        ],
    }


def plan():
    raw = CONTRACT.read_bytes()
    v = build_plan(clean_commit(), raw, observe(), datetime.now(timezone.utc))
    encoded = canonical(v)
    digest = sha(encoded)
    p = OUTPUT / f"final-keys-{digest}.json"
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
    if (
        p.name != f"final-keys-{digest}.json"
        or v.get("format") != "home-lab-proxmox-final-key-retirement-plan-v1"
        or v.get("commit") != clean_commit()
        or v.get("contract_sha256") != sha(contract)
        or v.get("inventory_sha256") != sha(INVENTORY.read_bytes())
        or v.get("host_key_fingerprint") != HOST_FP
        or v.get("access_cutover_state") != policy(contract)
        or v.get("authorized") is not False
        or v.get("recovery_evidence") != recovery_proof()
        or datetime.now(timezone.utc)
        > datetime.fromisoformat(v["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("final key plan binding differs")
    return v, raw, digest


def complete_evidence(v):
    p = v.get("proofs", {})
    return (
        p.get("strict_host_key") is True
        and p.get("plan_observer", {}).get("positive") is True
        and p.get("plan_observer", {}).get("injection_rejected") is True
        and p.get("deploy_transport", {}).get("positive") is True
        and p.get("deploy_transport", {}).get("injection_rejected") is True
        and p.get("firewall_transport", {}).get("positive") is True
        and p.get("firewall_transport", {}).get("injection_rejected") is True
        and p.get("human_session", {}).get("positive") is True
        and p.get("tailnet_policy", {}).get("tests_present") is True
        and p.get("tailnet_policy", {}).get("live_plan_noop") is True
        and p.get("root_keys", {}).get("complete") is True
        and p.get("console")
        == {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}
    )


def validate_access_evidence(value, raw, plan, expected_root_fingerprints):
    if len(raw) > 262144 or raw != canonical(value):
        raise SystemExit("access evidence encoding or size differs")
    top = {
        "format",
        "draft_sha256",
        "commit",
        "contract_sha256",
        "inventory_sha256",
        "host_key_fingerprint",
        "created_at",
        "expires_at",
        "proofs",
        "console_attested_at",
    }
    if (
        set(value) != top
        or value.get("format") != "home-lab-proxmox-access-evidence-v1"
    ):
        raise SystemExit("access evidence schema differs")
    if (
        value.get("commit") != plan["commit"]
        or value.get("contract_sha256") != plan["contract_sha256"]
        or value.get("inventory_sha256") != plan["inventory_sha256"]
        or value.get("host_key_fingerprint") != HOST_FP
        or not isinstance(value.get("draft_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["draft_sha256"]) is None
    ):
        raise SystemExit("access evidence source binding differs")
    try:
        created = datetime.fromisoformat(value["created_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        attested = datetime.fromisoformat(
            value["console_attested_at"].replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("access evidence timestamps differ") from error
    now = datetime.now(timezone.utc)
    if (
        created > attested
        or attested > now
        or expires <= created
        or (expires - created).total_seconds() != 1800
        or now > expires
    ):
        raise SystemExit("access evidence freshness differs")
    proofs = value.get("proofs")
    proof_keys = {
        "strict_host_key",
        "plan_observer",
        "firewall_transport",
        "deploy_transport",
        "human_session",
        "tailnet_policy",
        "root_keys",
        "console",
    }
    if (
        not isinstance(proofs, dict)
        or set(proofs) != proof_keys
        or not complete_evidence(value)
    ):
        raise SystemExit("access evidence proofs differ")
    hash_proofs = {
        "plan_observer": {"positive", "injection_rejected", "observation_sha256"},
        "firewall_transport": {"positive", "injection_rejected", "inspect_sha256"},
        "deploy_transport": {"positive", "injection_rejected", "marker_plan_sha256"},
    }
    for name, keys in hash_proofs.items():
        item = proofs[name]
        hash_key = next(key for key in keys if key.endswith("sha256"))
        if (
            set(item) != keys
            or re.fullmatch(r"[0-9a-f]{64}", item.get(hash_key, "")) is None
        ):
            raise SystemExit(f"access evidence {name} differs")
    if proofs["human_session"] != {"positive": True} or proofs["console"] != {
        "attested": True,
        "method": "physical-console-bootstrap-install-and-verify",
    }:
        raise SystemExit("access evidence session or console proof differs")
    tailnet = proofs["tailnet_policy"]
    base_tailnet = {
        "tests_present",
        "live_plan_noop",
        "expected_retirement_drift",
        "controller_plan_stdout_sha256",
    }
    drift_tailnet = base_tailnet | {
        "controller_plan_sha256",
        "retirement_drift_targets",
    }
    if (
        set(tailnet) not in (base_tailnet, drift_tailnet)
        or tailnet.get("tests_present") is not True
        or tailnet.get("live_plan_noop") is not True
        or re.fullmatch(
            r"[0-9a-f]{64}", tailnet.get("controller_plan_stdout_sha256", "")
        )
        is None
    ):
        raise SystemExit("access evidence tailnet proof differs")
    if tailnet.get("expected_retirement_drift") is True:
        permitted = {
            "/etc/sudoers.d/tofu-apply",
            "/etc/sudoers.d/tofu-plan",
            "/etc/ssh/sshd_config.d/60-home-lab.conf",
            "protected-access",
        }
        if (
            set(tailnet) != drift_tailnet
            or re.fullmatch(r"[0-9a-f]{64}", tailnet.get("controller_plan_sha256", ""))
            is None
            or not isinstance(tailnet.get("retirement_drift_targets"), list)
            or not set(tailnet["retirement_drift_targets"]).issubset(permitted)
            or (
                not expected_root_fingerprints
                and "protected-access" in tailnet["retirement_drift_targets"]
            )
        ):
            raise SystemExit("access evidence retirement drift differs")
    elif (
        tailnet.get("expected_retirement_drift") is not False
        or set(tailnet) != base_tailnet
    ):
        raise SystemExit("access evidence no-op proof differs")
    root_keys = proofs["root_keys"]
    if (
        set(root_keys)
        != {
            "records",
            "attributed",
            "attributed_count",
            "total_count",
            "unresolved",
            "complete",
        }
        or root_keys.get("attributed") != ACCESS_ATTRIBUTIONS
        or root_keys.get("unresolved") != []
        or root_keys.get("complete") is not True
    ):
        raise SystemExit("access evidence root-key catalog differs")
    records = root_keys.get("records")
    if not isinstance(records, list) or any(
        not isinstance(item, dict)
        or set(item) != {"bits", "fingerprint", "comment", "type"}
        or not isinstance(item["bits"], int)
        or isinstance(item["bits"], bool)
        or not 256 <= item["bits"] <= 16384
        or item["fingerprint"] not in ACCESS_ATTRIBUTIONS
        or not isinstance(item["comment"], str)
        or len(item["comment"]) > 1024
        or item["type"] not in {"RSA", "ED25519"}
        for item in records
    ):
        raise SystemExit("access evidence root-key records differ")
    fingerprints = sorted(item["fingerprint"] for item in records)
    if (
        fingerprints != sorted(expected_root_fingerprints)
        or len(fingerprints) != len(set(fingerprints))
        or root_keys.get("total_count") != len(records)
        or root_keys.get("attributed_count") != len(records)
    ):
        raise SystemExit("access evidence root-key set differs")


def stage(files, digest):
    base = f"/var/lib/home-lab/final-key-retirement/staged/{digest}"
    program = (
        f"import os,stat\nbase={base!r}\nos.makedirs(base,mode=0o700,exist_ok=False)\n"
    )
    for name, raw in files.items():
        program += f"p=os.path.join(base,{name!r});fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=os.fdopen(fd,'wb');h.write(bytes.fromhex({raw.hex()!r}));h.flush();os.fsync(h.fileno());h.close()\n"
    r = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
        timeout=120,
    )
    if r.returncode or r.stderr:
        raise SystemExit("final key bundle staging failed")
    return {name: f"{base}/{name}" for name in files}


def authorize(p, e):
    v, raw, digest = load_plan(p)
    evidence, eraw = load_private(e)
    edigest = sha(eraw)
    now = datetime.now(timezone.utc)
    validate_access_evidence(evidence, eraw, v, ROOT_FPS)
    req = [
        "physical-console-attestation-required",
        "durable-rollback-required",
        "separate-authorization-required",
    ]
    if (
        v["actions"]
        != [{"kind": "remove-final-conventional-key-paths", "paths": list(PATHS)}]
        or v["findings"]
        or v["blockers"] != req
        or evidence.get("commit") != v["commit"]
        or evidence.get("contract_sha256") != v["contract_sha256"]
        or evidence.get("inventory_sha256") != v["inventory_sha256"]
        or not complete_evidence(evidence)
        or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("fresh complete console evidence differs")
    confirmation = f"authorize-proxmox-final-keys-{digest}-{edigest}"
    if os.environ.get("PROXMOX_FINAL_KEY_AUTHORIZATION_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")
    created = now.replace(microsecond=0)
    auth = {
        "format": "home-lab-proxmox-final-key-retirement-authorization-v1",
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
    local = OUTPUT / f"authorization-{adigest}.json"
    write_private(local, araw)
    staged = stage(
        {
            p.name: raw,
            f"evidence-{edigest}.json": eraw,
            f"authorization-{adigest}.json": araw,
        },
        digest,
    )
    print(
        json.dumps(
            {"plan_sha256": digest, "authorization_sha256": adigest, "staged": staged},
            sort_keys=True,
        )
    )


def session(target, command, options=(), expect=True):
    r = subprocess.run(
        (*SSH, *options, target, command), text=True, capture_output=True, timeout=120
    )
    if expect and r.returncode:
        raise SystemExit(f"canary failed: {target}")
    if not expect and r.returncode == 0:
        raise SystemExit(f"negative canary unexpectedly passed: {target}")
    return r


def canary(p):
    _v, _, digest = load_plan(p)
    o = observe()
    if not all(o["paths"][x] == {"exists": False} for x in PATHS) or not retained_ok(o):
        raise SystemExit("final key postcondition differs")
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
    snippet = b"#cloud-config\nhostname: access-canary\n"
    sd = sha(snippet)
    stage = subprocess.run(
        (*SSH, "ansible-deploy@proxmox", f"restic-recovery stage-snippet {sd}"),
        input=snippet,
        capture_output=True,
        timeout=120,
    )
    if stage.returncode:
        raise SystemExit("fixed Restic stage canary failed")
    session("ansible-deploy@proxmox", f"restic-recovery remove-snippet {sd}")
    key = Path.home() / ".ssh/home-lab-arch-ansible"
    firewall_key = Path.home() / ".ssh/home-lab-proxmox-firewall"
    if fingerprint(
        subprocess.run(
            ("ssh-keygen", "-y", "-f", str(key)), capture_output=True, check=True
        ).stdout
    ) != ["SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w"] or fingerprint(
        subprocess.run(
            ("ssh-keygen", "-y", "-f", str(firewall_key)),
            capture_output=True,
            check=True,
        ).stdout
    ) != [FIREWALL_FP]:
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
        "plan": True,
        "deploy": True,
        "firewall": True,
        "human": True,
        "fixed_restic": True,
        "root_conventional_rejected": True,
        "firewall_conventional_rejected": True,
        "paths_absent": True,
        "retained_authority": True,
    }
    receipt = {
        "format": "home-lab-proxmox-final-key-retirement-canary-v1",
        "plan_sha256": digest,
        "captured_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "checks": checks,
    }
    rr = canonical(receipt)
    rd = sha(rr)
    local = OUTPUT / f"canary-{rd}.json"
    write_private(local, rr)
    dest = f"/var/lib/home-lab/final-key-retirement/{digest}/candidate-canary.json"
    program = f"import os\nraw=bytes.fromhex({rr.hex()!r});fd=os.open({dest!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=os.fdopen(fd,'wb');h.write(raw);h.flush();os.fsync(h.fileno());h.close()\n"
    r = subprocess.run(
        (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"),
        input=program,
        text=True,
        capture_output=True,
    )
    if r.returncode or r.stderr:
        raise SystemExit("canary staging failed")
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
