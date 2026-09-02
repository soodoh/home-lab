#!/usr/bin/env python3
"""Physical-console executor for final Proxmox OpenSSH tightening."""

from __future__ import annotations

import argparse
import fcntl
import grp
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path("/root/home-lab")
HERE = Path(__file__).resolve().parent
SOURCE = (
    HERE / "proxmox-openssh-tightening.py"
    if (HERE / "proxmox-openssh-tightening.py").exists()
    else REPO / "scripts/controller/proxmox-openssh-tightening.py"
)
BASE = (
    HERE / "proxmox-final-key-retirement.py"
    if (HERE / "proxmox-final-key-retirement.py").exists()
    else REPO / "scripts/controller/proxmox-final-key-retirement.py"
)
SPEC = importlib.util.spec_from_file_location("openssh_planner", SOURCE)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
CONFIG = Path(P.CONFIG)
CONTRACT = REPO / "infrastructure/contract/home-lab.yml"
INVENTORY = REPO / "ansible/inventory/production.yml"
JOURNAL = Path("/var/lib/home-lab/openssh-tightening")
LOCK = Path(P.B.SHARED_LOCK)
WATCHDOG = 900


def canonical(v):
    return P.canonical(v)


def sha(v):
    return P.sha(v)


def fsync_dir(p):
    fd = os.open(p, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(p, raw):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as h:
        h.write(raw)
        h.flush()
        os.fsync(h.fileno())


def replace_private(p, raw):
    t = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    write_private(t, raw)
    os.replace(t, p)
    fsync_dir(p.parent)


def load_private(p):
    s = p.lstat()
    raw = p.read_bytes()
    v = json.loads(raw)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != 0
        or s.st_nlink != 1
        or raw != canonical(v)
    ):
        raise SystemExit(f"protected artifact differs: {p}")
    return v, raw


def console():
    if (
        os.geteuid() != 0
        or os.environ.get("SSH_CONNECTION")
        or not os.isatty(0)
        or not os.isatty(1)
    ):
        raise SystemExit("transaction requires direct root physical console")
    tty = os.ttyname(0)
    if not re.fullmatch(r"/dev/tty[0-9]+", tty) or os.ttyname(1) != tty:
        raise SystemExit("transaction requires matching /dev/ttyN")


def acquire(blocking=False):
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    s = os.fstat(fd)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != 0
        or s.st_nlink != 1
    ):
        os.close(fd)
        raise SystemExit("OpenSSH lock differs")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise SystemExit("OpenSSH transaction locked")
    return fd


def meta():
    s = CONFIG.lstat()
    raw = CONFIG.read_bytes()
    return {
        "exists": True,
        "uid": s.st_uid,
        "gid": s.st_gid,
        "mode": format(stat.S_IMODE(s.st_mode), "04o"),
        "regular": stat.S_ISREG(s.st_mode),
        "symlink": stat.S_ISLNK(s.st_mode),
        "nlink": s.st_nlink,
        "size": s.st_size,
        "sha256": sha(raw),
        "bytes_hex": raw.hex(),
    }


def effective():
    out = subprocess.run(
        ("/usr/sbin/sshd", "-T"), capture_output=True, text=True, check=True
    ).stdout
    v = {
        "allow_users": [],
        "pubkey_authentication": None,
        "password_authentication": None,
        "kbd_interactive_authentication": None,
        "permit_root_login": None,
    }
    mapping = {
        "allowusers": "allow_users",
        "pubkeyauthentication": "pubkey_authentication",
        "passwordauthentication": "password_authentication",
        "kbdinteractiveauthentication": "kbd_interactive_authentication",
        "permitrootlogin": "permit_root_login",
    }
    for line in out.splitlines():
        k, _, x = line.partition(" ")
        m = mapping.get(k)
        if m == "allow_users":
            v[m].append(x)
        elif m:
            v[m] = x
    return v


def keys_absent():
    return all(not os.path.lexists(p) for p in P.B.AUTHORIZED_KEY_CATALOG)


def account_state():
    values = {}
    for name in P.B.ACCOUNT_NAMES:
        try:
            value = pwd.getpwnam(name)
        except KeyError:
            values[name] = {
                "exists": False,
                "group_exists": any(group.gr_name == name for group in grp.getgrall()),
                "home_exists": os.path.lexists(f"/home/{name}"),
                "sudo_exists": os.path.lexists(f"/etc/sudoers.d/{name}"),
            }
            continue
        status = subprocess.run(
            ("/usr/bin/passwd", "--status", name), capture_output=True, text=True
        )
        fields = status.stdout.split()
        values[name] = {
            "exists": True,
            "home": value.pw_dir,
            "shell": value.pw_shell,
            "groups": sorted(
                grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, value.pw_gid)
            ),
            "password_locked": status.returncode == 0
            and len(fields) > 1
            and fields[1] in {"L", "LK"},
        }
    return values


def final_key_receipt():
    receipts = []
    root = JOURNAL.parent / "final-key-retirement"
    for receipt in sorted(root.glob("*/receipt.json")):
        state_path = receipt.parent / "state.json"
        for path in (receipt, state_path):
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != 0
                or info.st_gid != 0
                or info.st_nlink != 1
            ):
                raise SystemExit("final-key receipt metadata differs")
        receipt_raw = receipt.read_bytes()
        state_raw = state_path.read_bytes()
        receipts.append(
            {
                "path": str(receipt),
                "receipt_hex": receipt_raw.hex(),
                "receipt_sha256": sha(receipt_raw),
                "state_hex": state_raw.hex(),
                "state_sha256": sha(state_raw),
            }
        )
    watchdog_units = sorted(
        str(path) for path in Path("/etc/systemd/system").glob("home-lab-final-key-*")
    )
    return P.validate_final_key_receipt(
        {"receipts": receipts, "watchdog_units": watchdog_units}
    )


def retained(plan):
    for path, expected in plan["retained_assets"].items():
        item = Path(path)
        s = item.lstat()
        raw = item.read_bytes()
        current = {
            "exists": True,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "mode": format(stat.S_IMODE(s.st_mode), "04o"),
            "regular": stat.S_ISREG(s.st_mode),
            "symlink": stat.S_ISLNK(s.st_mode),
            "nlink": s.st_nlink,
            "size": s.st_size,
            "sha256": sha(raw),
            "bytes_hex": raw.hex(),
        }
        if current != expected:
            return False
    items = json.loads(
        subprocess.run(
            (
                "/usr/sbin/pveum",
                "user",
                "token",
                "list",
                "root@pam",
                "--output-format",
                "json",
            ),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    tokens = sorted(
        [{"tokenid": i["tokenid"], "privsep": i["privsep"]} for i in items],
        key=lambda x: x["tokenid"],
    )
    root = pwd.getpwnam("root")
    apex = grp.getgrnam("apex")
    groups = sorted(
        grp.getgrgid(g).gr_name for g in os.getgrouplist("root", root.pw_gid)
    )
    return (
        account_state() == {**plan["retained_accounts"], **plan["retired_accounts"]}
        and plan["retained_accounts"] == P.B.RETAINED_ACCOUNTS
        and plan["retired_accounts"]
        == {
            name: {
                "exists": False,
                "group_exists": False,
                "home_exists": False,
                "sudo_exists": False,
            }
            for name in P.B.RETIRED_ACCOUNTS
        }
        and tokens == plan["retained_tokens"] == P.B.TOKENS
        and {
            "root_groups": groups,
            "apex": {"gid": apex.gr_gid, "members": sorted(apex.gr_mem)},
        }
        == plan["root_group_state"]
    )


def service_state():
    return {
        "active": subprocess.run(
            ("/usr/bin/systemctl", "is-active", "--quiet", "ssh.service")
        ).returncode
        == 0,
        "enabled": subprocess.run(
            ("/usr/bin/systemctl", "is-enabled", "--quiet", "ssh.service")
        ).returncode
        == 0,
    }


def before(plan):
    return (
        meta() == plan["before"]["config"]
        and effective() == plan["before"]["effective"]
        and service_state()
        == plan["service_state"]
        == {"active": True, "enabled": True}
        and final_key_receipt() == plan["final_key_receipt"]
        and keys_absent()
        and retained(plan)
    )


def after(plan):
    return (
        meta() == plan["after"]["config"]
        and effective() == plan["after"]["effective"]
        and service_state() == {"active": True, "enabled": True}
        and final_key_receipt() == plan["final_key_receipt"]
        and keys_absent()
        and retained(plan)
    )


def validate_plan(path):
    plan, raw = load_private(path)
    digest = sha(raw)
    contract = CONTRACT.read_bytes()
    commit = subprocess.check_output(
        ("/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"), text=True
    ).strip()
    expected = [
        {
            "kind": "tighten-openssh-drop-in",
            "path": P.CONFIG,
            "reload_service": "ssh.service",
        }
    ]
    P.desired_policy(contract)
    if (
        path.name != f"openssh-{digest}.json"
        or plan.get("format") != "home-lab-proxmox-openssh-tightening-plan-v1"
        or plan.get("commit") != commit
        or plan.get("contract_sha256") != sha(contract)
        or plan.get("inventory_sha256") != sha(INVENTORY.read_bytes())
        or plan.get("host_key_fingerprint") != P.B.HOST_FP
        or plan.get("authorized") is not False
        or plan.get("actions") != expected
        or plan.get("findings")
        or plan.get("key_paths")
        != {path: {"exists": False} for path in P.B.AUTHORIZED_KEY_CATALOG}
        or plan.get("retained_accounts") != P.B.RETAINED_ACCOUNTS
        or plan.get("retired_accounts")
        != {
            name: {
                "exists": False,
                "group_exists": False,
                "home_exists": False,
                "sudo_exists": False,
            }
            for name in P.B.RETIRED_ACCOUNTS
        }
        or not P.B.retained_content_ok(plan.get("retained_assets", {}), REPO)
        or plan.get("retained_tokens") != P.B.TOKENS
        or not isinstance(plan.get("final_key_receipt"), dict)
        or plan.get("root_group_state")
        != {"root_groups": ["root"], "apex": {"gid": 1000, "members": []}}
        or plan.get("after", {}).get("effective") != P.final_effective()
        or bytes.fromhex(plan.get("after", {}).get("config", {}).get("bytes_hex", ""))
        != P.DESIRED
        or plan.get("explicit_exclusions")
        != [
            "authorized-keys",
            "accounts",
            "groups",
            "sudoers",
            "fixed-transports",
            "pve-api-tokens",
            "host-keys",
            "firewall-policy",
        ]
        or datetime.now(timezone.utc)
        > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("OpenSSH plan binding differs")
    if not before(plan):
        raise SystemExit("OpenSSH state changed after planning")
    return plan, raw, digest


def validate_auth(plan, digest, evidence_path, auth_path):
    evidence, eraw = load_private(evidence_path)
    auth, _ = load_private(auth_path)
    edigest = sha(eraw)
    now = datetime.now(timezone.utc)
    confirmation = f"authorize-proxmox-openssh-{digest}-{edigest}"
    P.B.validate_access_evidence(evidence, eraw, plan, [])
    if (
        not P.B.complete_evidence(evidence)
        or evidence.get("commit") != plan["commit"]
        or evidence.get("contract_sha256") != plan["contract_sha256"]
        or evidence.get("inventory_sha256") != plan["inventory_sha256"]
        or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("fresh complete console evidence differs")
    requirements = [
        "physical-console-attestation-required",
        "persistent-watchdog-required",
        "separate-authorization-required",
    ]
    try:
        created = datetime.fromisoformat(auth["created_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00"))
        plan_expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
        evidence_expires = datetime.fromisoformat(
            evidence["expires_at"].replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("OpenSSH authorization timestamps differ") from error
    expected_auth = {
        "format": "home-lab-proxmox-openssh-tightening-authorization-v1",
        "plan_sha256": digest,
        "evidence_sha256": edigest,
        "created_at": auth.get("created_at"),
        "expires_at": auth.get("expires_at"),
        "confirmation": confirmation,
        "authorized": True,
    }
    if (
        plan.get("blockers") != requirements
        or auth != expected_auth
        or created > now
        or expires <= created
        or (expires - created).total_seconds() > 900
        or expires > min(plan_expires, evidence_expires)
        or now > expires
    ):
        raise SystemExit("OpenSSH authorization differs")


def reject_locks():
    if any(os.path.lexists(path) for path in P.B.LOCKS):
        raise SystemExit("protected infrastructure lock active")


def state(j):
    return load_private(j / "state.json")[0]


def set_state(j, v):
    replace_private(j / "state.json", canonical(v))


def capture(j, plan, raw, digest):
    JOURNAL.mkdir(mode=0o700, exist_ok=True)
    j.mkdir(mode=0o700)
    write_private(j / "plan.json", raw)
    for name, source in [
        ("rollback-executor.py", Path(__file__)),
        ("proxmox-openssh-tightening.py", SOURCE),
        ("proxmox-final-key-retirement.py", BASE),
    ]:
        write_private(j / name, source.read_bytes())
        os.chmod(j / name, 0o700)
    set_state(j, {"status": "prepared", "plan_sha256": digest})
    fsync_dir(j)
    fsync_dir(JOURNAL)


def unit(d):
    return f"home-lab-openssh-{d[:16]}"


def arm(j, d, deadline):
    u = unit(d)
    service = Path(f"/etc/systemd/system/{u}.service")
    timer = Path(f"/etc/systemd/system/{u}.timer")
    write_private(
        service,
        f"[Unit]\nDescription=Rollback OpenSSH tightening {d}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {j}/rollback-executor.py rollback {j}\nRestart=on-failure\nRestartSec=5s\n".encode(),
    )
    os.chmod(service, 0o644)
    write_private(
        timer,
        f"[Unit]\nDescription=Watchdog OpenSSH tightening {d}\n[Timer]\nOnCalendar={deadline.replace('T', ' ').replace('Z', ' UTC')}\nPersistent=true\nAccuracySec=1s\nUnit={u}.service\n[Install]\nWantedBy=timers.target\n".encode(),
    )
    os.chmod(timer, 0o644)
    fsync_dir(service.parent)
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), check=True)
    subprocess.run(("/usr/bin/systemctl", "enable", "--now", f"{u}.timer"), check=True)
    fsync_dir(Path("/etc/systemd/system/timers.target.wants"))
    enabled = subprocess.run(
        ("/usr/bin/systemctl", "is-enabled", f"{u}.timer"),
        capture_output=True,
        text=True,
    )
    active = subprocess.run(
        ("/usr/bin/systemctl", "is-active", f"{u}.timer"),
        capture_output=True,
        text=True,
    )
    if (
        enabled.returncode
        or enabled.stdout.strip() != "enabled"
        or active.returncode
        or active.stdout.strip() != "active"
    ):
        raise SystemExit("OpenSSH watchdog durability differs")


def disarm(d, service=False):
    u = unit(d)
    subprocess.run(
        ("/usr/bin/systemctl", "disable", "--now", f"{u}.timer"), capture_output=True
    )
    if service:
        subprocess.run(
            ("/usr/bin/systemctl", "stop", f"{u}.service"), capture_output=True
        )
    for s in ("service", "timer"):
        Path(f"/etc/systemd/system/{u}.{s}").unlink(missing_ok=True)
    fsync_dir(Path("/etc/systemd/system"))
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), capture_output=True)


def candidate(j):
    return j / "60-home-lab.conf.candidate"


def write_config(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as h:
        h.write(raw)
        h.flush()
        os.fchown(h.fileno(), 0, 0)
        os.fchmod(h.fileno(), 0o644)
        os.fsync(h.fileno())
    fsync_dir(path.parent)


def reload_ssh():
    subprocess.run(("/usr/bin/systemctl", "reload", "ssh.service"), check=True)


def install(j, plan):
    if not before(plan):
        raise RuntimeError("OpenSSH precondition differs")
    c = candidate(j)
    write_config(c, P.DESIRED)
    subprocess.run(("/usr/sbin/sshd", "-t", "-f", str(c)), check=True)
    os.replace(c, CONFIG)
    fsync_dir(CONFIG.parent)
    subprocess.run(("/usr/sbin/sshd", "-t"), check=True)
    reload_ssh()
    if not after(plan):
        raise RuntimeError("OpenSSH postcondition differs")


def restore(j, current):
    plan, _ = load_private(j / "plan.json")
    prior = bytes.fromhex(plan["before"]["config"]["bytes_hex"])
    desired = P.DESIRED
    c = candidate(j)
    if c.exists():
        candidate_raw = c.read_bytes()
        if candidate_raw != desired and not (
            len(candidate_raw) < len(desired) and desired.startswith(candidate_raw)
        ):
            raise SystemExit("unknown OpenSSH candidate drift preserved")
        c.unlink()
        fsync_dir(c.parent)
    current_raw = CONFIG.read_bytes()
    if current_raw != prior:
        if current_raw != desired:
            raise SystemExit("unknown OpenSSH drift blocks rollback")
        replacement = j / "60-home-lab.conf.rollback"
        if replacement.exists():
            replacement_raw = replacement.read_bytes()
            if not (
                len(replacement_raw) < len(prior) and prior.startswith(replacement_raw)
            ):
                raise SystemExit("unknown OpenSSH rollback candidate drift preserved")
            replacement.unlink()
            fsync_dir(replacement.parent)
        write_config(replacement, prior)
        subprocess.run(("/usr/sbin/sshd", "-t", "-f", str(replacement)), check=True)
        os.replace(replacement, CONFIG)
        fsync_dir(CONFIG.parent)
    subprocess.run(("/usr/sbin/sshd", "-t"), check=True)
    reload_ssh()
    if not before(plan):
        raise SystemExit("OpenSSH rollback differs")


def rollback(j):
    fd = acquire(True)
    try:
        current = state(j)
        if current.get("status") in {"committed", "rolled-back"}:
            disarm(current["plan_sha256"])
            return
        if current.get("status") not in {
            "prepared",
            "mutation-started",
            "awaiting-canary",
        }:
            raise SystemExit("invalid OpenSSH rollback phase")
        restore(j, current)
        set_state(
            j,
            {
                **current,
                "status": "rolled-back",
                "rolled_back_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        disarm(current["plan_sha256"], True)
    finally:
        os.close(fd)


def apply(plan_path, evidence, authorization):
    console()
    fd = acquire()
    try:
        reject_locks()
        plan, raw, digest = validate_plan(plan_path)
        validate_auth(plan, digest, evidence, authorization)
        expected = f"apply-proxmox-openssh-{digest}"
        if os.environ.get("PROXMOX_OPENSSH_TIGHTENING_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        j = JOURNAL / digest
        capture(j, plan, raw, digest)
        reject_locks()
        if not before(plan):
            raise SystemExit("OpenSSH precondition changed before watchdog")
        deadline = (
            (datetime.now(timezone.utc) + timedelta(seconds=WATCHDOG))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        set_state(
            j, {**state(j), "watchdog_deadline": deadline, "watchdog_seconds": WATCHDOG}
        )
        arm(j, digest, deadline)
        set_state(
            j,
            {
                **state(j),
                "status": "mutation-started",
                "mutation_started_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        try:
            install(j, plan)
            set_state(
                j,
                {
                    **state(j),
                    "status": "awaiting-canary",
                    "mutated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except BaseException:
            restore(j, state(j))
            set_state(j, {**state(j), "status": "rolled-back"})
            disarm(digest)
            raise
    finally:
        os.close(fd)
    print(
        json.dumps(
            {"status": "awaiting-canary", "plan_sha256": digest, "journal": str(j)},
            sort_keys=True,
        )
    )


def validate_canary(v, d):
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
    if (
        v.get("format") != "home-lab-proxmox-openssh-tightening-canary-v1"
        or v.get("plan_sha256") != d
        or v.get("checks") != checks
    ):
        raise SystemExit("OpenSSH canary differs")
    age = (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(v["captured_at"].replace("Z", "+00:00"))
    ).total_seconds()
    if age < 0 or age > 300:
        raise SystemExit("OpenSSH canary stale")


def commit(j, canary):
    console()
    fd = acquire()
    try:
        current = state(j)
        if current.get("status") != "awaiting-canary":
            raise SystemExit("journal not awaiting canary")
        plan, raw = load_private(j / "plan.json")
        digest = sha(raw)
        receipt, craw = load_private(canary)
        validate_canary(receipt, digest)
        expected = f"commit-proxmox-openssh-{digest}-{sha(craw)}"
        if os.environ.get("PROXMOX_OPENSSH_TIGHTENING_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        if not after(plan):
            raise SystemExit("OpenSSH state changed before commit")
        write_private(j / "canary.json", craw)
        done = {
            **current,
            "format": "home-lab-proxmox-openssh-tightening-receipt-v1",
            "status": "committed",
            "canary_sha256": sha(craw),
            "committed_at": datetime.now(timezone.utc).isoformat(),
        }
        write_private(j / "receipt.json", canonical(done))
        set_state(j, done)
        disarm(digest)
    finally:
        os.close(fd)
    print(
        json.dumps(
            {
                "status": "committed",
                "plan_sha256": digest,
                "receipt": str(j / "receipt.json"),
            },
            sort_keys=True,
        )
    )


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("apply")
    a.add_argument("plan", type=Path)
    a.add_argument("evidence", type=Path)
    a.add_argument("authorization", type=Path)
    r = sp.add_parser("rollback")
    r.add_argument("journal", type=Path)
    c = sp.add_parser("commit")
    c.add_argument("journal", type=Path)
    c.add_argument("canary", type=Path)
    x = ap.parse_args()
    if x.cmd == "apply":
        apply(x.plan.resolve(), x.evidence.resolve(), x.authorization.resolve())
    elif x.cmd == "rollback":
        rollback(x.journal.resolve())
    else:
        commit(x.journal.resolve(), x.canary.resolve())


if __name__ == "__main__":
    main()
