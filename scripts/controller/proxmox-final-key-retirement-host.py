#!/usr/bin/env python3
"""Physical-console executor for final Proxmox conventional-key retirement."""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
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
    HERE / "proxmox-final-key-retirement.py"
    if (HERE / "proxmox-final-key-retirement.py").exists()
    else REPO / "scripts/controller/proxmox-final-key-retirement.py"
)
SPEC = importlib.util.spec_from_file_location("final_key_planner", SOURCE)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
CONTRACT = REPO / "infrastructure/contract/home-lab.yml"
INVENTORY = REPO / "ansible/inventory/production.yml"
ROOT = Path(P.ROOT_KEY)
LINK = Path(P.ROOT_LINK)
FIREWALL = Path(P.FIREWALL_KEY)
PATHS = (ROOT, LINK, FIREWALL)
CATALOG = tuple(Path(path) for path in P.AUTHORIZED_KEY_CATALOG)
JOURNAL = Path("/var/lib/home-lab/final-key-retirement")
LOCK = Path(P.SHARED_LOCK)
WATCHDOG = 900


def canonical(v):
    return (json.dumps(v, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(v):
    return hashlib.sha256(v).hexdigest()


def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as h:
        h.write(raw)
        h.flush()
        os.fsync(h.fileno())


def replace_private(path, raw):
    t = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    write_private(t, raw)
    os.replace(t, path)
    fsync_dir(path.parent)


def load_private(path):
    s = path.lstat()
    raw = path.read_bytes()
    v = json.loads(raw)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != 0
        or s.st_nlink != 1
        or raw != canonical(v)
    ):
        raise SystemExit(f"protected artifact metadata differs: {path}")
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


def lock(blocking=False):
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    s = os.fstat(fd)
    if (
        not stat.S_ISREG(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o600
        or s.st_uid != 0
        or s.st_nlink != 1
    ):
        os.close(fd)
        raise SystemExit("final key lock metadata differs")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise SystemExit("final key transaction locked")
    return fd


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def meta(path):
    try:
        s = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    v = {
        "exists": True,
        "uid": s.st_uid,
        "gid": s.st_gid,
        "mode": format(stat.S_IMODE(s.st_mode), "04o"),
        "regular": stat.S_ISREG(s.st_mode),
        "symlink": stat.S_ISLNK(s.st_mode),
        "nlink": s.st_nlink,
        "size": s.st_size,
    }
    if v["regular"]:
        raw = path.read_bytes()
        v["sha256"] = sha(raw)
        v["bytes_hex"] = raw.hex()
    if v["symlink"]:
        v["target"] = os.readlink(path)
    return v


def snapshot():
    return {str(x): meta(x) for x in CATALOG}


def sshd_policy():
    output = subprocess.run(
        ("/usr/sbin/sshd", "-T"), capture_output=True, text=True, check=True
    ).stdout
    value = {
        "allow_users": [],
        "authorized_keys_file": [],
        "pubkey_authentication": None,
        "password_authentication": None,
        "kbd_interactive_authentication": None,
        "permit_root_login": None,
    }
    mapping = {
        "allowusers": "allow_users",
        "authorizedkeysfile": "authorized_keys_file",
        "pubkeyauthentication": "pubkey_authentication",
        "passwordauthentication": "password_authentication",
        "kbdinteractiveauthentication": "kbd_interactive_authentication",
        "permitrootlogin": "permit_root_login",
    }
    for line in output.splitlines():
        key, _, item = line.partition(" ")
        selected = mapping.get(key)
        if selected == "allow_users":
            value[selected].append(item)
        elif selected == "authorized_keys_file":
            value[selected] = item.split()
        elif selected:
            value[selected] = item
    return value


def accounts():
    program = r"""import grp,json,os,pwd,subprocess
names=["proxmox","firewall-apply","ansible-plan","ansible-deploy","tofu-plan","tofu-apply"]
def account(name):
 try:value=pwd.getpwnam(name)
 except KeyError:return {"exists":False,"group_exists":name in [g.gr_name for g in grp.getgrall()],"home_exists":os.path.lexists("/home/"+name),"sudo_exists":os.path.lexists("/etc/sudoers.d/"+name)}
 status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True);fields=status.stdout.split()
 return {"exists":True,"home":value.pw_dir,"shell":value.pw_shell,"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(name,value.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"}}
print(json.dumps({name:account(name) for name in names},sort_keys=True,separators=(",",":")))"""
    return json.loads(
        subprocess.run(
            ("/usr/bin/python3", "-c", program),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )


def retained(plan):
    for path, expected in plan["retained_assets"].items():
        current = meta(Path(path))
        current.pop("bytes_hex", None)
        copy = dict(expected)
        copy.pop("bytes_hex", None)
        if current != copy:
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
        accounts() == {**plan["retained_accounts"], **plan["retired_accounts"]}
        and plan["retained_accounts"] == P.RETAINED_ACCOUNTS
        and plan["retired_accounts"]
        == {
            name: {
                "exists": False,
                "group_exists": False,
                "home_exists": False,
                "sudo_exists": False,
            }
            for name in P.RETIRED_ACCOUNTS
        }
        and tokens == P.TOKENS
        and sshd_policy() == plan["retained_sshd_policy"] == P.SSHD_BEFORE
        and {
            "root_groups": groups,
            "apex": {"gid": apex.gr_gid, "members": sorted(apex.gr_mem)},
        }
        == plan["root_group_state"]
    )


def exact_before(plan):
    return snapshot() == plan["before"] and retained(plan)


def exact_after(plan):
    return snapshot() == plan["after"] and retained(plan)


def validate_plan(path):
    plan, raw = load_private(path)
    digest = sha(raw)
    contract = CONTRACT.read_bytes()
    commit = subprocess.check_output(
        ("/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"), text=True
    ).strip()
    expected = [{"kind": "remove-final-conventional-key-paths", "paths": list(P.PATHS)}]
    recovery = plan.get("recovery_evidence", {})
    try:
        recovery_completed = datetime.fromisoformat(
            recovery.get("completed_at", "").replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as error:
        raise SystemExit("final key recovery timestamp differs") from error
    recovery_age = datetime.now(timezone.utc) - recovery_completed
    recovery_valid = (
        recovery
        == {
            "commit": P.RECOVERY_COMMIT,
            "sha256": P.RECOVERY_SHA,
            "journal_sha256": P.RECOVERY_JOURNAL_SHA,
            "completed_at": recovery.get("completed_at"),
            "maximum_age_days": P.RECOVERY_MAX_AGE_DAYS,
            "repository_id": P.RECOVERY_REPOSITORY_ID,
            "snapshot_id": P.RECOVERY_SNAPSHOT_ID,
        }
        and 0 <= recovery_age.total_seconds() <= P.RECOVERY_MAX_AGE_DAYS * 86400
    )
    if (
        path.name != f"final-keys-{digest}.json"
        or plan.get("format") != "home-lab-proxmox-final-key-retirement-plan-v1"
        or plan.get("commit") != commit
        or plan.get("contract_sha256") != sha(contract)
        or plan.get("inventory_sha256") != sha(INVENTORY.read_bytes())
        or plan.get("host_key_fingerprint") != P.HOST_FP
        or plan.get("access_cutover_state") != P.policy(contract)
        or plan.get("authorized") is not False
        or plan.get("actions") != expected
        or plan.get("findings")
        or not recovery_valid
        or plan.get("after") != {p: {"exists": False} for p in P.AUTHORIZED_KEY_CATALOG}
        or not P.retained_content_ok(plan.get("retained_assets", {}), REPO)
        or plan.get("retained_tokens") != P.TOKENS
        or plan.get("retained_sshd_policy") != P.SSHD_BEFORE
        or plan.get("root_group_state")
        != {"root_groups": ["root"], "apex": {"gid": 1000, "members": []}}
        or plan.get("explicit_exclusions")
        != [
            "accounts",
            "groups",
            "sudoers",
            "fixed-transports",
            "pve-api-tokens",
            "openssh-policy",
            "host-keys",
            "firewall-policy",
        ]
        or datetime.now(timezone.utc)
        > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("final key plan binding differs")
    if set(plan.get("before", {})) != set(
        P.AUTHORIZED_KEY_CATALOG
    ) or not P.expected_present({"paths": plan["before"]}):
        raise SystemExit("final key reviewed before-state differs")
    if not exact_before(plan):
        raise SystemExit("final key state changed after planning")
    return plan, raw, digest


def validate_auth(plan, digest, evidence_path, auth_path):
    evidence, eraw = load_private(evidence_path)
    auth, _ = load_private(auth_path)
    edigest = sha(eraw)
    now = datetime.now(timezone.utc)
    expected = f"authorize-proxmox-final-keys-{digest}-{edigest}"
    P.validate_access_evidence(evidence, eraw, plan, P.ROOT_FPS)
    if (
        not P.complete_evidence(evidence)
        or evidence.get("commit") != plan["commit"]
        or evidence.get("contract_sha256") != plan["contract_sha256"]
        or evidence.get("inventory_sha256") != plan["inventory_sha256"]
        or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
    ):
        raise SystemExit("fresh complete console evidence differs")
    requirements = [
        "physical-console-attestation-required",
        "durable-rollback-required",
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
        raise SystemExit("final key authorization timestamps differ") from error
    expected_auth = {
        "format": "home-lab-proxmox-final-key-retirement-authorization-v1",
        "plan_sha256": digest,
        "evidence_sha256": edigest,
        "created_at": auth.get("created_at"),
        "expires_at": auth.get("expires_at"),
        "confirmation": expected,
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
        raise SystemExit("final key authorization differs")


def ensure_journal(j):
    JOURNAL.mkdir(mode=0o700, exist_ok=True)
    s = JOURNAL.lstat()
    if (
        not stat.S_ISDIR(s.st_mode)
        or stat.S_ISLNK(s.st_mode)
        or stat.S_IMODE(s.st_mode) != 0o700
        or s.st_uid != 0
    ):
        raise SystemExit("journal root differs")
    j.mkdir(mode=0o700)
    fsync_dir(JOURNAL)


def state(j):
    return load_private(j / "state.json")[0]


def set_state(j, v):
    replace_private(j / "state.json", canonical(v))


def capture(j, plan, raw, digest):
    ensure_journal(j)
    write_private(j / "plan.json", raw)
    write_private(j / "rollback-executor.py", Path(__file__).read_bytes())
    os.chmod(j / "rollback-executor.py", 0o700)
    write_private(j / "proxmox-final-key-retirement.py", SOURCE.read_bytes())
    os.chmod(j / "proxmox-final-key-retirement.py", 0o700)
    for path in P.PATHS:
        item = plan["before"][path]
        write_private(
            j / (hashlib.sha256(path.encode()).hexdigest() + ".json"),
            canonical({"path": path, "metadata": item}),
        )
    set_state(j, {"status": "prepared", "plan_sha256": digest})
    fsync_dir(j)
    fsync_dir(JOURNAL)


def unit(d):
    return f"home-lab-final-key-{d[:16]}"


def arm(j, d, deadline):
    u = unit(d)
    service = Path(f"/etc/systemd/system/{u}.service")
    timer = Path(f"/etc/systemd/system/{u}.timer")
    write_private(
        service,
        f"[Unit]\nDescription=Rollback final key retirement {d}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {j}/rollback-executor.py rollback {j}\nRestart=on-failure\nRestartSec=5s\n".encode(),
    )
    os.chmod(service, 0o644)
    write_private(
        timer,
        f"[Unit]\nDescription=Watchdog final key retirement {d}\n[Timer]\nOnCalendar={deadline.replace('T', ' ').replace('Z', ' UTC')}\nPersistent=true\nAccuracySec=1s\nUnit={u}.service\n[Install]\nWantedBy=timers.target\n".encode(),
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
        raise SystemExit("watchdog durability barrier differs")


def disarm(d, service=False):
    u = unit(d)
    subprocess.run(
        ("/usr/bin/systemctl", "disable", "--now", f"{u}.timer"), capture_output=True
    )
    if service:
        subprocess.run(
            ("/usr/bin/systemctl", "stop", f"{u}.service"), capture_output=True
        )
    for suffix in ("service", "timer"):
        Path(f"/etc/systemd/system/{u}.{suffix}").unlink(missing_ok=True)
    fsync_dir(Path("/etc/systemd/system"))
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), capture_output=True)


def reject_locks():
    active = [p for p in P.LOCKS if p != str(LOCK) and os.path.lexists(p)]
    if active:
        raise SystemExit("protected infrastructure lock active")


def remove(plan):
    if not exact_before(plan):
        raise RuntimeError("key removal precondition differs")
    for path in (LINK, FIREWALL, ROOT):
        path.unlink()
        fsync_dir(path.parent)
    if not exact_after(plan):
        raise RuntimeError("key removal postcondition differs")


def rollback_marker(j, path, item):
    marker = j / f"restore-{hashlib.sha256(str(path).encode()).hexdigest()}.json"
    expected = {
        "format": "home-lab-final-key-restore-marker-v1",
        "path": str(path),
        "expected": item,
    }
    if marker.exists():
        value, _ = load_private(marker)
        if value != expected:
            raise SystemExit(f"rollback marker differs: {path}")
    return marker, expected


def restore_file(j, path, item):
    marker, marker_value = rollback_marker(j, path, item)
    current = meta(path)
    if current == item:
        if marker.exists():
            marker.unlink()
            fsync_dir(marker.parent)
        return
    if current == {"exists": False}:
        if not marker.exists():
            write_private(marker, canonical(marker_value))
            fsync_dir(marker.parent)
    elif marker.exists() and item["regular"] and current.get("regular") is True:
        expected_raw = bytes.fromhex(item["bytes_hex"])
        current_raw = bytes.fromhex(current["bytes_hex"])
        owned_partial = (
            len(current_raw) < len(expected_raw)
            and expected_raw.startswith(current_raw)
            and all(
                current.get(key) == item[key] for key in ("uid", "gid", "mode", "nlink")
            )
        )
        if not owned_partial:
            raise SystemExit(f"unknown drift blocks rollback: {path}")
        path.unlink()
        fsync_dir(path.parent)
    else:
        raise SystemExit(f"unknown drift blocks rollback: {path}")
    if item["symlink"]:
        os.symlink(item["target"], path)
        fsync_dir(path.parent)
    else:
        raw = bytes.fromhex(item["bytes_hex"])
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IMODE(int(item["mode"], 8)),
        )
        with os.fdopen(fd, "wb") as h:
            if path == ROOT:
                created = os.fstat(h.fileno())
                if created.st_uid != item["uid"] or created.st_gid != item["gid"]:
                    raise SystemExit("pmxcfs rollback ownership differs")
            else:
                os.fchown(h.fileno(), item["uid"], item["gid"])
            os.fchmod(h.fileno(), int(item["mode"], 8))
            owned = os.fstat(h.fileno())
            if (
                owned.st_uid != item["uid"]
                or owned.st_gid != item["gid"]
                or stat.S_IMODE(owned.st_mode) != int(item["mode"], 8)
            ):
                raise SystemExit(f"rollback ownership differs before write: {path}")
            h.write(raw)
            h.flush()
            os.fsync(h.fileno())
        fsync_dir(path.parent)
    if meta(path) != item:
        raise SystemExit(f"rollback differs: {path}")
    marker.unlink()
    fsync_dir(marker.parent)


def restore(j, current):
    plan, _ = load_private(j / "plan.json")
    # Restore the pmxcfs target before its root symlink.
    for path in (ROOT, LINK, FIREWALL):
        restore_file(j, path, plan["before"][str(path)])
    if not exact_before(plan):
        raise SystemExit("final key rollback differs")


def rollback(j):
    fd = lock(True)
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
            raise SystemExit("invalid rollback phase")
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
    fd = lock()
    try:
        reject_locks()
        plan, raw, digest = validate_plan(plan_path)
        validate_auth(plan, digest, evidence, authorization)
        expected = f"apply-proxmox-final-keys-{digest}"
        if os.environ.get("PROXMOX_FINAL_KEY_RETIREMENT_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        j = JOURNAL / digest
        capture(j, plan, raw, digest)
        reject_locks()
        if not exact_before(plan):
            raise SystemExit("key precondition changed before watchdog")
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
            remove(plan)
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


def validate_canary(v, digest):
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
    if (
        v.get("format") != "home-lab-proxmox-final-key-retirement-canary-v1"
        or v.get("plan_sha256") != digest
        or v.get("checks") != checks
    ):
        raise SystemExit("final key canary differs")
    age = (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(v["captured_at"].replace("Z", "+00:00"))
    ).total_seconds()
    if age < 0 or age > 300:
        raise SystemExit("final key canary stale")


def commit(j, canary):
    console()
    fd = lock()
    try:
        current = state(j)
        if current.get("status") != "awaiting-canary":
            raise SystemExit("journal not awaiting canary")
        plan, raw = load_private(j / "plan.json")
        digest = sha(raw)
        receipt, craw = load_private(canary)
        validate_canary(receipt, digest)
        expected = f"commit-proxmox-final-keys-{digest}-{sha(craw)}"
        if os.environ.get("PROXMOX_FINAL_KEY_RETIREMENT_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        if not exact_after(plan):
            raise SystemExit("final key state changed before commit")
        write_private(j / "canary.json", craw)
        done = {
            **current,
            "format": "home-lab-proxmox-final-key-retirement-receipt-v1",
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
