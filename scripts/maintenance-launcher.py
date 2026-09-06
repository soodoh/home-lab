#!/usr/bin/env python3
"""Copy reviewed bytes outside the checkout before scheduling; never load repository Python."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import secrets
import stat
import subprocess
import sys
import time

MAX = 1048576
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
FLAGS = {"authorized": False, "automatic_apply": False, "automatic_reboot": False, "automatic_retry_allowed": False}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            if k in value:
                raise ValueError("duplicate field")
            value[k] = v
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    if canonical(value) != raw:
        raise ValueError("noncanonical input")
    return value


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError("unexpected fields")


def parents(path):
    if not path.is_absolute():
        raise ValueError("absolute path required")
    for parent in [path.parent, *path.parent.parents]:
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()):
            raise ValueError("unsafe ancestor")
        if s.st_mode & 0o022 and not (s.st_uid == 0 and s.st_mode & stat.S_ISVTX):
            raise ValueError("writable ancestor")


def regular(path, mode=0o600, limit=MAX):
    path = Path(path)
    parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid not in (0, os.getuid()) or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= limit:
            raise ValueError("unsafe file")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        current = path.lstat()
        # Reading may update atime. Compare stable identity/security fields and
        # nanosecond change times instead of stat_result's float-time tuple.
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) or
               getattr(after, field) != getattr(current, field) for field in fields) or len(raw) != before.st_size:
            raise ValueError("file changed")
        return raw
    finally:
        os.close(fd)


def bounded(argv, data=None, timeout=60, env=None, pass_fds=()):
    """One attempt, bounded stdout/stderr, no shell, no child output in diagnostics."""
    # Inputs are at most 1 MiB; tempfile avoids a pipe write deadlock.
    import tempfile
    with tempfile.TemporaryFile() as stdin:
        if data is not None:
            if len(data) > MAX:
                raise ValueError("input too large")
            stdin.write(data)
            stdin.seek(0)
        p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=ENV if env is None else env, pass_fds=pass_fds, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(p.stdout, selectors.EVENT_READ)
        selector.register(p.stderr, selectors.EVENT_READ)
        output = bytearray()
        length = 0
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError("command timed out")
                for key, _ in selector.select(min(0.1, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    length += len(chunk)
                    if length > MAX:
                        raise ValueError("command output too large")
                    if key.fileobj is p.stdout:
                        output.extend(chunk)
                    else:
                        raise ValueError("command diagnostic rejected")
            if p.wait(timeout=max(0.01, deadline-time.monotonic())):
                raise ValueError("command failed")
            return bytes(output)
        finally:
            if p.poll() is None:
                import signal
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
            selector.close()
            p.stdout.close()
            p.stderr.close()


def stamp():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def epoch(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ValueError("invalid timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


def expires(now):
    return dt.datetime.fromtimestamp(epoch(now)+86400, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_config(path):
    c = parse(regular(path))
    exact(c, "format repository reviewed_commit contract_sha256 launcher_sha256 node node_sha256 python python_sha256 output inputs known_hosts capability_evidence challenge_capabilities hosts")
    if c["format"] != "home-lab-maintenance-controller-v1":
        raise ValueError("config version")
    for field in ("contract_sha256", "launcher_sha256", "node_sha256", "python_sha256"):
        if not re.fullmatch("[0-9a-f]{64}", c[field]):
            raise ValueError("digest")
    if not re.fullmatch("[0-9a-f]{40}", c["reviewed_commit"]):
        raise ValueError("revision")
    if sha(regular(Path(__file__).absolute(), 0o755)) != c["launcher_sha256"]:
        raise ValueError("launcher bytes differ")
    for binary in ("node", "python"):
        if sha(regular(c[binary], 0o755, 200*MAX)) != c[binary+"_sha256"]:
            raise ValueError("runtime bytes differ")
    repo = Path(c["repository"])
    if Path(__file__).absolute().is_relative_to(repo):
        raise ValueError("schedule requires installed launcher outside checkout")
    parents(repo / "sentinel")
    git = ["/usr/bin/git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(repo)]
    if bounded([*git, "rev-parse", "HEAD"]).decode().strip() != c["reviewed_commit"] or bounded([*git, "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("reviewed clean source required")
    # Status alone is insufficient (assume-unchanged, skip-worktree or clean filters).
    # Verify the executable dependency closure against committed blobs, before running it.
    for name in ("scripts/maintenance-launcher.py", "scripts/controller/maintenance-report.js",
                 "scripts/controller/maintenance-package-candidate.js", "scripts/controller/package-transaction-lock.js",
                 "scripts/controller/controller-apply-lock.py", "scripts/controller/controller_lock.py"):
        raw = regular(repo / name, 0o644 if name in ("scripts/controller/controller_lock.py", "scripts/controller/package-transaction-lock.js") else 0o755)
        if raw != bounded([*git, "show", c["reviewed_commit"]+":"+name]):
            raise ValueError("executable source differs from review")
        if name == "scripts/maintenance-launcher.py" and sha(raw) != c["launcher_sha256"]:
            raise ValueError("installed launcher differs from reviewed source")
    if sha(regular(repo / "infrastructure/contract/home-lab.yml", 0o644)) != c["contract_sha256"]:
        raise ValueError("contract differs")
    exact(c["hosts"], "debian proxmox")
    exact(c["challenge_capabilities"], "debian proxmox")
    for value in c["challenge_capabilities"].values():
        if value is not None:
            exact(value, "known_hosts attestation package_artifact")
    for host, inventory in (("debian", "infrastructure.yml"), ("proxmox", "proxmox-production.yml")):
        exact(c["hosts"][host], "host_key_fingerprint inventory_sha256")
        if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", c["hosts"][host]["host_key_fingerprint"]):
            raise ValueError("host trust")
        if sha(regular(repo / ("ansible/inventory/"+inventory), 0o644)) != c["hosts"][host]["inventory_sha256"]:
            raise ValueError("inventory differs")
    for name in ("output", "inputs"):
        directory = Path(c[name]); parents(directory / "sentinel")
        s = directory.lstat()
        if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise ValueError("protected directory required")
    return c


def context(c):
    return {"source_commit": c["reviewed_commit"], "contract_sha256": c["contract_sha256"], "hosts": c["hosts"]}


def receipt(c, host, topic, now, payload, provenance, evidence):
    return {"format": "home-lab-maintenance-input-v1", "source_commit": c["reviewed_commit"], "contract_sha256": c["contract_sha256"],
            "host": host, "topic": topic, "host_key_fingerprint": c["hosts"][host]["host_key_fingerprint"],
            "observed_at": now, "expires_at": expires(now), "payload": payload, "payload_sha256": sha(canonical(payload)),
            "provenance": provenance, "evidence_sha256": evidence}


def save(c, value, kind):
    raw = canonical(value)
    output = Path(c["output"])
    # Never purge receipts automatically or overwrite a failed attempt.
    if sum(1 for _ in output.iterdir()) >= 5000:
        raise ValueError("receipt retention capacity reached")
    path = output / (kind + "-" + sha(raw) + ".json")
    if path.exists():
        if regular(path) != raw:
            raise ValueError("receipt collision")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(output, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def capability(c, now):
    raw = regular(c["capability_evidence"])
    v = parse(raw)
    exact(v, "format source_commit contract_sha256 host host_key_fingerprint observed_at expires_at producer_sha256 transport_sha256 audit_sha256 audit_domain_count audit_parity audit_changed active_locks provenance")
    if v["format"] != "home-lab-maintenance-capability-attestation-v1" or v["provenance"] != "attestation-only" or v["source_commit"] != c["reviewed_commit"] or v["contract_sha256"] != c["contract_sha256"] or v["host"] != "proxmox" or v["host_key_fingerprint"] != c["hosts"]["proxmox"]["host_key_fingerprint"]:
        raise ValueError("capability binding")
    if not epoch(v["observed_at"]) <= epoch(now) < epoch(v["expires_at"]) <= epoch(v["observed_at"])+86400:
        raise ValueError("capability freshness")
    if v["audit_domain_count"] != 17 or v["audit_parity"] is not True or v["audit_changed"] != 0 or v["active_locks"] != []:
        raise ValueError("complete audit prerequisite")
    for field in ("producer_sha256", "transport_sha256", "audit_sha256"):
        if not re.fullmatch("[a-f0-9]{64}", v[field]):
            raise ValueError("capability digest")
    repo = Path(c["repository"])
    if sha(regular(repo / "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport", 0o755)) != v["transport_sha256"]:
        raise ValueError("transport source differs")
    # A protected reviewer attests generated installed producer bytes, not a runtime challenge.
    known = regular(c["known_hosts"])
    parts = known.decode().strip().split()
    if len(parts) != 3 or parts[:2] != ["proxmox", "ssh-ed25519"] or len(known.splitlines()) != 1:
        raise ValueError("dedicated known-host entry required")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(parts[2], validate=True)).digest()).decode().rstrip("=")
    if fingerprint != v["host_key_fingerprint"]:
        raise ValueError("host key differs")
    return sha(raw)


def ssh_argv(c, host="proxmox", challenge=None):
    known = c["known_hosts"] if challenge is None else c["challenge_capabilities"][host]["known_hosts"]
    destination = "proxmox" if host == "proxmox" else "docker-host"
    command = ["observe-package"] if challenge is None else ["observe", challenge, c["reviewed_commit"], c["contract_sha256"]]
    user = "ansible-plan" if challenge is None else "ansible-maintenance-plan"
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile="+known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
            "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentityAgent=none", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none",
            "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", user+"@"+destination, *command]


class CollectionFailure(ValueError):
    def __init__(self, code, evidence="0"*64):
        super().__init__(code)
        self.code = code
        self.evidence = evidence


def challenge_collect(c, host, now):
    spec = c["challenge_capabilities"][host]
    proof_raw = regular(spec["attestation"])
    proof = parse(proof_raw)
    exact(proof, "format source_commit contract_sha256 host host_key_fingerprint observed_at expires_at producer_sha256 package_sha256 transport_sha256 audit_sha256 complete_audit active_locks")
    if proof["format"] != "home-lab-maintenance-challenge-installation-v1" or proof["source_commit"] != c["reviewed_commit"] or proof["contract_sha256"] != c["contract_sha256"] or proof["host"] != host or proof["host_key_fingerprint"] != c["hosts"][host]["host_key_fingerprint"]:
        raise ValueError("challenge installation binding")
    if not epoch(proof["observed_at"]) <= epoch(now) < epoch(proof["expires_at"]) <= epoch(proof["observed_at"])+86400 or proof["complete_audit"] is not True or proof["active_locks"] != []:
        raise ValueError("challenge installation prerequisite")
    for field in ("producer_sha256", "package_sha256", "transport_sha256", "audit_sha256"):
        if not re.fullmatch("[a-f0-9]{64}", proof[field]):
            raise ValueError("challenge hash")
    repo = Path(c["repository"])
    for field, name in (("producer_sha256", "maintenance-read-only-observer"), ("transport_sha256", "maintenance-plan-transport")):
        if sha(regular(repo / "infrastructure/maintenance/host" / name, 0o755)) != proof[field]:
            raise ValueError("challenge installed source differs")
    if sha(regular(spec["package_artifact"], 0o755)) != proof["package_sha256"]:
        raise ValueError("reviewed rendered package artifact differs")
    known = regular(spec["known_hosts"])
    parts = known.decode().strip().split()
    destination = "proxmox" if host == "proxmox" else "docker-host"
    if len(parts) != 3 or parts[:2] != [destination, "ssh-ed25519"] or len(known.splitlines()) != 1:
        raise ValueError("challenge host entry")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(parts[2], validate=True)).digest()).decode().rstrip("=")
    if fingerprint != proof["host_key_fingerprint"]:
        raise ValueError("challenge host trust")
    nonce = secrets.token_hex(32)
    started = stamp()
    try:
        raw = bounded(ssh_argv(c, host, nonce), timeout=120)
    except Exception:
        raise CollectionFailure("transport-failed") from None
    evidence = sha(raw)
    try:
        wire = parse(raw)
        validate_wire(wire, c, host, nonce, proof, started, stamp())
        payload = node(c, "maintenance-package-candidate.js", {"context": context(c), "proposal": wire["package"]["proposal"], "expires_at": expires(wire["package"]["proposal"]["observed_at"])})
    except Exception:
        raise CollectionFailure("invalid-output", evidence) from None
    save(c, wire, "wire")
    return {topic: receipt(c, host, topic, wire["package"]["proposal"]["observed_at"] if topic == "package" else wire["observed_at"], value, "challenge-verified", evidence)
            for topic, value in (("package", payload), ("reboot", wire["reboot"]))}


def validate_wire(wire, c, host, nonce, proof, started, finished):
    exact(wire, "format host nonce source_commit contract_sha256 observed_at producer_sha256 package_sha256 transport_sha256 package reboot active_locks authorized automatic_apply automatic_reboot automatic_retry_allowed")
    if wire["format"] != "home-lab-maintenance-observation-v1" or wire["host"] != host or wire["nonce"] != nonce or wire["source_commit"] != c["reviewed_commit"] or wire["contract_sha256"] != c["contract_sha256"] or any(wire[field] != proof[field] for field in ("producer_sha256", "package_sha256", "transport_sha256")):
        raise ValueError("challenge response binding")
    if not epoch(started) <= epoch(wire["observed_at"]) <= epoch(finished) <= epoch(started)+120:
        raise ValueError("challenge clock")
    if any(wire[k] is not False for k in FLAGS) or wire["active_locks"] != []:
        raise ValueError("challenge locks or authority")
    exact(wire["package"], "proposal"); exact(wire["reboot"], "required backup_proven")
    if wire["reboot"]["required"] is not None and type(wire["reboot"]["required"]) is not bool:
        raise ValueError("reboot state")
    if wire["reboot"]["backup_proven"] is not False or wire["package"]["proposal"].get("host") != host:
        raise ValueError("challenge package/reboot binding")
    if not epoch(started) <= epoch(wire["package"]["proposal"]["observed_at"]) <= epoch(wire["observed_at"]):
        raise ValueError("challenge package timestamp")


def node(c, script, value):
    return parse(bounded([c["node"], str(Path(c["repository"]) / "scripts/controller" / script)], canonical(value)))


def collect(c):
    now = stamp(); records = []
    # Persist intent first: interruption cannot masquerade as a successful last run.
    save(c, {"format": "home-lab-maintenance-attempt-v1", "observed_at": now, **context(c), "state": "started", **FLAGS}, "attempt")
    for host in ("debian", "proxmox"):
        challenged = None
        if c["challenge_capabilities"][host] is not None:
            try:
                challenged = challenge_collect(c, host, now)
            except Exception as error:
                code = error.code if isinstance(error, CollectionFailure) else "prerequisite-invalid"
                evidence = error.evidence if isinstance(error, CollectionFailure) else "0"*64
                challenged = {topic: receipt(c, host, topic, now, {"failure": code}, "failed-collection", evidence) for topic in ("package", "reboot")}
        for topic in ("package", "reboot", "release", "pins", "migrations"):
            if topic in ("release", "pins", "migrations"):
                evidence = "0" * 64
                try:
                    raw = regular(Path(c["inputs"]) / (host+"-"+topic+".json"))
                    evidence = sha(raw)
                    record = parse(raw)
                    if not isinstance(record, dict) or record.get("host") != host or record.get("topic") != topic:
                        raise ValueError("local input slot differs")
                    # Reuse the actual schema/binding/payload consumer, not a
                    # second weaker Python schema. Stale evidence stays stale.
                    checked = node(c, "maintenance-report.js", {"context": context(c), "records": [record], "observed_at": now})
                    entry = next(e for e in checked["entries"] if e["host"] == host and e["topic"] == topic)
                    if entry["status"] == "invalid":
                        raise ValueError("local input invalid")
                except FileNotFoundError:
                    continue  # Missing is reported; old success is never restamped.
                except Exception:
                    record = receipt(c, host, topic, now, {"failure": "invalid-output"}, "failed-collection", evidence)
                records.append(record); save(c, record, "input")
                continue
            if challenged is not None:
                records.append(challenged[topic]); save(c, challenged[topic], "input")
                continue
            failure = "capability-unavailable"
            evidence = "0"*64
            if host == "proxmox" and topic == "package":
                failure = "prerequisite-invalid"
                try:
                    evidence = capability(c, now)
                    failure = "transport-failed"
                    raw = bounded(ssh_argv(c), timeout=120)
                    failure = "invalid-output"
                    proposal = parse(raw)
                    payload = node(c, "maintenance-package-candidate.js", {"context": context(c), "proposal": proposal, "expires_at": expires(proposal["observed_at"])})
                    record = receipt(c, host, topic, proposal["observed_at"], payload, "attestation-only", evidence)
                    records.append(record); save(c, record, "input")
                    continue
                except Exception:
                    pass
            record = receipt(c, host, topic, now, {"failure": failure}, "failed-collection", evidence)
            records.append(record); save(c, record, "input")
    report = node(c, "maintenance-report.js", {"context": context(c), "records": records, "observed_at": stamp()})
    save(c, report, "report")
    save(c, {"format": "home-lab-maintenance-attempt-v1", "observed_at": now, **context(c), "state": "finished", "report_sha256": report["report_sha256"], **FLAGS}, "attempt")
    print(json.dumps({"report_sha256": report["report_sha256"], "complete": report["complete"], **FLAGS}, sort_keys=True))


def main():
    p = argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument("--config", required=True, type=Path)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--collect", action="store_true")
    mode.add_argument("--locked", action="store_true")
    args = p.parse_args(); c = validate_config(args.config)
    if args.dry_run:
        template = Path(c["repository"]) / "infrastructure/maintenance/mac/home-lab.maintenance.plist"
        value = plistlib.loads(regular(template, 0o644))
        value["ProgramArguments"] = [c["python"], "-I", str(Path(__file__).absolute()), "--config", str(args.config), "--collect"]
        sys.stdout.buffer.write(plistlib.dumps(value)); return
    runner = str(Path(c["repository"]) / "scripts/controller/controller-apply-lock.py")
    prefix = [c["python"], "-I", runner]
    bindings = ["--repo-root", c["repository"], "--commit", c["reviewed_commit"], "--phase", "steady"]
    if args.collect:
        if any(k.startswith("RECONCILE_CONTROLLER_LOCK") for k in os.environ):
            raise ValueError("inherited lock not allowed")
        os.execve(c["python"], [*prefix, "run", *bindings, "--", c["python"], "-I", str(Path(__file__).absolute()), "--config", str(args.config), "--locked"], ENV)
    # Use existing lock verifier; do not inspect PID text or unlink mutexes.
    from_env = {k: v for k, v in os.environ.items() if k.startswith("RECONCILE_CONTROLLER_LOCK")}
    fd_text = os.environ.get("RECONCILE_CONTROLLER_LOCK_FD", "")
    if not fd_text.isdecimal():
        raise ValueError("lock inheritance required")
    bounded([*prefix, "verify", *bindings], env={**ENV, **from_env}, pass_fds=(int(fd_text),))
    collect(c)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("maintenance launcher refused; retain receipts and review setup", file=sys.stderr)
        sys.exit(65)
