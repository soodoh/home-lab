#!/usr/bin/env python3
"""Non-authorizing fixture-only predecessor observation core.

Interface: observe(adapter) -> bounded dict; no caller-selected targets. There is
no production Adapter. Decoded manager primitives are an I/O seam, not a D-Bus
wire protocol or provenance certificate. Native PID1 pre-connect provenance,
EXTERNAL authentication, peer verification, wire/message/connection limits,
privileged descriptor operations and no-follow traversal remain unimplemented.

The finite Adapter contract is monotonic(), manager_get(fixed property),
boot_id(), open_pidfd(MainPID), open_proc(MainPID), read_stat(owned proc fd),
open_exe(owned proc fd), metadata(owned file fd), read(owned content fd, size),
open_dockerd(), open_packages(), exited(owned pidfd), close(owned fd). Descriptors
are unique nonnegative integers, ownership transfers on return. Metadata is
(dev, ino, size, mode, mtime_ns, ctime_ns); all scalars are integers, not bools.
The dockerd descriptor is metadata-only. File opening semantics belong to the
absent native Adapter, not to caller flags. Ordinary I/O errors are sanitized.
Confinement violations must derive from BaseException, not Exception.

Checks around synchronous calls are cooperative deadlines, not cancellation.
Matching samples never exclude away-and-back exec, pin loaded pages/libraries,
establish package ownership/source applicability, or permit startup/first stop.
"""
if __name__ == "__main__":
    raise SystemExit("production-unavailable")

import hashlib
import re


class _Stop(Exception):
    def __init__(self, outcome):
        self.outcome = outcome


def _integer(value, lower=0, upper=9223372036854775807):
    if type(value) is not int or not lower <= value <= upper:
        raise _Stop("malformed")
    return value


def _boot(raw):
    if type(raw) is not bytes:
        raise _Stop("malformed")
    if len(raw) > 64:
        raise _Stop("budget-exceeded")
    if not re.fullmatch(b"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\n?", raw):
        raise _Stop("malformed")
    return raw.rstrip(b"\n").decode("ascii")


def _stat(raw, pid):
    if type(raw) is not bytes:
        raise _Stop("malformed")
    if len(raw) > 4096:
        raise _Stop("budget-exceeded")
    left, right = raw.find(b" ("), raw.rfind(b") ")
    if left < 1 or right <= left or raw[:left] != str(pid).encode("ascii"):
        raise _Stop("malformed")
    fields = raw[right + 2:].split()
    if len(fields) < 20 or fields[0] not in (b"R", b"S", b"D", b"Z", b"T", b"t", b"X", b"x", b"K", b"W", b"P", b"I"):
        raise _Stop("malformed")
    if any(not re.fullmatch(b"-?[0-9]{1,20}", field) for field in fields[1:]):
        raise _Stop("malformed")
    return _integer(int(fields[19]))


def _metadata(raw):
    if type(raw) is not tuple or len(raw) != 6:
        raise _Stop("malformed")
    for value in raw:
        _integer(value)
    if raw[3] & 0o170000 != 0o100000:
        raise _Stop("unsupported")
    return raw


def _packages(raw):
    selected = []
    seen = set()
    for stanza in raw.split(b"\n\n"):
        lines = stanza.split(b"\n")
        names = [line[9:] for line in lines if line.startswith(b"Package: ")]
        if not any(name in (b"docker-ce", b"docker.io") for name in names):
            continue
        fields = {}
        key = None
        for line in lines:
            if not line:
                continue
            if line.startswith((b" ", b"\t")):
                # Only unprojected fields may have control-file continuations.
                if key is None or key in (b"Package", b"Version", b"Architecture", b"Status"):
                    raise _Stop("malformed")
                continue
            if b": " not in line:
                raise _Stop("malformed")
            key, value = line.split(b": ", 1)
            if key in fields:
                raise _Stop("malformed")
            fields[key] = value
        name = fields.get(b"Package")
        if name not in (b"docker-ce", b"docker.io") or name in seen:
            raise _Stop("malformed")
        seen.add(name)
        values = [fields.get(key) for key in (b"Version", b"Architecture", b"Status")]
        for value in values:
            if value is None:
                raise _Stop("malformed")
            if len(value) > 256:
                raise _Stop("budget-exceeded")
        version, architecture, status = values
        if not re.fullmatch(b"([0-9]+:)?[0-9][A-Za-z0-9.+:~\\-]*", version):
            raise _Stop("malformed")
        if not re.fullmatch(b"[a-z0-9][a-z0-9-]*", architecture):
            raise _Stop("malformed")
        if not re.fullmatch(b"(unknown|install|hold|deinstall|purge) (ok|reinstreq) (not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed)", status):
            raise _Stop("malformed")
        selected.append({"name": name.decode("ascii"), "version": version.decode("ascii"),
                         "architecture": architecture.decode("ascii"),
                         "status": status.split(b" ")[-1].decode("ascii")})
    return selected


def observe(adapter):
    """One fixed docker.service observation; results cannot authorize anything."""
    result = {"format": "predecessor-observation-v1", "outcome": "unsupported",
              "sampled": True, "atomic": False, "partial": {}}
    owned = []
    stage = "clock"
    last_time = None
    started = None

    def clock():
        nonlocal last_time, started
        value = adapter.monotonic()
        if type(value) not in (int, float) or not 0 <= value < float("inf"):
            raise _Stop("malformed")
        if last_time is not None and value < last_time:
            raise _Stop("malformed")
        last_time = value
        if started is None:
            started = value
        if value - started > 20:
            raise _Stop("budget-exceeded")
        return value

    def call(name, function, *args, deadline=None):
        nonlocal stage
        stage = name
        before = clock()
        if deadline is not None and before > deadline:
            raise _Stop("budget-exceeded")
        value = function(*args)
        after = clock()
        if name == "manager" and after - before > 1:
            raise _Stop("budget-exceeded")
        return value

    def acquire(name, function, *args):
        # Record ownership before the post-call deadline check, even on timeout.
        nonlocal stage
        stage = name
        clock()
        fd = function(*args)
        _integer(fd)
        if fd in owned:
            raise _Stop("malformed")
        owned.append(fd)
        clock()
        return fd

    def manager(previous=None):
        values = {}
        expected = {"Id": "docker.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        for prop in ("Id", "LoadState", "ActiveState", "SubState", "MainPID"):
            value = call("manager", adapter.manager_get, prop)
            if prop == "MainPID":
                values[prop] = _integer(value, 1, 2147483647)
            else:
                if type(value) is not str:
                    raise _Stop("malformed")
                if len(value) > 256:
                    raise _Stop("budget-exceeded")
                if previous is None and value != expected[prop]:
                    raise _Stop("prerequisite-unmet")
                values[prop] = value
            if previous is not None and values[prop] != previous[prop]:
                raise _Stop("changing")
        return values

    def poll(pidfd):
        value = call("exit", adapter.exited, pidfd)
        if type(value) is not bool:
            raise _Stop("malformed")
        if value:
            raise _Stop("changing")

    def content(fd, metadata, limit, hashing=False):
        if metadata[2] > limit:
            raise _Stop("budget-exceeded")
        begin = clock()
        total = 0
        digest = hashlib.sha256() if hashing else None
        chunks = []
        while True:
            requested = min(65536, metadata[2] - total + 1)
            chunk = call("executable" if hashing else "packages", adapter.read, fd, requested,
                         deadline=begin + 10 if hashing else None)
            if type(chunk) is not bytes:
                raise _Stop("malformed")
            if len(chunk) > requested or total + len(chunk) > limit:
                raise _Stop("budget-exceeded")
            if hashing and clock() - begin > 10:
                raise _Stop("budget-exceeded")
            if not chunk:
                if total != metadata[2]:
                    raise _Stop("changing")
                break
            total += len(chunk)
            if total > metadata[2]:
                raise _Stop("changing")
            if hashing:
                digest.update(chunk)
            else:
                chunks.append(chunk)
        if _metadata(call("executable" if hashing else "packages", adapter.metadata, fd)) != metadata:
            raise _Stop("changing")
        return (digest.hexdigest(), total) if hashing else b"".join(chunks)

    try:
        first = manager()
        pid = first["MainPID"]
        boot = _boot(call("boot", adapter.boot_id))
        result["partial"]["boot_id"] = boot
        pidfd = acquire("pidfd", adapter.open_pidfd, pid)
        poll(pidfd)
        proc = acquire("proc", adapter.open_proc, pid)
        start = _stat(call("stat", adapter.read_stat, proc), pid)
        result["partial"]["process"] = {"pid": pid, "start_ticks": start}
        exe = acquire("executable", adapter.open_exe, proc)
        original = _metadata(call("executable", adapter.metadata, exe))
        reopened = acquire("executable", adapter.open_exe, proc)
        comparison = _metadata(call("executable", adapter.metadata, reopened))
        if comparison != original:
            raise _Stop("changing")
        if not original[3] & 0o111:
            raise _Stop("unsupported")
        digest, count = content(exe, original, 128 * 1024 * 1024, hashing=True)
        poll(pidfd)
        dockerd = acquire("pathname", adapter.open_dockerd)
        pathname = _metadata(call("pathname", adapter.metadata, dockerd))
        packages_fd = acquire("packages", adapter.open_packages)
        package_meta = _metadata(call("packages", adapter.metadata, packages_fd))
        packages = _packages(content(packages_fd, package_meta, 32 * 1024 * 1024))
        poll(pidfd)
        if _stat(call("stat", adapter.read_stat, proc), pid) != start:
            raise _Stop("changing")
        fresh_proc = acquire("proc", adapter.open_proc, pid)
        if _stat(call("stat", adapter.read_stat, fresh_proc), pid) != start:
            raise _Stop("changing")
        if _metadata(call("executable", adapter.metadata, exe)) != original:
            raise _Stop("changing")
        if _metadata(call("executable", adapter.metadata, reopened)) != original:
            raise _Stop("changing")
        if _boot(call("boot", adapter.boot_id)) != boot:
            raise _Stop("changing")
        manager(first)
        poll(pidfd)
        result["candidate"] = {
            "unit": "docker.service",
            "executable": {"sha256": digest, "bytes": count, "metadata": original},
            "pathname": {"metadata": pathname, "same_object": pathname[:2] == original[:2]},
            "packages": packages,
        }
        result["outcome"] = "sampled-candidate"
    except _Stop as error:
        result["outcome"] = error.outcome
    except OSError as error:
        number = error.errno
        result["errno"] = number if type(number) is int and 0 <= number <= 4095 else 0
        result["outcome"] = {2: "not-found", 13: "denied", 1: "denied", 3: "changing", 38: "unsupported", 95: "unsupported", 110: "budget-exceeded"}.get(result["errno"], "unexpected-failure")
    except NotImplementedError:
        result["outcome"] = "unsupported"
    except Exception:
        result["outcome"] = "unexpected-failure"
    finally:
        failures = []
        while owned:
            fd = owned.pop()
            try:
                adapter.close(fd)
            except Exception as error:
                number = error.errno if isinstance(error, OSError) else 0
                failures.append(number if type(number) is int and 0 <= number <= 4095 else 0)
        if failures:
            result["prior_outcome"] = result["outcome"]
            result["outcome"] = "unexpected-failure"
            result["cleanup_errno"] = failures
            result.pop("candidate", None)
    result["stage"] = stage
    return result
