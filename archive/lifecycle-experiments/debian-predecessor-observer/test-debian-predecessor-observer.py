#!/usr/bin/env python3
"""Closed, in-memory public-Interface tests. Not a hostile-code sandbox.

Run only with the approved isolated Python argv. No native observation occurs.
"""
import ast
import builtins
import hashlib
from pathlib import Path
import re
import sys
from types import SimpleNamespace

SOURCE = Path(__file__).absolute().with_name("debian-predecessor-observer.py")
CASES = {"changed-executable", "stable", "process-change", "boot-change", "exit", "privacy", "io-errors", "budgets", "confinement", "production"}


class Refused(BaseException):
    """Confinement violations cannot be converted into ordinary I/O outcomes."""


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def load_core(entry=False):
    text = SOURCE.read_text()
    tree = ast.parse(text, filename=str(SOURCE))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(item.name not in {"hashlib", "re"} or item.asname for item in node.names):
                raise Refused("import refused")
        if isinstance(node, ast.ImportFrom):
            raise Refused("from import refused")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise Refused("dunder access refused")
    modules = {"hashlib": SimpleNamespace(sha256=hashlib.sha256),
               "re": SimpleNamespace(fullmatch=re.fullmatch)}

    def closed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name not in modules or fromlist or level:
            raise Refused("import refused")
        return modules[name]

    names = ("__build_class__", "Exception", "SystemExit", "OSError", "NotImplementedError",
             "TimeoutError", "ValueError", "TypeError", "object", "type", "int",
             "float", "bool", "bytes", "str", "dict", "tuple", "list", "set",
             "len", "range", "min", "max", "isinstance", "enumerate", "zip",
             "all", "any", "abs")
    safe = {name: getattr(builtins, name) for name in names}
    safe["__import__"] = closed_import
    scope = {"__builtins__": safe, "__name__": "__main__" if entry else "fixture_observer"}
    exec(compile(tree, str(SOURCE), "exec"), scope)
    return scope


BOOT = b"12345678-1234-1234-1234-123456789abc\n"
# Field 22 is 900; embedded ')' and secret comm never become output.
STAT = b"42 (secret ) comm) S " + b"0 " * 18 + b"900 0\n"
META = (8, 101, 3, 0o100755, 1000, 2000)
PACKAGES = (b"Package: docker-ce\nStatus: install ok installed\nVersion: 5:28.0.1-1~debian.12~bookworm\nArchitecture: amd64\n\n"
            b"Package: unrelated\nDescription: secret package body\n\n")


class Fixture:
    """Finite owned descriptor registry; no real I/O forwarding exists."""
    OPERATIONS = {"monotonic", "manager_get", "boot_id", "open_pidfd", "open_proc",
                  "read_stat", "open_exe", "metadata", "close", "exited",
                  "read", "open_dockerd", "open_packages"}

    def __init__(self, changed=False):
        self.changed = changed
        self.packages = PACKAGES
        self.trace = []
        self.handles = {}
        self.next_handle = 10
        self.exe_opens = 0
        self.proc_opens = 0
        self.boot_reads = 0
        self.gets = {}
        self.stat_reads = 0
        self.polls = 0
        self.positions = {}
        self.metadata_reads = {}
        self.fixed_opens = set()

    def adapter(self):
        fixture = self

        class Closed:
            def __getattribute__(self, name):
                if name not in Fixture.OPERATIONS:
                    raise Refused("unknown operation")
                return getattr(fixture, name)
        return Closed()

    def event(self, name, *args):
        self.trace.append((name, *args))

    def handle(self, fd, kinds):
        if type(fd) is not int or fd not in self.handles or self.handles[fd] not in kinds:
            raise Refused("unknown descriptor")
        return self.handles[fd]

    def allocate(self, kind):
        fd = self.next_handle
        self.next_handle += 1
        self.handles[fd] = kind
        return fd

    def monotonic(self):
        return 0.0

    def manager_get(self, prop):
        values = {"Id": "docker.service", "LoadState": "loaded", "ActiveState": "active",
                  "SubState": "running", "MainPID": 42}
        if prop not in values or self.gets.get(prop, 0) >= 2:
            raise Refused("unknown manager request")
        self.gets[prop] = self.gets.get(prop, 0) + 1
        self.event("manager_get", prop)
        return values[prop]

    def boot_id(self):
        if self.boot_reads >= 2:
            raise Refused("boot read limit")
        self.boot_reads += 1
        self.event("boot_id")
        return BOOT

    def open_pidfd(self, pid):
        if type(pid) is not int or pid != 42 or "pidfd" in self.handles.values():
            raise Refused("unknown pidfd request")
        self.event("open_pidfd", pid)
        return self.allocate("pidfd")

    def open_proc(self, pid):
        if type(pid) is not int or pid != 42 or self.proc_opens >= 2:
            raise Refused("unknown proc request")
        self.proc_opens += 1
        self.event("open_proc", pid)
        return self.allocate("proc")

    def read_stat(self, fd):
        self.handle(fd, {"proc"})
        if self.stat_reads >= 3:
            raise Refused("stat read limit")
        self.stat_reads += 1
        self.event("read_stat", fd)
        return STAT

    def open_exe(self, fd):
        self.handle(fd, {"proc"})
        if self.exe_opens >= 2:
            raise Refused("exe open limit")
        self.exe_opens += 1
        self.event("open_exe", fd)
        return self.allocate("exe" if self.exe_opens == 1 else "reopened")

    def metadata(self, fd):
        kind = self.handle(fd, {"exe", "reopened", "dockerd", "packages"})
        if self.metadata_reads.get(fd, 0) >= 3:
            raise Refused("metadata limit")
        self.metadata_reads[fd] = self.metadata_reads.get(fd, 0) + 1
        self.event("metadata", fd)
        if kind == "packages":
            return (8, 301, len(self.packages), 0o100644, 1000, 2000)
        if kind == "reopened" and self.changed:
            return (8, 102, 3, 0o100755, 1000, 2000)
        return META

    def exited(self, fd):
        self.handle(fd, {"pidfd"})
        if self.polls >= 16:
            raise Refused("poll limit")
        self.polls += 1
        self.event("exited", fd)
        return False

    def open_dockerd(self):
        if "dockerd" in self.fixed_opens:
            raise Refused("dockerd open limit")
        self.fixed_opens.add("dockerd")
        self.event("open_dockerd")
        return self.allocate("dockerd")

    def open_packages(self):
        if "packages" in self.fixed_opens:
            raise Refused("packages open limit")
        self.fixed_opens.add("packages")
        self.event("open_packages")
        return self.allocate("packages")

    def read(self, fd, size):
        kind = self.handle(fd, {"exe", "packages"})
        if type(size) is not int or not 1 <= size <= 65536:
            raise Refused("read size refused")
        self.event("read", fd, size)
        data = b"abc" if kind == "exe" else self.packages
        position = self.positions.get(fd, 0)
        if position > len(data):
            raise Refused("read past EOF")
        result = data[position:position + size]
        self.positions[fd] = position + (len(result) if result else 1)
        return result

    def close(self, fd):
        self.handle(fd, {"proc", "pidfd", "exe", "reopened", "dockerd", "packages"})
        self.event("close", fd)
        del self.handles[fd]


def changed_executable(core):
    fixture = Fixture(changed=True)
    result = core["observe"](fixture.adapter())
    # Assert causal input delivery first: bootstrap failures cannot count as RED.
    metadata = [event for event in fixture.trace if event[0] == "metadata"]
    require(len(metadata) == 2, "original and reopened metadata must be consumed")
    last = fixture.trace.index(metadata[-1])
    require(all(event[0] == "close" for event in fixture.trace[last + 1:]), "later read after changed exe")
    require(not fixture.handles, "owned descriptor leak")
    require("candidate" not in result, "candidate on changed exe")
    require(result["outcome"] == "changing", f"expected changing, got {result['outcome']}")


def refusal(core, fixture, expected, terminal):
    result = core["observe"](fixture.adapter())
    require(not fixture.handles, "owned descriptor leak")
    require("candidate" not in result, "candidate on refusal")
    require(result["outcome"] == expected, f"expected {expected}, got {result['outcome']}")
    last = max(index for index, event in enumerate(fixture.trace) if event[0] == terminal)
    require(all(event[0] == "close" for event in fixture.trace[last + 1:]), "later I/O after refusal")
    return result


def process_change(core):
    class FinalActiveStateChange(Fixture):
        def manager_get(self, prop):
            value = super().manager_get(prop)
            return "inactive" if prop == "ActiveState" and self.gets[prop] == 2 else value
    fixture = FinalActiveStateChange()
    result = core["observe"](fixture.adapter())
    require(fixture.gets.get("ActiveState") == 2, "valid initial then changed final state delivered")
    last = max(index for index, event in enumerate(fixture.trace) if event == ("manager_get", "ActiveState"))
    require(all(event[0] == "close" for event in fixture.trace[last + 1:]), "later I/O after final state change")
    require(not fixture.handles and "candidate" not in result and "inactive" not in str(result), "final change cleanup and privacy")
    require(result["outcome"] == "changing", f"expected changing, got {result['outcome']}")

    for prop, value in (("Id", "secret-other.service"), ("LoadState", "not-found"),
                        ("ActiveState", "inactive"), ("SubState", "dead")):
        for sample, expected in ((1, "prerequisite-unmet"), (2, "changing")):
            class ManagerState(Fixture):
                def manager_get(self, requested):
                    raw = super().manager_get(requested)
                    return value if requested == prop and self.gets[requested] == sample else raw
            fixture = ManagerState()
            result = refusal(core, fixture, expected, "manager_get")
            require(fixture.gets[prop] == sample, "requested manager sample delivered")
            require([event for event in fixture.trace if event[0] == "manager_get"][-1] == ("manager_get", prop),
                    "no subsequent property after manager change")
            require(value not in str(result), "changed manager value escaped")
    for prop, value, expected in (("Id", True, "malformed"), ("ActiveState", b"inactive", "malformed"),
                                  ("Id", "x" * 257, "budget-exceeded"),
                                  ("ActiveState", "x" * 257, "budget-exceeded"),
                                  ("MainPID", True, "malformed"), ("MainPID", 0, "malformed")):
        for sample in (1, 2):
            class InvalidManager(Fixture):
                def manager_get(self, requested):
                    raw = super().manager_get(requested)
                    return value if requested == prop and self.gets[requested] == sample else raw
            fixture = InvalidManager()
            result = refusal(core, fixture, expected, "manager_get")
            require(fixture.gets[prop] == sample, "invalid manager scalar delivered")
            require([event for event in fixture.trace if event[0] == "manager_get"][-1] == ("manager_get", prop),
                    "no subsequent property after invalid manager scalar")
            require("inactive" not in str(result) and "xxx" not in str(result), "invalid manager privacy")

    for sample in (2, 3):
        class ProcessChange(Fixture):
            def read_stat(self, fd):
                raw = super().read_stat(fd)
                return raw.replace(b"900 0", b"901 0") if self.stat_reads == sample else raw
        refusal(core, ProcessChange(), "changing", "read_stat")
    class ManagerChange(Fixture):
        def manager_get(self, prop):
            value = super().manager_get(prop)
            return 43 if prop == "MainPID" and self.gets[prop] == 2 else value
    refusal(core, ManagerChange(), "changing", "manager_get")


def boot_change(core):
    class BootChange(Fixture):
        def boot_id(self):
            raw = super().boot_id()
            return raw.replace(b"12345678", b"87654321", 1) if self.boot_reads == 2 else raw
    refusal(core, BootChange(), "changing", "boot_id")


def process_exit(core):
    for sample in (1, 2, 3, 4):
        class Exited(Fixture):
            def exited(self, fd):
                super().exited(fd)
                return self.polls == sample
        refusal(core, Exited(), "changing", "exited")


def privacy(core):
    class BadBoot(Fixture):
        def boot_id(self):
            super().boot_id()
            return b"secret-boot"
    class BadStat(Fixture):
        def read_stat(self, fd):
            super().read_stat(fd)
            return STAT.replace(b"900 0", b"secret-ticks 0")
    class BadManager(Fixture):
        def manager_get(self, prop):
            super().manager_get(prop)
            return "secret-manager"
    for fixture, expected, terminal in ((BadBoot(), "malformed", "boot_id"),
                                        (BadStat(), "malformed", "read_stat"),
                                        (BadManager(), "prerequisite-unmet", "manager_get")):
        result = refusal(core, fixture, expected, terminal)
        require("secret" not in str(result), "raw secret escaped")
    for raw in (PACKAGES.replace(b"Version: 5:", b"Version: secret:"),
                PACKAGES + PACKAGES,
                PACKAGES.replace(b"Architecture: amd64", b"Architecture: secret/arch"),
                PACKAGES.replace(b"Status: install ok installed", b"Status: secret-status")):
        fixture = Fixture()
        fixture.packages = raw
        result = refusal(core, fixture, "malformed", "metadata")
        require("secret" not in str(result), "raw package escaped")
    selected_lines = PACKAGES.split(b"\n\n", 1)[0].split(b"\n")
    malformed_packages = [b" secret orphan\n" + PACKAGES,
                          PACKAGES.replace(b"\n\n", b"\nDescription: summary\n secret continuation\nDescription: duplicate\n\n", 1),
                          PACKAGES.replace(b"Package: docker-ce\n", b"Package: docker-ce\nPackage: docker.io\n", 1)]
    for line in selected_lines:
        malformed_packages.append(PACKAGES.replace(line + b"\n", line + b"\n secret continuation\n", 1))
        malformed_packages.append(PACKAGES.replace(line + b"\n", line + b"\n" + line + b"\n", 1))
    for raw in malformed_packages:
        fixture = Fixture()
        fixture.packages = raw
        result = refusal(core, fixture, "malformed", "metadata")
        require("secret" not in str(result) and "summary" not in str(result), "continuation refusal privacy")
    fixture = Fixture()
    fixture.packages = PACKAGES.replace(b"\n\n", b"\nDescription: summary\n\tsecret continuation\n Package: docker.io\n\n", 1)
    result = core["observe"](fixture.adapter())
    require(result["outcome"] == "sampled-candidate" and not fixture.handles, "private positive fixture")
    require(result["candidate"]["packages"] == [{"name": "docker-ce", "version": "5:28.0.1-1~debian.12~bookworm",
                                                "architecture": "amd64", "status": "installed"}], "continuation is not a projected field")
    require("summary" not in str(result), "description summary escaped")
    require("secret" not in str(result) and "abc" not in str(result["candidate"]), "raw content escaped")


def io_errors(core):
    for number, expected in ((2, "not-found"), (13, "denied"), (1, "denied"),
                             (3, "changing"), (38, "unsupported"), (95, "unsupported"),
                             (110, "budget-exceeded"), (5, "unexpected-failure")):
        class ReadError(Fixture):
            def read(self, fd, size):
                super().read(fd, size)
                raise OSError(number, "secret-error")
        result = refusal(core, ReadError(), expected, "read")
        require(result.get("errno") == number and "secret" not in str(result), "sanitized errno")
    class Unsupported(Fixture):
        def open_pidfd(self, pid):
            require(pid == 42, "fixed PID")
            self.event("open_pidfd", pid)
            raise NotImplementedError("secret-native")
    refusal(core, Unsupported(), "unsupported", "open_pidfd")
    class PrematureEOF(Fixture):
        def read(self, fd, size):
            super().read(fd, size)
            return b""
    refusal(core, PrematureEOF(), "changing", "read")
    class FileChange(Fixture):
        def metadata(self, fd):
            raw = super().metadata(fd)
            if self.handles[fd] == "exe" and self.metadata_reads[fd] == 2:
                return (*raw[:4], 1001, 2001)
            return raw
    refusal(core, FileChange(), "changing", "metadata")
    class CleanupError(Fixture):
        def close(self, fd):
            kind = self.handles[fd]
            super().close(fd)
            if kind == "reopened":
                raise OSError(5, "secret-close")
    for changed, prior in ((True, "changing"), (False, "sampled-candidate")):
        fixture = CleanupError(changed=changed)
        result = core["observe"](fixture.adapter())
        require(result["outcome"] == "unexpected-failure" and result["prior_outcome"] == prior,
                "cleanup preserves failure lineage")
        require(result["cleanup_errno"] == [5] and "secret" not in str(result), "cleanup diagnostics")
        require("candidate" not in result and not fixture.handles, "cleanup attempts remaining owned handles")
        require(len([event for event in fixture.trace if event[0] == "close"]) == fixture.next_handle - 10,
                "all acquired handles receive close attempts")


def budgets(core):
    class ExpiredBeforeExecutableRead(Fixture):
        def __init__(self):
            super().__init__()
            self.after_read_samples = []

        def monotonic(self):
            if not any(event[0] == "read" for event in self.trace):
                return 0.0
            # Post-read samples remain in time; the next dispatch sample expires.
            value = 0.0 if len(self.after_read_samples) < 2 else 10.01
            self.after_read_samples.append(value)
            return value

    fixture = ExpiredBeforeExecutableRead()
    result = core["observe"](fixture.adapter())
    require(fixture.after_read_samples[:3] == [0.0, 0.0, 10.01], "external clock expiration delivered")
    require(result["outcome"] == "budget-exceeded" and "candidate" not in result and not fixture.handles,
            "executable deadline refusal and cleanup")
    reads = [event for event in fixture.trace if event[0] == "read"]
    require(len(reads) == 1, "executable read dispatched after pre-dispatch clock exceeded 10s")
    last = fixture.trace.index(reads[0])
    require(all(event[0] == "close" for event in fixture.trace[last + 1:]), "later I/O after executable deadline")

    class LargeBoot(Fixture):
        def boot_id(self):
            super().boot_id()
            return b"x" * 65
    class LargeStat(Fixture):
        def read_stat(self, fd):
            super().read_stat(fd)
            return b"x" * 4097
    class LargeManager(Fixture):
        def manager_get(self, prop):
            super().manager_get(prop)
            return "x" * 257
    class LargeRead(Fixture):
        def read(self, fd, size):
            super().read(fd, size)
            return b"x" * (size + 1)
    for fixture, terminal in ((LargeBoot(), "boot_id"), (LargeStat(), "read_stat"),
                              (LargeManager(), "manager_get"), (LargeRead(), "read")):
        refusal(core, fixture, "budget-exceeded", terminal)
    for kind, size in (("exe", 134217729), ("packages", 33554433)):
        class LargeMetadata(Fixture):
            def metadata(self, fd):
                raw = super().metadata(fd)
                if self.handles[fd] in ({"exe", "reopened"} if kind == "exe" else {"packages"}):
                    return (*raw[:2], size, *raw[3:])
                return raw
        refusal(core, LargeMetadata(), "budget-exceeded", "metadata")
    fixture = Fixture()
    fixture.packages = PACKAGES.replace(b"Architecture: amd64", b"Architecture: " + b"x" * 257)
    refusal(core, fixture, "budget-exceeded", "metadata")
    for value in (True, "42", 0, 2147483648):
        class BadPID(Fixture):
            def manager_get(self, prop):
                raw = super().manager_get(prop)
                return value if prop == "MainPID" else raw
        refusal(core, BadPID(), "malformed", "manager_get")
    class BadMetadata(Fixture):
        def metadata(self, fd):
            super().metadata(fd)
            return (8, True, 3, 0o100755, 1000, 2000)
    refusal(core, BadMetadata(), "malformed", "metadata")
    for value in (True, float("nan"), float("inf"), -1):
        class BadClock(Fixture):
            def monotonic(self):
                return value
        fixture = BadClock()
        result = core["observe"](fixture.adapter())
        require(result["outcome"] == "malformed" and not fixture.trace and not fixture.handles,
                "invalid clock must refuse before dispatch")
    for operation, elapsed in (("manager_get", 1.01), ("open_exe", 20.01), ("read", 10.01)):
        class SlowIO(Fixture):
            def monotonic(self):
                return elapsed if any(event[0] == operation for event in self.trace) else 0.0
        refusal(core, SlowIO(), "budget-exceeded", operation)
    class ReversedClock(Fixture):
        def monotonic(self):
            return 0.0 if self.trace else 1.0
    refusal(core, ReversedClock(), "malformed", "manager_get")


def confinement(core):
    fixture = Fixture()
    adapter = fixture.adapter()
    probes = [lambda: getattr(adapter, "open"), lambda: getattr(adapter, "connect"),
              lambda: adapter.manager_get("Environment"), lambda: adapter.open_pidfd(True),
              lambda: adapter.open_proc(43), lambda: adapter.metadata(999),
              lambda: adapter.read(999, 1), lambda: adapter.close(999),
              lambda: core["__builtins__"]["__import__"]("os"),
              lambda: core["__builtins__"]["__import__"]("socket"),
              lambda: core["__builtins__"]["__import__"]("re", fromlist=("fullmatch",))]
    for probe in probes:
        try:
            probe()
        except Refused:
            pass
        else:
            raise AssertionError("unknown operation dispatched")
    require(not fixture.trace and not fixture.handles, "refused before dispatch")
    require(all(name not in core["__builtins__"] for name in ("open", "eval", "exec", "compile", "getattr", "input")),
            "ambient effect builtins unavailable")
    for selectors in ({"pid": 42}, {"path": "/proc"}, {"package": "docker-ce"}, {"ready": True}):
        try:
            core["observe"](adapter, **selectors)
        except TypeError:
            pass
        else:
            raise AssertionError("caller-selected target accepted")
    require(not fixture.trace, "selectors must fail before I/O")
    fd = fixture.open_dockerd()
    trace = list(fixture.trace)
    try:
        adapter.read(fd, 1)
    except Refused:
        pass
    else:
        raise AssertionError("metadata-only descriptor content read")
    require(fixture.trace == trace, "descriptor refusal before dispatch")
    adapter.close(fd)
    class DeniedDispatch(Fixture):
        def boot_id(self):
            raise Refused("closed effect refusal")
    try:
        core["observe"](DeniedDispatch().adapter())
    except Refused:
        pass
    else:
        raise AssertionError("confinement violation swallowed")


def production(core):
    # Exercise the actual module entry under the same closed import/effect guard.
    # No production Adapter is constructed, and no child/native process is run.
    try:
        load_core(entry=True)
    except SystemExit as error:
        require(error.code == "production-unavailable", "fixed production refusal")
    else:
        raise AssertionError("production entry must refuse")


def stable(core):
    fixture = Fixture()
    fixture.packages = PACKAGES.replace(b"Architecture: amd64\n", b"Architecture: amd64\nDescription: summary\n secret continuation\n", 1)
    result = core["observe"](fixture.adapter())
    require(not fixture.handles, "owned descriptor leak")
    require(result["outcome"] == "sampled-candidate", f"expected sampled-candidate, got {result['outcome']}")
    require(result["sampled"] is True and result["atomic"] is False, "sampling limits")
    require(result["partial"] == {"boot_id": "12345678-1234-1234-1234-123456789abc",
                                  "process": {"pid": 42, "start_ticks": 900}}, "identity projection")
    require(result["candidate"] == {
        "unit": "docker.service",
        "executable": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                       "bytes": 3, "metadata": (8, 101, 3, 0o100755, 1000, 2000)},
        "pathname": {"metadata": (8, 101, 3, 0o100755, 1000, 2000), "same_object": True},
        "packages": [{"name": "docker-ce", "version": "5:28.0.1-1~debian.12~bookworm",
                      "architecture": "amd64", "status": "installed"}],
    }, "bounded candidate projection")
    require(fixture.boot_reads == 2 and fixture.stat_reads == 3 and fixture.exe_opens == 2,
            "repeated identity samples required")
    require(all(count == 2 for count in fixture.gets.values()), "repeated manager sample required")
    require(fixture.polls >= 2, "exit samples required")
    require("secret" not in str(result) and "summary" not in str(result), "raw fixture privacy")


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
        raise Refused("isolated argv required")
    if len(sys.argv) != 2 or sys.argv[1] not in CASES | {"all"}:
        raise Refused("unknown argv")
    core = load_core()
    tests = {"changed-executable": changed_executable, "stable": stable,
             "process-change": process_change, "boot-change": boot_change,
             "exit": process_exit, "privacy": privacy, "io-errors": io_errors,
             "budgets": budgets, "confinement": confinement, "production": production}
    for case in tests if sys.argv[1] == "all" else (sys.argv[1],):
        tests[case](core)
        print("PASS " + case + " (fixture-only, non-authorizing)")
