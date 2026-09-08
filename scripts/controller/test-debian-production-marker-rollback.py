#!/usr/bin/env python3
"""Actual production executor, closed controller-only adapters; no installed proof.

Run only with python3 -I -B -S. Each invocation retains a fresh 0700 evidence
root under /tmp, including source, fixtures and results. Modeled successful
starts are premises for reaching cleanup, NOT production-guard admission.
"""
import ast
import builtins
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import traceback
from types import SimpleNamespace

ROOT = Path(__file__).absolute().parents[2]
EXECUTOR = ROOT / "ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction"
MARKER = "/var/lib/home-lab/lifecycle-state.json"
TOKEN = "/etc/home-lab/allow-storage-activation"
POLICY = "/etc/home-lab/debian-production-dependencies.json"
IDENTITY = "/fixture/identity"
UNITS = ["docker.service", "home-lab-compose.service", "home-lab-restic-daily.timer", "home-lab-restic-maintenance.timer"]
EDGES = ["home-lab-production-guard.service", "mnt-games.mount", "mnt-storage.mount", r"srv-home\x2dlab\x2dstate.mount"]
GRAPH = {UNITS[0]: {"Requires": EDGES, "After": EDGES},
         UNITS[1]: {"Requires": [UNITS[0]] + EDGES, "After": [UNITS[0]] + EDGES},
         UNITS[2]: {"Requires": [], "After": [UNITS[1]]},
         UNITS[3]: {"Requires": [], "After": [UNITS[1]]}}
BEFORE = b'{ "state": "recovery", "fixture": "exact before bytes" }\n'
AFTER = b'{"source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"production","updated_at":"2026-09-05T12:00:00Z","version":1}\n'
FOREIGN = b'foreign marker: do not overwrite\n'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Refused(BaseException):
    """Unknown effects must not become an accepted injected RuntimeError."""


class Closed:
    def __init__(self, **allowed):
        self.__dict__.update(allowed)

    def __getattr__(self, name):
        raise Refused(f"unknown adapter attribute: {name}")


class FixedClock:
    @staticmethod
    def now(tz):
        require(tz is timezone.utc, "unknown clock request")
        return datetime(2026, 9, 5, 12, tzinfo=timezone.utc)


class Fixture:
    def __init__(self, root, case):
        self.root, self.case = root, case
        self.files, self.metadata, self.fds = {}, {}, {}
        self.commands, self.effects = [], []
        self.started, self.stopped = [], []
        self.publications = 0
        self.fired = False
        self.original = RuntimeError("injected activation failure")
        self.after_inode = None
        self.publication_pinned = False
        self.add(MARKER, BEFORE)
        self.add(TOKEN, b"plan_sha256=" + b"5" * 64 + b"\n")
        self.add(IDENTITY, b"fixture identity, not a credential\n")
        policy = {"format": "home-lab-debian-production-dependencies-v1", "contract_sha256": "c" * 64,
                  "production_units": UNITS, "systemd_dependencies": GRAPH}
        self.add(POLICY, canonical(policy))
        receipt = {"commit": "a" * 40, "format": "home-lab-restic-recovery-activation-receipt-v1",
                   "producer_sha256": "d" * 64, "repository_id": "1" * 64,
                   "restore_manifest_sha256": "2" * 64, "snapshot_id": "3" * 64,
                   "snapshot_manifest_sha256": "4" * 64, "status": "verified", "target": "debian",
                   "tree_sha256": "6" * 64, "version": 1}
        params = {"mounts": [], "storage_plan_sha256": "5" * 64, "identity_recipient": "fixture-recipient",
                  "tailscale_hostname": "fixture-node", "tailscale_tags": ["tag:fixture"],
                  "systemd_dependencies": GRAPH, "lifecycle_marker_sha256": sha(BEFORE),
                  "compose_command": ["/usr/bin/docker", "compose"]}
        for key, data in (("compose_artifact", b"fixture compose\n"), ("compose_image_lock", b"fixture images\n"),
                          ("root_environment", b"fixture environment, no secrets\n"), ("restic_recovery_receipt", canonical(receipt))):
            path = "/fixture/" + key
            self.add(path, data)
            params[key + "_path"], params[key + "_sha256"] = path, sha(data)
        self.plan = {"base_commit": "a" * 40,
                     "bindings": {"contract_sha256": "c" * 64, "production_dependency_policy_sha256": sha(canonical(policy)), "authority_producer_sha256": "d" * 64},
                     "request": {"format": "home-lab-debian-lifecycle-request-v2", "parameters": params},
                     "precondition": {"format": "home-lab-debian-lifecycle-observation-v2", "identity": {"path": IDENTITY}}}
        self.dirs = {"/", "/var", "/var/lib", "/var/lib/home-lab", "/etc", "/etc/home-lab", "/fixture"}
        fixture = self

        class ConfinedPath(PurePosixPath):
            def read_bytes(self):
                return fixture.read_bytes(str(self))

            def read_text(self):
                return self.read_bytes().decode()

            def exists(self):
                return fixture.exists(str(self))

            def unlink(self):
                return fixture.unlink(str(self))

        self.Path = ConfinedPath
        self.os = Closed(**{name: getattr(os, name) for name in ("O_RDONLY", "O_RDWR", "O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_DIRECTORY")},
                         lstat=self.lstat, fstat=self.fstat, open=self.open, close=self.close,
                         read=self.read, pread=self.pread, write=self.write, fchown=self.fchown,
                         fchmod=self.fchmod, fsync=self.fsync, replace=self.replace, unlink=self.unlink,
                         path=Closed(exists=self.exists))

    def add(self, path, data):
        target = self.root / ("file-" + str(len(self.files)))
        with target.open("xb") as handle:
            handle.write(data)
        self.files[path] = target
        value = target.stat()
        self.metadata[(value.st_dev, value.st_ino)] = (0, 0, 0o600)

    def target(self, path):
        path = str(path)
        if path not in self.files:
            raise Refused(f"unknown path: {path}")
        return self.files[path]

    def modeled(self, value):
        uid, gid, mode = self.metadata[(value.st_dev, value.st_ino)]
        return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino, st_size=value.st_size,
                               st_nlink=value.st_nlink, st_uid=uid, st_gid=gid,
                               st_mode=stat.S_IFMT(value.st_mode) | mode)

    def lstat(self, path):
        path = str(path)
        self.effects.append(["lstat", path])
        if path in self.dirs:
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
        value = os.lstat(self.target(path))
        if stat.S_ISLNK(value.st_mode):
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino, st_size=value.st_size,
                                   st_nlink=value.st_nlink, st_uid=0, st_gid=0, st_mode=value.st_mode)
        return self.modeled(value)

    def fd_path(self, fd):
        if fd not in self.fds:
            raise Refused(f"unknown descriptor: {fd}")
        return self.fds[fd]

    def fstat(self, fd):
        self.fd_path(fd)
        return self.modeled(os.fstat(fd))

    def open(self, path, flags, mode=0o600):
        path = str(path)
        self.effects.append(["open", path, flags])
        if path in self.dirs and flags == os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW:
            target = self.root
        elif flags == os.O_RDONLY | os.O_NOFOLLOW:
            target = self.target(path)
        else:
            raise Refused(f"unknown open: {path}, {flags}")
        fd = os.open(target, flags, mode)
        self.fds[fd] = path
        return fd

    def close(self, fd):
        # The baseline double-closes; refuse before dispatch, with OS EBADF shape.
        if fd not in self.fds:
            raise OSError(9, "closed fixture descriptor")
        self.effects.append(["close", self.fds[fd]])
        os.close(fd)
        del self.fds[fd]

    def read(self, fd, count):
        self.fd_path(fd)
        return os.read(fd, count)

    def pread(self, fd, count, offset):
        self.fd_path(fd)
        return os.pread(fd, count, offset)

    def fchown(self, fd, uid, gid):
        path = self.fd_path(fd)
        require((uid, gid) == (0, 0), "unknown ownership effect")
        if self.case == "publication-chown" and path.startswith("/var/lib/home-lab/.lifecycle-state-"):
            raise self.original
        value = os.fstat(fd)
        old = self.metadata[(value.st_dev, value.st_ino)]
        self.metadata[(value.st_dev, value.st_ino)] = (uid, gid, old[2])

    def fchmod(self, fd, mode):
        self.fd_path(fd)
        require(mode == 0o600, "unknown mode effect")
        if self.case == "publication-chmod" and ".lifecycle-state-" in self.fd_path(fd):
            raise self.original
        value = os.fstat(fd)
        self.metadata[(value.st_dev, value.st_ino)] = (0, 0, mode)

    def mkstemp(self, *, prefix, dir):
        require(str(dir) == "/var/lib/home-lab" and prefix in (".lifecycle-state-", ".lifecycle-rollback-"), "unknown temporary file effect")
        if self.case == "rollback-create" and prefix == ".lifecycle-rollback-":
            raise RuntimeError("injected rollback create failure")
        fd, raw = tempfile.mkstemp(prefix=prefix, dir=self.root)
        path = str(PurePosixPath(str(dir)) / Path(raw).name)
        self.files[path] = Path(raw)
        self.fds[fd] = path
        value = os.fstat(fd)
        self.metadata[(value.st_dev, value.st_ino)] = (0, 0, 0o600)
        return fd, path

    def write(self, fd, data):
        path = self.fd_path(fd)
        require(path.startswith("/var/lib/home-lab/.lifecycle-"), "unknown write effect")
        if self.case == "publication-short" and ".lifecycle-state-" in path:
            return os.write(fd, data[:7])
        if self.case == "rollback-short" and ".lifecycle-rollback-" in path:
            return os.write(fd, data[:7])
        return os.write(fd, data)

    def exists(self, path):
        return self.target(path).exists()

    def unlink(self, path):
        path = str(path)
        require(path.startswith("/var/lib/home-lab/.lifecycle-"), "unknown unlink effect")
        self.target(path).unlink()

    def read_bytes(self, path):
        target = self.target(path)
        # A read-only postpublication cut; changes are made only inside fixtures.
        if path == MARKER and self.publications == 1 and not self.fired and self.case == "post-read":
            self.fired = True
            raise self.original
        require(not target.is_symlink(), "refuse pathname symlink read")
        return target.read_bytes()

    def replace(self, source, destination):
        source, destination = str(source), str(destination)
        require(destination == MARKER and source.startswith("/var/lib/home-lab/.lifecycle-"), "unknown replace effect")
        rollback = ".lifecycle-rollback-" in source
        if (self.case == "replace-before" and not rollback) or (self.case == "rollback-replace" and rollback):
            raise self.original if not rollback else RuntimeError("injected rollback replace failure")
        os.replace(self.target(source), self.target(destination))
        self.publications += 1
        self.effects.append(["replace", source, destination])
        if not rollback:
            self.after_inode = self.target(MARKER).stat().st_ino
            self.publication_pinned = any(os.fstat(fd).st_ino == self.after_inode for fd in self.fds)
            require(self.target(MARKER).read_bytes() == AFTER, "independent published bytes")
            if self.case == "replace-after":
                raise self.original

    def fsync(self, fd):
        path = self.fd_path(fd)
        os.fsync(fd)
        if self.case == "publication-file-fsync" and ".lifecycle-state-" in path:
            raise self.original
        if self.case == "rollback-directory-fsync" and path == "/var/lib/home-lab" and self.publications == 2:
            raise RuntimeError("injected rollback directory fsync failure")
        if self.case == "rollback-late-foreign" and ".lifecycle-rollback-" in path:
            self.target(MARKER).write_bytes(FOREIGN)
        if path == "/var/lib/home-lab" and self.publications == 1 and not self.fired and self.case not in ("success", "post-read", "replace-after"):
            self.fired = True
            target = self.target(MARKER)
            if self.case in ("foreign-bytes", "foreign-identical"):
                foreign = self.root / "foreign"
                foreign.write_bytes(FOREIGN if self.case == "foreign-bytes" else AFTER)
                value = foreign.stat()
                self.metadata[(value.st_dev, value.st_ino)] = (0, 0, 0o600)
                os.replace(foreign, target)
                require(target.stat().st_ino != self.after_inode, "foreign inode fixture")
            elif self.case == "same-inode-bytes":
                target.write_bytes(FOREIGN)
                require(target.stat().st_ino == self.after_inode, "same inode fixture")
            elif self.case == "missing":
                target.unlink()
            elif self.case == "symlink":
                target.unlink()
                link_target = self.root / "link-target"
                link_target.write_bytes(FOREIGN)
                target.symlink_to(link_target)
            elif self.case == "hardlink":
                os.link(target, self.root / "hardlink")
            elif self.case == "directory":
                target.unlink()
                target.mkdir(mode=0o700)
                value = target.stat()
                self.metadata[(value.st_dev, value.st_ino)] = (0, 0, 0o700)
            elif self.case in ("unsafe-mode", "unsafe-uid", "unsafe-gid"):
                value = target.stat()
                self.metadata[(value.st_dev, value.st_ino)] = {"unsafe-mode": (0, 0, 0o644), "unsafe-uid": (1, 0, 0o600), "unsafe-gid": (0, 1, 0o600)}[self.case]
            raise self.original

    def popen(self, argv, **kwargs):
        allowed_kwargs = {"start_new_session", "stdout", "stderr", "text"}
        if set(kwargs) - allowed_kwargs or kwargs.get("start_new_session") is not True or kwargs.get("stdout") not in (-1, -3) or kwargs.get("stderr") not in (-1, -3):
            raise Refused("unknown command options")
        text, code = "", 0
        if argv == ["/usr/local/bin/age-keygen", "-y", IDENTITY]:
            text = "fixture-recipient\n"
        elif argv == ["/usr/bin/tailscale", "status", "--json"]:
            text = json.dumps({"BackendState": "Running", "Self": {"HostName": "fixture-node", "Tags": ["tag:fixture"]}})
        elif argv == ["/usr/bin/docker", "compose", "config", "--quiet"]:
            pass
        elif len(argv) == 4 and argv[:2] == ["/usr/bin/systemctl", "show"] and argv[2] in UNITS and argv[3] == "--property=Requires,After":
            text = "".join(prop + "=" + " ".join(values) + "\n" for prop, values in GRAPH[argv[2]].items())
        elif len(argv) == 4 and argv[:2] == ["/usr/bin/systemctl", "show"] and argv[2] in UNITS and argv[3] == "--property=LoadState,ActiveState,SubState":
            text = "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        elif len(argv) == 3 and argv[:2] == ["/usr/bin/systemctl", "start"] and argv[2] in UNITS:
            self.started.append(argv[2])
        elif len(argv) == 4 and argv[:3] == ["/usr/bin/systemctl", "is-active", "--quiet"] and argv[3] in self.started:
            if self.case == "partial-start" and argv[3] == UNITS[1]:
                code = 1
        elif len(argv) == 3 and argv[:2] == ["/usr/bin/systemctl", "stop"] and argv[2] in self.started:
            self.stopped.append(argv[2])
            if self.case == "stop-failure" and argv[2] == UNITS[-1]:
                code = 1
        else:
            raise Refused(f"unknown command: {argv}")
        self.commands.append(argv)
        output = text if kwargs.get("text") else text.encode()
        return Closed(returncode=code, communicate=lambda: (output, "" if kwargs.get("text") else b""))

    def load(self, source):
        modules = {"argparse": Closed(), "fcntl": Closed(), "hashlib": Closed(sha256=hashlib.sha256),
                   "json": Closed(dumps=json.dumps, loads=json.loads, JSONDecoder=json.JSONDecoder, JSONDecodeError=json.JSONDecodeError),
                   "os": self.os, "re": Closed(compile=re.compile, fullmatch=re.fullmatch), "signal": Closed(),
                   "stat": Closed(**{name: getattr(stat, name) for name in ("S_ISREG", "S_ISLNK", "S_ISDIR", "S_IMODE")}),
                   "subprocess": Closed(PIPE=-1, DEVNULL=-3, Popen=self.popen, CompletedProcess=lambda argv, code, out, err: SimpleNamespace(returncode=code, stdout=out, stderr=err)),
                   "tempfile": Closed(mkstemp=self.mkstemp), "datetime": Closed(datetime=FixedClock, timezone=timezone),
                   "pathlib": Closed(Path=self.Path), "__future__": Closed(annotations=__import__("__future__").annotations)}

        def import_closed(name, globals=None, locals=None, fromlist=(), level=0):
            if level or name not in modules:
                raise Refused(f"unknown module: {name}")
            return modules[name]

        safe = {name: getattr(builtins, name) for name in ("BaseException", "Exception", "RuntimeError", "SystemExit", "OSError", "FileNotFoundError", "BlockingIOError", "ValueError", "KeyError", "TypeError", "InterruptedError", "len", "str", "bytes", "int", "bool", "dict", "list", "set", "tuple", "sorted", "reversed", "isinstance", "any", "all", "format")}
        safe["__import__"] = import_closed
        namespace = {"__name__": "confined_executor", "__builtins__": safe}
        exec(compile(source, str(self.root.parent / "executor.py"), "exec"), namespace)
        return namespace


def run_case(root, source, case):
    case_root = root / case
    case_root.mkdir(mode=0o700)
    fixture = Fixture(case_root, case)
    host = fixture.load(source)
    error = None
    if case == "preflight":
        fixture.plan["request"]["parameters"]["lifecycle_marker_sha256"] = "0" * 64
    if case == "unknown-command":
        fixture.plan["request"]["parameters"]["compose_command"].append("unapproved")
    try:
        host["production"](fixture.plan, "f" * 64)
    except BaseException as caught:
        error = caught
    result = {"case": case, "commands": fixture.commands, "effects": fixture.effects,
              "error": None if error is None else type(error).__name__ + ": " + str(error),
              "open_descriptors": list(fixture.fds), "publications": fixture.publications,
              "publication_pinned": fixture.publication_pinned}
    (case_root / "result.json").write_bytes(canonical(result))
    (case_root / "plan.json").write_bytes(canonical(fixture.plan))
    if error:
        (case_root / "exception.txt").write_text("".join(traceback.format_exception(error)))
    marker = fixture.target(MARKER)
    # Independent oracles; never use production rollback helper output as expected.
    protected = {"foreign-bytes", "foreign-identical", "same-inode-bytes", "missing", "symlink", "hardlink", "unsafe-mode", "unsafe-uid", "unsafe-gid", "directory", "rollback-late-foreign"}
    cleanup_failures = protected | {"replace-before", "rollback-short", "rollback-create", "rollback-replace", "rollback-directory-fsync", "stop-failure"}
    before_cases = {"owned-fsync", "post-read", "replace-after", "publication-chown", "publication-chmod", "publication-file-fsync", "publication-short", "replace-before", "rollback-directory-fsync", "stop-failure", "preflight", "partial-start", "unknown-command"}
    if case in {"foreign-bytes", "same-inode-bytes", "rollback-late-foreign"}:
        require(marker.read_bytes() == FOREIGN, "foreign marker bytes were overwritten")
    elif case in before_cases:
        require(marker.read_bytes() == BEFORE, "exact before bytes not preserved/restored")
    elif case == "missing":
        require(not marker.exists(), "missing marker was recreated")
    elif case == "directory":
        require(marker.is_dir(), "foreign directory was replaced")
    elif case == "symlink":
        require(marker.is_symlink() and marker.read_bytes() == FOREIGN, "foreign symlink was replaced")
    else:
        require(marker.read_bytes() == AFTER, "published bytes were replaced or truncated")
    if case == "foreign-identical":
        require(marker.stat().st_ino != fixture.after_inode, "foreign identical inode was adopted")
    if case == "hardlink":
        require(marker.stat().st_nlink == 2 and marker.stat().st_ino == fixture.after_inode, "hardlink state was replaced")
    if case.startswith("unsafe-"):
        require(marker.stat().st_ino == fixture.after_inode, "unsafe metadata inode was replaced")
        require(fixture.metadata[(marker.stat().st_dev, marker.stat().st_ino)] != (0, 0, 0o600), "unsafe metadata was reset")
    initial_only = case in {"preflight", "unknown-command"}
    expected_starts = [] if initial_only else UNITS[:2] if case == "partial-start" else UNITS
    require(fixture.started == expected_starts, "modeled start order differs")
    require(fixture.stopped == ([] if case == "success" else list(reversed(expected_starts))), "bounded reverse cleanup differs")
    require(not fixture.fds, "executor leaked fixture descriptors")
    require(all(not target.exists() for path, target in fixture.files.items() if "/.lifecycle-" in path), "temporary publication file leaked")
    if case == "success":
        require(error is None and fixture.publications == 1, "success behavior changed")
    elif case == "unknown-command":
        require(isinstance(error, Refused) and "unknown command" in str(error), "unknown command did not refuse")
        require(not any("unapproved" in argv for argv in fixture.commands), "unknown command dispatched")
    elif case == "preflight":
        require(isinstance(error, SystemExit) and str(error) == "recovery lifecycle marker changed", "preflight refusal changed")
    elif case in cleanup_failures:
        require(isinstance(error, RuntimeError) and str(error) == "production activation rollback postcondition failed", "cleanup failure is not visible")
        require(error.__cause__ is fixture.original, "original activation exception lineage lost")
    elif case in {"publication-short", "partial-start"}:
        expected = "short lifecycle marker write" if case == "publication-short" else "production unit failed to become active"
        require(isinstance(error, RuntimeError) and str(error) == expected, "original executor failure changed")
    else:
        require(error is fixture.original, "original injected activation exception lost")
    if fixture.publications:
        require(fixture.publication_pinned, "publication inode was not pinned by an open descriptor")
    if case in protected | {"rollback-short", "rollback-create", "rollback-replace"}:
        require(fixture.publications == 1, "foreign, ambiguous or incomplete marker was republished")
    for index, unit in enumerate(expected_starts):
        start = fixture.commands.index(["/usr/bin/systemctl", "start", unit])
        require(fixture.commands[start + 1] == ["/usr/bin/systemctl", "is-active", "--quiet", unit], "start verification order differs")
    return result


CASES = ("foreign-bytes", "owned-fsync", "foreign-identical", "same-inode-bytes", "missing", "symlink", "hardlink", "unsafe-mode", "unsafe-uid", "unsafe-gid", "directory", "publication-chown", "publication-chmod", "publication-file-fsync", "publication-short", "replace-before", "replace-after", "post-read", "rollback-short", "rollback-create", "rollback-replace", "rollback-directory-fsync", "rollback-late-foreign", "stop-failure", "success", "preflight", "partial-start", "unknown-command")


def refusal_cases(root, source):
    directory = root / "unknown-effects"
    directory.mkdir(mode=0o700)
    fixture = Fixture(directory, "unknown-effects")
    host = fixture.load(source)
    probes = {
        "path": lambda: fixture.os.lstat("/unapproved"),
        "write-open": lambda: fixture.os.open(MARKER, os.O_WRONLY),
        "descriptor": lambda: fixture.os.write(-1, b"forbidden"),
        "module": lambda: host["__builtins__"]["__import__"]("socket"),
        "os-effect": lambda: fixture.os.chmod(MARKER, 0o777),
        "command": lambda: host["run"](["/usr/bin/systemctl", "reboot"]),
    }
    for label, probe in probes.items():
        try:
            probe()
        except Refused:
            continue
        raise AssertionError("unknown effect accepted: " + label)
    require(fixture.target(MARKER).read_bytes() == BEFORE and not fixture.commands and not fixture.fds, "refusal dispatched effects")
    (directory / "passed.json").write_bytes(canonical(list(probes)))


def main():
    require(sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site, "use -I -B -S")
    require(sys.argv[1:] in (["--red"], ["--green"], ["--mutant"]), "use --red, --green or --mutant")
    mode = sys.argv[1][2:]
    root = Path(tempfile.mkdtemp(prefix=f"debian-marker-rollback-{mode}-", dir="/tmp"))
    require(stat.S_IMODE(root.stat().st_mode) == 0o700, "fixture root must be private")
    print(f"RETAINED_ROOT={root}", flush=True)
    source = EXECUTOR.read_text()
    (root / "executor.py").write_text(source)
    (root / "test.py").write_bytes(Path(__file__).read_bytes())
    try:
        if mode == "mutant":
            # Bypass the actual nested ownership check, not a parallel transaction.
            tree = ast.parse(source)
            production = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "production")
            owned = next(node for node in production.body if isinstance(node, ast.FunctionDef) and node.name == "require_owned_marker")
            lines = source.splitlines(keepends=True)
            lines[owned.lineno:owned.end_lineno] = ["        pass  # causal mutant: bypass ownership protection\n"]
            source = "".join(lines)
            (root / "mutant-executor.py").write_text(source)
        for case in CASES if mode == "green" else ("foreign-bytes",):
            run_case(root, source, case)
            print("PASS " + case, flush=True)
        if mode == "green":
            refusal_cases(root, source)
            print("PASS unknown-effects", flush=True)
    except BaseException:
        log = traceback.format_exc()
        (root / "failure.txt").write_text(log)
        print(log, file=sys.stderr)
        return 1
    (root / "passed.txt").write_text("\n".join(CASES if mode == "green" else ("foreign-bytes",)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
