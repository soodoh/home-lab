#!/usr/bin/env python3
"""Attended LiteLLM config-only deployment. No controller, secret refresh or pulls."""
import argparse
import base64
import hashlib
import importlib.util
import re
import subprocess
import time
import uuid
import fcntl
import grp
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import shutil
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "services/data/litellm/config.yaml"
FORMAT = "home-lab-litellm-v1"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 16
MAX_COMMAND_BYTES = 16 * 1024 * 1024
PAYLOAD_LIMIT = 8 * 1024 * 1024
COLLECTORS = ("litellm-deployment.py", "compose-artifact.py", "compose-model-inventory.py", "compose-action-plan.py")
_VERIFIED_MODULES = globals().get("_VERIFIED_MODULES")
_VERIFIED_ENVELOPE_SHA256 = globals().get("_VERIFIED_ENVELOPE_SHA256")


def require(condition, reason):
    if not condition:
        raise SystemExit(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_bytes(path, limit=MAX_FILE_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "file type/byte limit exceeded")
        raw = stream.read(limit + 1)
        require(len(raw) <= limit, "file byte limit exceeded during read")
        return raw


def bounded_tree(root, entries=MAX_ENTRIES):
    count = 0
    def walk(directory, depth):
        nonlocal count
        require(depth <= MAX_DEPTH, "tree depth limit exceeded")
        with os.scandir(directory) as stream:
            for item in stream:
                count += 1
                require(count <= entries, "tree entry limit exceeded")
                path = Path(item.path)
                require(len(os.fsencode(path.relative_to(root))) <= 4096, "tree path byte limit exceeded")
                info = item.stat(follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "unsupported tree link/special file")
                yield path, info
                if stat.S_ISDIR(info.st_mode):
                    yield from walk(path, depth + 1)
    yield from walk(root, 0)


def bounded_run(argv, *, input=None, text=False, timeout=60, cwd=None, env=None, check=False, runner=None):
    """Drain command pipes incrementally; close on overflow, never buffer unbounded output.

    Existing subprocess.run remains the OS test seam. Native stdout/stderr go to
    descriptors, so communicate() can buffer only the explicitly bounded stdin.
    """
    require(input is None or len(input.encode() if isinstance(input, str) else input) <= MAX_FILE_BYTES,
            "command input byte limit exceeded")
    runner = runner or subprocess.run
    pipes = [os.pipe(), os.pipe()]
    chunks = [[], []]
    total = 0
    overflow = False
    mutex = threading.Lock()
    def drain(index):
        nonlocal total, overflow
        fd = pipes[index][0]
        try:
            while True:
                raw = os.read(fd, 65536)
                if not raw:
                    break
                with mutex:
                    total += len(raw)
                    if total > MAX_COMMAND_BYTES:
                        overflow = True
                        break
                    chunks[index].append(raw)
        finally:
            os.close(fd)
    threads = [threading.Thread(target=drain, args=(index,), daemon=True) for index in range(2)]
    for thread in threads:
        thread.start()
    try:
        result = runner(argv, input=input, text=text, stdout=pipes[0][1], stderr=pipes[1][1],
                        timeout=timeout, cwd=cwd, env=env)
    finally:
        for _, fd in pipes:
            os.close(fd)
        for thread in threads:
            thread.join(timeout=1)
    require(not any(thread.is_alive() for thread in threads), "command output drain time limit exceeded")
    require(not overflow, "command output byte limit exceeded; outcome unknown, no retry")
    output = []
    for index, field in enumerate((result.stdout, result.stderr)):
        # A substituted OS runner can return bytes directly; native runs use the descriptors above.
        raw = field if field is not None else b"".join(chunks[index])
        raw = raw.encode() if isinstance(raw, str) else raw
        output.append(raw)
    require(sum(map(len, output)) <= MAX_COMMAND_BYTES, "command output byte limit exceeded")
    result = subprocess.CompletedProcess(argv, result.returncode,
                *(raw.decode() if text else raw for raw in output))
    if check:
        result.check_returncode()
    return result


def private(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "input must be an owned regular mode-0600 file")
    return json.loads(bounded_bytes(path))


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def write_bytes_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    if _VERIFIED_MODULES is None:
        spec.loader.exec_module(module)
    else:
        filename = name + ".py"
        require(filename in _VERIFIED_MODULES, "verified helper absent; no filesystem fallback")
        sys.modules[spec.name] = module
        try:
            exec(compile(_VERIFIED_MODULES[filename], str(Path(__file__).with_name(filename)), "exec"), module.__dict__)
        except BaseException:
            sys.modules.pop(spec.name, None)
            raise
    return module


def git(*arguments):
    return bounded_run(["git", *arguments], cwd=ROOT, check=True, text=True).stdout.strip()


def manifest(root, tracked=False):
    artifact = helper("compose-artifact")
    if tracked:
        candidates = git("ls-files", "-z").split("\0")
        require(len(candidates) <= MAX_ENTRIES, "tracked artifact entry limit exceeded")
    else:
        candidates = [path.relative_to(root).as_posix() for path, info in bounded_tree(root)
                      if stat.S_ISREG(info.st_mode)]
    paths = sorted(name for name in candidates if artifact.is_selected(name))
    require(paths and artifact.EXPLICIT_PATHS.issubset(paths), "artifact is missing a required explicit path")
    result, total = {}, 0
    digest = hashlib.sha256(artifact.FORMAT_MARKER)
    for name in paths:
        artifact.reject_unsafe_path(name)
        path = root / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "artifact links/special files are not supported by this operation")
        raw = bounded_bytes(path, min(MAX_FILE_BYTES, MAX_TREE_BYTES - total))
        total += len(raw)
        result[name] = {"sha256": sha(raw), "mode": stat.S_IMODE(info.st_mode), "size": len(raw)}
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return result, digest.hexdigest()


def source_identity():
    commit = git("rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and commit == git("rev-parse", "origin/main") and
            not git("status", "--porcelain=v1", "--untracked-files=all"),
            "requires clean committed published source (local origin/main binding; no fetch)")
    files, digest = manifest(ROOT, True)
    return {"source": commit, "artifact": files, "artifact_sha256": digest,
            "collector": {name: sha(bounded_bytes(Path(__file__).with_name(name))) for name in COLLECTORS},
            "contract_sha256": sha(bounded_bytes(ROOT / "infrastructure/contract/home-lab.yml")),
            "image_lock": json.loads(bounded_bytes(ROOT / "infrastructure/debian/production-image-lock.json"))}


def validate_request(request):
    require(request.get("format") == FORMAT and request.get("operation") == "capture" and
            request.get("target") == "docker-host/VM100/docker-compose/litellm" and
            re.fullmatch(r"[0-9a-f]{32}", request.get("nonce", "")) and
            request["created_at"] <= time.time() <= request["expires_at"] and
            request["expires_at"] - request["created_at"] == 1800,
            "wrong or expired capture request")


def delta(request, state):
    current, candidate = state["current"], request["artifact"]
    changed = sorted(name for name in set(current) | set(candidate) if current.get(name) != candidate.get(name))
    require(changed == [CONFIG], "requires exact config-only artifact delta; equality is not process adoption")
    require(set(current) == set(candidate) and current[CONFIG]["mode"] == candidate[CONFIG]["mode"],
            "artifact file-set or mode change is forbidden")
    require(state["host"]["hostname"] == "docker-host", "wrong host")
    return changed


def make_plan(capture):
    require(capture.get("format") == FORMAT and capture.get("status") == "captured",
            "plan requires a successful attended capture, not a partial/refused sample")
    request = capture["request"]
    validate_request(request)
    require(request["created_at"] <= capture["captured_at"] <= time.time() <= request["expires_at"],
            "capture time is stale or invalid")
    require(all(request[key] == value for key, value in source_identity().items()), "source binding changed")
    changed = delta(request, capture["state"])
    plan = {"format": FORMAT, "operation": "apply", "authorized": False, "request": request,
            "capture_sha256": sha(canonical(capture)), "before": capture["state"],
            "effects": {"changed_paths": changed, "recreate": ["litellm"], "pull": False,
                        "decrypt": False, "preserve_previous": True, "automatic_recovery": False}}
    plan["plan_sha256"] = sha(canonical(plan))
    return plan


def validate_plan(plan):
    material = dict(plan)
    digest = material.pop("plan_sha256", None)
    require(digest == sha(canonical(material)) and plan.get("format") == FORMAT and
            plan.get("operation") == "apply" and plan.get("authorized") is False,
            "saved plan hash or operation differs")
    validate_request(plan["request"])
    changed = delta(plan["request"], plan["before"])
    require(plan["effects"] == {"changed_paths": changed, "recreate": ["litellm"], "pull": False,
                                "decrypt": False, "preserve_previous": True, "automatic_recovery": False},
            "saved effect set differs")


def approval_for(operation, document):
    request = document if operation == "capture" else document["request"]
    digest = sha(canonical(document))
    return {"operation": operation, "document_sha256": digest,
            "confirmation": f"{operation}-litellm:{digest}:source:{request['source']}:artifact:{request['artifact_sha256']}"}


def confirm(operation, document, approval_path):
    expected = approval_for(operation, document)
    if approval_path is not None:
        require(private(approval_path) == expected, "exact approval differs")
    else:
        require(sys.stdin.isatty() and sys.stdout.isatty(), "exact approval file or real terminal required")
        require(input(expected["confirmation"] + "\nType the entire confirmation: ") == expected["confirmation"],
                "confirmation differs")
    return expected


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def open_directory(path):
    """Pin every component without following symlinks; caller owns the returned fd."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "unsafe directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def owned_directory(fd, mode=0o700):
    info = os.fstat(fd)
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode,
            "private directory metadata differs")


def read_owned(fd, name, *, limit=MAX_FILE_BYTES, mode=None, protect=False):
    handle = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    try:
        info = os.fstat(handle)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                info.st_size <= limit and (mode is None or stat.S_IMODE(info.st_mode) == mode),
                "owned file metadata/byte limit differs")
        if protect:
            require(stat.S_IMODE(info.st_mode) in (0o600, 0o644), "unsafe fetched result permissions")
            os.fchmod(handle, 0o600)
        with os.fdopen(handle, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, "owned file byte limit exceeded during read")
        return raw
    finally:
        os.close(handle)


def finalize_result(incoming_fd, output_fd, operation, document):
    raw = read_owned(incoming_fd, "result.json", protect=True)
    result = unique_json(raw)
    require(isinstance(result, dict), "delivered result must be an object")
    require(result.get("status") == ("captured" if operation == "capture" else "applied") and
            (result.get("request") == document if operation == "capture" else
             result.get("plan_sha256") == document["plan_sha256"]), "delivered result operation binding differs")
    info = os.fstat(output_fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0, "reserved output identity differs")
    with os.fdopen(output_fd, "wb", closefd=False) as stream:
        stream.write(raw)  # Exactly the bounded, validated buffer, never a second pathname read.
        stream.flush()
        os.fsync(output_fd)
    return result


def dispatch(operation, document, approval, known_hosts, output):
    output = output.absolute()
    request = document if operation == "capture" else document["request"]
    validate_request(request)
    require(all(request[key] == value for key, value in source_identity().items()), "source binding changed")
    approved_transport(known_hosts)
    require(known_hosts.is_absolute() and not known_hosts.is_symlink() and
            sha(bounded_bytes(known_hosts)) == request["known_hosts_sha256"], "SSH trust binding changed")
    require(not output.exists() and not output.is_symlink(), "output exists")
    executable = shutil.which("ansible-playbook")
    require(executable is not None, "existing Ansible executable prerequisite missing; no installation")
    # Reuse this entrypoint's existing virtualenv interpreter, not the operator Python.
    shebang = bounded_bytes(Path(executable)).split(b"\n", 1)[0].decode()
    require(re.fullmatch(r"#!/[A-Za-z0-9_./-]+/python(?:[0-9]+(?:\.[0-9]+)*)?", shebang),
            "existing Ansible must have an absolute Python shebang; no launcher fallback")
    interpreter = shebang[2:]
    require(Path(interpreter).is_file() and os.access(interpreter, os.X_OK), "existing Ansible interpreter absent")
    # Consume authority before transport; both local destinations are exclusively reserved.
    parent_fd = open_directory(output.parent)
    output_fd = incoming_fd = run_fd = None
    try:
        owned_directory(parent_fd)
        attempt = output.parent / ("litellm-" + sha(canonical(document)) + ".attempt.json")
        write_private(attempt, approval)
        output_fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=parent_fd)
        run_name = "litellm-transport-" + uuid.uuid4().hex
        os.mkdir(run_name, 0o700, dir_fd=parent_fd)
        run_fd = os.open(run_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        bundle = output.parent / run_name
        os.mkdir("incoming", 0o700, dir_fd=run_fd)
        incoming_fd = os.open("incoming", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_fd)
        for name, digest in request["collector"].items():
            raw = bounded_bytes(Path(__file__).with_name(name))
            require(sha(raw) == digest, "collector changed")
            write_bytes_private(bundle / name, raw)
        raw = bounded_bytes(ROOT / "infrastructure/contract/home-lab.yml")
        require(sha(raw) == request["contract_sha256"], "contract changed")
        write_bytes_private(bundle / "home-lab.yml", raw)
        write_private(bundle / "envelope.json", {"operation": operation, "document": document, "approval": approval})
        if operation == "apply":
            helper("compose-artifact").copy_artifact(ROOT, bundle / "artifact", sorted(request["artifact"]))
        variables = bundle / "variables.json"
        write_private(variables, {"litellm_bundle": str(bundle)})
        prepared_payload(bundle, private(bundle / "envelope.json"))
        env = {"PATH": str(Path(executable).parent) + ":" + os.defpath, "HOME": str(Path.home()), "LANG": "C.UTF-8",
               "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"), "ANSIBLE_SSH_RETRIES": "0",
               "ANSIBLE_AUTO_INSTALL_MODULE_DEPS": "false", "PYTHONNOUSERSITE": "1",
               "HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS": str(known_hosts)}
        try:
            result = bounded_run([interpreter, "-I", "-B", executable, "-i", str(ROOT / "ansible/inventory/production.yml"),
                                  "--limit", "docker-host-production", "--extra-vars", "@" + str(variables),
                                  str(ROOT / "ansible/playbooks/deploy-litellm.yml")], cwd=ROOT, env=env, timeout=900)
            require(result.returncode == 0, "Ansible delivery failed")
            require(os.path.samestat(os.fstat(parent_fd), output.parent.stat()) and
                    os.path.samestat(os.fstat(run_fd), bundle.lstat()) and
                    os.path.samestat(os.fstat(incoming_fd), (bundle / "incoming").lstat()), "local delivery directory changed")
            owned_directory(incoming_fd)
            result = finalize_result(incoming_fd, output_fd, operation, document)
            require(os.path.samestat(os.fstat(output_fd), output.lstat()), "reserved output path changed")
        except (OSError, subprocess.SubprocessError, SystemExit, ValueError) as error:
            write_private(bundle / "transport-result.json", {"status": "unknown", "error_type": type(error).__name__,
                          "next_decision": "inspect actual host/process/ownership and retained delivery evidence; no retry"})
            raise SystemExit("delivery failed/unknown; host may have completed and released ownership; no retry")
        write_private(bundle / "transport-result.json", {"status": "delivered", "result_sha256": sha(canonical(result))})
        print(sha(canonical(result)))
    finally:
        for fd in (incoming_fd, run_fd, output_fd, parent_fd):
            if fd is not None:
                os.close(fd)


CURRENT = "/srv/docker-compose/current"
PREVIOUS = "/srv/docker-compose/previous"
ENV = "/etc/docker-compose/production.env"
OVERRIDE = "/var/lib/home-lab/production-image-override.json"
OWNER = "/var/lib/iac-ansible-production.lock"
BACKUP_LOCK = "/run/lock/home-lab-backup.lock"
RECOVERY_FILES = {ENV: 0o600, "/etc/docker-compose/previous.env": 0o600,
                  OVERRIDE: 0o644, "/var/lib/docker-compose/current-images.json": 0o600,
                  "/var/lib/docker-compose/previous-images.json": 0o600,
                  "/var/lib/docker-compose/current-artifact.sha256": 0o444}
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
UP = ["up", "--detach", "--no-build", "--pull", "never", "--no-deps", "--force-recreate", "litellm"]


# Pinned 1.94.0 startup evidence: CLI config -> initialize/load_config before ASGI lifespan yield.
# This observes file-read startup adoption only; Router may ignore invalid deployments.
STARTUP_PROBE = r'''
import hashlib, http.client, importlib.metadata, json, os, pathlib
import yaml

def need(ok):
    if not ok: raise SystemExit(65)

def read(path):
    with open(path, "rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    need(len(raw) <= 8 * 1024 * 1024)
    return raw

def entries(path):
    with os.scandir(path) as stream:
        for count, entry in enumerate(stream, 1):
            need(count <= 4096)
            yield pathlib.Path(entry.path)

def digest(path):
    return hashlib.sha256(read(path)).hexdigest()

need(importlib.metadata.version("litellm") == "1.94.0")
config = yaml.safe_load(read("/app/config.yaml"))
need(set(config) == {"model_list", "litellm_settings", "general_settings"})
need(config["general_settings"] == {"master_key": "os.environ/LITELLM_MASTER_KEY"})
need(config["litellm_settings"] == {"check_provider_endpoint": True,
     "callbacks": ["custom_callbacks.service_tier_passthrough"]})
need(isinstance(config["model_list"], list) and bool(config["model_list"]))
for model in config["model_list"]:
    need(set(model) <= {"model_name", "model_info", "litellm_params"})
    need(set(model["litellm_params"]) == {"model"})
    need(isinstance(model["model_name"], str) and isinstance(model["litellm_params"]["model"], str))
listeners = set()
for table in ("/proc/net/tcp", "/proc/net/tcp6"):
    for line in read(table).decode().splitlines()[1:]:
        fields = line.split()
        if fields[1].endswith(":0FA0") and fields[3] == "0A": listeners.add(fields[9])
need(bool(listeners))
servers = []
for proc in entries("/proc"):
    if not proc.name.isdigit(): continue
    try:
        fds = {os.readlink(fd) for fd in entries(proc / "fd")}
        if any("socket:[" + inode + "]" in fds for inode in listeners): servers.append(proc)
    except (FileNotFoundError, ProcessLookupError): pass
need(len(servers) == 1)
proc = servers[0]
argv = read(proc / "cmdline").decode().rstrip("\0").split("\0")
expected = ["--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "4000"]
need(argv[-6:] == expected and len(argv) in (7, 8) and pathlib.Path(argv[-7]).name == "litellm")
env = dict(item.split("=", 1) for item in read(proc / "environ").decode().split("\0") if item)
for key in ("CONFIG_FILE_PATH", "LITELLM_CONFIG_BUCKET_NAME", "LITELLM_CONFIG_BUCKET_TYPE",
            "LITELLM_CONFIG_BUCKET_OBJECT_KEY", "DATABASE_URL", "DATABASE_DIRECT_URL", "STORE_MODEL_IN_DB",
            "USE_GUNICORN", "NUM_WORKERS", "LITELLM_NUM_WORKERS"):
    need(not env.get(key))
# Explicit production mode excludes CLI development dotenv loading. No implicit fallback.
need(env.get("LITELLM_MODE") == "PRODUCTION")
if env.get("WORKER_CONFIG"):
    need(json.loads(env["WORKER_CONFIG"]).get("config") == "/app/config.yaml")
need(not pathlib.Path("/app/.env").exists())
connection = http.client.HTTPConnection("127.0.0.1", 4000, timeout=3)
connection.request("GET", "/health/liveliness")
response = connection.getresponse()
body = response.read(129)
need(response.status == 200 and len(body) <= 128 and json.loads(body) == "I'm alive!")
connection.close()
print(json.dumps({"config_sha256": digest("/app/config.yaml"),
                  "callback_sha256": digest("/app/custom_callbacks.py"),
                  "server_pid": int(proc.name), "server_start_ticks": read(proc / "stat").decode().rsplit(")", 1)[1].split()[19],
                  "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                  "environment_sha256": hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest(),
                  "version": "1.94.0", "liveness": True}))
'''


class NativeHost:
    """Fixed host effects used by the guarded Ansible transaction, never a general executor."""
    def __init__(self, root, run, workspace):
        self.root, self.run = root, run
        self.docker_config = workspace / "docker-cli-config"
        self.docker_config_created = False
        self.inventory = helper("compose-model-inventory")
        self.actions = helper("compose-action-plan")

    def path(self, name):
        return self.root / name.lstrip("/")

    def execute(self, argv, *, data=None, timeout=60):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/", "LANG": "C.UTF-8"}
        def execute(command):
            return bounded_run(command, input=data, text=True, timeout=timeout, env=env, runner=self.run)
        if argv[0] == "/usr/bin/docker":
            require(argv[:3] == DOCKER, "Docker endpoint must be the local socket")
            # No user context, credentials, plugin directory or CLI defaults from /home/docker.
            if not self.docker_config_created:
                self.docker_config.mkdir(mode=0o700)  # Retain inside the already approved protected workspace.
                self.docker_config_created = True
            info = self.docker_config.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                    info.st_uid == os.geteuid(), "Docker CLI config directory metadata differs")
            with os.scandir(self.docker_config) as entries:
                require(next(entries, None) is None, "Docker CLI config directory is not empty")
            return execute(argv[:3] + ["--config", str(self.docker_config)] + argv[3:])
        return execute(argv)

    def command(self, argv, *, data=None, timeout=60):
        result = self.execute(argv, data=data, timeout=timeout)
        require(result.returncode == 0, "native command failed (output suppressed); retain ownership, no retry")
        return result.stdout

    def daemon(self):
        values = dict(line.split("=", 1) for line in self.command(["/usr/bin/systemctl", "show", "docker.service",
                      "--property=ActiveState,SubState,MainPID"]).splitlines())
        require(values.get("ActiveState") == "active" and values.get("SubState") == "running" and
                values.get("MainPID", "0").isdigit() and int(values.get("MainPID", "0")) > 0,
                "Docker must already be running; refusing socket activation")
        return values

    def docker(self, *argv, data=None):
        self.daemon()
        return self.command([*DOCKER, *argv], data=data)

    def compose(self, directory=CURRENT):
        command = [*DOCKER, "compose", "--ansi", "never", "--project-name", "docker-compose",
                   "--project-directory", str(self.path(directory)),
                   "--env-file", str(self.path(ENV if directory == CURRENT else "/etc/docker-compose/previous.env")),
                   "--file", str(self.path(directory) / "docker-compose.yml")]
        # The current override must never conceal the previous artifact's declarations.
        return command + ["--file", str(self.path(OVERRIDE))] if directory == CURRENT else command

    def retained_image_matches(self, reference, inspected):
        require(isinstance(reference, str) and bool(reference), "retained image reference absent")
        if reference.startswith("sha256:"):
            return reference == inspected["Id"]
        if "@sha256:" in reference:
            repository, digest = reference.rsplit("@", 1)
            if ":" in repository.rsplit("/", 1)[-1]:
                repository = repository.rsplit(":", 1)[0]
            return repository + "@" + digest in (inspected.get("RepoDigests") or [])
        # Mutable references have no historical identity unless their local mapping still agrees.
        return json.loads(self.docker("image", "inspect", reference))[0]["Id"] == inspected["Id"]

    def file_identity(self, name, mode=None):
        path = self.path(name)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
                (mode is None or stat.S_IMODE(info.st_mode) == mode) and not info.st_mode & 0o022,
                "protected file metadata differs: " + name)
        return {"sha256": sha(bounded_bytes(path)), "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}

    def artifact(self, name):
        path = self.path(name)
        if path.is_symlink():
            require(name == CURRENT and os.readlink(path) ==
                    "/var/lib/home-lab/compose-staging/d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c",
                    "unrecognized artifact root symlink")
        require(path.is_dir(), "artifact directory absent")
        info = path.stat()
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "artifact root metadata differs")
        actual, total = set(), 0
        for entry, info in bounded_tree(path):
            require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "artifact metadata differs")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                require(info.st_size <= MAX_FILE_BYTES and total <= MAX_TREE_BYTES, "artifact byte limit exceeded")
                actual.add(entry.relative_to(path).as_posix())
        selected, digest = manifest(path)
        require(actual == set(selected), "unselected artifact file present (including dotenv)")
        return selected, digest

    @contextmanager
    def exclusion(self):
        # Existing backup descriptor, never replace/unlink it or install a missing lock.
        path = self.path(BACKUP_LOCK)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o660 and info.st_gid == grp.getgrnam("restic-proton").gr_gid,
                "existing backup mutex metadata differs")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        additional = []
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SystemExit("backup exclusion is held")
            for name in ("/run/lock/home-lab-vfio-recovery.lock", "/run/lock/home-lab-debian-package.lock",
                         "/var/lib/home-lab/reconciliation/operation.lock"):
                if self.path(name).exists():
                    self.file_identity(name)
                    other = os.open(self.path(name), os.O_RDONLY | os.O_NOFOLLOW)
                    additional.append(other)
                    try:
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise SystemExit("competing native operation is held")
            self.conflicts()
            yield
        finally:
            for other in additional:
                os.close(other)
            os.close(fd)

    def conflicts(self, owned=None):
        for name in (OWNER, "/var/lib/home-lab/reconciliation/apply.lock",
                     "/var/lib/home-lab/reconciliation/owner.lock", "/var/lib/home-lab/reconciliation/nix.lock"):
            path = self.path(name)
            if name == OWNER and owned is not None:
                require(path.is_dir() and not path.is_symlink() and
                        sorted(p.name for p in path.iterdir()) == ["owner"] and
                        bounded_bytes(path / "owner") == owned, "foreign production ownership")
            else:
                require(not path.exists() and not path.is_symlink(), "production ownership/conflict present")
        require(not self.path("/var/lib/home-lab-restic/interruption.json").exists(), "Restic recovery pending")

    def dry_run(self):
        self.daemon()
        command = self.compose()
        command.insert(command.index("compose") + 1, "--dry-run")
        result = self.execute(command + UP, timeout=120)
        require(result.returncode == 0, "native no-pull dry run failed")
        text = self.actions.ANSI_PATTERN.sub("", result.stdout + result.stderr)
        actions = self.actions.canonical_actions(self.actions.ACTION_PATTERN.findall(text))
        statuses = re.findall(r"\bContainer\s+(\S+)\s+(\w+)", text)
        require(("litellm", "Recreate") in actions and all(name == "litellm" and action in
                ("Recreate", "Start", "Stop") for name, action in actions) and
                all(name == "litellm" and action in ("Recreate", "Recreating", "Recreated", "Start", "Starting",
                    "Started", "Stop", "Stopping", "Stopped", "Running", "Healthy", "Waiting") for name, action in statuses) and
                not re.search(r"\b(Network|Volume|Image|Pull|Pulling|Pulled|Build|Building|Built|Create|Creating|Created|Remove|Removing|Removed)\b", text),
                "dry run proposes unapproved or unknown effects")
        return [list(action) for action in actions]

    def startup(self, container, artifact):
        probe = json.loads(self.docker("exec", "-i", container["id"], "python", "-I", "-B", "-", data=STARTUP_PROBE))
        require(probe["config_sha256"] == artifact[CONFIG]["sha256"] and
                probe["callback_sha256"] == artifact["services/data/litellm/custom_callbacks.py"]["sha256"] and
                probe["version"] == "1.94.0" and probe["liveness"] is True and probe["server_pid"] > 0,
                "startup read-path/liveness verification failed")
        return probe

    def mounts(self, service, model, image, row):
        desired = {}
        for item in service.get("volumes", []):
            target = item["target"]
            require(target not in desired, "duplicate desired mount")
            require(item["type"] in ("bind", "tmpfs"), "unsupported explicit mount type")
            desired[target] = {"source": item.get("source", ""), "target": target,
                               "read_only": item.get("read_only", False), "type": item["type"]}
            if item["type"] == "tmpfs":
                options = item.get("tmpfs", {})
                require(set(options) <= {"size", "mode"}, "unsupported tmpfs options")
                actual = [m for m in row["HostConfig"].get("Mounts", []) if m.get("Target") == target]
                require(len(actual) == 1 and actual[0].get("Type") == "tmpfs" and
                        not actual[0].get("Source") and actual[0].get("ReadOnly", False) == item.get("read_only", False) and
                        actual[0].get("TmpfsOptions", {}).get("SizeBytes", 0) == options.get("size", 0) and
                        actual[0].get("TmpfsOptions", {}).get("Mode", 0) == options.get("mode", 0) and
                        set(actual[0].get("TmpfsOptions", {})) <= {"SizeBytes", "Mode"}, "tmpfs options differ")
        require(not row["HostConfig"].get("Tmpfs"), "unmodeled short-form tmpfs")
        require({m["Target"] for m in row["HostConfig"].get("Mounts", []) if m["Type"] == "tmpfs"} ==
                {target for target, m in desired.items() if m["type"] == "tmpfs"}, "tmpfs set differs")
        for secret in service.get("secrets", []):
            require(isinstance(secret, dict), "unresolved secret mount")
            definition = model.get("secrets", {}).get(secret["source"], {})
            require(set(definition) <= {"name", "file"} and definition.get("file", "").startswith("/"),
                    "only existing file-backed Compose secrets are supported")
            target = secret.get("target", secret["source"])
            target = target if target.startswith("/") else "/run/secrets/" + target
            require(target not in desired, "duplicate secret mount")
            desired[target] = {"source": definition["file"], "target": target, "read_only": True, "type": "bind"}
        require(not service.get("configs"), "unsupported Compose config mount")
        actual = {}
        for item in row["Mounts"]:
            target = item["Destination"]
            require(target not in actual, "duplicate runtime mount")
            actual[target] = {"source": item.get("Source", ""), "target": target,
                              "read_only": not item["RW"], "type": item["Type"]}
            if target not in desired and target in (image["Config"].get("Volumes") or {}):
                name = item.get("Name", "")
                require(item["Type"] == "volume" and item.get("Driver") == "local" and
                        re.fullmatch(r"[0-9a-f]{64}", name) and item["RW"], "image volume identity differs")
                volume = json.loads(self.docker("volume", "inspect", name))
                require(len(volume) == 1 and volume[0]["Name"] == name and volume[0]["Driver"] == "local" and
                        volume[0]["Scope"] == "local" and not volume[0].get("Options") and
                        volume[0]["Mountpoint"] == item["Source"], "image volume source differs")
                desired[target] = dict(actual[target])
                actual[target].update(name=name, driver=item["Driver"])
                desired[target].update(name=name, driver=item["Driver"])
        # Engine versions may represent tmpfs only in HostConfig.Mounts, not top-level Mounts.
        for target, mount in desired.items():
            if mount["type"] == "tmpfs" and target not in actual:
                actual[target] = dict(mount)
        require(set(image["Config"].get("Volumes") or {}) <= set(desired), "image volume absent")
        require(actual == desired, "desired/runtime mounts differ")
        return sorted(actual.values(), key=lambda item: item["target"])

    def snapshot(self, request, contract, owned=None):
        self.conflicts(owned)
        daemon = self.daemon()
        jobs = json.loads(self.command(["/usr/bin/systemctl", "list-jobs", "--output=json", "--no-pager"]))
        require(jobs == [], "queued systemd work exists")
        current, current_hash = self.artifact(CURRENT)
        previous, previous_hash = self.artifact(PREVIOUS)
        files = {name: self.file_identity(name, mode) for name, mode in RECOVERY_FILES.items()}
        require(bounded_bytes(self.path("/var/lib/docker-compose/current-artifact.sha256")).decode().strip() == current_hash,
                "active artifact marker differs from recomputed tree")
        storage = contract["proxmox"]["vm"]["state_disk"]
        mount = json.loads(self.command(["/usr/bin/findmnt", "--json", "--target", "/srv/home-lab-state/litellm-data",
                                       "--output", "TARGET,SOURCE,FSTYPE,UUID,OPTIONS"]))["filesystems"]
        require(len(mount) == 1 and mount[0]["target"] == storage["mountpoint"] and
                mount[0]["uuid"] == storage["filesystem_uuid"] and mount[0]["fstype"] == storage["filesystem"] and
                "rw" in mount[0]["options"].split(","), "protected state mount differs")
        token_path = self.path("/srv/home-lab-state/litellm-data")
        token = token_path.lstat()
        require(stat.S_ISDIR(token.st_mode), "token-data bind directory absent or linked")
        token_files, total = {}, 0
        for path, info in bounded_tree(token_path, entries=1000):
            content = "directory"
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "unsupported token-data hardlink")
                raw = bounded_bytes(path, min(1048576, 16 * 1024 * 1024 - total))
                total += len(raw)
                content = sha(raw)
            token_files[path.relative_to(token_path).as_posix()] = [stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, content]
        model = json.loads(self.command(self.compose() + ["config", "--format", "json"]))
        services = model["services"]
        require(model.get("name") == "docker-compose" and "litellm" in services, "wrong Compose project")
        ids = self.docker("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=docker-compose").splitlines()
        require(ids, "runtime service set absent")
        rows = json.loads(self.docker("inspect", *ids))
        runtime = {}
        for row in rows:
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            require(name not in runtime, "duplicate runtime service")
            runtime[name] = row
        require(set(runtime) == set(services), "runtime service-set differs")
        override = json.loads(bounded_bytes(self.path(OVERRIDE)))
        require(set(override) == {"services"} and set(override["services"]) <= set(services), "installed override shape differs")
        for name, entry in override["services"].items():
            require(entry == {"image": runtime[name]["Image"]}, "installed override/image ID disagreement")
        previous_model = json.loads(self.command(self.compose(PREVIOUS) + ["config", "--format", "json"]))
        require(previous_model.get("name") == "docker-compose" and previous_model.get("services"),
                "previous Compose project absent or differs")
        retained = {}
        for filename in ("current-images.json", "previous-images.json"):
            lock = json.loads(bounded_bytes(self.path("/var/lib/docker-compose/" + filename)))
            require(lock.get("schema") == 1 and lock.get("images"), "retained image lock invalid")
            names = set()
            for image in lock["images"]:
                require(image["service"] not in names, "duplicate retained image service")
                names.add(image["service"])
                inspected = json.loads(self.docker("image", "inspect", image["image_id"]))[0]
                require(inspected["Id"] == image["image_id"], "retained recovery image missing")
                if filename == "current-images.json":
                    require(image["service"] in runtime and runtime[image["service"]]["Image"] == image["image_id"],
                            "current image lock differs")
                else:
                    declared = previous_model["services"].get(image["service"], {})
                    require(not declared.get("build") and declared.get("image") and
                            self.retained_image_matches(declared["image"], inspected) and
                            (("@sha256:" in declared["image"] and
                              image.get("reference") == declared["image"].split("@", 1)[0]) or
                             self.retained_image_matches(image.get("reference"), inspected)),
                            "previous image lock/declaration identity differs")
            require(names == set(services if filename == "current-images.json" else previous_model["services"]),
                    filename + " service set differs")
            retained[filename] = lock
        pinned = [entry for entry in request["image_lock"]["images"] if entry["service"] == "litellm"]
        require(len(pinned) == 1 and runtime["litellm"]["Image"] == pinned[0]["image_id"] and
                pinned[0]["reference"] in bounded_bytes(self.path(CURRENT + "/services/apps.yml")).decode(),
                "LiteLLM image differs from committed retention association")
        config_hashes = dict(line.split() for line in self.command(self.compose() + ["config", "--hash", "*"]).splitlines())
        require(set(config_hashes) == set(services) and all(runtime[name]["Config"]["Labels"].get(
                "com.docker.compose.config-hash") == value for name, value in config_hashes.items()),
                "resolved Compose/runtime configuration identity differs")
        containers = {}
        for name, row in runtime.items():
            service = services[name]
            require(not service.get("build") and not service.get("develop"), "build/develop is forbidden")
            image = json.loads(self.docker("image", "inspect", service["image"]))[0]
            require(image["Id"] == row["Image"], "desired/runtime image differs")
            config, state = row["Config"], row["State"]
            require(state["Running"] and not state.get("Paused") and not state.get("Restarting") and
                    not state.get("Dead") and state.get("Health", {}).get("Status") not in ("starting", "unhealthy"),
                    "runtime service is not stable/running")
            expected_env = dict(item.split("=", 1) for item in (image["Config"].get("Env") or []))
            for key, value in (service.get("environment") or {}).items():
                if value is None:
                    expected_env.pop(key, None)
                else:
                    expected_env[key] = str(value)
            actual_env = dict(item.split("=", 1) for item in (config.get("Env") or []))
            require(expected_env == actual_env, "desired/runtime environment differs")
            for desired_key, runtime_key in (("command", "Cmd"), ("entrypoint", "Entrypoint"), ("user", "User"),
                                             ("working_dir", "WorkingDir")):
                expected = service.get(desired_key, image["Config"].get(runtime_key))
                require(expected == config.get(runtime_key), "desired/runtime startup configuration differs")
            mounts = self.mounts(service, model, image, row)
            require(self.inventory.desired_ports(service.get("ports") or []) ==
                    self.inventory.runtime_ports(row["HostConfig"].get("PortBindings") or {}), "ports differ")
            actual_devices = sorted((d["PathOnHost"], d["PathInContainer"], d["CgroupPermissions"])
                                    for d in row["HostConfig"].get("Devices") or [])
            desired_devices = sorted((d["source"], d["target"], d["permissions"]) for d in service.get("devices") or [])
            require(actual_devices == desired_devices, "devices differ")
            memberships = sorted(row["NetworkSettings"]["Networks"])
            network_mode = row["HostConfig"].get("NetworkMode")
            if network_mode and network_mode.startswith("container:"):
                peer = network_mode.split(":", 1)[1]
                matches = [key for key, value in runtime.items() if peer in (value["Id"], value["Id"][:12], key)]
                require(len(matches) == 1, "unknown shared network namespace")
                network_mode = "service:" + matches[0]
            elif network_mode == "host":
                memberships = []
            elif network_mode in memberships:
                network_mode = None
            expected_networks = sorted(model["networks"][key]["name"] for key in service.get("networks") or {})
            require(network_mode == service.get("network_mode") and memberships == expected_networks,
                    "network mode/membership differs")
            restart = service.get("restart", "no").split(":", 1)
            actual_restart = row["HostConfig"].get("RestartPolicy") or {}
            require(actual_restart.get("Name", "no") == restart[0] and
                    actual_restart.get("MaximumRetryCount", 0) == (int(restart[1]) if len(restart) == 2 else 0),
                    "restart policy differs")
            if service.get("logging"):
                logging = service["logging"]
                require(row["HostConfig"]["LogConfig"] == {"Type": logging["driver"],
                        "Config": logging.get("options", {})}, "logging configuration differs")
            health = self.inventory.normalized_healthcheck(image["Config"].get("Healthcheck")) or {}
            override_health = self.inventory.normalized_healthcheck(service.get("healthcheck")) or {}
            health = override_health if override_health.get("disable") else dict(health, **override_health)
            require((health or None) == self.inventory.normalized_healthcheck(config.get("Healthcheck")), "healthcheck differs")
            stable_config = dict(config, Labels={key: value for key, value in config.get("Labels", {}).items()
                                                 if key != "com.docker.compose.replace"})
            if service.get("hostname"):
                require(config.get("Hostname") == service["hostname"], "explicit runtime hostname differs")
            elif service.get("network_mode") == "host":
                require(config.get("Hostname") == bounded_bytes(self.path("/etc/hostname")).decode().strip(),
                        "host-network runtime hostname differs")
            else:
                require(config.get("Hostname") == row["Id"][:12], "generated runtime hostname differs")
                stable_config.pop("Hostname")  # Docker assigns the new container ID prefix at recreation.
            containers[name] = {"id": row["Id"], "hostname": config["Hostname"],
                                "pid": state["Pid"], "started": state["StartedAt"],
                                "restarts": row["RestartCount"], "image_id": row["Image"],
                                "config_sha256": sha(canonical(stable_config)), "host_config_sha256": sha(canonical(row["HostConfig"])),
                                "mounts_sha256": sha(canonical(mounts)), "environment_sha256": sha(canonical(actual_env)),
                                "networks_sha256": sha(canonical(row["NetworkSettings"]["Networks"]))}
        network_ids = {}
        for name, network in model.get("networks", {}).items():
            entry = json.loads(self.docker("network", "inspect", network["name"]))[0]
            require(not network.get("driver") or entry["Driver"] == network["driver"], "network driver differs")
            network_ids[name] = entry["Id"]
        require(not model.get("volumes"), "named-volume creation is outside this operation")
        target = services["litellm"]
        require(target["command"] == ["--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "4000"] and
                not target.get("depends_on") and not target.get("secrets") and not target.get("configs"),
                "unsupported LiteLLM startup/dependency inputs")
        expected_mounts = [(CURRENT + "/services/data/litellm/config.yaml", "/app/config.yaml", True),
                           (CURRENT + "/services/data/litellm/custom_callbacks.py", "/app/custom_callbacks.py", True),
                           ("/srv/home-lab-state/litellm-data", "/data", False)]
        require(sorted((m["source"], m["target"], m.get("read_only", False)) for m in target["volumes"]) ==
                sorted(expected_mounts), "LiteLLM mounts/token location differ")
        return {"daemon": daemon, "host": {"hostname": bounded_bytes(self.path("/etc/hostname")).decode().strip(),
                         "machine_id_sha256": sha(bounded_bytes(self.path("/etc/machine-id"))),
                         "boot_id": bounded_bytes(self.path("/proc/sys/kernel/random/boot_id")).decode().strip()},
                "current": current, "current_sha256": current_hash, "previous": previous,
                "previous_sha256": previous_hash, "files": files, "model_sha256": sha(canonical(model)),
                "containers": containers, "networks": network_ids, "state_mount": mount,
                "token_directory": {"device": token.st_dev, "inode": token.st_ino, "uid": token.st_uid,
                                    "gid": token.st_gid, "mode": stat.S_IMODE(token.st_mode),
                                    "tree_sha256": sha(canonical(token_files))}}


def host_transaction(workspace, *, root=Path("/"), run=subprocess.run, sleep=time.sleep):
    """Ansible transaction seam; root/run/sleep substitute external effects in offline tests only."""
    envelope = private(workspace / "envelope.json")
    operation, document = envelope["operation"], envelope["document"]
    require(operation in ("capture", "apply") and envelope["approval"] == approval_for(operation, document),
            "host requires exact operation approval")
    request = document if operation == "capture" else document["request"]
    validate_request(request)
    if operation == "apply":
        validate_plan(document)
    require(_VERIFIED_ENVELOPE_SHA256 == sha(bounded_bytes(workspace / "envelope.json")),
            "host requires pre-execution authenticated payload")
    for name, digest in request["collector"].items():
        require(sha(bounded_bytes(workspace / name)) == digest, "host collector differs")
    host = NativeHost(root, run, workspace)
    host.daemon()
    with host.exclusion():
        require(sha(bounded_bytes(workspace / "home-lab.yml")) == request["contract_sha256"], "host contract differs")
        try:
            import yaml
        except ImportError:
            raise SystemExit("native PyYAML prerequisite missing; no installation permitted")
        contract = yaml.safe_load(bounded_bytes(workspace / "home-lab.yml"))
        require(contract["vm_100"]["host_name"] == "docker-host", "contract host differs")
        attempt = host.path("/var/lib/docker-compose/litellm-" + request["nonce"] + "-" + operation)
        attempt.mkdir(mode=0o700)  # Exclusive durable host attempt; never reused.
        write_private(attempt / "approval.json", envelope["approval"])
        owned = None
        if operation == "apply":
            require(manifest(workspace / "artifact") == (request["artifact"], request["artifact_sha256"]),
                    "transferred artifact differs")
            candidate_config = yaml.safe_load(bounded_bytes(workspace / "artifact" / CONFIG))
            require(isinstance(candidate_config, dict) and set(candidate_config) ==
                    {"model_list", "litellm_settings", "general_settings"} and
                    candidate_config["general_settings"] == {"master_key": "os.environ/LITELLM_MASTER_KEY"} and
                    candidate_config["litellm_settings"] == {"check_provider_endpoint": True,
                        "callbacks": ["custom_callbacks.service_tier_passthrough"]} and
                    isinstance(candidate_config["model_list"], list) and bool(candidate_config["model_list"]),
                    "candidate introduces unsupported config sources/settings")
            for model in candidate_config["model_list"]:
                require(isinstance(model, dict) and set(model) <= {"model_name", "model_info", "litellm_params"} and
                        isinstance(model.get("model_name"), str) and isinstance(model.get("litellm_params"), dict) and
                        set(model["litellm_params"]) == {"model"} and isinstance(model["litellm_params"]["model"], str),
                        "candidate introduces unsupported model inputs")
            lock = host.path(OWNER)
            lock.mkdir(mode=0o700)
            owned = ("controller=ansible-deploy\noperation=litellm:" + sha(canonical(document)) +
                     "\nstarted=" + datetime.now(timezone.utc).isoformat() + "\n").encode()
            fd = os.open(lock / "owner", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(owned)
                stream.flush()
                os.fsync(stream.fileno())
        def observe():
            state = host.snapshot(request, contract, owned)
            state["startup"] = host.startup(state["containers"]["litellm"], state["current"])
            state["dry_run"] = host.dry_run()
            return state
        before = observe()
        delta(request, before)
        if operation == "capture":
            sleep(2)
            require(observe() == before, "attended observation changed during capture")
            result = {"format": FORMAT, "status": "captured", "request": request, "state": before,
                      "captured_at": int(time.time()), "authority": "attended-admin-capable",
                      "exclusion": "existing-native-descriptors; no production owner published"}
            write_private(workspace / "result.json", result)
            return result
        require(before == document["before"], "before-state changed; retained owner requires attended disposition")
        recovery = host.path("/srv/docker-compose/.litellm-" + document["plan_sha256"])
        recovery.mkdir(mode=0o700)
        write_private(recovery / "plan.json", document)
        write_private(recovery / "before.json", before)
        for name in RECOVERY_FILES:
            shutil.copyfile(host.path(name), recovery / Path(name).name)
            (recovery / Path(name).name).chmod(0o600)
        incoming = recovery / "incoming"
        helper("compose-artifact").copy_artifact(workspace / "artifact", incoming, sorted(request["artifact"]))
        incoming.chmod(0o755)
        for path, info in bounded_tree(incoming):
            if stat.S_ISDIR(info.st_mode):
                path.chmod(0o755)
        require(manifest(incoming) == (request["artifact"], request["artifact_sha256"]), "incoming artifact differs")
        # Last real recheck under exclusion, after retention and before any live publication.
        require(observe() == before, "before-state changed immediately before publication")
        validate_request(request)
        host.path(CURRENT).rename(recovery / "current")
        incoming.rename(host.path(CURRENT))
        marker = recovery / "new-artifact.sha256"
        marker.write_text(request["artifact_sha256"] + "\n")
        marker.chmod(0o444)
        marker.replace(host.path("/var/lib/docker-compose/current-artifact.sha256"))
        published = host.snapshot(request, contract, owned)
        unchanged_after_publication(before, published, request)
        host.dry_run()
        host.daemon()
        host.command(host.compose() + UP, timeout=120)
        sleep(20)  # One bounded startup wait, not a retry/recovery loop.
        after = observe()
        verify_adoption(before, after, request)
        sleep(10)
        require(observe() == after, "post-deployment process/input stability failed")
        result = {"format": FORMAT, "status": "applied", "plan_sha256": document["plan_sha256"],
                  "state": after, "adoption": "new-single-serving-process/startup-file-read-and-passive-liveness",
                  "provider_qualification": False, "readiness_qualification": False,
                  "recovery": str(recovery), "automatic_recovery": False}
        write_private(recovery / "result.json", result)
        write_private(workspace / "result.json", result)
        host.conflicts(owned)
        (host.path(OWNER) / "owner").unlink()
        host.path(OWNER).rmdir()
        return result


def unchanged_after_publication(before, after, request):
    require(after["current"] == request["artifact"] and after["current_sha256"] == request["artifact_sha256"],
            "published artifact differs")
    for key in ("host", "daemon", "previous", "previous_sha256", "model_sha256", "networks", "state_mount", "token_directory"):
        require(before[key] == after[key], "unapproved publication effect: " + key)
    for name in RECOVERY_FILES:
        if name != "/var/lib/docker-compose/current-artifact.sha256":
            require(before["files"][name] == after["files"][name], "recovery/environment/override input changed")
    require(before["containers"] == after["containers"], "container changed before approved recreation")


def verify_adoption(before, after, request):
    unchanged = dict(after, containers=before["containers"])
    unchanged_after_publication(before, unchanged, request)
    for name, container in before["containers"].items():
        current = after["containers"][name]
        if name != "litellm":
            require(current == container, "unrelated service changed")
            continue
        require(current["id"] != container["id"] and current["started"] != container["started"] and
                current["restarts"] == 0 and current["pid"] > 0, "new stable LiteLLM process not established")
        for field in ("image_id", "config_sha256", "host_config_sha256", "mounts_sha256", "environment_sha256"):
            require(current[field] == container[field], "LiteLLM runtime identity changed: " + field)
    require(after["startup"]["config_sha256"] == request["artifact"][CONFIG]["sha256"] and
            after["startup"]["liveness"] is True, "new process did not adopt intended startup input")


def approved_transport(known_hosts):
    require(known_hosts.is_absolute() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(known_hosts)) and
            not known_hosts.is_symlink() and known_hosts.is_file(), "unsafe SSH trust path")
    common = ("-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes "
              "-o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o UserKnownHostsFile=" + str(known_hosts) +
              " -o IdentityAgent=none -o IdentityFile=none -o IdentitiesOnly=yes -o PreferredAuthentications=none"
              " -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
              " -o GSSAPIAuthentication=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -o ConnectTimeout=10"
              " -o ServerAliveInterval=15 -o ServerAliveCountMax=2 -o RequestTTY=no")
    return {"host": "docker-host", "user": "ansible-deploy", "connection": "ssh", "port": 22,
            "ssh_executable": "/usr/bin/ssh", "ssh_args": "-o ControlMaster=no -o ControlPath=none",
            "ssh_common_args": common, "ssh_extra_args": "", "sftp_extra_args": "", "scp_extra_args": "",
            "private_key_file": "", "password": "", "retries": 0,
            "host_key_checking": True, "ssh_host_key_checking": True,
            "become": True, "become_method": "sudo", "become_user": "root", "become_exe": "/usr/bin/sudo",
            "become_flags": "-H -S -n", "python_interpreter": "/usr/bin/python3", "transfer_method": "piped",
            "shell_type": "sh", "shell_executable": "/bin/sh", "use_tty": False,
            "pipelining": True, "ssh_pipelining": True, "facts_modules": [], "check_mode": False,
            "inventory_hostname": "docker-host-production",
            "legacy": {"host": "docker-host", "user": "ansible-deploy", "port": 22, "key": "",
                       "password": "", "become_password": "", "become_pass": "", "sudo_exe": "/usr/bin/sudo",
                       "sudo_flags": "-H -S -n", "sudo_user": "root", "sudo_pass": ""}}


# These inline programs come from the reviewed controller, never a transferred verifier.
ALLOCATE = r"""
import os, re, stat, sys
if len(sys.argv) != 2 or not re.fullmatch('[0-9a-f]{64}', sys.argv[1]): raise SystemExit(65)
fd = os.open('/var/lib/docker-compose', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022: raise SystemExit(65)
    os.mkdir('.litellm-' + sys.argv[1], 0o700, dir_fd=fd)
finally:
    os.close(fd)
""".strip()

PREEXEC = r"""
import base64, hashlib, json, os, pathlib, re, stat, sys
LIMIT = 8 * 1024 * 1024
COLLECTORS = ('litellm-deployment.py', 'compose-artifact.py', 'compose-model-inventory.py', 'compose-action-plan.py')
def need(ok):
    if not ok: raise SystemExit('pre-execution payload admission failed')
def digest(raw):
    return hashlib.sha256(raw).hexdigest()
def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result)
        result[key] = value
    return result
def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)
need(len(sys.argv) == 3 and all(re.fullmatch('[0-9a-f]{64}', x) for x in sys.argv[1:]))
document_sha, payload_sha = sys.argv[1:]
workspace = pathlib.Path('/var/lib/docker-compose/.litellm-' + document_sha)
fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
info = os.fstat(fd)
need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
handle = os.open('payload.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
with os.fdopen(handle, 'rb') as stream:
    info = os.fstat(stream.fileno())
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= LIMIT)
    sealed = stream.read(LIMIT + 1)
need(len(sealed) <= LIMIT and digest(sealed) == payload_sha)
# No pathname reread: parse, extract and execute only the authenticated buffer.
payload = parse(base64.b64decode(sealed, validate=True))
need(set(payload) == {'format', 'document_sha256', 'files'} and payload['format'] == 'home-lab-litellm-v1' and
     payload['document_sha256'] == document_sha and isinstance(payload['files'], list) and
     0 < len(payload['files']) <= 4096)
files, modes, total = {}, {}, 0
for entry in payload['files']:
    need(set(entry) == {'path', 'mode', 'data'} and isinstance(entry['path'], str))
    name = entry['path']
    path = pathlib.PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts and
         0 < len(path.parts) <= 17 and len(name.encode()) <= 4096 and name not in files)
    need(type(entry['mode']) is int and 0 <= entry['mode'] <= 0o777 and not entry['mode'] & 0o022 and
         isinstance(entry['data'], str) and len(entry['data']) <= LIMIT)
    raw = base64.b64decode(entry['data'], validate=True)
    total += len(raw)
    need(total <= LIMIT)
    files[name], modes[name] = raw, entry['mode']
envelope = parse(files['envelope.json'])
need(set(envelope) == {'operation', 'document', 'approval'} and envelope['operation'] in ('capture', 'apply'))
document = envelope['document']
canonical = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
need(digest(canonical(document)) == document_sha)
request = document if envelope['operation'] == 'capture' else document['request']
need(set(request['collector']) == set(COLLECTORS))
expected = dict(request['collector'], **{'home-lab.yml': request['contract_sha256']})
expected_modes = {name: 0o600 for name in (*expected, 'envelope.json')}
if envelope['operation'] == 'apply':
    for name, identity in request['artifact'].items():
        expected['artifact/' + name] = identity['sha256']
        expected_modes['artifact/' + name] = identity['mode']
need(set(files) == set(expected) | {'envelope.json'} and modes == expected_modes and
     all(digest(files[name]) == value for name, value in expected.items()))
directories = {parent.as_posix() for name in files for parent in pathlib.PurePosixPath(name).parents if parent.as_posix() != '.'}
need(len(directories) + len(files) <= 4096)
os.mkdir('input', 0o700, dir_fd=fd)
input_fd = os.open('input', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
for name in sorted(directories, key=lambda name: (name.count('/'), name)):
    os.mkdir(name, 0o755, dir_fd=input_fd)
for name, raw in files.items():
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=input_fd)
    with os.fdopen(handle, 'wb') as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), modes[name])
        stream.flush()
        os.fsync(stream.fileno())
os.close(input_fd)
os.close(fd)
script = str(workspace / 'input/litellm-deployment.py')
sys.argv = [script, 'host-transaction', '--workspace', str(workspace / 'input')]
namespace = {'__name__': '__main__', '__file__': script, '__package__': None,
             '_VERIFIED_MODULES': {name: files[name] for name in COLLECTORS},
             '_VERIFIED_ENVELOPE_SHA256': digest(files['envelope.json'])}
exec(compile(files['litellm-deployment.py'], script, 'exec'), namespace)
""".strip()


def prepared_payload(workspace, envelope):
    """Read a bounded exact source tree; the return value is the ONLY copy.content buffer."""
    document = envelope['document']
    request = document if envelope['operation'] == 'capture' else document['request']
    require(set(request['collector']) == set(COLLECTORS), "prepared collector set differs")
    expected = {name: {'sha256': value, 'mode': 0o600} for name, value in request['collector'].items()}
    expected['home-lab.yml'] = {'sha256': request['contract_sha256'], 'mode': 0o600}
    expected['envelope.json'] = {'sha256': sha(canonical(envelope)), 'mode': 0o600}
    if envelope['operation'] == 'apply':
        expected.update({'artifact/' + name: identity for name, identity in request['artifact'].items()})
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent.as_posix() != '.'}
    root_fd = open_directory(workspace)
    entries, result, total, count = set(), [], 0, 0
    def walk(fd, prefix='', depth=0):
        nonlocal total, count
        require(depth <= MAX_DEPTH, "prepared tree depth limit exceeded")
        with os.scandir(fd) as stream:
            for entry in stream:
                name = prefix + entry.name
                entries.add(name)
                count += 1
                require(count <= MAX_ENTRIES and len(os.fsencode(name)) <= 4096, "prepared tree entry/path limit exceeded")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(name in directories | {'incoming'} and info.st_uid == os.getuid() and
                            not info.st_mode & 0o022, "unexpected prepared directory")
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if name == 'incoming':
                            owned_directory(child)
                        walk(child, name + '/', depth + 1)
                    finally:
                        os.close(child)
                elif name in expected:
                    identity = expected[name]
                    raw = read_owned(fd, entry.name, mode=identity['mode'], limit=min(MAX_FILE_BYTES, PAYLOAD_LIMIT - total))
                    total += len(raw)
                    require(sha(raw) == identity['sha256'] and ('size' not in identity or len(raw) == identity['size']),
                            "prepared payload bytes differ: " + name)
                    result.append({'path': name, 'mode': identity['mode'], 'data': base64.b64encode(raw).decode()})
                else:
                    require(name == 'variables.json' or name in {'transport-' + phase + '.json' for phase in TRANSPORT_PHASES} or
                            re.fullmatch(r'admission-rejected-[0-9a-f]{32}\.json', name), "unexpected prepared file")
                    value = unique_json(read_owned(fd, entry.name, mode=0o600, limit=65536))
                    if name == 'variables.json':
                        require(value == {'litellm_bundle': str(workspace)}, "prepared variables differ")
                    elif name.startswith('admission-rejected-'):
                        require(set(value) == {'status', 'phase', 'workspace', 'envelope_sha256', 'reason'} and
                                value['status'] == 'rejected' and value['workspace'] == str(workspace) and
                                len(value['reason']) <= 512, "prepared rejection receipt differs")
        # File identities are read through pinned directory fds, not traversal pathnames.
    try:
        owned_directory(root_fd)
        walk(root_fd)
    finally:
        os.close(root_fd)
    require(set(expected) | directories | {'variables.json', 'incoming'} <= entries and
            {entry['path'] for entry in result} == set(expected), "prepared payload file set differs")
    raw = canonical({'format': FORMAT, 'document_sha256': sha(canonical(document)),
                     'files': sorted(result, key=lambda entry: entry['path'])})
    require(len(raw) <= PAYLOAD_LIMIT * 3 // 4, "encoded payload byte limit exceeded")
    return base64.b64encode(raw).decode()


def transport_effects(workspace, document, payload):
    document_sha = sha(canonical(document))
    remote = '/var/lib/docker-compose/.litellm-' + document_sha
    return {
        'allocate': {'argv': ['/usr/bin/python3', '-I', '-B', '-c', ALLOCATE, document_sha], 'expand_argument_vars': False},
        'transfer': {'content_sha256': sha(payload.encode()), 'dest': remote + '/payload.json', 'mode': '0600',
                     'owner': 'root', 'group': 'root', 'force': False, 'follow': False},
        'execute': {'argv': ['/usr/bin/python3', '-I', '-B', '-c', PREEXEC, document_sha, sha(payload.encode())],
                    'expand_argument_vars': False},
        'fetch': {'src': remote + '/input/result.json', 'dest': str(workspace / 'incoming/result.json'), 'flat': True},
    }


TRANSPORT_PHASES = ("allocate", "transfer", "execute", "fetch")


def validate_bundle(workspace, *, known_hosts, transport, phase="allocate", view="gate", overrides=None):
    envelope = private(workspace / "envelope.json")
    operation, document = envelope["operation"], envelope["document"]
    require(operation in ("capture", "apply") and envelope["approval"] == approval_for(operation, document),
            "prepared bundle approval differs")
    request = document if operation == "capture" else document["request"]
    validate_request(request)
    if operation == "apply":
        validate_plan(document)
    attempt = workspace.parent / ("litellm-" + sha(canonical(document)) + ".attempt.json")
    require(private(attempt) == envelope["approval"], "operator attempt is absent or differs")
    require(not overrides, "effect path/argv override is forbidden")
    require(transport == approved_transport(known_hosts), "effective Ansible transport differs")
    require(sha(bounded_bytes(known_hosts)) == request["known_hosts_sha256"], "SSH trust binding changed")
    require(all(request[key] == value for key, value in source_identity().items()), "source binding changed")
    payload = prepared_payload(workspace, envelope)
    effects = transport_effects(workspace, document, payload)
    if phase == "target":
        require(view == "gate", "invalid target view")
        return "docker-host-production"  # Read-only/idempotent before host scheduling.
    require(phase in TRANSPORT_PHASES and view in ("gate", "arguments"), "unknown transport admission boundary/view")
    def receipt(name):
        return {"approval": envelope["approval"], "phase": name, "effect": effects[name],
                "payload_sha256": sha(payload.encode())}
    for prior in TRANSPORT_PHASES[:TRANSPORT_PHASES.index(phase)]:
        require(private(workspace / ("transport-" + prior + ".json")) == receipt(prior),
                "preceding transport effect admission absent or differs")
    path = workspace / ("transport-" + phase + ".json")
    if view == "gate":
        write_private(path, receipt(phase))
        return "validated"
    require(private(path) == receipt(phase), "actual effect differs from phase admission")
    arguments = dict(effects[phase])
    if phase == "transfer":
        require(arguments.pop("content_sha256") == sha(payload.encode()), "copy buffer differs")
        arguments["content"] = payload  # This very buffer becomes the module arguments; no independent src read.
    return canonical(arguments).decode().rstrip("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    request = sub.add_parser("request", help="offline exact attended observation request")
    request.add_argument("--known-hosts", type=Path, required=True)
    request.add_argument("--output", type=Path, required=True)
    plan = sub.add_parser("plan", help="credential-free offline plan")
    plan.add_argument("--capture", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    for operation, field in (("capture", "request"), ("apply", "plan")):
        command = sub.add_parser(operation)
        command.add_argument("--" + field, type=Path, required=True)
        command.add_argument("--approval-file", type=Path)
        command.add_argument("--known-hosts", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    approval = sub.add_parser("approval-template", help="offline template; operator/harness must separately approve")
    approval.add_argument("--input", type=Path, required=True)
    approval.add_argument("--output", type=Path, required=True)
    bundle = sub.add_parser("validate-bundle", help=argparse.SUPPRESS)
    bundle.add_argument("--workspace", type=Path, required=True)
    bundle.add_argument("--phase", choices=("target", *TRANSPORT_PHASES), default="allocate")
    bundle.add_argument("--known-hosts", type=Path, required=True)
    bundle.add_argument("--view", choices=("gate", "arguments"), default="gate")
    bundle.add_argument("--overrides", type=json.loads, default=[])
    bundle.add_argument("--transport", type=json.loads, required=True)
    host = sub.add_parser("host-transaction", help=argparse.SUPPRESS)
    host.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "validate-bundle":
        try:
            output = validate_bundle(args.workspace, known_hosts=args.known_hosts, transport=args.transport,
                                     phase=args.phase, view=args.view, overrides=args.overrides)
        except SystemExit as error:
            # Only an explicit validator rejection gets this receipt, not import/tool/parser failures.
            info = args.workspace.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == 0o700, "unsafe admission receipt directory")
            write_private(args.workspace / ("admission-rejected-" + uuid.uuid4().hex + ".json"),
                          {"status": "rejected", "phase": args.phase,
                           "workspace": str(args.workspace.absolute()),
                           "envelope_sha256": sha(bounded_bytes(args.workspace / "envelope.json")),
                           "reason": str(error)[:512]})
            raise
        print(output)
    elif args.command == "host-transaction":
        require(os.geteuid() == 0 and sys.platform == "linux", "host transaction requires native Linux root")
        try:
            host_transaction(args.workspace)
        except (Exception, SystemExit) as error:
            write_private(args.workspace / "failure.json", {"status": "failed-or-unknown",
                          "reason": str(error) if isinstance(error, SystemExit) else type(error).__name__,
                          "next_decision": "attended inspection of retained attempt/owner/current/recovery; no retry or compensation"})
            raise SystemExit("guarded host attempt failed/unknown; inspect retained failure.json and ownership")
    elif args.command == "approval-template":
        document = private(args.input)
        operation = document["operation"]
        require(operation in ("capture", "apply"), "invalid operation")
        write_private(args.output, approval_for(operation, document))
    elif args.command in ("capture", "apply"):
        document = private(args.request if args.command == "capture" else args.plan)
        if args.command == "apply":
            validate_plan(document)
        else:
            validate_request(document)
        approval = confirm(args.command, document, args.approval_file)
        dispatch(args.command, document, approval, args.known_hosts, args.output)
    elif args.command == "request":
        request = dict(source_identity(), format=FORMAT, operation="capture",
                       target="docker-host/VM100/docker-compose/litellm", nonce=uuid.uuid4().hex,
                       known_hosts_sha256=sha(bounded_bytes(args.known_hosts)),
                       created_at=int(time.time()))
        request["expires_at"] = request["created_at"] + 1800
        write_private(args.output, request)
        print(sha(canonical(request)))
    else:
        plan = make_plan(private(args.capture))
        write_private(args.output, plan)
        print(plan["plan_sha256"])


if __name__ == "__main__":
    main()
