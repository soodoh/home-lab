#!/usr/bin/env python3
"""Capture a fixed, read-only Ansible versus Nix Proxmox shadow audit."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any

sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "infrastructure/policy/proxmox-nix-shadow.json"
POLICY_FORMAT = "home-lab-proxmox-nix-shadow-policy-v1"
EVIDENCE_FORMAT = "home-lab-proxmox-nix-shadow-evidence-v1"
MAX_CAPTURE = 16 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLAN_RESULT = re.compile(
    r"^status=(ready|blocked) actions=([0-9]+) blockers=([0-9]+) "
    r"planSha256=([0-9a-f]{64}) path=(/[^\n]+)\n?$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RECAP = re.compile(
    r"^(?P<host>[^\s]+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)\s+skipped=(?P<skipped>\d+)\s+"
    r"rescued=(?P<rescued>\d+)\s+ignored=(?P<ignored>\d+)\s*$"
)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def load_policy() -> str:
    raw = POLICY.read_bytes()
    value = exact(json.loads(raw), {"format", "state"}, "shadow policy")
    if raw != canonical(value) or value["format"] != POLICY_FORMAT or value["state"] not in {
        "pre-bootstrap", "shadow-required",
    }:
        raise ValueError("shadow policy is invalid or noncanonical")
    return value["state"]


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(("git", "-C", str(repo), *arguments), capture_output=True, text=True, timeout=10)
    if result.returncode or result.stderr:
        raise ValueError("fixed Git binding failed")
    return result.stdout.strip()


def repository_identity(repo: Path) -> tuple[str, str]:
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("shadow capture requires a clean worktree")
    commit = git(repo, "rev-parse", "HEAD")
    if commit != git(repo, "rev-parse", "refs/remotes/origin/main") or HEX40.fullmatch(commit) is None:
        raise ValueError("shadow capture requires HEAD to equal origin/main")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    if HEX40.fullmatch(tree) is None:
        raise ValueError("Git tree binding is invalid")
    return commit, tree


def open_directory(path: Path, secure_from: Path, create: bool = False) -> int:
    absolute = path.absolute()
    root = secure_from.absolute()
    try:
        relative = absolute.relative_to(root)
        resolved_root = root.resolve(strict=True)
    except (ValueError, OSError) as error:
        raise ValueError("fixed path escapes or lacks its protected root") from error
    descriptor = os.open(
        resolved_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        root_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != os.getuid() or \
                stat.S_IMODE(root_metadata.st_mode) != 0o700:
            raise ValueError("protected root must be a controller-owned mode-0700 directory")
        for component in relative.parts:
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            next_descriptor = os.open(
                component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or \
                    stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("protected path components must be controller-owned mode 0700")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def secure_read(path: Path, root: Path, label: str, maximum: int = 64 * 1024 * 1024) -> bytes:
    parent = open_directory(path.parent, root)
    try:
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    except OSError as error:
        os.close(parent)
        raise ValueError(f"{label} is missing or unsafe") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or \
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError(f"{label} must be a controller-owned mode-0600 single-link regular file")
        chunks = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(65536, before.st_size - offset), offset)
            if not chunk:
                raise ValueError(f"{label} changed while being read")
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)
        os.close(parent)


def run_bounded(command: tuple[str, ...], cwd: Path, timeout: int) -> tuple[int, bytes, bytes]:
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        def limits() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE, MAX_CAPTURE))
        process = subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
            start_new_session=True, preexec_fn=limits,
        )
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ValueError("fixed shadow subprocess timed out") from error
        if os.fstat(stdout_file.fileno()).st_size > MAX_CAPTURE or os.fstat(stderr_file.fileno()).st_size > MAX_CAPTURE:
            raise ValueError("fixed shadow subprocess output exceeded its bound")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return exit_code, stdout_file.read(), stderr_file.read()


def normalize_ansible(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Ansible output is not UTF-8") from error
    text = ANSI.sub("", text)
    text = re.sub(r'(?m)^\s*"(?:delta|end|start)":\s*"[^"]*",?\s*\n', "", text)
    text = re.sub(r'(?m)^\s*"(?:atime|ctime|inode|mtime|version)":\s*(?:"[^"]*"|[^,\n]+),?\s*\n', "", text)
    text = re.sub(r"(?m)(?:/[^\s\"']+)?/\.ansible/tmp/ansible-tmp-[^/\s\"']+", "/.ansible/tmp/<normalized>", text)
    text = re.sub(r"(?m)(?:/[^\s\"']+)?/\.ansible/tmp/ansible-local-[^/\s\"']+", "/.ansible/tmp/<normalized>", text)
    return re.sub(r"(?m)(/\.ansible/tmp/<normalized>)/[^/\s\"']+/", r"\1/<normalized>/", text)


def ansible_summary(normalized: str) -> dict[str, Any]:
    recaps = []
    for line in normalized.splitlines():
        match = RECAP.fullmatch(line)
        if match is not None and match.group("host") == "proxmox":
            recaps.append(match.groupdict())
    if len(recaps) != 1:
        raise ValueError("Ansible output must contain exactly one Proxmox recap")
    recap = {key: (value if key == "host" else int(value)) for key, value in recaps[0].items()}
    if recap["failed"] or recap["unreachable"]:
        raise ValueError("Ansible shadow audit failed or was unreachable")
    lines = normalized.splitlines()
    return {
        "handlerCount": sum(line.startswith("RUNNING HANDLER [") for line in lines),
        "playCount": sum(line.startswith("PLAY [") for line in lines),
        "recap": recap,
        "taskCount": sum(line.startswith("TASK [") for line in lines),
    }


def run_ansible(repo: Path) -> list[dict[str, Any]]:
    command = (
        "ansible-playbook", "-i", "inventory/infrastructure.yml", "playbooks/proxmox-site.yml",
        "--check", "--diff", "-e", "proxmox_ssh_access_proven=true",
    )
    normalized_runs = []
    summaries = []
    for _ in range(2):
        exit_code, stdout, stderr = run_bounded(command, repo / "ansible", 300)
        combined = stdout + stderr
        normalized = normalize_ansible(combined)
        summary = ansible_summary(normalized)
        if exit_code != 0:
            raise ValueError("Ansible shadow audit returned a nonzero status")
        normalized_runs.append(normalized)
        summaries.append(summary)
    if normalized_runs[0] != normalized_runs[1] or summaries[0] != summaries[1]:
        raise ValueError("Ansible shadow audit was not reproducible")
    return summaries


def validate_schema(repo: Path, schema_relative: str, raw: bytes, label: str) -> None:
    program = """
const fs=require('fs'); const Ajv=require('ajv/dist/2020');
const schema=JSON.parse(fs.readFileSync(process.argv[1])); const chunks=[];
process.stdin.on('data',(chunk)=>chunks.push(chunk)); process.stdin.on('end',()=>{
  let value; try { value=JSON.parse(Buffer.concat(chunks)); } catch { process.exit(2); }
  const validate=new Ajv({strict:true,allErrors:true}).compile(schema); if(!validate(value)) process.exit(3);
});
"""
    result = subprocess.run(
        ("node", "-e", program, str(repo / schema_relative)), cwd=repo, input=raw,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
    )
    if result.returncode:
        raise ValueError(f"{label} failed its closed JSON Schema")


def load_planner(repo: Path):
    source = repo / "nix/proxmox/planner.py"
    specification = importlib.util.spec_from_file_location("proxmox_shadow_planner", source)
    if specification is None or specification.loader is None:
        raise ValueError("fixed planner is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def parse_plan_result(output: bytes, stderr: bytes, exit_code: int, repo: Path) -> tuple[str, str]:
    if stderr:
        raise ValueError("fixed Nix planner emitted unexpected stderr")
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("fixed Nix planner output is not UTF-8") from error
    match = PLAN_RESULT.fullmatch(text)
    if match is None:
        raise ValueError("fixed Nix planner output is malformed")
    status, actions, blockers, plan_sha, path = match.groups()
    if (status, exit_code) not in {("ready", 0), ("blocked", 2)}:
        raise ValueError("fixed Nix planner status and exit code disagree")
    if Path(path) != repo / ".reconcile/plans" / f"{plan_sha}.json":
        raise ValueError("fixed Nix planner reported a non-fixed plan path")
    return plan_sha, f"{status}:{actions}:{blockers}"


def fixed_bindings(repo: Path, planner: Any) -> dict[str, Any]:
    build_code, build_out, build_err = run_bounded((
        "nix", "build", "--no-link", "--print-out-paths", "--no-update-lock-file", "--no-write-lock-file",
        "path:./nix#proxmox-host-bundle",
    ), repo, 300)
    outputs = build_out.decode("utf-8").splitlines()
    if build_code or build_err or len(outputs) != 1:
        raise ValueError("fixed sanitized bundle build failed")
    archive_code, archive_out, archive_err = run_bounded((
        "nix", "flake", "archive", "--json", "--no-update-lock-file", "--no-write-lock-file", "path:./nix",
    ), repo, 300)
    if archive_code or archive_err:
        raise ValueError("fixed sanitized source archive failed")
    try:
        source = Path(json.loads(archive_out)["path"])
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("fixed sanitized source archive output is invalid") from error
    output = Path(outputs[0])
    bindings, _, _, _ = planner.bundle_inputs(output / "bundle", output / "bundle.sha256", repo, source)
    return bindings


def require_exact_bindings(actual: Any, expected: dict[str, Any]) -> None:
    if actual != expected:
        raise ValueError("Nix shadow plan bindings differ from the exact reviewed bundle and Git revision")


def validate_plan(repo: Path, plan_sha: str, protocol: str) -> tuple[dict[str, Any], bytes, Any]:
    path = repo / ".reconcile/plans" / f"{plan_sha}.json"
    raw = secure_read(path, repo / ".reconcile", "Nix shadow plan")
    try:
        plan = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Nix shadow plan is not valid JSON") from error
    planner = load_planner(repo)
    if raw != planner.canonical_json(plan):
        raise ValueError("Nix shadow plan is not canonical")
    validate_schema(repo, "nix/proxmox/plan.schema.json", raw, "Nix shadow plan")
    projection = json.loads((repo / "nix/proxmox/projection.json").read_bytes())
    package_manifest = json.loads((repo / "nix/proxmox/package-manifest.json").read_bytes())
    planner.validate_plan(plan, projection, package_manifest)
    if plan["mode"] != "steady" or plan["planSha256"] != plan_sha:
        raise ValueError("Nix shadow plan mode or semantic hash is invalid")
    status, actions, blockers = protocol.split(":")
    if plan["status"] != status or len(plan["actions"]) != int(actions) or len(plan["blockers"]) != int(blockers):
        raise ValueError("Nix shadow plan differs from its strict result protocol")
    require_exact_bindings(plan["bindings"], fixed_bindings(repo, planner))
    sidecar = path.with_name(f"{plan_sha}.private.json")
    if sidecar.exists() or sidecar.is_symlink():
        raise ValueError("private sidecars are forbidden in shadow mode")
    return plan, raw, planner


def run_nix(repo: Path) -> tuple[dict[str, Any], bytes, Any]:
    command = (
        "nix", "run", "--no-update-lock-file", "--no-write-lock-file", "path:./nix#proxmox-host", "--",
        "plan", "--repo-root", str(repo),
    )
    exit_code, stdout, stderr = run_bounded(command, repo, 180)
    plan_sha, protocol = parse_plan_result(stdout, stderr, exit_code, repo)
    return validate_plan(repo, plan_sha, protocol)


def domain_counts(plan: dict[str, Any], planner: Any) -> dict[str, dict[str, int]]:
    counts = {name: {"actions": 0, "blockers": 0, "findings": 0} for name in planner.DOMAIN_ORDER}
    for collection, field in (("actions", "actions"), ("blockers", "blockers"), ("findings", "findings")):
        for record in plan[collection]:
            counts[record["domain"]][field] += 1
    return dict(sorted(counts.items()))


def load_controller_manifest(repo: Path, commit: str, phase: str) -> tuple[dict[str, Any], bytes, str]:
    relative = Path(".reconcile/plans") / commit / phase / "manifest.json"
    raw = secure_read(repo / relative, repo / ".reconcile", "controller manifest", 16 * 1024 * 1024)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("controller manifest is not valid JSON") from error
    if raw != canonical(value) or not isinstance(value, dict) or value.get("version") != 3 or \
            value.get("commit") != commit or value.get("phase") != phase:
        raise ValueError("controller manifest identity is invalid or noncanonical")
    return value, raw, relative.as_posix()


def evidence_value(phase: str, commit: str, tree: str, manifest_raw: bytes, manifest_relative: str,
                   summaries: list[dict[str, Any]], plan: dict[str, Any], plan_raw: bytes,
                   planner: Any) -> dict[str, Any]:
    return {
        "ansible": {"reproducible": True, "runs": summaries},
        "controllerManifest": {"relativePath": manifest_relative, "sha256": digest(manifest_raw), "version": 3},
        "format": EVIDENCE_FORMAT,
        "git": {"commit": commit, "tree": tree},
        "nix": {
            "actionCount": len(plan["actions"]),
            "applyEligible": plan["applyEligible"],
            "bindings": plan["bindings"],
            "blockerCount": len(plan["blockers"]),
            "domainCounts": domain_counts(plan, planner),
            "findingCount": len(plan["findings"]),
            "planRawSha256": digest(plan_raw),
            "planRelativePath": f".reconcile/plans/{plan['planSha256']}.json",
            "planSha256": plan["planSha256"],
            "status": plan["status"],
        },
        "observationOrder": ["ansible", "nix"],
        "observationsAtomic": False,
        "phase": phase,
        "version": 1,
    }


def write_evidence(repo: Path, commit: str, phase: str, plan_sha: str, content: bytes) -> tuple[str, str]:
    root = repo / ".reconcile"
    destination_dir = root / "proxmox-nix-shadow" / commit / phase
    directory_fd = open_directory(destination_dir, root, create=True)
    destination = f"{plan_sha}.json"
    temporary = f".{plan_sha}.{os.getpid()}.pending"
    try:
        try:
            existing = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                metadata = os.fstat(existing)
                raw = os.read(existing, metadata.st_size + 1)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or \
                        stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or raw != content:
                    raise ValueError("existing shadow evidence conflicts with exact capture")
            finally:
                os.close(existing)
            return digest(content), (destination_dir.relative_to(repo) / destination).as_posix()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            written = 0
            while written < len(content):
                written += os.write(fd, content[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, destination, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except Exception:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            raise
        return digest(content), (destination_dir.relative_to(repo) / destination).as_posix()
    finally:
        os.close(directory_fd)


def capture(phase: str) -> str:
    state = load_policy()
    if state == "pre-bootstrap":
        return "shadow_state=pre-bootstrap status=disabled evidence_sha256=none evidence_path=none"
    commit, tree = repository_identity(REPO)
    _, manifest_raw, manifest_relative = load_controller_manifest(REPO, commit, phase)
    summaries = run_ansible(REPO)
    plan, plan_raw, planner = run_nix(REPO)
    if plan["bindings"]["gitCommit"] != commit or plan["bindings"]["gitTree"] != tree:
        raise ValueError("sequential shadow observations crossed a Git revision boundary")
    evidence = evidence_value(phase, commit, tree, manifest_raw, manifest_relative, summaries, plan, plan_raw, planner)
    content = canonical(evidence)
    validate_schema(REPO, "infrastructure/policy/proxmox-nix-shadow-evidence.schema.json", content, "shadow evidence")
    evidence_sha, evidence_path = write_evidence(REPO, commit, phase, plan["planSha256"], content)
    return f"shadow_state=shadow-required status={plan['status']} evidence_sha256={evidence_sha} evidence_path={evidence_path}"


def main() -> None:
    parser = argparse.ArgumentParser(prog="proxmox-nix-shadow.py", allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture", allow_abbrev=False)
    capture_parser.add_argument("--phase", choices=("steady", "recovery"), required=True)
    arguments = parser.parse_args()
    try:
        print(capture(arguments.phase))
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"proxmox-nix-shadow: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
