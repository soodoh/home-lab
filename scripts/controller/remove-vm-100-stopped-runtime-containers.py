#!/usr/bin/env python3
"""Remove one exact approved set of stopped unlabeled VM 100 runtime containers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "home-lab-vm-100-stopped-runtime-removal-request-v1"
EVIDENCE_FORMAT = "home-lab-vm-100-stopped-runtime-removal-evidence-v1"
CONFIRMATION = "remove-exact-seven-stopped-runtime-containers-preserve-volumes"
ID = re.compile(r"^[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLEAN_ENV = {"HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def read_canonical(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 64 * 1024):
            raise ValueError("request metadata differs")
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if stable(before) != stable(after):
        raise ValueError("request changed while read")
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("request is noncanonical")
    return value, raw


def run(argv, *, check=True):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV)
    if check and (result.returncode != 0 or result.stderr):
        raise ValueError("fixed Docker observation or mutation failed")
    return result


def inspect_all():
    listed = run(["/usr/bin/docker", "ps", "--all", "--quiet"])
    identifiers = listed.stdout.decode().splitlines()
    if not identifiers:
        return []
    result = run(["/usr/bin/docker", "inspect", "--", *identifiers])
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise ValueError("complete Docker inspection differs")
    return value


def running_inventory(values):
    running = []
    for value in values:
        if value.get("State", {}).get("Running") is True:
            labels = value.get("Config", {}).get("Labels") or {}
            project = labels.get("com.docker.compose.project")
            service = labels.get("com.docker.compose.service")
            if project != "docker-compose" or not isinstance(service, str) or not service:
                raise ValueError("running noncanonical container exists")
            running.append((service, value["Id"]))
    if len(running) != 41 or len({service for service, _ in running}) != 41:
        raise ValueError("running canonical container inventory differs")
    return sorted(running)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--expected-request-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0 or args.confirmation != CONFIRMATION or SHA256.fullmatch(args.expected_request_sha256 or "") is None:
        raise SystemExit("stopped runtime removal authorization differs")
    request, raw = read_canonical(args.request)
    if hashlib.sha256(raw).hexdigest() != args.expected_request_sha256:
        raise SystemExit("stopped runtime removal request hash differs")
    if (not isinstance(request, dict) or set(request) != {"confirmation", "containers", "format", "preserveVolumes", "vmId"}
            or request["format"] != FORMAT or request["confirmation"] != CONFIRMATION
            or request["preserveVolumes"] is not True or request["vmId"] != 100
            or not isinstance(request["containers"], list) or len(request["containers"]) != 7):
        raise SystemExit("stopped runtime removal request shape differs")
    expected = {}
    for item in request["containers"]:
        if (not isinstance(item, dict) or set(item) != {"id", "name"} or ID.fullmatch(item["id"] or "") is None
                or not isinstance(item["name"], str) or not item["name"] or "/" in item["name"] or item["id"] in expected):
            raise SystemExit("stopped runtime removal entry differs")
        expected[item["id"]] = item["name"]
    root = Path(__file__).resolve().parents[2]
    head = run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"]).stdout.decode().strip()
    upstream = run(["/usr/bin/git", "-C", str(root), "rev-parse", "refs/remotes/origin/main"]).stdout.decode().strip()
    status = run(["/usr/bin/git", "-C", str(root), "status", "--porcelain"]).stdout
    if head != args.expected_commit or upstream != args.expected_commit or status:
        raise SystemExit("stopped runtime removal checkout differs")
    authority = run(["/usr/bin/node", str(root / "scripts/controller/check-vm-100-authority.js"), "--require-ordinary-mutation"])
    if authority.stdout != b"vm_100_mutation_authority=arch\n":
        raise SystemExit("stopped runtime removal authority differs")
    before = inspect_all()
    running_before = running_inventory(before)
    stopped = {}
    volume_names = set()
    for value in before:
        if value.get("State", {}).get("Running") is not True:
            identifier = value.get("Id")
            name = str(value.get("Name", "")).removeprefix("/")
            labels = value.get("Config", {}).get("Labels") or {}
            if labels.get("com.docker.compose.project") or labels.get("com.docker.compose.service"):
                raise SystemExit("stopped Compose container is not removable runtime state")
            stopped[identifier] = name
            for mount in value.get("Mounts") or []:
                if mount.get("Type") == "volume" and isinstance(mount.get("Name"), str):
                    volume_names.add(mount["Name"])
    if stopped != expected:
        raise SystemExit("exact stopped unlabeled container set differs")
    removed = run(["/usr/bin/docker", "rm", "--", *sorted(expected)])
    if sorted(removed.stdout.decode().splitlines()) != sorted(expected):
        raise SystemExit("Docker removed-container acknowledgement differs")
    after = inspect_all()
    running_after = running_inventory(after)
    if running_after != running_before or len(after) != 41:
        raise SystemExit("running container inventory changed during stopped runtime removal")
    for volume in sorted(volume_names):
        result = run(["/usr/bin/docker", "volume", "inspect", "--", volume], check=False)
        if result.returncode != 0:
            raise SystemExit("attached runtime volume was not preserved")
    output = args.output_root
    info = output.lstat()
    if (not output.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700 or output.is_symlink() or any(output.iterdir())):
        raise SystemExit("stopped runtime evidence root differs")
    evidence = {"format": EVIDENCE_FORMAT, "preservedVolumeCount": len(volume_names), "removedCount": 7,
        "requestSha256": args.expected_request_sha256, "result": "passed", "runningContainerCount": 41,
        "runningInventoryStable": True, "vmId": 100}
    descriptor = os.open(output / "stopped-runtime-removal-evidence.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(canonical(evidence)); target.flush(); os.fsync(target.fileno())
    print(f"stopped_runtime_removal_evidence={output / 'stopped-runtime-removal-evidence.json'}")


if __name__ == "__main__":
    main()
