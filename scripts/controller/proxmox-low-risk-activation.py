#!/usr/bin/env python3
"""Build and apply immutable Proxmox repository and chrony transactions."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from protected_execution import acquire_transfer_lock

ROOT = Path(__file__).resolve().parents[2]
PLAN_DIR = ROOT / ".local/proxmox-low-risk-activations"
LOCK = ROOT / ".local/proxmox-low-risk-activation.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH_BASE = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no")
SOURCE_PATHS = (
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/debian-security.sources",
    "/etc/apt/sources.list.d/debian.sources",
    "/etc/apt/sources.list.d/pve-no-subscription.sources",
    "/etc/apt/sources.list.d/tailscale.sources",
)
KEYRING_PATHS = (
    "/usr/share/keyrings/debian-archive-keyring.gpg",
    "/usr/share/keyrings/proxmox-archive-keyring.gpg",
    "/usr/share/keyrings/tailscale-archive-keyring.gpg",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*arguments: str) -> str:
    return subprocess.check_output(("git", *arguments), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("low-risk activation requires clean pushed HEAD")
    return commit


def observe() -> dict:
    result = subprocess.run((*SSH_BASE, "ansible-plan@proxmox", "observe"), capture_output=True, timeout=90)
    if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
        raise SystemExit("fixed low-risk observation failed")
    value = json.loads(result.stdout)
    if value.get("format") != "home-lab-proxmox-observation-v1" or value.get("protocol") != 4:
        raise SystemExit("fixed low-risk observer protocol differs")
    return value


def handoff_state(domain: str) -> dict:
    script = """const fs=require('node:fs');const {load}=require('js-yaml');const value=load(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(JSON.stringify(value.lifecycle.hosts.proxmox.domain_handoffs[process.argv[2]]));"""
    result = subprocess.run(("node", "-e", script, str(ROOT / "infrastructure/contract/home-lab.yml"), domain),
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
    if result.returncode or result.stderr:
        raise SystemExit("low-risk handoff contract parsing failed")
    state = json.loads(result.stdout)
    if state != {"current_owner": "ansible", "target_owner": "ansible", "state": "transferred", "parity_required": True, "single_writer": True}:
        raise SystemExit(f"{domain} ownership is not transferred to Ansible")
    return state


def repository_material(observation: dict) -> tuple[list[dict], list[dict]]:
    projection = json.loads((ROOT / "nix/proxmox/projection.json").read_text())
    desired_files = {item["path"]: item for item in projection["managedFiles"] if item["path"] in SOURCE_PATHS}
    if tuple(sorted(desired_files)) != tuple(sorted(SOURCE_PATHS)):
        raise SystemExit("projected repository source cardinality differs")
    observed_files = {item["target"]: item for item in observation["domains"]["managedFiles"]["records"] if item["target"] in SOURCE_PATHS}
    if observation["domains"]["managedFiles"]["status"] != "complete" or tuple(sorted(observed_files)) != tuple(sorted(SOURCE_PATHS)):
        raise SystemExit("fixed observer repository cardinality differs")
    records = []
    for path in SOURCE_PATHS:
        desired = desired_files[path]; observed = observed_files[path]; content = desired["content"]; digest = sha(content.encode())
        if observed != {"contentMatches": True, "groupMatches": True, "mode": "0644", "ownerMatches": True, "target": path, "type": "file"}:
            raise SystemExit("fixed observer does not prove repository parity")
        records.append({"after_sha256": digest, "before_sha256": digest, "content": content, "gid": 0, "mode": "0644", "path": path, "uid": 0})
    desired_artifacts = {item["path"]: item for item in projection["managedArtifacts"] if item["path"] in KEYRING_PATHS}
    observed_artifacts = {item["target"]: item for item in observation["domains"]["managedArtifacts"]["records"] if item["target"] in KEYRING_PATHS}
    if observation["domains"]["managedArtifacts"]["status"] != "complete" or tuple(sorted(desired_artifacts)) != tuple(sorted(KEYRING_PATHS) ) or tuple(sorted(observed_artifacts)) != tuple(sorted(KEYRING_PATHS)):
        raise SystemExit("fixed observer keyring cardinality differs")
    keyrings = []
    for path in KEYRING_PATHS:
        observed = observed_artifacts[path]
        if not all(observed.get(name) is True for name in ("contentMatches", "groupMatches", "ownerMatches", "symlinkTargetMatches")) or observed.get("mode") != "0644":
            raise SystemExit("fixed observer does not prove keyring parity")
        artifact = desired_artifacts[path]
        keyrings.append({"path": path, "sha256": artifact["sha256"], "symlink_target": artifact["symlinkTarget"]})
    return records, keyrings


def chrony_material(observation: dict) -> dict:
    services = {item["name"]: item for item in observation["domains"]["services"]["records"]}
    item = services.get("chrony.service")
    if observation["domains"]["services"]["status"] != "complete" or not isinstance(item, dict) or \
            set(item) != {"active", "enabled", "name"} or any(not isinstance(item[name], bool) for name in ("active", "enabled")):
        raise SystemExit("fixed observer does not prove chrony service state")
    return {"active": item["active"], "enabled": item["enabled"]}


def write_plan(value: dict) -> tuple[str, Path]:
    raw = canonical(value); digest = sha(raw)
    PLAN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(PLAN_DIR, 0o700)
    path = PLAN_DIR / f"{digest}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return digest, path


def build(domain: str) -> None:
    if domain not in ("apt-repositories", "chrony-service"):
        raise SystemExit("unsupported low-risk domain")
    commit = clean_pushed_commit(); observation = observe(); now = datetime.now(timezone.utc).replace(microsecond=0)
    common = {"authorized": False, "automatic_reboot": False, "commit": commit,
              "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
              "created_at": now.isoformat().replace("+00:00", "Z"), "domain": domain,
              "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
              "format": "home-lab-proxmox-low-risk-activation-v1", "host": "proxmox",
              "host_key_fingerprint": FINGERPRINT, "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml")}
    if domain == "apt-repositories":
        handoff_state("apt_repositories"); records, keyrings = repository_material(observation)
        value = {**common, "keyrings": keyrings, "metadata_refresh": False, "records": records, "unknown_source_files": []}
    else:
        handoff_state("chrony_service"); before = chrony_material(observation)
        value = {**common, "before": before, "config_mutation": False, "desired": {"active": True, "enabled": True},
                 "restart_if_healthy": False}
    digest, path = write_plan(value)
    print(json.dumps({"activation_sha256": digest, "authorized": False, "path": str(path)}, sort_keys=True))


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    metadata = path.lstat(); raw = path.read_bytes(); digest = sha(raw)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or \
            path.name != f"{digest}.json":
        raise SystemExit("low-risk activation metadata differs")
    value = json.loads(raw)
    if canonical(value) != raw or value.get("authorized") is not False or value.get("format") != "home-lab-proxmox-low-risk-activation-v1":
        raise SystemExit("low-risk activation is not canonical or inert")
    return value, raw, digest


def apply(path: Path) -> None:
    value, raw, digest = load_plan(path); commit = clean_pushed_commit(); domain = value.get("domain")
    if domain not in ("apt-repositories", "chrony-service") or value.get("commit") != commit or \
            value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or \
            value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or value.get("host_key_fingerprint") != FINGERPRINT:
        raise SystemExit("low-risk activation source binding differs")
    handoff_state("apt_repositories" if domain == "apt-repositories" else "chrony_service")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("low-risk activation expired")
    expected = f"apply-proxmox-{domain}-{digest}"
    if os.environ.get("PROXMOX_LOW_RISK_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        observation = observe()
        if domain == "apt-repositories":
            current_records, current_keyrings = repository_material(observation)
            if current_records != value["records"] or current_keyrings != value["keyrings"]:
                raise SystemExit("low-risk activation evidence changed")
        elif chrony_material(observation) != value["before"]:
            raise SystemExit("low-risk activation evidence changed")
        staged = subprocess.run((*SSH_BASE, "ansible-deploy@proxmox", f"stage low-risk {digest}"), input=raw, capture_output=True, timeout=90)
        if staged.returncode or staged.stderr or json.loads(staged.stdout) != {"staged": True}:
            raise SystemExit("low-risk activation staging failed")
        inspected = subprocess.run((*SSH_BASE, "ansible-deploy@proxmox", f"inspect low-risk {digest}"), capture_output=True, timeout=60)
        if inspected.returncode or inspected.stderr or json.loads(inspected.stdout) != {"present": True}:
            raise SystemExit("low-risk activation inspection failed")
        result = subprocess.run((*SSH_BASE, "ansible-deploy@proxmox", f"apply {domain} {digest}"), capture_output=True, timeout=300)
        if result.returncode or result.stderr:
            raise SystemExit("low-risk apply failed; inspect the retained root-only journal")
        output = json.loads(result.stdout)
        if domain == "apt-repositories":
            expected_output = {"changed_files": sum(item["before_sha256"] != item["after_sha256"] for item in value["records"]),
                               "plan_sha256": digest, "repository_transaction": "committed"}
        else:
            expected_output = {"changed": value["before"] != value["desired"], "chrony_transaction": "committed", "plan_sha256": digest}
        if output != expected_output:
            raise SystemExit("low-risk receipt differs")
        print(json.dumps(output, sort_keys=True))
    finally:
        os.close(lock)


def recover(path: Path) -> None:
    value, _, digest = load_plan(path); commit = clean_pushed_commit(); domain = value.get("domain")
    if domain not in ("apt-repositories", "chrony-service") or value.get("commit") != commit or \
            value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or \
            value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml"):
        raise SystemExit("low-risk recovery source binding differs")
    handoff_state("apt_repositories" if domain == "apt-repositories" else "chrony_service")
    expected = f"recover-proxmox-{domain}-{digest}"
    if os.environ.get("PROXMOX_LOW_RISK_RECOVER_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        inspected = subprocess.run((*SSH_BASE, "ansible-deploy@proxmox", f"inspect low-risk {digest}"), capture_output=True, timeout=60)
        if inspected.returncode or inspected.stderr or json.loads(inspected.stdout) != {"present": True}:
            raise SystemExit("low-risk recovery inspection failed")
        result = subprocess.run((*SSH_BASE, "ansible-deploy@proxmox", f"recover {domain} {digest}"), capture_output=True, timeout=300)
        if result.returncode or result.stderr:
            raise SystemExit("low-risk recovery failed; inspect the retained root-only journal")
        output = json.loads(result.stdout); transaction_key = "repository_transaction" if domain == "apt-repositories" else "chrony_transaction"
        if output.get("plan_sha256") != digest or output.get(transaction_key) not in ("committed", "rolled-back"):
            raise SystemExit("low-risk recovery receipt differs")
        print(json.dumps(output, sort_keys=True))
    finally:
        os.close(lock)


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build"); build_parser.add_argument("domain", choices=("apt-repositories", "chrony-service"))
    apply_parser = commands.add_parser("apply"); apply_parser.add_argument("activation", type=Path)
    recover_parser = commands.add_parser("recover"); recover_parser.add_argument("activation", type=Path)
    args = parser.parse_args()
    if args.command == "build": build(args.domain)
    elif args.command == "apply": apply(args.activation.resolve())
    else: recover(args.activation.resolve())


if __name__ == "__main__":
    main()
