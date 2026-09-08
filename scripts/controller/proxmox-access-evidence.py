#!/usr/bin/env python3
"""Capture immutable additive Proxmox access proofs and console attestation."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-access-evidence"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH_OPTIONS = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("access evidence requires clean pushed HEAD")
    return commit


def run_ssh(target: str, command: str, expected: int = 0, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run((*SSH_OPTIONS, target, command), input=input_data, capture_output=True, timeout=120)
    if result.returncode != expected:
        raise SystemExit(f"fixed access canary failed for {target} with status {result.returncode}")
    return result


def known_host_proven() -> bool:
    found = subprocess.run(("ssh-keygen", "-F", "proxmox"), capture_output=True, timeout=15)
    if found.returncode or not found.stdout:
        return False
    fingerprints = set()
    for line in found.stdout.splitlines():
        if not line or line.startswith(b"#"):
            continue
        result = subprocess.run(("ssh-keygen", "-lf", "-"), input=line + b"\n", capture_output=True, timeout=15)
        if result.returncode == 0:
            fields = result.stdout.decode().split()
            if len(fields) > 1:
                fingerprints.add(fields[1])
    return FINGERPRINT in fingerprints


def root_key_evidence() -> dict:
    program = r'''
import json,re,subprocess
records=[]
try: lines=open("/etc/pve/priv/authorized_keys")
except FileNotFoundError: lines=[]
for line in lines:
 value=line.strip()
 if not value: continue
 match=re.search(r'(ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?: .*)?)$',value)
 if match is None: raise SystemExit(65)
 result=subprocess.run(["/usr/bin/ssh-keygen","-lf","-"],input=match.group(1)+"\n",text=True,capture_output=True)
 if result.returncode or result.stderr: raise SystemExit(65)
 fields=result.stdout.split(); records.append({"bits":int(fields[0]),"fingerprint":fields[1],"comment":" ".join(fields[2:-1]),"type":fields[-1].strip("()")})
print(json.dumps(sorted(records,key=lambda item:item["fingerprint"]),sort_keys=True,separators=(",",":")))
'''
    result = run_ssh("proxmox@proxmox", "sudo -n -- /usr/bin/python3 -", input_data=program.encode())
    records = json.loads(result.stdout)
    attributed = {
        "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw": "current-proxmox-root-id-rsa",
        "SHA256:xnvOo0mjS/Ghwrbf8JovxNp51qFXQncLO4ygGvZPR7w": "personal-laptop",
        "SHA256:6RaXU5sJ5bREB69ozsxdAFWVhYvCm9jlPAu7rSOx+dU": "iphone-termius",
        "SHA256:UKIt1zHVexMpz9we72AErUd+DBrQh4cyoGa1gqOGPmA": "work-laptop",
        "SHA256:/qSECkXxkpCIjTkBwa8XZZdRW2/seScon5uAKGlLC80": "obsolete-proxmox-root-identity",
        "SHA256:SNH3GBfBBvbkycl78DbrIjbaC0rJxkvue+KF9qhpXrs": "obsolete-proxmox-root-identity",
    }
    unresolved = sorted(item["fingerprint"] for item in records if item["fingerprint"] not in attributed)
    return {"records": records, "attributed": attributed, "attributed_count": len(records) - len(unresolved),
            "total_count": len(records), "unresolved": unresolved, "complete": not unresolved}


def latest_marker_plan_digest() -> str:
    candidates = sorted(OUTPUT.parent.joinpath("lifecycle-marker-plans").glob("proxmox-*.json"))
    candidates = [path for path in candidates if not path.name.endswith(".evidence.json")]
    if not candidates:
        raise SystemExit("saved Proxmox marker plan is unavailable for deploy inspect canary")
    match = re.fullmatch(r"proxmox-([0-9a-f]{64})\.json", candidates[-1].name)
    if match is None:
        raise SystemExit("saved Proxmox marker plan name is invalid")
    return match.group(1)


def boundary_command(action: str, boundary: Path, *extra: str) -> bytes:
    result = subprocess.run((sys.executable, "-I", "-B", "-S",
                             ROOT / "scripts/controller/controller-boundary-manifest.py",
                             action, "--manifest", str(boundary), *extra),
                            cwd=ROOT, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise SystemExit("controller boundary manifest refused")
    return result.stdout


def generation_path(commit: str, generation: str, *, absent: bool) -> Path:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", generation) is None:
        raise SystemExit("explicit valid controller generation required")
    directory = ROOT
    for index, part in enumerate((".reconcile", "plans", commit, "steady", generation)):
        directory /= part
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise SystemExit("unsafe controller generation path")
        if index == 4 and absent:
            raise SystemExit("controller generation already exists; preserve evidence")
    return directory / "manifest.json"


def manifest_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= 2 * 1024 * 1024):
            raise SystemExit("unsafe controller manifest")
        raw = stream.read(2 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    named = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(item, key) for item in (after, named) for key in fields):
        raise SystemExit("controller manifest changed while reading")
    return raw


def controller_plan_proof(result: subprocess.CompletedProcess[bytes], commit: str,
                          generation: str, boundary: Path, binding: str) -> dict:
    if result.returncode != 0:
        raise SystemExit("controller generation failed; preserve evidence")
    path = generation_path(commit, generation, absent=False)
    raw = manifest_bytes(path)
    boundary_command("verify", boundary, "--binding", binding, "--saved-plan", str(path))
    verified = subprocess.run(("node", ROOT / "scripts/controller/proxmox-check-evidence.js", "verify", path),
                              cwd=ROOT, capture_output=True, timeout=180)
    if verified.returncode != 0:
        raise SystemExit("saved controller generation verification refused")
    # The shared verifier binds v6 source/dependencies, binary hashes and fresh
    # host audit evidence. Never infer that proof from legacy display strings.
    value = json.loads(raw)
    if (value.get("version") != 6 or value.get("commit") != commit
            or value.get("phase") != "steady" or value.get("stage") != "converge"):
        raise SystemExit("controller generation source or scope differs")
    plans = value.get("plans", [])
    tailnet = [item for item in plans if item.get("root") == "tailscale"]
    if (not plans or any(item.get("changed") is not False for item in plans) or len(tailnet) != 1):
        raise SystemExit("controller generation is not a steady tailnet no-op")
    before = tailnet[0].get("tailscale_policy_before_sha256")
    if (not isinstance(before, str) or re.fullmatch(r"[0-9a-f]{64}", before) is None
            or before != tailnet[0].get("tailscale_policy_after_sha256")):
        raise SystemExit("controller generation tailnet policy differs")
    generation_path(commit, generation, absent=False)
    if manifest_bytes(path) != raw:
        raise SystemExit("controller manifest changed during verification")
    boundary_command("verify", boundary, "--binding", binding, "--saved-plan", str(path))
    # Strict v1 consumers require these exact keys. The stdout hash is only a
    # diagnostic; v1 cannot independently expose the selected generation binding.
    return {"tests_present": True, "live_plan_noop": True, "expected_retirement_drift": False,
            "controller_plan_stdout_sha256": sha(result.stdout)}


def capture(generation: str, boundary: Path) -> tuple[Path, str]:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", generation) is None or not boundary.is_absolute():
        raise SystemExit("explicit valid generation and absolute boundary manifest required")
    inputs = boundary_command("load", boundary).decode().rstrip("\n").split("\t")
    if len(inputs) != 3:
        raise SystemExit("controller boundary binding differs")
    binding = inputs[2]
    commit = clean_pushed_commit()
    generation_path(commit, generation, absent=True)
    if not known_host_proven():
        raise SystemExit("strict Proxmox host-key fingerprint is unavailable")
    plan = run_ssh("ansible-plan@proxmox", "observe")
    plan_value = json.loads(plan.stdout)
    if plan_value.get("format") != "home-lab-proxmox-observation-v1" or plan_value.get("protocol") != 4:
        raise SystemExit("fixed plan observer output differs")
    run_ssh("ansible-plan@proxmox", "observe;id", expected=64)
    firewall = run_ssh("firewall-apply@proxmox", "inspect")
    run_ssh("firewall-apply@proxmox", "inspect;id", expected=64)
    marker_digest = latest_marker_plan_digest()
    deploy = run_ssh("ansible-deploy@proxmox", f"inspect lifecycle-marker {marker_digest}")
    if deploy.stdout != b'{"present":true}\n':
        raise SystemExit("fixed deploy inspect canary differs")
    run_ssh("ansible-deploy@proxmox", "apply lifecycle-marker a;id", expected=64)
    run_ssh("proxmox@proxmox", "true")
    root_keys = root_key_evidence()
    generation_path(commit, generation, absent=True)
    boundary_command("verify", boundary, "--binding", binding)
    controller = subprocess.run((ROOT / "scripts/local-controller", "plan", "steady", "--generation", generation, "--boundary-manifest", str(boundary)), cwd=ROOT, capture_output=True, timeout=1800)
    tailnet_proof = controller_plan_proof(controller, commit, generation, boundary, binding)
    if clean_pushed_commit() != commit:
        raise SystemExit("access evidence source changed during capture")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    evidence = {
        "format": "home-lab-proxmox-access-evidence-draft-v1", "commit": commit,
        "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
        "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
        "host_key_fingerprint": FINGERPRINT, "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
        "proofs": {
            "strict_host_key": True,
            "plan_observer": {"positive": True, "injection_rejected": True, "observation_sha256": sha(plan.stdout)},
            "firewall_transport": {"positive": True, "injection_rejected": True, "inspect_sha256": sha(firewall.stdout)},
            "deploy_transport": {"positive": True, "injection_rejected": True, "marker_plan_sha256": marker_digest},
            "human_session": {"positive": True},
            "tailnet_policy": tailnet_proof,
            "root_keys": root_keys,
            "console": {"attested": False},
        },
        "authorized": False,
    }
    raw = canonical(evidence); digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    path = OUTPUT / f"{digest}.draft.json"; fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return path, digest


def attest(path: Path) -> None:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or path.name != f"{digest}.draft.json" or raw != canonical(value):
        raise SystemExit("access evidence draft metadata differs")
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml"):
        raise SystemExit("access evidence source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("access evidence draft expired")
    expected = f"attest-proxmox-physical-console-{digest}"
    if os.environ.get("PROXMOX_CONSOLE_ATTESTATION_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    receipt = {"format": "home-lab-proxmox-access-evidence-v1", "draft_sha256": digest, "commit": value["commit"],
               "contract_sha256": value["contract_sha256"], "inventory_sha256": value["inventory_sha256"],
               "host_key_fingerprint": value["host_key_fingerprint"], "created_at": value["created_at"],
               "expires_at": value["expires_at"], "proofs": value["proofs"], "console_attested_at": now}
    receipt["proofs"]["console"] = {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}
    receipt_raw = canonical(receipt); receipt_digest = sha(receipt_raw); receipt_path = OUTPUT / f"{receipt_digest}.json"
    fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(receipt_raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"evidence_sha256": receipt_digest, "path": str(receipt_path), "root_keys_complete": receipt["proofs"]["root_keys"]["complete"]}, sort_keys=True))


class ExplicitInput(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate capture input")
        setattr(namespace, self.dest, values)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    captured = commands.add_parser("capture", allow_abbrev=False)
    captured.add_argument("--generation", required=True, action=ExplicitInput)
    captured.add_argument("--boundary-manifest", required=True, type=Path, action=ExplicitInput)
    attested = commands.add_parser("attest-console", allow_abbrev=False)
    attested.add_argument("draft", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        path, digest = capture(args.generation, args.boundary_manifest)
        print(json.dumps({"authorized": False, "draft_sha256": digest, "path": str(path)}, sort_keys=True))
    else:
        attest(args.draft.resolve())


if __name__ == "__main__": main()
