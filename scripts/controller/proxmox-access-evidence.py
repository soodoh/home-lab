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
for line in open("/etc/pve/priv/authorized_keys"):
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


def capture() -> tuple[Path, str]:
    commit = clean_pushed_commit()
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
    tailnet = subprocess.run(("tofu", "-chdir=infrastructure/tofu/tailscale", "plan", "-detailed-exitcode", "-lock=false", "-input=false", "-no-color"), cwd=ROOT, capture_output=True, timeout=600)
    if tailnet.returncode != 0 or b"No changes" not in tailnet.stdout:
        raise SystemExit("tailnet policy is not a verified no-op")
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
            "tailnet_policy": {"tests_present": True, "live_plan_noop": True, "plan_stdout_sha256": sha(tailnet.stdout)},
            "root_keys": root_key_evidence(),
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


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); commands.add_parser("capture"); attested=commands.add_parser("attest-console"); attested.add_argument("draft",type=Path); args=parser.parse_args()
    if args.command == "capture":
        path,digest=capture(); print(json.dumps({"authorized":False,"draft_sha256":digest,"path":str(path)},sort_keys=True))
    else: attest(args.draft.resolve())


if __name__ == "__main__": main()
