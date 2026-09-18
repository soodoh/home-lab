#!/usr/bin/env python3
"""Plan/apply deletion of the one state-owned VM9900 Restic base image."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from protected_execution import canonical_bytes, load_canonical_object, load_protected_bytes, require_private_root, verify_exact_checkout, write_json

ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / "infrastructure/tofu/proxmox-restic-recovery-qualification"
LINEAGE_ROOT = ROOT / ".reconcile/restic-recovery-vm/09d091e5c9f44eafaf5a8b89576c9929e1fa5644"
STATE = LINEAGE_ROOT / "tofu.tfstate"
JOURNAL = LINEAGE_ROOT / "journal.json"
LOCK = ROOT / ".reconcile/restic-recovery-vm/transaction.lock"
ADDRESS = "proxmox_download_file.recovery_image[0]"
IMAGE_ID = "local:import/home-lab-restic-recovery-debian-20260810-2566.qcow2"
INITIAL_STATE_SHA256 = "6fa9556295404743504e60566cdb9dca7ddd7796ed415844ba1734eec40ea88d"
JOURNAL_SHA256 = "8b8130d85b1019bf13711c730ca1b696311ed24e88adbdf5c47a771ae52f0aeb"
CONFIRM = "DESTROY_REVIEWED_RESTIC_RECOVERY_BASE_IMAGE"
HEX = re.compile(r"^[0-9a-f]{64}$")
os.umask(0o077)


def fail(reason: str) -> None:
    raise SystemExit(f"restic_recovery_image_retirement=failed reason={reason}")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str):
        fail("manifest-time")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("manifest-time")
    if parsed.tzinfo is None:
        fail("manifest-time")
    return parsed


def revision(expected: str | None = None) -> str:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
    verify_exact_checkout("git", expected or commit, os.environ.copy())
    return commit


def acquire_lock() -> int:
    item = LOCK.lstat()
    if LOCK.is_symlink() or not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600:
        fail("transaction-lock-metadata")
    descriptor = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        fail("transaction-lock-held")
    return descriptor


def protected_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = load_protected_bytes(path, label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail(f"{label}-json")
    if not isinstance(value, dict):
        fail(f"{label}-shape")
    return value, raw


def contract_image() -> dict[str, object]:
    script = 'const fs=require("fs"),yaml=require("js-yaml");const c=yaml.load(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify(c.debian.image))'
    result = subprocess.run(["node", "-e", script, str(ROOT / "infrastructure/contract/home-lab.yml")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode or result.stderr:
        fail("contract-image")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("contract-image")
    if not isinstance(value, dict):
        fail("contract-image")
    return value


def expected_image() -> dict[str, object]:
    image = contract_image()
    return {
        "checksum": image.get("sha512"),
        "checksum_algorithm": "sha512",
        "content_type": "import",
        "datastore_id": "local",
        "file_name": "home-lab-restic-recovery-debian-20260810-2566.qcow2",
        "id": IMAGE_ID,
        "node_name": "proxmox",
        "size": 436404224,
    }


def inspect_initial_state(raw: bytes) -> dict[str, object]:
    if sha(raw) != INITIAL_STATE_SHA256:
        fail("initial-state-identity")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail("initial-state-json")
    resources = value.get("resources", []) if isinstance(value, dict) else []
    if not isinstance(resources, list) or len(resources) != 1:
        fail("initial-state-scope")
    resource = resources[0]
    if not isinstance(resource, dict) or (resource.get("mode"), resource.get("type"), resource.get("name")) != ("managed", "proxmox_download_file", "recovery_image"):
        fail("initial-state-scope")
    instances = resource.get("instances")
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict) or instances[0].get("index_key") != 0:
        fail("initial-state-scope")
    attributes = instances[0].get("attributes")
    expected = expected_image()
    if not isinstance(attributes, dict) or any(attributes.get(key) != item for key, item in expected.items()):
        fail("initial-state-image")
    return expected


def inspect_empty_state(raw: bytes) -> None:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail("empty-state-json")
    if not isinstance(value, dict) or value.get("lineage") != "91d17ecc-787b-e540-300e-3fbc1bce89df" or not isinstance(value.get("serial"), int) or value["serial"] < 2 or value.get("resources") != []:
        fail("empty-state-identity")


def preserve_state_before(output: Path, raw: bytes) -> Path:
    path = output / f"{INITIAL_STATE_SHA256}.state-before.tfstate"
    if path.exists():
        if sha(load_protected_bytes(path, "preserved state before")) != INITIAL_STATE_SHA256:
            fail("preserved-state-before")
        return path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            if stream.write(raw) != len(raw):
                fail("preserved-state-before")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    directory = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def inspect_journal() -> None:
    value, raw = protected_json(JOURNAL, "journal")
    expected = {
        "checkpoints": [{"detail": "legacy-local-state-adopted", "state": "create-replanning", "time": 1787737091}],
        "commit": "09d091e5c9f44eafaf5a8b89576c9929e1fa5644",
        "owner": "68971e5c963176acb3a8142d63b9839f53e19a99a8ceee19072a9b780feaa9d4",
        "replans": [],
        "state": "create-replanning",
        "version": 1,
    }
    if sha(raw) != JOURNAL_SHA256 or value != expected:
        fail("journal-identity")


def credentials(kind: str) -> dict[str, str]:
    directory = Path(os.environ.get("HOME_LAB_CONTROLLER_CONFIG_DIR", Path.home() / ".config/home-lab/controller"))
    value, _raw = protected_json(directory / f"{kind}-credentials.json", f"{kind}-credentials")
    token_key = "PROXMOX_PLAN_API_TOKEN" if kind == "plan" else "PROXMOX_APPLY_API_TOKEN"
    required = (token_key, "TF_VAR_proxmox_endpoint", "PROXMOX_CA_PEM")
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        fail("credential-structure")
    return {"token": str(value[token_key]), "endpoint": str(value["TF_VAR_proxmox_endpoint"]), "ca": str(value["PROXMOX_CA_PEM"])}


def endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/api2/json":
        fail("provider-endpoint")
    port = f":{parsed.port}" if parsed.port else ""
    return f"https://{parsed.hostname.lower()}{port}/api2/json"


def provider_binding(values: dict[str, str]) -> dict[str, str]:
    return {"endpoint_sha256": sha(endpoint(values["endpoint"]).encode()), "ca_sha256": sha(values["ca"].encode())}


def api(values: dict[str, str], path: str) -> object:
    context = ssl.create_default_context(cadata=values["ca"])
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    request = urllib.request.Request(endpoint(values["endpoint"]) + path, headers={"Authorization": f"PVEAPIToken={values['token']}"})
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            return json.load(response)["data"]
    except (KeyError, OSError, ValueError):
        fail("provider-observation")


def live_precondition(values: dict[str, str], *, image_present: bool) -> str:
    resources = api(values, "/cluster/resources?type=vm")
    if not isinstance(resources, list) or any(item.get("vmid") == 9900 for item in resources if isinstance(item, dict)):
        fail("vm9900-still-present")
    production = [item for item in resources if isinstance(item, dict) and item.get("vmid") == 100]
    config = api(values, "/nodes/proxmox/qemu/100/config")
    if len(production) != 1 or production[0].get("name") != "docker-host" or production[0].get("status") != "running" or not isinstance(config, dict) or config.get("name") != "docker-host" or config.get("protection") not in (1, True, "1"):
        fail("production-vm-identity")
    content = api(values, "/nodes/proxmox/storage/local/content?content=import")
    matches = [item for item in content if isinstance(item, dict) and item.get("volid") == IMAGE_ID] if isinstance(content, list) else []
    if image_present and (len(matches) != 1 or int(matches[0].get("size", -1)) != 436404224):
        fail("recovery-image-live-identity")
    if not image_present and matches:
        fail("recovery-image-live-identity")
    normalized = {key: item for key, item in config.items() if key not in {"digest", "lock", "pending"}}
    return sha(canonical_bytes({"configuration": normalized, "vmid": 100}) + b"\n")


def tofu_environment(values: dict[str, str], data: Path, ca_path: Path) -> dict[str, str]:
    return {
        "HOME": os.environ["HOME"],
        "PATH": os.environ["PATH"],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SSL_CERT_FILE": str(ca_path),
        "TF_DATA_DIR": str(data),
        "PROXMOX_VE_API_TOKEN": values["token"],
        "TF_VAR_proxmox_endpoint": endpoint(values["endpoint"]),
    }


def setup_tofu(output: Path, values: dict[str, str]) -> tuple[Path, dict[str, str]]:
    run = Path(tempfile.mkdtemp(prefix="restic-image-retirement-", dir=output))
    os.chmod(run, 0o700)
    data = run / "tf-data"
    data.mkdir(mode=0o700)
    ca_path = run / "ca.pem"
    descriptor = os.open(ca_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(values["ca"].encode())
        stream.flush()
        os.fsync(stream.fileno())
    env = tofu_environment(values, data, ca_path)
    init_env = dict(env)
    init_env.pop("SSL_CERT_FILE")
    result = subprocess.run(["tofu", f"-chdir={TF_ROOT}", "init", "-reconfigure", "-input=false", "-lockfile=readonly", f"-backend-config=path={STATE}"], env=init_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        shutil.rmtree(run, ignore_errors=True)
        fail("tofu-init")
    return run, env


def inspect_plan(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("plan-json")
    changed = [item for item in value.get("resource_changes", []) if isinstance(item, dict) and item.get("change", {}).get("actions") != ["no-op"]]
    if len(changed) != 1 or changed[0].get("address") != ADDRESS or changed[0].get("type") != "proxmox_download_file" or changed[0].get("change", {}).get("actions") != ["delete"]:
        fail("plan-actions")
    change = changed[0]["change"]
    if change.get("after") is not None or change.get("after_unknown") not in (None, {}, False):
        fail("plan-after")
    before = change.get("before")
    expected = expected_image()
    if not isinstance(before, dict) or any(before.get(key) != item for key, item in expected.items()):
        fail("plan-before")
    return expected


def plan(args: argparse.Namespace) -> None:
    output = require_private_root(args.output_dir, (LINEAGE_ROOT,))
    descriptor = acquire_lock()
    run = None
    try:
        commit = revision()
        state_raw = load_protected_bytes(STATE, "state")
        inspect_initial_state(state_raw)
        inspect_journal()
        values = credentials("plan")
        production_sha = live_precondition(values, image_present=True)
        run, env = setup_tofu(output, values)
        binary = run / "retire-image.tfplan"
        shown = run / "retire-image.plan.json"
        result = subprocess.run(["tofu", f"-chdir={TF_ROOT}", "plan", "-input=false", "-lock=true", "-var=enable_qualification=false", "-out", str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            fail("tofu-plan")
        with shown.open("wb") as stream:
            result = subprocess.run(["tofu", f"-chdir={TF_ROOT}", "show", "-json", str(binary)], env=env, stdout=stream, stderr=subprocess.DEVNULL)
        if result.returncode:
            fail("tofu-show")
        inspect_plan(json.loads(shown.read_text()))
        plan_sha = sha(binary.read_bytes())
        plan_json_sha = sha(shown.read_bytes())
        final_binary = output / f"{plan_sha}.tfplan"
        final_json = output / f"{plan_sha}.plan.json"
        os.chmod(binary, 0o600)
        os.chmod(shown, 0o600)
        os.link(binary, final_binary, follow_symlinks=False)
        os.link(shown, final_json, follow_symlinks=False)
        created = now()
        manifest = {
            "actionable": True,
            "address": ADDRESS,
            "authorized": False,
            "automatic_apply": False,
            "ca_sha256": provider_binding(values)["ca_sha256"],
            "commit": commit,
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "endpoint_sha256": provider_binding(values)["endpoint_sha256"],
            "expires_at": (created + dt.timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
            "format": "home-lab-restic-recovery-image-retirement-plan-v1",
            "image_id": IMAGE_ID,
            "journal_sha256": JOURNAL_SHA256,
            "operation": "delete-state-owned-recovery-base-image",
            "plan_json_sha256": plan_json_sha,
            "plan_sha256": plan_sha,
            "production_vm_sha256": production_sha,
            "state_before_sha256": sha(state_raw),
            "version": 1,
        }
        manifest_sha = sha(canonical_bytes(manifest) + b"\n")
        write_json(output, f"{manifest_sha}.manifest.json", manifest)
        print(json.dumps({"actionable": True, "authorization_sha256": manifest_sha, "authorized": False, "manifest": str(output / f"{manifest_sha}.manifest.json"), "plan_sha256": plan_sha}, sort_keys=True))
    finally:
        if run is not None:
            shutil.rmtree(run, ignore_errors=True)
        os.close(descriptor)


def load_manifest(args: argparse.Namespace, output: Path, *, allow_expired: bool = False) -> dict[str, object]:
    value, raw = load_canonical_object(args.manifest, "retirement manifest")
    required = {"actionable", "address", "authorized", "automatic_apply", "ca_sha256", "commit", "created_at", "endpoint_sha256", "expires_at", "format", "image_id", "journal_sha256", "operation", "plan_json_sha256", "plan_sha256", "production_vm_sha256", "state_before_sha256", "version"}
    created = parse_time(value.get("created_at"))
    expires = parse_time(value.get("expires_at"))
    if set(value) != required or sha(raw) != args.authorization_sha or value.get("format") != "home-lab-restic-recovery-image-retirement-plan-v1" or value.get("version") != 1 or value.get("operation") != "delete-state-owned-recovery-base-image" or value.get("address") != ADDRESS or value.get("image_id") != IMAGE_ID or value.get("journal_sha256") != JOURNAL_SHA256 or value.get("state_before_sha256") != INITIAL_STATE_SHA256 or value.get("plan_sha256") != args.plan_sha or value.get("actionable") is not True or value.get("authorized") is not False or value.get("automatic_apply") is not False or any(HEX.fullmatch(str(value.get(key, ""))) is None for key in ("ca_sha256", "endpoint_sha256", "plan_json_sha256", "plan_sha256", "production_vm_sha256", "state_before_sha256")) or created > now() + dt.timedelta(seconds=5) or (not allow_expired and (created < now() - dt.timedelta(minutes=20) or expires <= now())) or expires - created > dt.timedelta(minutes=20):
        fail("manifest-binding")
    if args.manifest.parent.resolve() != output:
        fail("manifest-output-root")
    return value


def apply(args: argparse.Namespace) -> None:
    if args.confirm != CONFIRM or args.approve_plan_sha != args.plan_sha or args.approve_authorization_sha != args.authorization_sha or HEX.fullmatch(args.plan_sha or "") is None or HEX.fullmatch(args.authorization_sha or "") is None:
        fail("exact-authorization-required")
    output = require_private_root(args.output_dir, (LINEAGE_ROOT,))
    descriptor = acquire_lock()
    run = None
    try:
        state_raw = load_protected_bytes(STATE, "state")
        completed = sha(state_raw) != INITIAL_STATE_SHA256
        if completed:
            inspect_empty_state(state_raw)
        else:
            inspect_initial_state(state_raw)
        manifest = load_manifest(args, output, allow_expired=completed)
        revision(str(manifest["commit"]))
        inspect_journal()
        binary = output / f"{args.plan_sha}.tfplan"
        shown = output / f"{args.plan_sha}.plan.json"
        if sha(load_protected_bytes(binary, "saved plan")) != args.plan_sha or sha(load_protected_bytes(shown, "plan JSON")) != manifest["plan_json_sha256"]:
            fail("saved-plan-binding")
        inspect_plan(json.loads(load_protected_bytes(shown, "plan JSON")))
        values = credentials("apply")
        expected_binding = {"ca_sha256": manifest["ca_sha256"], "endpoint_sha256": manifest["endpoint_sha256"]}
        if provider_binding(values) != expected_binding or live_precondition(values, image_present=not completed) != manifest["production_vm_sha256"]:
            fail("current-live-binding")
        preserve_state_before(output, load_protected_bytes(output / f"{INITIAL_STATE_SHA256}.state-before.tfstate", "preserved state before") if completed else state_raw)
        if not completed:
            run, env = setup_tofu(output, values)
            result = subprocess.run(["tofu", f"-chdir={TF_ROOT}", "apply", "-input=false", "-lock=true", "-auto-approve", str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                fail("tofu-apply-no-retry")
            state_raw = load_protected_bytes(STATE, "state")
            inspect_empty_state(state_raw)
            if live_precondition(values, image_present=False) != manifest["production_vm_sha256"]:
                fail("current-live-binding")
        inspect_journal()
        state_after = sha(state_raw)
        receipt = {"address": ADDRESS, "commit": manifest["commit"], "format": "home-lab-restic-recovery-image-retirement-receipt-v1", "image_absent": True, "image_id": IMAGE_ID, "journal_sha256": JOURNAL_SHA256, "operation": manifest["operation"], "plan_sha256": args.plan_sha, "state_after_sha256": state_after, "state_before_sha256": manifest["state_before_sha256"], "version": 1}
        receipt_path = output / f"{args.plan_sha}.receipt.json"
        if receipt_path.exists():
            observed, _raw = load_canonical_object(receipt_path, "retirement receipt")
            if observed != receipt:
                fail("receipt-identity")
        else:
            write_json(output, receipt_path.name, receipt)
        print(json.dumps({"image_absent": True, "receipt": str(receipt_path), "state_empty": True}, sort_keys=True))
    finally:
        if run is not None:
            shutil.rmtree(run, ignore_errors=True)
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--output-dir", type=Path, required=True)
    apply_parser.add_argument("--manifest", type=Path, required=True)
    apply_parser.add_argument("--plan-sha", required=True)
    apply_parser.add_argument("--approve-plan-sha", required=True)
    apply_parser.add_argument("--authorization-sha", required=True)
    apply_parser.add_argument("--approve-authorization-sha", required=True)
    apply_parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    if getattr(args, "manifest", None) is not None:
        args.manifest = args.manifest.resolve()
    apply(args) if args.command == "apply" else plan(args)


if __name__ == "__main__":
    main()
