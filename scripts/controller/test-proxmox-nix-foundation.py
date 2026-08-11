#!/usr/bin/env python3
"""Tests for deterministic Proxmox Nix foundation bundle construction."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
NIX_ROOT = ROOT / "nix"
BUILDER = NIX_ROOT / "proxmox/bundle.py"
PROJECTION = NIX_ROOT / "proxmox/projection.json"
MANIFEST = NIX_ROOT / "proxmox/package-manifest.json"
LOCK = NIX_ROOT / "flake.lock"
EXPECTED_SOURCE_FILES = {
    "flake.lock", "flake.nix", "proxmox/activation-envelope.schema.json", "proxmox/activator-template.py",
    "proxmox/apply.py", "proxmox/bundle.py", "proxmox/package-manifest.json", "proxmox/fixture-observation.json",
    "proxmox/observation.schema.json", "proxmox/observer-template.py", "proxmox/package-manifest.schema.json",
    "proxmox/plan.schema.json", "proxmox/planner.py", "proxmox/prepare.py", "proxmox/private-preconditions.schema.json",
    "proxmox/private-preparation-request.schema.json", "proxmox/private-preparer-template.py",
    "proxmox/projection.json", "proxmox/projection.schema.json",
}

sys.dont_write_bytecode = True
specification = importlib.util.spec_from_file_location("proxmox_bundle", BUILDER)
if specification is None or specification.loader is None:
    raise RuntimeError("unable to load Proxmox bundle module")
bundle_module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(bundle_module)


class ProxmoxNixFoundationTests(unittest.TestCase):
    def build(self, root: Path) -> tuple[Path, Path]:
        bundle = root / "bundle"
        content_hash = root / "bundle.sha256"
        subprocess.run([
            sys.executable, BUILDER, "build",
            "--projection", PROJECTION,
            "--package-manifest", MANIFEST,
            "--flake-lock", LOCK,
            "--output", bundle,
            "--hash-output", content_hash,
        ], check=True)
        return bundle, content_hash

    def verify(self, bundle: Path, content_hash: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, BUILDER, "verify", "--bundle", bundle, "--hash-file", content_hash],
            check=check,
            capture_output=True,
            text=True,
        )

    def rehash(self, bundle: Path, content_hash: Path) -> None:
        content_hash.write_text(f"{bundle_module.canonical_tree_sha256(bundle)}\n", encoding="utf-8")

    def assert_semantic_verify_failure(
        self,
        mutation: Callable[[Path], None],
        expected: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle, content_hash = self.build(Path(name))
            mutation(bundle)
            self.rehash(bundle, content_hash)
            result = self.verify(bundle, content_hash, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_sanitized_flake_source_contains_only_approved_inputs(self) -> None:
        self.assertFalse((ROOT / "flake.nix").exists())
        self.assertFalse((ROOT / "flake.lock").exists())
        local_files = {
            path.relative_to(NIX_ROOT).as_posix()
            for path in bundle_module.canonical_tree_files(NIX_ROOT)
        }
        self.assertEqual(local_files, EXPECTED_SOURCE_FILES)
        source_store_path = os.environ.get("PROXMOX_NIX_SOURCE_STORE_PATH")
        if source_store_path:
            source_root = Path(source_store_path)
            source_files = {
                path.relative_to(source_root).as_posix()
                for path in bundle_module.canonical_tree_files(source_root)
            }
            self.assertEqual(source_files, EXPECTED_SOURCE_FILES)
            for relative in EXPECTED_SOURCE_FILES:
                self.assertEqual((source_root / relative).read_bytes(), (NIX_ROOT / relative).read_bytes())

    def test_bundle_is_reproducible_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first, first_hash = self.build(Path(first_name))
            second, second_hash = self.build(Path(second_name))
            self.assertEqual(first_hash.read_bytes(), second_hash.read_bytes())
            first_files = {path.relative_to(first): path.read_bytes() for path in first.rglob("*") if path.is_file()}
            second_files = {path.relative_to(second): path.read_bytes() for path in second.rglob("*") if path.is_file()}
            self.assertEqual(first_files, second_files)
            self.verify(first, first_hash)
            metadata = json.loads((first / "metadata.json").read_bytes())
            manifest = json.loads((first / "packages/proxmox-package-manifest.json").read_bytes())
            installed_delta = manifest["provenance"]["installedInventory"]["installedRecords"] + sum(
                1 if change["action"] == "install" else -1 if change["action"] == "remove" else 0
                for change in manifest["provenance"]["solverResult"]["changes"]
            )
            self.assertEqual(metadata["packageCount"], len(manifest["packages"]))
            self.assertEqual(len(manifest["packages"]), installed_delta)
            self.assertEqual(len(manifest["packages"]), 1353)
            self.assertFalse(metadata["target"]["requiresNix"])
            self.assertEqual(metadata["helperInstall"], {
                "deployment": "copy-out-of-store", "owner": "root", "group": "root", "mode": "0755",
            })

    def test_hash_is_outside_hashed_tree_and_detects_changes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle, content_hash = self.build(Path(name))
            self.assertEqual(content_hash.parent, bundle.parent)
            self.assertFalse((bundle / "bundle.sha256").exists())
            target = bundle / "rendered/managed-files.json"
            target.write_bytes(target.read_bytes() + b" ")
            result = self.verify(bundle, content_hash, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bundle content hash mismatch", result.stderr)

    def test_tree_hash_rejects_every_symlink_and_unsupported_entry(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "file").write_text("content", encoding="utf-8")
            (root / "broken").symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                bundle_module.canonical_tree_sha256(root)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "directory"
            target.mkdir()
            (root / "directory-link").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                bundle_module.canonical_tree_sha256(root)
        if hasattr(os, "mkfifo"):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                os.mkfifo(root / "fifo")
                with self.assertRaisesRegex(ValueError, "unsupported entry"):
                    bundle_module.canonical_tree_sha256(root)

    def test_protocol_and_helper_structure_are_exact(self) -> None:
        def rewrite_json(bundle: Path, relative: str, mutation: Callable[[dict], None]) -> None:
            path = bundle / relative
            value = json.loads(path.read_bytes())
            mutation(value)
            path.write_bytes(bundle_module.canonical_json(value))

        def replace_schema_and_self_hash(bundle: Path) -> None:
            schema_path = bundle / "policy/observation.schema.json"
            schema_path.write_bytes(b"{}\n")
            metadata_path = bundle / "metadata.json"
            metadata = json.loads(metadata_path.read_bytes())
            metadata["observationSchemaSha256"] = bundle_module.sha256_file(schema_path)
            metadata_path.write_bytes(bundle_module.canonical_json(metadata))

        cases = [
            (lambda bundle: (bundle / "protocol.json").write_bytes(b"{}\n"), "protocol structure is invalid"),
            (lambda bundle: rewrite_json(bundle, "protocol.json", lambda value: value.pop("uploadedCodeExecution")), "protocol structure is invalid"),
            (lambda bundle: rewrite_json(bundle, "protocol.json", lambda value: value.update({"extra": False})), "protocol structure is invalid"),
            (lambda bundle: rewrite_json(bundle, "protocol.json", lambda value: value.update({"helpers": {}})), "protocol structure is invalid"),
            (lambda bundle: rewrite_json(bundle, "protocol.json", lambda value: value["helpers"].update({"extra": {"commands": [], "mutating": False}})), "protocol structure is invalid"),
            (lambda bundle: (bundle / "helpers/proxmox-observer").unlink(), "unknown or missing file"),
            (lambda bundle: (bundle / "helpers/extra-helper").write_text("inert", encoding="utf-8"), "unknown or missing file"),
            (lambda bundle: rewrite_json(bundle, "metadata.json", lambda value: value.update({"helperSha256": {}})), "helper hash key set is invalid"),
            (lambda bundle: rewrite_json(bundle, "metadata.json", lambda value: value["helperSha256"].update({"extra": "0" * 64})), "helper hash key set is invalid"),
            (lambda bundle: rewrite_json(bundle, "metadata.json", lambda value: value["helperSha256"].update({"proxmox-observer": "0" * 64})), "metadata hash differs"),
            (replace_schema_and_self_hash, "schema binding failed"),
        ]
        for mutation, expected in cases:
            with self.subTest(expected=expected, mutation=repr(mutation)):
                self.assert_semantic_verify_failure(mutation, expected)

    def test_builder_rejects_protected_or_malformed_projection(self) -> None:
        cases = [
            (lambda value: value.update({"unexpected": True}), "top-level shape"),
            (lambda value: value["managedFiles"][0].update({"path": "/etc/pve/firewall/cluster.fw"}), "PVE-owned"),
            (lambda value: value["hostNetworking"].update({"mac": "AA:BB:CC:DD:EE:FF"}), "forbidden key"),
            (lambda value: value["hostNetworking"].update({"hostname": "HOMELAB_ZFS_MEMBER_01_BY_ID"}), "protected or PVE-owned"),
        ]
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as name:
                    temporary = Path(name)
                    projection = json.loads(PROJECTION.read_bytes())
                    mutation(projection)
                    projection_path = temporary / "projection.json"
                    projection_path.write_bytes(bundle_module.canonical_json(projection))
                    result = subprocess.run([
                        sys.executable, BUILDER, "build", "--projection", projection_path,
                        "--package-manifest", MANIFEST, "--flake-lock", LOCK,
                        "--output", temporary / "bundle", "--hash-output", temporary / "bundle.sha256",
                    ], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_builder_rejects_manifest_architecture_and_provenance_drift(self) -> None:
        cases = [
            (lambda value: value.update({"architecture": "arm64"}), "version or architecture"),
            (lambda value: value["provenance"]["installedInventory"].update({
                "installedRecords": value["provenance"]["installedInventory"]["installedRecords"] + 1,
            }), "count differs from provenance"),
            (lambda value: value["packages"][0].update({"version": "TAILSCALE_AUTH_KEY"}), "protected or PVE-owned"),
        ]
        for mutation, expected in cases:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as name:
                    temporary = Path(name)
                    manifest = json.loads(MANIFEST.read_bytes())
                    mutation(manifest)
                    manifest_path = temporary / "manifest.json"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    result = subprocess.run([
                        sys.executable, BUILDER, "build", "--projection", PROJECTION,
                        "--package-manifest", manifest_path, "--flake-lock", LOCK,
                        "--output", temporary / "bundle", "--hash-output", temporary / "bundle.sha256",
                    ], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_recomputed_hash_cannot_authorize_malicious_helper(self) -> None:
        malicious = b'''#!/usr/bin/python3
import json
import sys
print("TAILSCALE_AUTH_KEY")
if sys.argv[1:] == ["version"]:
    print(json.dumps({"version": 999}))
if sys.argv[1:] == ["apply"]:
    print("applied")
'''

        def replace_helper_and_self_hash(bundle: Path) -> None:
            helper = bundle / "helpers/proxmox-observer"
            helper.write_bytes(malicious)
            helper.chmod(0o755)
            metadata_path = bundle / "metadata.json"
            metadata = json.loads(metadata_path.read_bytes())
            metadata["helperSha256"]["proxmox-observer"] = bundle_module.sha256_bytes(malicious)
            metadata_path.write_bytes(bundle_module.canonical_json(metadata))

        self.assert_semantic_verify_failure(
            replace_helper_and_self_hash,
            "content differs from the fixed builder template",
        )

    def test_builder_has_no_external_helper_inputs(self) -> None:
        for argument in ("--observer", "--activator"):
            with self.subTest(argument=argument), tempfile.TemporaryDirectory() as name:
                temporary = Path(name)
                result = subprocess.run([
                    sys.executable, BUILDER, "build",
                    "--projection", PROJECTION,
                    "--package-manifest", MANIFEST,
                    "--flake-lock", LOCK,
                    argument, temporary / "malicious-helper",
                    "--output", temporary / "bundle",
                    "--hash-output", temporary / "bundle.sha256",
                ], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"unrecognized arguments: {argument}", result.stderr)

    def test_helpers_expose_only_exact_fixed_protocol_commands(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle, content_hash = self.build(Path(name))
            self.verify(bundle, content_hash)
            for helper_name in bundle_module.EXPECTED_HELPERS:
                helper = bundle / "helpers" / helper_name
                projection = json.loads(PROJECTION.read_bytes())
                self.assertEqual(helper.read_bytes(), bundle_module.expected_helper_content(helper_name, projection))

                if helper_name == "proxmox-private-preparer":
                    expected_usage = b"usage: proxmox-private-preparer <summary|prepare>\n"
                    for command in ("version", "self-check", "observe", "session", "unknown"):
                        result = subprocess.run([sys.executable, helper, command], capture_output=True)
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (64, b"", expected_usage))
                    continue
                version = subprocess.run(
                    [sys.executable, helper, "version"], check=True, capture_output=True,
                )
                self.assertEqual(version.stdout, bundle_module.expected_helper_version(helper_name))
                self.assertEqual(version.stderr, b"")

                self_check = subprocess.run(
                    [sys.executable, helper, "self-check"], check=True, capture_output=True,
                )
                self.assertEqual(
                    self_check.stdout,
                    f"{helper_name}=self-check-passed protocol=4 capabilities={'observe' if helper_name == 'proxmox-observer' else 'guarded-session'}\n".encode(),
                )
                self.assertEqual(self_check.stderr, b"")

                commands = "version|self-check|observe" if helper_name == "proxmox-observer" else "version|self-check|session"
                expected_usage = f"usage: {helper_name} <{commands}>\n".encode()
                for command in ("plan", "apply", "verify", "bootstrap", "unknown"):
                    result = subprocess.run([sys.executable, helper, command], capture_output=True)
                    self.assertEqual(result.returncode, 64)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, expected_usage)


if __name__ == "__main__":
    unittest.main()
