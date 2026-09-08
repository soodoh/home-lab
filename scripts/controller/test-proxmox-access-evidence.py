#!/usr/bin/env python3
"""Confined synthetic tests of capture admission; Node audit is a strict stub."""
from __future__ import annotations

import contextlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("proxmox_access_evidence", ROOT / "scripts/controller/proxmox-access-evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
RUN = subprocess.run
FIXTURE_ROOTS = []
COMMIT = "0" * 40


class AccessEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="proxmox-access-fixture-")).resolve()
        FIXTURE_ROOTS.append(self.root)
        print(f"fixture_root={self.root}", flush=True)
        scripts = self.root / "scripts/controller"
        scripts.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/controller/controller-boundary-manifest.py", scripts / "controller-boundary-manifest.py")
        for name in ("infrastructure/contract/home-lab.yml", "ansible/inventory/production.yml"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic-only\n")
        self.boundary = self.root / "boundary.json"
        self.document = {"version": 1, "account_id": "658271954302", "partition": "aws",
                         "plan_policy_arn": "arn:aws:iam::658271954302:policy/fixture/plan",
                         "apply_policy_arn": "arn:aws:iam::658271954302:policy/fixture/apply",
                         "provenance": {"review_reference": "synthetic-only", "plan_policy_sha256": "a" * 64,
                                        "apply_policy_sha256": "b" * 64}}
        self.boundary.write_text(json.dumps(self.document))
        self.boundary.chmod(0o600)
        self.manifest = self.root / ".reconcile/plans" / COMMIT / "steady/selected/manifest.json"
        self.events = []
        self.controller_status = 0
        self.verifier_status = 0
        self.mutate_manifest = lambda value: None
        self.verifier_effect = lambda: None
        self.controller_effect = lambda: None
        self.write_selected = True
        self.stdout = b"synthetic controller display, not proof\n"
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("ROOT", self.root), ("OUTPUT", self.root / "output")):
            self.stack.enter_context(mock.patch.object(MODULE, name, value))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(mock.patch.object(MODULE.subprocess, "run", side_effect=self.dispatch))
        self.stack.enter_context(mock.patch.object(MODULE.subprocess, "check_output", side_effect=AssertionError("unknown check_output")))
        self.stack.enter_context(mock.patch.object(MODULE, "git", side_effect=self.git))
        self.stack.enter_context(mock.patch.object(MODULE, "known_host_proven", side_effect=lambda: self.effect("host-key", True)))
        self.stack.enter_context(mock.patch.object(MODULE, "run_ssh", side_effect=self.ssh))
        self.stack.enter_context(mock.patch.object(MODULE, "latest_marker_plan_digest", side_effect=lambda: self.effect("marker", "a" * 64)))
        self.stack.enter_context(mock.patch.object(MODULE, "root_key_evidence", side_effect=lambda: self.effect("root-keys", {"records": [], "complete": True})))

    def effect(self, name, result):
        self.events.append(name)
        return result

    def git(self, *args):
        self.events.append(("git", args))
        if args in (("rev-parse", "HEAD"), ("rev-parse", "origin/main")):
            return COMMIT
        if args == ("status", "--porcelain=v1", "--untracked-files=all"):
            return ""
        raise AssertionError(f"unknown git command: {args}")

    def ssh(self, target, command, expected=0, input_data=None):
        self.assertIsNone(input_data)
        allowed = {
            ("ansible-plan@proxmox", "observe", 0): b'{"format":"home-lab-proxmox-observation-v1","protocol":4}',
            ("ansible-plan@proxmox", "observe;id", 64): b"",
            ("firewall-apply@proxmox", "inspect", 0): b"synthetic inspect\n",
            ("firewall-apply@proxmox", "inspect;id", 64): b"",
            ("ansible-deploy@proxmox", "inspect lifecycle-marker " + "a" * 64, 0): b'{"present":true}\n',
            ("ansible-deploy@proxmox", "apply lifecycle-marker a;id", 64): b"",
            ("proxmox@proxmox", "true", 0): b"",
        }
        key = (target, command, expected)
        self.assertIn(key, allowed)
        self.events.append(("ssh", key))
        return subprocess.CompletedProcess([], expected, allowed[key], b"")

    def value(self):
        binding = {"path": str(self.boundary), "sha256": MODULE.file_sha(self.boundary), "document": self.document}
        return {"version": 6, "commit": COMMIT, "phase": "steady", "stage": "converge",
                "controller_boundary_manifest": binding,
                "plans": [{"root": root, "changed": False,
                           "tailscale_policy_before_sha256": "a" * 64 if root == "tailscale" else "",
                           "tailscale_policy_after_sha256": "a" * 64 if root == "tailscale" else ""}
                          for root in ("aws-foundation", "proxmox", "tailscale")]}

    def save_manifest(self):
        self.manifest.parent.mkdir(parents=True, mode=0o700)
        value = self.value()
        self.mutate_manifest(value)
        self.manifest.write_bytes(MODULE.canonical(value))
        self.manifest.chmod(0o600)

    def dispatch(self, argv, **kwargs):
        argv = tuple(map(str, argv))
        self.assertEqual(kwargs, {"cwd": self.root, "capture_output": True,
                                  "timeout": 30 if argv[0] == sys.executable else 180 if argv[0] == "node" else 1800})
        helper_prefix = (sys.executable, "-I", "-B", "-S", str(self.root / "scripts/controller/controller-boundary-manifest.py"))
        if argv[:5] == helper_prefix:
            self.assertIn(argv[5], ("load", "verify"))
            self.assertEqual(argv[6:8], ("--manifest", str(self.boundary)))
            if argv[5] == "load":
                self.assertEqual(len(argv), 8)
            else:
                self.assertIn(len(argv), (10, 12))
                self.assertEqual(argv[8], "--binding")
                if len(argv) == 12:
                    self.assertEqual(argv[10:], ("--saved-plan", str(self.manifest)))
            self.events.append(("boundary", argv[5]))
            return RUN(argv, **kwargs)
        if argv == (str(self.root / "scripts/local-controller"), "plan", "steady", "--generation", "selected", "--boundary-manifest", str(self.boundary)):
            self.assertFalse(os.path.lexists(self.manifest.parent))
            self.events.append("controller")
            if self.write_selected:
                self.save_manifest()
            self.controller_effect()
            return subprocess.CompletedProcess(argv, self.controller_status, self.stdout, b"")
        if argv == ("node", str(self.root / "scripts/controller/proxmox-check-evidence.js"), "verify", str(self.manifest)):
            self.events.append("verifier")
            self.verifier_effect()
            return subprocess.CompletedProcess(argv, self.verifier_status, b'{"verified":true}\n', b"")
        raise AssertionError(f"unknown subprocess dispatch: {argv}")

    def cli(self, *args):
        with mock.patch.object(sys, "argv", ["proxmox-access-evidence.py", *args]), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            MODULE.main()

    def capture(self):
        return MODULE.capture("selected", self.boundary)

    def assert_no_remote_effects(self):
        self.assertNotIn("host-key", self.events)
        self.assertNotIn("controller", self.events)
        self.assertFalse(any(isinstance(item, tuple) and item[0] == "ssh" for item in self.events))
        self.assertFalse((self.root / "output").exists())

    def test_capture_requires_explicit_inputs_before_effects(self):
        reached = []
        def forbidden_capture(*args, **kwargs):
            reached.append("capture")
            raise SystemExit(91)
        with mock.patch.object(MODULE, "capture", side_effect=forbidden_capture):
            with self.assertRaises(SystemExit) as refused:
                self.cli("capture")
        (self.root / "result.json").write_text(json.dumps({"exit": refused.exception.code, "effects": reached}))
        self.assertEqual(refused.exception.code, 2)
        self.assertEqual(reached, [])

    def test_cli_missing_duplicate_abbreviated_and_malformed_inputs(self):
        base = ("--generation", "selected", "--boundary-manifest", str(self.boundary))
        cases = [("--generation", "selected"), ("--boundary-manifest", str(self.boundary)),
                 (*base, "--generation", "other"), (*base, "--boundary-manifest", str(self.boundary)),
                 ("--gen", "selected", "--boundary-manifest", str(self.boundary)),
                 ("--generation", "selected", "--boundary", str(self.boundary)), (*base, "--unknown")]
        cases += [("--generation", item, "--boundary-manifest", str(self.boundary))
                  for item in ("", "UPPER", "../selected", "a" * 65, "selected\n", "first/second")]
        cases.append(("--generation", "selected", "--boundary-manifest", "relative.json"))
        for args in cases:
            with self.subTest(args=args), self.assertRaises(SystemExit):
                self.cli("capture", *args)
        self.assert_no_remote_effects()

    def test_boundary_invalid_missing_symlink_and_overrides_refuse_before_effects(self):
        original = self.boundary.read_bytes()
        for raw in (b"{}", b"null", b'{"version":1,"version":1}', b"x" * 16385):
            self.boundary.write_bytes(raw)
            with self.assertRaisesRegex(SystemExit, "boundary manifest refused"):
                self.capture()
        self.boundary.unlink()
        with self.assertRaisesRegex(SystemExit, "boundary manifest refused"):
            self.capture()
        target = self.root / "boundary-target.json"
        target.write_bytes(original)
        self.boundary.symlink_to(target)
        with self.assertRaisesRegex(SystemExit, "boundary manifest refused"):
            self.capture()
        self.boundary.unlink()
        self.boundary.write_bytes(original)
        self.boundary.chmod(0o600)
        for key, value in (("TF_VAR_controller_plan_permissions_boundary_arn", "wrong"),
                           ("TF_VAR_controller_apply_permissions_boundary_arn", "wrong"),
                           ("TF_CLI_ARGS", "-anything"), ("TF_CLI_ARGS_plan", "-anything")):
            with mock.patch.dict(os.environ, {key: value}), self.assertRaisesRegex(SystemExit, "boundary manifest refused"):
                self.capture()
        self.assert_no_remote_effects()

    def test_existing_failed_generation_and_unsafe_paths_are_retained(self):
        self.manifest.parent.mkdir(parents=True)
        retained = self.manifest.parent / "failed.json"
        retained.write_bytes(b"old failure must remain failed\n")
        with self.assertRaisesRegex(SystemExit, "already exists"):
            self.capture()
        self.assertEqual(retained.read_bytes(), b"old failure must remain failed\n")
        self.assert_no_remote_effects()

    def test_dangling_generation_and_symlink_ancestor_refuse(self):
        self.manifest.parent.parent.mkdir(parents=True)
        self.manifest.parent.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(SystemExit, "unsafe controller generation path"):
            self.capture()
        self.assertTrue(self.manifest.parent.is_symlink())
        self.assert_no_remote_effects()

    def test_writable_generation_ancestor_refuses(self):
        self.manifest.parent.parent.mkdir(parents=True)
        self.manifest.parent.parent.chmod(0o777)
        with self.assertRaisesRegex(SystemExit, "unsafe controller generation path"):
            self.capture()
        self.assert_no_remote_effects()

    def test_success_uses_exact_generation_and_unchanged_v1_shape(self):
        unrelated = self.manifest.parent.parent / "unrelated/manifest.json"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_bytes(b"unrelated expired evidence\n")
        path, digest = self.capture()
        value = json.loads(path.read_bytes())
        proof = value["proofs"]["tailnet_policy"]
        self.assertEqual(set(proof), {"tests_present", "live_plan_noop", "expected_retirement_drift", "controller_plan_stdout_sha256"})
        self.assertEqual(proof, {"tests_present": True, "live_plan_noop": True, "expected_retirement_drift": False,
                                 "controller_plan_stdout_sha256": MODULE.sha(self.stdout)})
        self.assertFalse(value["authorized"])
        self.assertEqual(digest, MODULE.file_sha(path))
        self.assertEqual(unrelated.read_bytes(), b"unrelated expired evidence\n")
        self.assertLess(self.events.index(("boundary", "load")), self.events.index("host-key"))
        self.assertLess(self.events.index("controller"), self.events.index("verifier"))
        self.assertEqual(self.events.count("controller"), 1)

    def test_legacy_stdout_and_unrelated_latest_plan_cannot_supply_proof(self):
        self.stdout = b"[tailscale]\nNo changes\n"
        self.write_selected = False
        old = self.root / ".reconcile/plans" / ("a" * 64 + ".json")
        old.parent.mkdir(parents=True)
        raw = b'{"status":"blocked","applyEligible":false,"actions":[]}'
        old.write_bytes(raw)
        with self.assertRaises(FileNotFoundError):
            self.capture()
        self.assertEqual(old.read_bytes(), raw)
        self.assertNotIn("verifier", self.events)
        self.assertFalse((self.root / "output").exists())

    def test_failed_controller_never_accepts_even_noop_stdout_and_manifest(self):
        self.controller_status = 66
        self.stdout = b"[tailscale]\nNo changes\n"
        with self.assertRaisesRegex(SystemExit, "generation failed"):
            self.capture()
        self.assertTrue(self.manifest.exists())
        self.assertNotIn("verifier", self.events)
        self.assertFalse((self.root / "output").exists())

    def test_current_verifier_refusal_propagates_without_retry(self):
        # Expiry/dependency/binary/audit semantics belong to the unchanged real
        # Node verifier, not this adapter. Any such refusal must be terminal.
        self.verifier_status = 66
        with self.assertRaisesRegex(SystemExit, "verification refused"):
            self.capture()
        self.assertEqual(self.events.count("verifier"), 1)
        self.assertEqual(self.events.count("controller"), 1)
        self.assertTrue(self.manifest.exists())
        self.assertFalse((self.root / "output").exists())

    def test_scope_source_changes_and_all_non_noop_records_refuse(self):
        # Exercise actual proof function repeatedly against private synthetic
        # manifests, not capture retries of an attempted generation.
        mutations = [lambda v: v.update(version=5), lambda v: v.update(commit="1" * 40),
                     lambda v: v.update(phase="other"), lambda v: v.update(stage="other"),
                     lambda v: v["plans"][0].update(changed=True),
                     lambda v: v["plans"][1].update(changed=0),
                     lambda v: v["plans"].pop(),
                     lambda v: v["plans"].append(dict(v["plans"][-1])),
                     lambda v: v["plans"][-1].update(tailscale_policy_before_sha256=""),
                     lambda v: v["plans"][-1].update(tailscale_policy_after_sha256="b" * 64),
                     lambda v: v["controller_boundary_manifest"].update(sha256="f" * 64)]
        self.save_manifest()
        binding = json.dumps(self.value()["controller_boundary_manifest"])
        result = subprocess.CompletedProcess([], 0, b"[tailscale]\nNo changes\n", b"")
        for mutation in mutations:
            value = self.value()
            mutation(value)
            self.manifest.write_bytes(MODULE.canonical(value))
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                MODULE.controller_plan_proof(result, COMMIT, "selected", self.boundary, binding)
        self.assertFalse((self.root / "output").exists())

    def test_manifest_replacement_during_verifier_refuses(self):
        self.verifier_effect = lambda: self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(SystemExit, "changed during verification"):
            self.capture()
        self.assertFalse((self.root / "output").exists())

    def test_boundary_change_during_verifier_refuses(self):
        self.verifier_effect = lambda: self.boundary.write_bytes(self.boundary.read_bytes() + b" ")
        with self.assertRaisesRegex(SystemExit, "boundary manifest refused"):
            self.capture()
        self.assertFalse((self.root / "output").exists())

    def test_source_change_before_publication_refuses(self):
        original_git = self.git
        def changed_git(*args):
            if "verifier" in self.events and args == ("rev-parse", "HEAD"):
                return "1" * 40
            return original_git(*args)
        with mock.patch.object(MODULE, "git", side_effect=changed_git), self.assertRaisesRegex(SystemExit, "clean pushed HEAD"):
            self.capture()
        self.assertFalse((self.root / "output").exists())

    def test_manifest_unsafe_metadata_refuses_before_verifier(self):
        self.controller_effect = lambda: self.manifest.chmod(0o644)
        with self.assertRaisesRegex(SystemExit, "unsafe controller manifest"):
            self.capture()
        self.assertNotIn("verifier", self.events)

    def test_root_key_evidence_treats_final_absence_as_complete_empty_input(self):
        # Inspect the original function, not the declared effect adapter.
        source = (ROOT / "scripts/controller/proxmox-access-evidence.py").read_text()
        self.assertIn("except FileNotFoundError: lines=[]", source)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    if result.wasSuccessful():
        for directory in FIXTURE_ROOTS:
            shutil.rmtree(directory)
    else:
        print("retained_failed_fixture_roots=" + json.dumps(list(map(str, FIXTURE_ROOTS))), flush=True)
    sys.exit(not result.wasSuccessful())
