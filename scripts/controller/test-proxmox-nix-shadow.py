#!/usr/bin/env python3
"""Behavioral tests for the read-only Proxmox Nix shadow lane."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO / "scripts/controller/proxmox-nix-shadow.py"
BASELINE = "2e3b3108eb0ed1ea00a14ae82365aeb9a89160de"


def load_module():
    specification = importlib.util.spec_from_file_location("proxmox_nix_shadow_tests", MODULE_PATH)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


shadow = load_module()


def bindings() -> dict:
    result = {
        "activationEnvelopeSchemaSha256": "1" * 64,
        "activatorSha256": "2" * 64,
        "bundleContentSha256": "3" * 64,
        "bundleFormat": "home-lab-proxmox-host-bundle-v1",
        "flakeLockSha256": "4" * 64,
        "gitCommit": "5" * 40,
        "gitTree": "6" * 40,
        "observerProtocol": 4,
        "observerSha256": "7" * 64,
        "packageManifestSha256": "8" * 64,
        "planSchemaSha256": "9" * 64,
        "privatePreconditionsSchemaSha256": "a" * 64,
        "privatePreparationRequestSchemaSha256": "b" * 64,
        "privatePreparerSha256": "c" * 64,
        "projectionSha256": "d" * 64,
    }
    return result


def summary(changed: int = 0) -> dict:
    return {
        "handlerCount": 1,
        "playCount": 1,
        "recap": {"changed": changed, "failed": 0, "host": "proxmox", "ignored": 0, "ok": 3,
                  "rescued": 0, "skipped": 1, "unreachable": 0},
        "taskCount": 4,
    }


def evidence() -> dict:
    commit = "e" * 40
    phase = "steady"
    return {
        "ansible": {"reproducible": True, "runs": [summary(), summary()]},
        "controllerManifest": {
            "relativePath": f".reconcile/plans/{commit}/{phase}/manifest.json",
            "sha256": "f" * 64,
            "version": 3,
        },
        "format": shadow.EVIDENCE_FORMAT,
        "git": {"commit": commit, "tree": "1" * 40},
        "nix": {
            "actionCount": 0,
            "applyEligible": False,
            "bindings": bindings(),
            "blockerCount": 1,
            "domainCounts": {"identity": {"actions": 0, "blockers": 1, "findings": 0}},
            "findingCount": 0,
            "planRawSha256": "2" * 64,
            "planRelativePath": f".reconcile/plans/{'3' * 64}.json",
            "planSha256": "3" * 64,
            "status": "blocked",
        },
        "observationOrder": ["ansible", "nix"],
        "observationsAtomic": False,
        "phase": phase,
        "version": 1,
    }


class ShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="proxmox-shadow-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary, ignore_errors=True)

    def test_tracked_policy_is_canonical_prebootstrap(self) -> None:
        self.assertEqual(shadow.load_policy(), "pre-bootstrap")
        self.assertEqual(shadow.POLICY.read_bytes(), shadow.canonical(json.loads(shadow.POLICY.read_bytes())))

    def test_prebootstrap_full_capture_has_no_transport(self) -> None:
        binaries = self.temporary / "bin"
        binaries.mkdir()
        marker = self.temporary / "transport"
        for command in ("ansible-playbook", "nix", "git", "ssh"):
            executable = binaries / command
            executable.write_text(f"#!/bin/sh\necho {command} >>'{marker}'\nexit 91\n")
            executable.chmod(0o700)
        result = subprocess.run(
            [sys.executable, MODULE_PATH, "capture", "--phase", "steady"],
            cwd=REPO, env={**os.environ, "PATH": str(binaries)}, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "shadow_state=pre-bootstrap status=disabled evidence_sha256=none evidence_path=none\n")
        self.assertFalse(marker.exists())

    def test_cli_is_closed(self) -> None:
        for arguments in (("capture",), ("capture", "--phase", "bad"),
                          ("capture", "--phase", "steady", "--repo-root", "/tmp"),
                          ("apply", "--phase", "steady")):
            result = subprocess.run([sys.executable, MODULE_PATH, *arguments], cwd=REPO, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_policy_rejects_unknown_malformed_and_noncanonical(self) -> None:
        original = shadow.POLICY
        shadow.POLICY = self.temporary / "policy.json"
        try:
            invalid = [b"not-json\n", b'{"format":"home-lab-proxmox-nix-shadow-policy-v1","state":"unknown"}\n',
                       b'{ "format":"home-lab-proxmox-nix-shadow-policy-v1", "state":"pre-bootstrap" }\n',
                       b'{"extra":true,"format":"home-lab-proxmox-nix-shadow-policy-v1","state":"pre-bootstrap"}\n']
            for raw in invalid:
                shadow.POLICY.write_bytes(raw)
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    shadow.load_policy()
        finally:
            shadow.POLICY = original

    def test_strict_ready_and_blocked_protocol(self) -> None:
        repo = self.temporary
        for status, code in (("ready", 0), ("blocked", 2)):
            sha = "a" * 64
            line = f"status={status} actions=0 blockers={int(status == 'blocked')} planSha256={sha} path={repo}/.reconcile/plans/{sha}.json\n"
            self.assertEqual(shadow.parse_plan_result(line.encode(), b"", code, repo)[0], sha)

    def test_protocol_rejects_stderr_error_and_malformed(self) -> None:
        repo = self.temporary
        sha = "a" * 64
        ready = f"status=ready actions=0 blockers=0 planSha256={sha} path={repo}/.reconcile/plans/{sha}.json\n".encode()
        for output, stderr, code in ((ready, b"warning", 0), (ready, b"", 2), (b"garbage\n", b"", 0),
                                     (ready + b"extra\n", b"", 0)):
            with self.assertRaises(ValueError):
                shadow.parse_plan_result(output, stderr, code, repo)

    def test_ansible_runs_fixed_command_twice_and_summarizes(self) -> None:
        text = ("PLAY [host] ********************************************************\n"
                "TASK [one] ********************************************************\n"
                "TASK [two] ********************************************************\n"
                "TASK [three] ******************************************************\n"
                "TASK [four] *******************************************************\n"
                "RUNNING HANDLER [handler] *****************************************\n"
                "proxmox : ok=3 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0\n").encode()
        calls = []
        def fake(command, cwd, timeout):
            calls.append((command, cwd, timeout))
            return 0, text, b""
        with mock.patch.object(shadow, "run_bounded", side_effect=fake):
            summaries = shadow.run_ansible(REPO)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], ("ansible-playbook", "-i", "inventory/infrastructure.yml",
                                     "playbooks/proxmox-site.yml", "--check", "--diff", "-e",
                                     "proxmox_ssh_access_proven=true"))
        self.assertEqual(summaries, [summary(), summary()])

    def test_ansible_rejects_failed_unreachable_nonzero_and_nonreproducible(self) -> None:
        base = "proxmox : ok=1 changed=0 unreachable={u} failed={f} skipped=0 rescued=0 ignored=0\n"
        for responses in (
            [(0, base.format(u=0, f=1).encode(), b"")],
            [(0, base.format(u=1, f=0).encode(), b"")],
            [(3, base.format(u=0, f=0).encode(), b"")],
            [(0, ("TASK [one]\n" + base.format(u=0, f=0)).encode(), b""),
             (0, ("TASK [two]\n" + base.format(u=0, f=0)).encode(), b"")],
        ):
            expanded = responses if len(responses) == 2 else responses * 2
            with mock.patch.object(shadow, "run_bounded", side_effect=expanded):
                with self.assertRaises(ValueError):
                    shadow.run_ansible(REPO)

    def test_anonymous_capture_leaves_no_path_after_sigkill(self) -> None:
        capture_root = self.temporary / "capture"
        capture_root.mkdir()
        code = (
            "import importlib.util,pathlib;"
            f"p=pathlib.Path({str(MODULE_PATH)!r});s=importlib.util.spec_from_file_location('s',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.run_bounded(('python3','-c','import time;time.sleep(30)'),pathlib.Path('.'),60)"
        )
        process = subprocess.Popen([sys.executable, "-c", code], cwd=REPO,
                                   env={**os.environ, "TMPDIR": str(capture_root)})
        time.sleep(0.5)
        os.kill(process.pid, signal.SIGKILL)
        process.wait()
        self.assertEqual(list(capture_root.iterdir()), [])

    def test_fixed_nix_transport_is_plan_only(self) -> None:
        sha = "a" * 64
        output = f"status=blocked actions=0 blockers=1 planSha256={sha} path={REPO}/.reconcile/plans/{sha}.json\n".encode()
        calls = []
        def fake(command, cwd, timeout):
            calls.append(command)
            return 2, output, b""
        with mock.patch.object(shadow, "run_bounded", side_effect=fake), \
                mock.patch.object(shadow, "validate_plan", return_value=({}, b"", object())):
            shadow.run_nix(REPO)
        self.assertEqual(calls, [("nix", "run", "--no-update-lock-file", "--no-write-lock-file",
                                  "path:./nix#proxmox-host", "--", "plan", "--repo-root", str(REPO))])
        self.assertNotIn("prepare", " ".join(calls[0]))
        self.assertNotIn("apply", " ".join(calls[0]))

    def test_secure_files_reject_mode_symlink_hardlink_and_noncanonical(self) -> None:
        root = self.temporary / ".reconcile"
        root.mkdir(mode=0o700)
        path = root / "item.json"
        path.write_bytes(shadow.canonical({"ok": True}))
        path.chmod(0o600)
        self.assertTrue(shadow.secure_read(path, root, "item"))
        path.chmod(0o644)
        with self.assertRaises(ValueError): shadow.secure_read(path, root, "item")
        path.chmod(0o600)
        hardlink = self.temporary / "hardlink"
        os.link(path, hardlink)
        with self.assertRaises(ValueError): shadow.secure_read(path, root, "item")
        hardlink.unlink()
        path.unlink()
        target = self.temporary / "target"
        target.write_text("x")
        path.symlink_to(target)
        with self.assertRaises(ValueError): shadow.secure_read(path, root, "item")

    def test_manifest_requires_canonical_v3_fixed_identity(self) -> None:
        root = self.temporary / ".reconcile"
        commit = "a" * 40
        path = root / "plans" / commit / "steady"
        path.mkdir(parents=True, mode=0o700)
        for parent in (root, root / "plans", root / "plans" / commit): parent.chmod(0o700)
        manifest = path / "manifest.json"
        value = {"commit": commit, "phase": "steady", "version": 3}
        manifest.write_bytes(shadow.canonical(value)); manifest.chmod(0o600)
        loaded, raw, relative = shadow.load_controller_manifest(self.temporary, commit, "steady")
        self.assertEqual(loaded, value); self.assertEqual(relative, f".reconcile/plans/{commit}/steady/manifest.json")
        manifest.write_bytes(json.dumps(value, indent=2).encode()); manifest.chmod(0o600)
        with self.assertRaises(ValueError): shadow.load_controller_manifest(self.temporary, commit, "steady")

    def test_atomic_evidence_identity_conflict_mode_link_and_symlink(self) -> None:
        root = self.temporary / ".reconcile"
        root.mkdir(mode=0o700)
        commit, sha = "a" * 40, "b" * 64
        content = shadow.canonical(evidence())
        evidence_sha, relative = shadow.write_evidence(self.temporary, commit, "steady", sha, content)
        destination = self.temporary / relative
        self.assertEqual(evidence_sha, shadow.digest(content)); self.assertEqual(destination.read_bytes(), content)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(shadow.write_evidence(self.temporary, commit, "steady", sha, content)[0], evidence_sha)
        destination.write_text("conflict"); destination.chmod(0o600)
        with self.assertRaises(ValueError): shadow.write_evidence(self.temporary, commit, "steady", sha, content)
        destination.write_bytes(content); destination.chmod(0o644)
        with self.assertRaises(ValueError): shadow.write_evidence(self.temporary, commit, "steady", sha, content)
        destination.chmod(0o600)
        hardlink = self.temporary / "evidence-hardlink"; os.link(destination, hardlink)
        with self.assertRaises(ValueError): shadow.write_evidence(self.temporary, commit, "steady", sha, content)
        hardlink.unlink(); destination.unlink()
        target = self.temporary / "evidence-target"; target.write_bytes(content); target.chmod(0o600)
        destination.symlink_to(target)
        with self.assertRaises((OSError, ValueError)): shadow.write_evidence(self.temporary, commit, "steady", sha, content)

    def test_evidence_schema_closed_and_forbidden_scan(self) -> None:
        schema = REPO / "infrastructure/policy/proxmox-nix-shadow-evidence.schema.json"
        fixture = self.temporary / "evidence.json"
        fixture.write_bytes(shadow.canonical(evidence()))
        validator = """
const fs=require('fs'); const Ajv=require('ajv/dist/2020');
const schema=JSON.parse(fs.readFileSync(process.argv[1])); const value=JSON.parse(fs.readFileSync(process.argv[2]));
const validate=new Ajv({strict:true,allErrors:true}).compile(schema); if(!validate(value)){console.error(validate.errors);process.exit(1)}
value.extra=true; if(validate(value)) process.exit(2);
"""
        result = subprocess.run(["node", "-e", validator, schema, fixture], cwd=REPO, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        scan = subprocess.run(["node", "scripts/controller/test-proxmox-nix-projection.js", "--scan-path", fixture],
                              cwd=REPO, text=True, capture_output=True)
        self.assertEqual(scan.returncode, 0, scan.stderr)
        serialized = fixture.read_text().lower()
        for forbidden in ("authorized_keys", "/dev/disk", "/dev/serial", "pool_guid", "secret_ref", "hardware"):
            self.assertNotIn(forbidden, serialized)

    def test_plan_noncanonical_and_semantic_validation_tamper_is_rejected(self) -> None:
        repo = self.temporary
        plans = repo / ".reconcile/plans"
        plans.mkdir(parents=True, mode=0o700); (repo / ".reconcile").chmod(0o700)
        source = repo / "nix/proxmox"; source.mkdir(parents=True)
        shutil.copy2(REPO / "nix/proxmox/projection.json", source / "projection.json")
        shutil.copy2(REPO / "nix/proxmox/package-manifest.json", source / "package-manifest.json")
        sha = "a" * 64
        plan = {"actions": [], "applyEligible": False, "bindings": {}, "blockers": [], "findings": [],
                "mode": "steady", "planSha256": sha, "status": "blocked"}
        path = plans / f"{sha}.json"
        planner = mock.Mock(); planner.canonical_json = shadow.canonical
        with mock.patch.object(shadow, "load_planner", return_value=planner), \
                mock.patch.object(shadow, "validate_schema"), \
                mock.patch.object(shadow, "fixed_bindings", return_value={}):
            path.write_bytes(json.dumps(plan, indent=2).encode()); path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "canonical"):
                shadow.validate_plan(repo, sha, "blocked:0:0")
            path.write_bytes(shadow.canonical(plan)); path.chmod(0o600)
            planner.validate_plan.side_effect = ValueError("plan hash binding is invalid")
            with self.assertRaisesRegex(ValueError, "plan hash"):
                shadow.validate_plan(repo, sha, "blocked:0:0")

    def test_bundle_and_git_binding_tamper_is_rejected(self) -> None:
        expected = bindings()
        shadow.require_exact_bindings(expected, dict(expected))
        for key, value in (("bundleContentSha256", "0" * 64), ("gitCommit", "0" * 40),
                           ("projectionSha256", "0" * 64), ("privatePreparerSha256", "0" * 64)):
            tampered = dict(expected)
            tampered[key] = value
            with self.assertRaises(ValueError):
                shadow.require_exact_bindings(tampered, expected)

    def test_plan_validation_rejects_sidecar_before_acceptance(self) -> None:
        repo = self.temporary
        plans = repo / ".reconcile/plans"
        plans.mkdir(parents=True, mode=0o700); (repo / ".reconcile").chmod(0o700)
        source = repo / "nix/proxmox"
        source.mkdir(parents=True)
        shutil.copy2(REPO / "nix/proxmox/projection.json", source / "projection.json")
        shutil.copy2(REPO / "nix/proxmox/package-manifest.json", source / "package-manifest.json")
        sha = "a" * 64
        plan_path = plans / f"{sha}.json"
        plan = {"actions": [], "applyEligible": False, "bindings": {}, "blockers": [], "findings": [],
                "mode": "steady", "planSha256": sha, "status": "blocked"}
        plan_path.write_bytes(shadow.canonical(plan)); plan_path.chmod(0o600)
        sidecar = plans / f"{sha}.private.json"; sidecar.write_text("{}"); sidecar.chmod(0o600)
        planner = mock.Mock()
        planner.canonical_json = shadow.canonical
        planner.validate_plan.return_value = None
        with mock.patch.object(shadow, "load_planner", return_value=planner), \
                mock.patch.object(shadow, "validate_schema"), \
                mock.patch.object(shadow, "fixed_bindings", return_value={}):
            with self.assertRaises(ValueError): shadow.validate_plan(repo, sha, "blocked:0:0")

    def test_local_controller_routes_only_plan_and_baseline_apply_is_unchanged(self) -> None:
        current = (REPO / "scripts/local-controller").read_text()
        baseline = subprocess.run(["git", "show", f"{BASELINE}:scripts/local-controller"], cwd=REPO,
                                  check=True, text=True, capture_output=True).stdout
        def branch(text: str, name: str) -> str:
            start = text.index(f"  {name})")
            end = text.index("    ;;", start) + len("    ;;\n")
            return text[start:end]
        self.assertEqual(branch(current, "apply"), branch(baseline, "apply"))
        self.assertIn('proxmox-nix-shadow.py capture --phase "$operation"', branch(current, "plan"))
        self.assertNotIn("proxmox-nix-shadow.py", branch(current, "apply"))
        self.assertIn("{version: 3", (REPO / "scripts/reconcile-infrastructure").read_text())

    def test_reconciler_nonvalidation_suffix_matches_baseline(self) -> None:
        current = (REPO / "scripts/reconcile-infrastructure").read_text()
        baseline = subprocess.run(["git", "show", f"{BASELINE}:scripts/reconcile-infrastructure"], cwd=REPO,
                                  check=True, text=True, capture_output=True).stdout
        marker = "for command in tofu node python3 jq git ansible ansible-playbook curl cmp; do"
        self.assertEqual(current[current.index(marker):], baseline[baseline.index(marker):])


if __name__ == "__main__":
    unittest.main()
