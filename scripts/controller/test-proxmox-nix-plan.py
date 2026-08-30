#!/usr/bin/env python3
"""Security and determinism tests for the plan-only Proxmox controller."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
PLANNER = NIX / "proxmox/planner.py"
spec = importlib.util.spec_from_file_location("proxmox_planner", PLANNER)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load planner")
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
BUNDLE = NIX / "proxmox/bundle.py"
bundle_spec = importlib.util.spec_from_file_location("proxmox_bundle_for_plan_tests", BUNDLE)
if bundle_spec is None or bundle_spec.loader is None:
    raise RuntimeError("unable to load bundle builder")
bundle = importlib.util.module_from_spec(bundle_spec)
bundle_spec.loader.exec_module(bundle)


class ProxmoxNixPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.projection = json.loads((NIX / "proxmox/projection.json").read_bytes())
        cls.manifest = json.loads((NIX / "proxmox/package-manifest.json").read_bytes())
        cls.observation = json.loads((NIX / "proxmox/fixture-observation.json").read_bytes())
        cls.bindings = {
            "activationEnvelopeSchemaSha256": "7" * 64, "activatorSha256": "8" * 64,
            "bundleContentSha256": "1" * 64, "bundleFormat": planner.BUNDLE_FORMAT,
            "flakeLockSha256": "2" * 64, "gitCommit": "3" * 40, "gitTree": "4" * 40,
            "observerProtocol": 4, "observerSha256": cls.observation["observerSha256"],
            "packageManifestSha256": "6" * 64, "planSchemaSha256": "9" * 64,
            "privatePreconditionsSchemaSha256": "a" * 64, "privatePreparationRequestSchemaSha256": "b" * 64,
            "privatePreparerSha256": "c" * 64, "projectionSha256": "5" * 64,
        }

    def make_plan(self, observation=None, start="2026-08-11T00:00:00Z", end="2026-08-11T00:00:01Z"):
        return planner.build_plan(self.bindings, self.projection, self.manifest,
                                  observation or self.observation, start, end, True)

    def test_fixture_is_canonical_closed_blocked_evidence_and_never_eligible(self) -> None:
        raw = (NIX / "proxmox/fixture-observation.json").read_bytes()
        self.assertEqual(raw, planner.canonical_json(json.loads(raw)))
        plan = self.make_plan()
        self.assertEqual(plan["status"], "fixture")
        self.assertFalse(plan["applyEligible"])
        self.assertEqual(plan["privatePreconditionsRequired"], bool(plan["blockers"] or plan["actions"]))
        self.assertNotIn("contractSha256", plan["bindings"])
        planner.validate_plan(plan, self.projection, self.manifest)

    def test_same_inputs_are_byte_identical_and_every_binding_or_fact_changes_hash(self) -> None:
        first = self.make_plan()
        second = self.make_plan()
        self.assertEqual(planner.canonical_json(first), planner.canonical_json(second))
        for key in ("activationEnvelopeSchemaSha256", "activatorSha256", "bundleContentSha256", "flakeLockSha256", "gitCommit", "gitTree", "observerSha256", "packageManifestSha256", "planSchemaSha256", "privatePreconditionsSchemaSha256", "projectionSha256"):
            bindings = dict(self.bindings)
            bindings[key] = ("b" * len(bindings[key]))
            changed = planner.build_plan(bindings, self.projection, self.manifest, self.observation,
                                         "2026-08-11T00:00:00Z", "2026-08-11T00:00:01Z", True)
            self.assertNotEqual(first["planSha256"], changed["planSha256"], key)
        observation = copy.deepcopy(self.observation)
        observation["host"]["kernel"] = "different-safe-kernel"
        self.assertNotEqual(first["planSha256"], self.make_plan(observation)["planSha256"])

    def test_recursive_unknown_fields_and_protected_values_are_rejected(self) -> None:
        for mutation in (
            lambda value: value.update({"unknown": True}),
            lambda value: value["domains"]["services"]["records"][0].update({"unknown": True}),
            lambda value: value["host"].update({"hostname": "/etc/pve/nodes/name"}),
            lambda value: value["domains"]["managedFiles"]["records"][0].update({"command": "id"}),
        ):
            observation = copy.deepcopy(self.observation)
            mutation(observation)
            with self.assertRaises(ValueError):
                planner.validate_observation(observation)

    def test_observation_rejects_sensitive_literals_wrong_types_and_duplicates_before_planning(self) -> None:
        sensitive = ("HOME" + "LAB_PRIVATE_REF", "PROXMOX_" + "APPLY_SSH_PUBLIC_KEYS", "PROXMOX_" + "FIREWALL_SSH_PUBLIC_KEYS",
                     "TAIL" + "SCALE_AUTH_KEY", "12345678-1234-1234-1234-123456789abc", "a" * 64)
        for literal in sensitive:
            observation = copy.deepcopy(self.observation)
            observation["host"]["kernel"] = literal
            with self.assertRaisesRegex(ValueError, "sensitive"):
                planner.validate_observation(observation)
        mutations = (
            lambda value: value["domains"]["services"]["records"][0].update({"active": "true"}),
            lambda value: value["domains"]["auditAbsence"]["records"][0].update({"count": "0"}),
            lambda value: value["domains"]["services"]["records"].append(
                copy.deepcopy(value["domains"]["services"]["records"][0])),
            lambda value: value["domains"]["managedFiles"]["records"].append(
                copy.deepcopy(value["domains"]["managedFiles"]["records"][0])),
        )
        for mutate in mutations:
            observation = copy.deepcopy(self.observation)
            mutate(observation)
            with self.assertRaises(ValueError):
                planner.validate_observation(observation)

    def test_target_identity_mismatch_blocks_without_actions(self) -> None:
        for field, wrong in (("hostname", "not-proxmox"), ("architecture", "aarch64"),
                             ("os", "not-debian"), ("pveVersion", "pve-manager/0.0.0")):
            observation = copy.deepcopy(self.observation)
            observation["host"][field] = wrong
            observation["domains"]["managedFiles"]["records"][0]["contentMatches"] = False
            plan = self.make_plan(observation)
            self.assertEqual(plan["actions"], [])
            self.assertTrue(any(item["code"] == "wrong-target" for item in plan["blockers"]))

    def test_actions_are_typed_exact_ordered_and_observation_order_is_canonical(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["domains"]["managedFiles"]["records"][0]["contentMatches"] = False
        observation["domains"]["services"]["records"][0]["active"] = False
        first = self.make_plan(observation)
        reversed_observation = copy.deepcopy(observation)
        reversed_observation["domains"]["managedFiles"]["records"].reverse()
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.make_plan(reversed_observation)
        self.assertEqual([item["sequence"] for item in first["actions"]], list(range(1, len(first["actions"]) + 1)))
        for action in first["actions"]:
            self.assertIn(action["kind"], planner.ACTION_KINDS.values())
            self.assertEqual(action["preconditionSha256"], planner.digest({
                "before": action["before"], "domain": action["domain"],
                "target": action["target"].get("path", action["target"].get("name")),
            }))
            self.assertEqual(action["postconditions"], [{"expected": action["after"], "type": "state-equals"}])
            self.assertEqual(action["dependsOn"], [] if action["sequence"] == 1 else [first["actions"][action["sequence"] - 2]["id"]])
            self.assertFalse(set(action) & planner.FORBIDDEN_KEYS)

    def test_transferred_timezone_is_audited_but_never_planned_by_nix(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["domains"]["timezone"]["records"][0]["timezone"] = "Etc/UTC"
        plan = self.make_plan(observation)
        actions = [action for action in plan["actions"] if action["domain"] == "timezone"]
        self.assertEqual(actions, [])
        self.assertNotIn("timezone", planner.ACTION_KINDS)
        self.assertNotIn("timezone", planner.TARGET_TYPES)

        malformed = copy.deepcopy(self.observation)
        malformed["domains"]["timezone"]["records"][0]["timezone"] = "../UTC"
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.make_plan(malformed)
        unavailable = copy.deepcopy(self.observation)
        unavailable["domains"]["timezone"] = {"records": [], "status": "unavailable", "unexpectedCount": None}
        blocked = self.make_plan(unavailable)
        self.assertEqual([action for action in blocked["actions"] if action["domain"] == "timezone"], [])
        self.assertTrue(any(item["domain"] == "timezone" and item["code"] == "observation-unavailable" for item in blocked["blockers"]))

    def test_ready_chrony_and_critical_services_are_audit_only(self) -> None:
        expected = {
            "chrony.service": ("guarded", False, False),
            "nfs-server.service": ("data-critical", False, False),
            "ssh.service": ("access-critical", False, True),
            "tailscaled.service": ("access-critical", False, True),
        }
        policies = {item["name"]: item for item in self.projection["planningPolicy"]["servicePolicies"]}
        self.assertEqual(set(policies), set(expected))
        for name, flags in expected.items():
            self.assertEqual((policies[name]["safetyClass"], policies[name]["automatic"], policies[name]["requiresWatchdog"]), flags)
        for name in expected:
            observation = copy.deepcopy(self.observation)
            record = next(item for item in observation["domains"]["services"]["records"] if item["name"] == name)
            record["active"] = False
            plan = self.make_plan(observation)
            service_actions = [action for action in plan["actions"] if action["domain"] == "services"]
            self.assertEqual(service_actions, [])
            self.assertTrue(any(blocker["domain"] == "services" and blocker["target"] == name for blocker in plan["blockers"]))

    def test_audit_and_opentofu_drift_are_findings_and_blockers_never_actions(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["domains"]["auditAbsence"]["records"][0]["count"] = 1
        observation["domains"]["vm"] = {"expectedCount": 1, "matches": False, "observedCount": 1, "status": "complete"}
        plan = self.make_plan(observation)
        self.assertTrue(any(item["kind"] == "audit" for item in plan["findings"]))
        self.assertTrue(any(item["kind"] == "opentofu" for item in plan["findings"]))
        self.assertFalse(any(item["domain"] in {"audit-absence", "opentofu"} for item in plan["actions"]))
        self.assertFalse(any(action["target"].get("path", "").startswith("/etc/pve") for action in plan["actions"]))

    def test_validate_plan_rejects_rehashed_action_mutations(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["domains"]["managedFiles"]["records"][0]["contentMatches"] = False
        original = self.make_plan(observation)
        self.assertTrue(original["actions"])
        mutations = (
            lambda action: action.update({"kind": "reconcile-service"}),
            lambda action: action.update({"approvalRequired": not action["approvalRequired"]}),
            lambda action: action.update({"id": "a" * 64}),
            lambda action: action.update({"preconditionSha256": "b" * 64}),
            lambda action: action.update({"before": {"state": "absent"}}),
            lambda action: action.update({"postconditions": [{"expected": {"state": "absent"}, "type": "state-equals"}]}),
            lambda action: action.update({"dependsOn": ["c" * 64]}),
        )
        for mutate in mutations:
            plan = copy.deepcopy(original)
            mutate(plan["actions"][0])
            plan["planSha256"] = planner.digest({key: value for key, value in plan.items() if key != "planSha256"})
            with self.assertRaises(ValueError):
                planner.validate_plan(plan, self.projection, self.manifest)

    def test_validate_plan_derives_status_and_rejects_nonautomatic_policy_actions(self) -> None:
        original = self.make_plan()
        for status, eligible in (("ready", True), ("blocked", False)):
            plan = copy.deepcopy(original)
            plan["status"] = status
            plan["applyEligible"] = eligible
            plan["planSha256"] = planner.digest({key: value for key, value in plan.items() if key != "planSha256"})
            with self.assertRaisesRegex(ValueError, "status"):
                planner.validate_plan(plan, self.projection, self.manifest)
        observation = copy.deepcopy(self.observation)
        package = observation["domains"]["packages"]["records"][0]
        package["version"] = "wrong-version"
        policy_projection = copy.deepcopy(self.projection)
        package_policy = next(item for item in policy_projection["planningPolicy"]["domains"] if item["domain"] == "packages")
        package_policy["automatic"] = True
        action_plan = planner.build_plan(self.bindings, policy_projection, self.manifest, observation,
                                         "2026-08-11T00:00:00Z", "2026-08-11T00:00:01Z", True)
        self.assertFalse(any(action["domain"] == "packages" for action in action_plan["actions"]))
        package_blockers = [item for item in action_plan["blockers"] if item["domain"] == "packages"]
        self.assertEqual(len(package_blockers), 1)
        self.assertEqual(package_blockers[0]["code"], "sealed-package-session-required")

    def test_realistic_dpkg_parser_handles_rc_all_held_and_multiarch(self) -> None:
        rendered = bundle.expected_helper_content("proxmox-observer", self.projection)
        namespace = {"__name__": "observer_parser_test", "__file__": "/tmp/fixed-observer"}
        exec(compile(rendered, "fixed-observer", "exec"), namespace)
        raw = (b"ii \tbase-files\tamd64\t13.8+deb13u2\n"
               b"rc \tremoved-package\tamd64\t1.0\n"
               b"hi \theld-package\tall\t2:3.0-1\n"
               b"ii \tlibexample:arm64\tarm64\t4.2\n")
        self.assertEqual(namespace["parse_dpkg_query"](raw), [
            {"name": "base-files", "version": "13.8+deb13u2"},
            {"name": "held-package", "version": "2:3.0-1"},
            {"name": "libexample:arm64", "version": "4.2"},
        ])
        self.assertIsNone(namespace["parse_dpkg_query"](b"bad\trecord\n"))

    def test_realistic_pve_firewall_and_storage_normalizers(self) -> None:
        rendered = bundle.expected_helper_content("proxmox-observer", self.projection)
        namespace = {"__name__": "observer_normalizer_test", "__file__": "/tmp/fixed-observer"}
        exec(compile(rendered, "fixed-observer", "exec"), namespace)
        self.assertEqual(namespace["SPEC"]["expectedIdentity"], {
            "architecture": "amd64", "hostname": "proxmox", "os": "debian", "pveVersion": "pve-manager/9.2.11",
        })
        self.assertEqual(namespace["SPEC"]["tailscale"]["hostname"], "proxmox")
        self.assertEqual(namespace["SPEC"]["tailscale"]["advertiseTags"], ["tag:proxmox"])
        actual_rule = {"type": "in", "action": "ACCEPT", "source": "192.168.0.0/24",
                       "proto": "tcp", "dport": "22", "log": "nolog", "pos": 0}
        normalized_rule = namespace["normalized_firewall_rule"](actual_rule)
        self.assertEqual(normalized_rule, {
            "action": "ACCEPT", "destination": None, "destination_port": 22, "direction": "IN",
            "enabled": True, "interface": None, "log": "nolog", "protocol": "tcp",
            "source": "192.168.0.0/24", "source_port": None,
        })
        disabled_rule = dict(actual_rule, enable=0)
        self.assertNotEqual(namespace["normalized_firewall_rule"](disabled_rule), normalized_rule)
        constrained_rule = dict(actual_rule, dest="10.0.0.1", sport="1024", iface="vmbr0")
        self.assertNotEqual(namespace["normalized_firewall_rule"](constrained_rule), normalized_rule)
        expected_storage = self.projection["apiIntent"]["pveStorage"]
        actual_storage = {"type": expected_storage["type"], "pool": expected_storage["pool"],
                          "mountpoint": expected_storage["mountpoint"],
                          "content": ",".join(reversed(expected_storage["content"])),
                          "nodes": ",".join(expected_storage["nodes"])}
        self.assertEqual(namespace["normalized_storage"](actual_storage),
                         namespace["normalized_storage"](expected_storage))
        self.assertNotEqual(namespace["normalized_storage"](dict(actual_storage, disable=1)),
                            namespace["normalized_storage"](expected_storage))
        expected_export = b"/storage/docker 192.168.0.100/32(rw,sync,no_subtree_check,no_root_squash)\n"
        self.assertEqual(namespace["parse_nfs_exports"](expected_export), [{
            "client": "192.168.0.100/32", "export": "/storage/docker",
            "options": ["no_root_squash", "no_subtree_check", "rw", "sync"],
        }])
        cross_line = (b"/storage/docker wrong-client(rw,sync)\n"
                      b"/wrong 192.168.0.100/32(no_subtree_check,no_root_squash)\n")
        self.assertNotEqual(namespace["parse_nfs_exports"](cross_line), namespace["parse_nfs_exports"](expected_export))
        self.assertEqual(namespace["normalized_privileges"]("VM.Audit,Sys.Audit"), ["Sys.Audit", "VM.Audit"])
        self.assertEqual(namespace["normalized_privileges"](["VM.Audit", "Sys.Audit"]), ["Sys.Audit", "VM.Audit"])
        self.assertIsNone(namespace["normalized_privileges"](["VM.Audit", "VM.Audit"]))

    def test_freshness_boundary_and_expiry(self) -> None:
        boundary = self.make_plan(end="2026-08-11T00:30:00Z")
        with self.assertRaisesRegex(ValueError, "expired"):
            self.make_plan(end="2026-08-11T00:30:01Z")
        with self.assertRaises(ValueError):
            self.make_plan(start="2026-08-11T00:00:01Z", end="2026-08-11T00:00:00Z")
        expired = copy.deepcopy(boundary)
        expired["freshness"]["completedAt"] = "2026-08-11T00:30:01Z"
        expired["planSha256"] = planner.digest({key: value for key, value in expired.items() if key != "planSha256"})
        with self.assertRaisesRegex(ValueError, "freshness"):
            planner.validate_plan(expired, self.projection, self.manifest)

    def test_atomic_output_modes_symlink_and_overwrite_refusal(self) -> None:
        plan = self.make_plan()
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "plans"
            destination = planner.secure_output(plan, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(destination.read_bytes(), planner.canonical_json(plan))
            with self.assertRaisesRegex(ValueError, "overwrite"):
                planner.secure_output(plan, output)
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "target"
            target.mkdir()
            link = Path(name) / "plans"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                planner.secure_output(plan, link)
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name) / "repo"
            repo.mkdir()
            destination = planner.secure_live_output(plan, repo)
            self.assertEqual(destination.read_bytes(), planner.canonical_json(plan))
            self.assertEqual(stat.S_IMODE((repo / ".reconcile").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((repo / ".reconcile/plans").stat().st_mode), 0o700)
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name) / "repo"
            repo.mkdir()
            ignored_target = Path(name) / "ignored-target"
            ignored_target.mkdir(mode=0o700)
            (repo / ".reconcile").symlink_to(ignored_target, target_is_directory=True)
            with self.assertRaises(OSError):
                planner.secure_live_output_directory(repo)

    def test_git_requires_clean_origin_main_without_fetching(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            subprocess.run(("git", "init", "-q", "-b", "main", root), check=True)
            subprocess.run(("git", "-C", root, "config", "user.email", "test@example.invalid"), check=True)
            subprocess.run(("git", "-C", root, "config", "user.name", "Test"), check=True)
            (root / "file").write_text("x", encoding="utf-8")
            subprocess.run(("git", "-C", root, "add", "file"), check=True)
            subprocess.run(("git", "-C", root, "commit", "-qm", "test"), check=True)
            subprocess.run(("git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"), check=True)
            planner.git_bindings(root)
            (root / "dirty").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "clean"):
                planner.git_bindings(root)

    def test_transport_failure_and_helper_mismatch_fail_before_plan_output(self) -> None:
        failed = subprocess.CompletedProcess(planner.SSH_COMMAND, 255, b"", b"redacted transport error")
        with patch.object(planner.subprocess, "run", return_value=failed), self.assertRaisesRegex(ValueError, "bootstrap-required"):
            planner.live_observation(self.bindings["observerSha256"])
        mismatched = copy.deepcopy(self.observation)
        mismatched["observerSha256"] = "b" * 64
        completed = subprocess.CompletedProcess(planner.SSH_COMMAND, 0, planner.canonical_json(mismatched), b"")
        with patch.object(planner.subprocess, "run", return_value=completed), self.assertRaisesRegex(ValueError, "differs"):
            planner.live_observation(self.bindings["observerSha256"])

    def test_cli_surface_and_transport_are_fully_fixed(self) -> None:
        self.assertEqual(planner.SSH_COMMAND[-2:], (
            "tofu-plan@192.168.0.123", "sudo -n -- /usr/local/libexec/home-lab/proxmox-observer observe"))
        self.assertEqual(planner.SSH_COMMAND[1:3], ("-F", "/dev/null"))
        self.assertIn(str(Path.home() / ".ssh/home-lab-proxmox-plan"), planner.SSH_COMMAND)
        for option in ("IdentitiesOnly=yes", "BatchMode=yes",
                       "ClearAllForwardings=yes", "PermitLocalCommand=no", "RequestTTY=no",
                       "StrictHostKeyChecking=yes", "UpdateHostKeys=no"):
            self.assertIn(option, planner.SSH_COMMAND)
        self.assertFalse(any(value.startswith("ProxyCommand=") for value in planner.SSH_COMMAND))
        with self.assertRaisesRegex(ValueError, "capability"):
            planner.fixed_ssh_command("admin", "id")
        source = (NIX / "flake.nix").read_text(encoding="utf-8")
        self.assertIn("proxmox-host =", source)
        self.assertIn("++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.netcat-openbsd ];", source)
        self.assertNotIn("runtimeInputs = [ pkgs.git pkgs.netcat-openbsd", source)
        self.assertNotIn("proxmox-bootstrap =", source)
        self.assertNotIn("proxmox-host-apply", source)
        with self.assertRaises(SystemExit) as rejected:
            old = list(__import__("sys").argv)
            try:
                __import__("sys").argv = ["proxmox-host", "--bundle", "x", "plan", "--repo-root", str(ROOT)]
                planner.parse_args()
            finally:
                __import__("sys").argv = old
        self.assertEqual(rejected.exception.code, 64)

    def test_schemas_and_sanitized_sources_are_closed_secret_free_and_bound(self) -> None:
        for name in ("observation.schema.json", "plan.schema.json"):
            schema = json.loads((NIX / "proxmox" / name).read_bytes())
            self.assertFalse(schema["additionalProperties"])
        forbidden = (("PROXMOX_" + "PLAN_SSH_PUBLIC_KEYS").encode(), ("PROXMOX_" + "FIREWALL_SSH_PUBLIC_KEYS").encode(), ("TAIL" + "SCALE_AUTH_KEY").encode())
        for path in NIX.rglob("*"):
            if path.is_file() and "package-manifest" not in path.name and "__pycache__" not in path.parts:
                content = path.read_bytes()
                for token in forbidden:
                    self.assertNotIn(token, content, f"{token!r} in {path}")
        plan = self.make_plan()
        with tempfile.TemporaryDirectory() as name:
            plan_path = Path(name) / "plan.json"
            plan_path.write_bytes(planner.canonical_json(plan))
            validation = subprocess.run(("node", "-e", """
const fs=require('node:fs'); const Ajv=require('ajv/dist/2020');
for (const [schemaPath,valuePath] of [[process.argv[1],process.argv[2]],[process.argv[3],process.argv[4]]]) {
  const validate=new Ajv({strict:true,allErrors:true}).compile(JSON.parse(fs.readFileSync(schemaPath)));
  if (!validate(JSON.parse(fs.readFileSync(valuePath)))) throw new Error(JSON.stringify(validate.errors));
}
""", str(NIX / "proxmox/observation.schema.json"), str(NIX / "proxmox/fixture-observation.json"),
                str(NIX / "proxmox/plan.schema.json"), str(plan_path)), capture_output=True, text=True)
            self.assertEqual(validation.returncode, 0, validation.stderr)


if __name__ == "__main__":
    unittest.main()
