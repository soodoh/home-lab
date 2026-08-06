#!/usr/bin/env python3
"""Focused lifecycle, real-root rendering, and plan-policy tests."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("tailscale-gateway-policy.py")
INSPECTOR = REPOSITORY / "infrastructure/policy/inspect-plan.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gateway = load(HELPER, "tailscale_gateway_policy")
inspector = load(INSPECTOR, "tailscale_policy_inspector")


def contract(path: Path, gateway_stage: str, ct_stage: str) -> None:
    path.write_text(
        "proxmox:\n  legacy_container:\n    retirement_stage: " + ct_stage
        + "\ntailscale:\n  gateway_policy_stage: " + gateway_stage + "\n"
    )


def plan(before: dict, after: dict, extra_changes: list[dict] | None = None) -> dict:
    changes = [{
        "address": "terraform_data.tailscale_policy[0]",
        "type": "terraform_data",
        "mode": "managed",
        "change": {
            "actions": ["update"],
            "before": {"input": {"policy_json": json.dumps(before, separators=(",", ":"))}},
            "after": {"input": {"policy_json": json.dumps(after, separators=(",", ":"))}},
        },
    }]
    changes.extend(extra_changes or [])
    return {"resource_changes": changes}


class GatewayLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policies = cls.render_real_root_policies()

    @staticmethod
    def render_real_root_policies() -> dict[str, dict]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "infrastructure/tofu/tailscale"
            root.mkdir(parents=True)
            shutil.copy(REPOSITORY / "infrastructure/tofu/tailscale/main.tf", root / "main.tf")
            versions = (REPOSITORY / "infrastructure/tofu/tailscale/versions.tf").read_text()
            versions = re.sub(r'\n  backend "s3" \{.*?\n  \}\n', "\n", versions, flags=re.DOTALL)
            (root / "versions.tf").write_text(versions)
            contract_dir = Path(directory) / "infrastructure/contract"
            contract_dir.mkdir(parents=True)
            shutil.copy(REPOSITORY / "infrastructure/contract/home-lab.yml", contract_dir / "home-lab.yml")
            subprocess.run(["tofu", f"-chdir={root}", "init", "-backend=false", "-input=false"], check=True, capture_output=True, text=True)
            rendered: dict[str, dict] = {}
            for stage in ("active", "detached", "retired"):
                expression = f"jsonencode(local.{stage}_policy)\n"
                result = subprocess.run(["tofu", f"-chdir={root}", "console"], input=expression, check=True, capture_output=True, text=True)
                rendered[stage] = json.loads(json.loads(result.stdout.strip()))
            return rendered

    def pre_access_policy(self) -> dict:
        policy = deepcopy(self.policies["detached"])
        owner_rule = {
            "action": "accept",
            "src": ["autogroup:owner", "autogroup:admin"],
            "dst": ["tag:proxmox"],
            "users": ["root", "tofu-plan", "tofu-apply"],
        }
        arch_rule = {
            "action": "accept",
            "src": ["tag:docker-host"],
            "dst": ["tag:proxmox"],
            "users": ["root"],
        }
        owner_index = policy["ssh"].index(owner_rule)
        self.assertEqual(policy["ssh"][owner_index + 1], arch_rule)
        policy["ssh"][owner_index:owner_index + 2] = [{
            "action": "accept",
            "src": ["autogroup:owner", "autogroup:admin", "tag:docker-host"],
            "dst": ["tag:proxmox"],
            "users": ["root"],
        }]
        policy["sshTests"] = policy["sshTests"][1:]
        return policy

    def legacy_detached_policy(self) -> dict:
        policy = self.pre_access_policy()
        policy["tagOwners"].update({
            "tag:ci-plan": ["autogroup:admin"],
            "tag:ci-apply": ["autogroup:admin"],
        })
        policy["grants"][1]["src"].extend(["tag:ci-plan", "tag:ci-apply"])
        policy["grants"].extend([
            {"src": ["tag:ci-plan"], "dst": ["tag:proxmox"], "ip": ["tcp:22", "tcp:8006"]},
            {"src": ["tag:ci-apply"], "dst": ["tag:proxmox"], "ip": ["tcp:22", "tcp:8006"]},
            {"src": ["tag:ci-plan", "tag:ci-apply"], "dst": ["tag:docker-host"], "ip": ["tcp:8043"]},
        ])
        policy["ssh"][1]["src"] = ["autogroup:admin"]
        policy["ssh"][2:2] = [
            {"action": "accept", "src": ["tag:ci-plan"], "dst": ["tag:docker-host"], "users": ["ansible-plan"]},
            {"action": "accept", "src": ["tag:ci-apply"], "dst": ["tag:docker-host"], "users": ["ansible-plan", "ansible-deploy"]},
        ]
        policy["tests"][0:0] = [
            {"src": "tag:ci-plan", "proto": "tcp", "accept": ["tag:docker-host:22", "tag:docker-host:8043", "tag:proxmox:22", "tag:proxmox:8006"], "deny": ["tag:proxmox:8007"]},
            {"src": "tag:ci-apply", "proto": "tcp", "accept": ["tag:docker-host:22", "tag:docker-host:8043", "tag:proxmox:22", "tag:proxmox:8006"], "deny": ["tag:proxmox:8007"]},
        ]
        policy["sshTests"][0:0] = [
            {"src": "tag:ci-plan", "dst": ["tag:proxmox"], "accept": ["tofu-plan"], "deny": ["root", "tofu-apply"]},
            {"src": "tag:ci-apply", "dst": ["tag:proxmox"], "accept": ["tofu-apply"], "deny": ["root", "tofu-plan"]},
        ]
        return policy

    @staticmethod
    def identity_deletions() -> list[dict]:
        descriptions = {
            "tailscale_federated_identity.ci_plan[0]": "infrastructure-plan",
            "tailscale_federated_identity.ci_apply[0]": "infrastructure-apply",
            "tailscale_federated_identity.provider_plan[0]": "home-lab GitHub OpenTofu Tailscale plan provider",
            "tailscale_federated_identity.provider_apply[0]": "home-lab GitHub OpenTofu Tailscale apply provider",
        }
        return [
            {
                "address": address,
                "type": "tailscale_federated_identity",
                "mode": "managed",
                "change": {
                    "actions": ["delete"],
                    "before": {
                        "description": description,
                        "issuer": "https://token.actions.githubusercontent.com",
                    },
                    "after": None,
                },
            }
            for address, description in descriptions.items()
        ]

    def test_real_root_exact_stages_and_unrelated_policy(self) -> None:
        active = self.policies["active"]
        detached = self.policies["detached"]
        retired = self.policies["retired"]
        self.assertEqual(detached, inspector.detached_gateway_policy(active))
        self.assertEqual(retired, inspector.retired_gateway_policy(detached))
        for tag in ("tag:ci", "tag:ci-plan", "tag:ci-apply"):
            self.assertFalse(inspector.contains_exact(detached, tag))
            self.assertFalse(inspector.contains_exact(retired, tag))
        self.assertNotIn("autoApprovers", detached)
        self.assertFalse(inspector.contains_exact(retired, "tag:infra-router"))

    def test_transition_and_cross_lifecycle_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.yml"
            head = Path(directory) / "head.yml"
            permitted = {
                ("active", "active", "protected", "protected"): "none",
                ("active", "detached", "protected", "protected"): "detach",
                ("detached", "active", "unprotected", "unprotected"): "none",
                ("detached", "retired", "retired", "retired"): "retire",
                ("retired", "retired", "retired", "retired"): "none",
            }
            for stages, operation in permitted.items():
                contract(base, stages[0], stages[2])
                contract(head, stages[1], stages[3])
                self.assertEqual(gateway.transition_operation(base, head), operation)
            rejected = (
                ("active", "retired", "retired", "retired"),
                ("retired", "detached", "retired", "retired"),
                ("detached", "active", "retired", "retired"),
                ("active", "detached", "protected", "unprotected"),
                ("detached", "active", "protected", "unprotected"),
                ("detached", "retired", "unprotected", "unprotected"),
            )
            for stages in rejected:
                contract(base, stages[0], stages[2])
                contract(head, stages[1], stages[3])
                with self.assertRaises(gateway.GatewayPolicyError):
                    gateway.transition_operation(base, head)

    def run_policy(self, before: dict, after: dict, mode: str, extra_changes: list[dict] | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as fixture:
            json.dump(plan(before, after, extra_changes), fixture)
            fixture.flush()
            return subprocess.run(["python3", str(INSPECTOR), fixture.name, "--mode", mode], check=False, capture_output=True, text=True)

    def test_exact_detach_and_retire_plans(self) -> None:
        self.assertEqual(self.run_policy(self.policies["active"], self.policies["detached"], "ct-gateway-detach").returncode, 0)
        self.assertEqual(self.run_policy(self.policies["detached"], self.policies["retired"], "ct-gateway-retire").returncode, 0)

    def test_exact_local_controller_retirement(self) -> None:
        legacy_detached = self.legacy_detached_policy()
        result = self.run_policy(
            legacy_detached,
            self.policies["detached"],
            "tailscale-controller-retirement",
            self.identity_deletions(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        missing_identity = self.identity_deletions()[:-1]
        self.assertNotEqual(
            self.run_policy(legacy_detached, self.policies["detached"], "tailscale-controller-retirement", missing_identity).returncode,
            0,
        )

    def test_exact_local_controller_access_repair(self) -> None:
        before = self.pre_access_policy()
        result = self.run_policy(before, self.policies["detached"], "tailscale-controller-access")
        self.assertEqual(result.returncode, 0, result.stderr)
        changed = deepcopy(self.policies["detached"])
        changed["sshTests"] = []
        self.assertNotEqual(self.run_policy(before, changed, "tailscale-controller-access").returncode, 0)

    def test_normal_rejects_required_lifecycle_mutation_but_allows_pre_retirement_rollback_shape(self) -> None:
        self.assertNotEqual(self.run_policy(self.policies["active"], self.policies["detached"], "normal").returncode, 0)
        self.assertEqual(self.run_policy(self.policies["detached"], self.policies["active"], "normal").returncode, 0)

    def test_noop_repeat_extra_identity_and_wrong_mode_are_rejected(self) -> None:
        active, detached, retired = (self.policies[name] for name in ("active", "detached", "retired"))
        for before, after, mode in (
            (detached, detached, "ct-gateway-detach"),
            (retired, retired, "ct-gateway-retire"),
            (active, detached, "ct-gateway-retire"),
        ):
            self.assertNotEqual(self.run_policy(before, after, mode).returncode, 0)

        identity_addresses = (
            "tailscale_federated_identity.ci_apply[0]",
            "tailscale_federated_identity.ci_plan[0]",
            "tailscale_federated_identity.provider_apply[0]",
            "tailscale_federated_identity.provider_plan[0]",
        )
        for address, field in zip(identity_addresses, ("tags", "subject", "scopes", "issuer"), strict=True):
            identity_change = {
                "address": address,
                "type": "tailscale_federated_identity",
                "mode": "managed",
                "change": {"actions": ["update"], "before": {field: ["before"]}, "after": {field: ["after"]}},
            }
            self.assertNotEqual(self.run_policy(active, detached, "ct-gateway-detach", [identity_change]).returncode, 0)
        root_change = {
            "address": "aws_s3_bucket.example",
            "type": "aws_s3_bucket",
            "mode": "managed",
            "change": {"actions": ["update"], "before": {"name": "before"}, "after": {"name": "after"}},
        }
        self.assertNotEqual(self.run_policy(active, detached, "ct-gateway-detach", [root_change]).returncode, 0)

    def test_unrelated_and_wrong_occurrence_mutations_are_rejected(self) -> None:
        active = self.policies["active"]
        detached = self.policies["detached"]
        mutations = []
        for field in ("tests", "sshTests"):
            changed = deepcopy(detached)
            changed[field] = []
            mutations.append(changed)
        for field, value in (("autoApprovers", {}), ("tagOwners", {})):
            changed = deepcopy(detached)
            changed[field] = value
            mutations.append(changed)
        changed = deepcopy(detached)
        changed["grants"][0]["src"] = ["autogroup:owner"]
        mutations.append(changed)
        changed = deepcopy(detached)
        changed["ssh"][0]["src"] = ["autogroup:admin"]
        mutations.append(changed)
        malformed_before = deepcopy(active)
        malformed_before["grants"][3]["src"].append("tag:ci")
        self.assertNotEqual(self.run_policy(malformed_before, detached, "ct-gateway-detach").returncode, 0)
        for changed in mutations:
            self.assertNotEqual(self.run_policy(active, changed, "ct-gateway-detach").returncode, 0)

    def test_legacy_base_defaults_active_but_head_requires_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.yml"
            head = Path(directory) / "head.yml"
            base.write_text("proxmox:\n  legacy_container:\n    retirement_stage: protected\ntailscale:\n  tags: {}\n")
            contract(head, "detached", "protected")
            self.assertEqual(gateway.transition_operation(base, head), "detach")
            with self.assertRaises(gateway.GatewayPolicyError):
                gateway.gateway_stage(base)

    def test_retire_requires_exact_temporary_device_absence_approval(self) -> None:
        for environment, expected in (({}, False), ({gateway.DEVICE_ABSENCE_APPROVAL_ENVIRONMENT: "false"}, False), ({gateway.DEVICE_ABSENCE_APPROVAL_ENVIRONMENT: "true"}, True)):
            with mock.patch.dict("os.environ", environment, clear=True):
                self.assertEqual(gateway.device_absence_approved("retire"), expected)
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(gateway.device_absence_approved("detach"))

    def test_retire_cli_fails_closed_without_device_absence_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "contract.yml"
            contract(target, "retired", "retired")
            command = ["python3", str(HELPER), "validate-operation", "--contract", str(target), "--operation", "retire"]
            denied = subprocess.run(command, check=False, capture_output=True, text=True, env={})
            self.assertNotEqual(denied.returncode, 0)
            approved = subprocess.run(command, check=False, capture_output=True, text=True, env={gateway.DEVICE_ABSENCE_APPROVAL_ENVIRONMENT: "true"})
            self.assertEqual(approved.returncode, 0)

    def test_saved_plan_before_and_after_are_canonicalized_identically(self) -> None:
        active = self.policies["active"]
        detached = self.policies["detached"]
        saved_plan = plan(active, detached)
        planned_before = gateway.policy_from_plan(saved_plan, "before")
        planned_after = gateway.policy_from_plan(saved_plan, "after")
        self.assertEqual(
            gateway.canonical_policy_sha256(planned_before),
            gateway.canonical_policy_sha256(active),
        )
        self.assertEqual(
            gateway.canonical_policy_sha256(planned_after),
            gateway.canonical_policy_sha256(detached),
        )

    def test_missing_or_noncanonical_saved_plan_before_is_rejected(self) -> None:
        active = self.policies["active"]
        detached = self.policies["detached"]
        missing_before = plan(active, detached)
        del missing_before["resource_changes"][0]["change"]["before"]["input"]["policy_json"]
        duplicate_key_before = plan(active, detached)
        duplicate_key_before["resource_changes"][0]["change"]["before"]["input"]["policy_json"] = '{"grants":[],"grants":[]}'
        duplicate_resource = plan(active, detached)
        duplicate_resource["resource_changes"].append(deepcopy(duplicate_resource["resource_changes"][0]))
        for saved_plan in (missing_before, duplicate_key_before, duplicate_resource):
            with self.assertRaises(gateway.GatewayPolicyError):
                gateway.policy_from_plan(saved_plan, "before")

    def test_unrelated_live_drift_cannot_authorize_saved_plan_before(self) -> None:
        planned_before = self.policies["active"]
        unrelated_live_drift = deepcopy(planned_before)
        unrelated_live_drift["tests"].append({
            "src": "autogroup:owner",
            "proto": "tcp",
            "accept": ["autogroup:self:443"],
        })
        planned_sha = gateway.canonical_policy_sha256(planned_before)
        live_sha = gateway.canonical_policy_sha256(unrelated_live_drift)
        self.assertNotEqual(planned_sha, live_sha)
        with self.assertRaises(gateway.GatewayPolicyError):
            gateway.validate_before_identity(planned_sha, live_sha)
        gateway.validate_before_identity(planned_sha, planned_sha)

        planned_after_sha = gateway.canonical_policy_sha256(self.policies["detached"])
        with self.assertRaises(gateway.GatewayPolicyError):
            gateway.apply_disposition(
                live_sha,
                '"plan-etag"',
                planned_sha,
                planned_after_sha,
                '"plan-etag"',
            )
        self.assertEqual(
            gateway.apply_disposition(
                planned_sha,
                '"plan-etag"',
                planned_sha,
                planned_after_sha,
                '"plan-etag"',
            ),
            "post",
        )
        self.assertEqual(
            gateway.apply_disposition(
                planned_after_sha,
                '"new-etag"',
                planned_sha,
                planned_after_sha,
                '"plan-etag"',
            ),
            "recovered",
        )

    def test_operation_and_manifest_binding(self) -> None:
        self.assertTrue(gateway.operation_matches_stage("detach", "detached", "protected"))
        self.assertTrue(gateway.operation_matches_stage("retire", "retired", "retired"))
        self.assertFalse(gateway.operation_matches_stage("retire", "retired", "unprotected"))
        self.assertFalse(gateway.operation_matches_stage("none", "active", "retired"))
        self.assertFalse(gateway.operation_matches_stage("none", "retired", "unprotected"))
        policy_record = {
            "root": "tailscale",
            "tailscale_policy_before_sha256": "a" * 64,
            "tailscale_policy_after_sha256": "b" * 64,
            "tailscale_policy_etag": 'W/"reviewed-etag"',
        }
        valid = {
            "version": 2,
            "tailscale_gateway_operation": "detach",
            "tailscale_gateway_policy_stage": "detached",
            "plans": [policy_record],
        }
        gateway.verify_manifest_fields(valid, "detach", "detached")
        invalid = (
            {**valid, "tailscale_gateway_operation": "none"},
            {**valid, "tailscale_gateway_policy_stage": "active"},
            {**valid, "plans": [{**policy_record, "tailscale_policy_before_sha256": ""}]},
            {**valid, "plans": [{**policy_record, "tailscale_policy_after_sha256": ""}]},
            {**valid, "plans": [{**policy_record, "tailscale_policy_etag": "unquoted"}]},
            {**valid, "plans": [{**policy_record, "tailscale_policy_after_sha256": "a" * 64}]},
        )
        for changed in invalid:
            with self.assertRaises(gateway.GatewayPolicyError):
                gateway.verify_manifest_fields(changed, "detach", "detached")


if __name__ == "__main__":
    unittest.main()
