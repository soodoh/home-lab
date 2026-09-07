#!/usr/bin/env python3
"""Offline OIDC plan-policy fixtures; no provider, backend or credentials used."""

from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
OIDC_TYPE = "aws_iam_openid_connect_provider"


def fixture(name):
    return json.loads((ROOT / "fixtures" / f"{name}.json").read_text())


def addresses(value):
    if isinstance(value, dict):
        if isinstance(value.get("address"), str):
            yield value["address"]
        for child in value.values():
            yield from addresses(child)
    elif isinstance(value, list):
        for child in value:
            yield from addresses(child)


def source_owns_oidc(path):
    """Scoped source early warning, NOT an HCL parser/security boundary.

    Native HCL follows the repository's literal block-header/traversal conventions.
    Comments/templates can cause false positives; escaped/unusual headers can be
    missed. The generated-plan structural gate is authoritative. Do not evaluate
    expressions, fetch modules, or read any backend/variable files here.
    """
    text = path.read_text()
    if path.name.endswith(".tf.json"):
        source = json.loads(text)

        def blocks(value):
            return value if isinstance(value, list) else [value]

        return any(OIDC_TYPE in block for block in blocks(source.get("resource", {}))) or any(
            re.search(rf"\b{OIDC_TYPE}\.", block.get("to", ""))
            for block in blocks(source.get("import", {}))
        )
    managed_header = rf'\bresource\s+"{OIDC_TYPE}"\s+"'
    import_target = rf'\bto\s*=\s*(?:module\.[\w-]+(?:\[[^\]\n]+\])?\.)*{OIDC_TYPE}\.'
    return bool(re.search(managed_header, text) or re.search(import_target, text))


class OidcSourceTests(unittest.TestCase):
    def test_foundation_source_has_no_managed_or_imported_oidc(self):
        foundation = ROOT.parent / "tofu" / "aws-foundation"
        sources = sorted([*foundation.glob("*.tf"), *foundation.glob("*.tf.json")])
        self.assertTrue(sources, "foundation source scope must not be empty")
        for path in sources:
            with self.subTest(source=path.name):
                self.assertFalse(source_owns_oidc(path), f"{path}: OIDC ownership must stay outside home-lab")

    def test_native_source_conventions(self):
        cases = [
            (f'resource "{OIDC_TYPE}" "renamed" {{ count = 0 }}', True),
            (f'resource\n "{OIDC_TYPE}"\n "renamed" {{}}', True),
            (f'import {{ to = {OIDC_TYPE}.renamed\n id = "synthetic" }}', True),
            (f'import {{ to = module.identity["one"].module.nested.{OIDC_TYPE}.renamed\n id = "synthetic" }}', True),
            (f'data "{OIDC_TYPE}" "shared" {{ url = "https://issuer.invalid" }}', False),
            (f'output "provider" {{ value = data.{OIDC_TYPE}.shared.arn }}', False),
            ('resource "aws_iam_role" "controller" {}', False),
            ('import { to = aws_iam_role.controller\n id = "synthetic" }', False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.tf"
            for text, expected in cases:
                with self.subTest(source=text):
                    path.write_text(text)
                    self.assertEqual(source_owns_oidc(path), expected)

    def test_json_source_structure(self):
        cases = [
            ({"resource": {OIDC_TYPE: {"renamed": {"count": 0}}}}, True),
            ({"resource": [{OIDC_TYPE: {"renamed": {}}}]}, True),
            ({"import": [{"to": f"${{module.identity.{OIDC_TYPE}.renamed}}", "id": "synthetic"}]}, True),
            ({"import": {"to": f"{OIDC_TYPE}.renamed", "id": "synthetic"}}, True),
            ({"data": {OIDC_TYPE: {"shared": {}}}, "output": {
                "provider": {"value": f"${{data.{OIDC_TYPE}.shared.arn}}"}}}, False),
            ({"resource": {"aws_iam_role": {"controller": {}}}, "import": [
                {"to": "${aws_iam_role.controller}", "id": "synthetic"}]}, False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.tf.json"
            for source, expected in cases:
                with self.subTest(source=source):
                    path.write_text(json.dumps(source))
                    self.assertEqual(source_owns_oidc(path), expected)


class OidcPlanTests(unittest.TestCase):
    def inspect(self, plan, allowed=True, mode="normal"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "plan.json").write_text(json.dumps(plan))
            # Deliberately allow every address: OIDC must not be overridable here.
            (path / "allow.txt").write_text("\n".join(addresses(plan)) + "\n")
            command = [sys.executable, "-B", "-E", "-s", "-S",
                       str(ROOT / "inspect-plan.py"), str(path / "plan.json"), "--mode", mode]
            if allowed:
                command += ["--allow-change-file", str(path / "allow.txt")]
            return subprocess.run(command, capture_output=True, text=True, timeout=10)

    def assert_denied(self, plan, **kwargs):
        result = self.inspect(plan, **kwargs)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("managed IAM OIDC provider ownership is forbidden", result.stderr)

    def assert_passed(self, plan, **kwargs):
        result = self.inspect(plan, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_managed_actions_and_imports_cannot_be_allowlisted(self):
        for actions in (["create"], ["update"], ["delete"], ["delete", "create"],
                        ["no-op"], ["read"], []):
            for importing in (False, True):
                for prefix in ("", "module.identity.module.nested."):
                    with self.subTest(actions=actions, importing=importing, prefix=prefix):
                        plan = fixture("oidc-managed")
                        resource = plan["resource_changes"][0]
                        resource["address"] = prefix + resource["address"]
                        resource["change"]["actions"] = actions
                        if importing:
                            resource["change"]["importing"] = {"id": "synthetic-provider"}
                        self.assert_denied(plan)

    def test_type_not_name_issuer_or_missing_mode_controls_ownership(self):
        plan = fixture("oidc-managed")
        resource = plan["resource_changes"][0]
        resource["address"] = "example.innocent"
        resource["change"]["after"]["url"] = "https://another-issuer.invalid"
        for mode in (None, "unexpected", "managed"):
            with self.subTest(mode=mode):
                resource.pop("mode", None)
                if mode is not None:
                    resource["mode"] = mode
                self.assert_denied(plan)
        self.assert_denied(plan, allowed=False)

    def test_configuration_only_root_and_nested_count_zero(self):
        plan = fixture("oidc-configuration-only")
        self.assert_denied(plan)
        root = plan["configuration"]["root_module"]
        child = root["module_calls"]["identity"]["module"]
        root["module_calls"]["identity"]["module"] = {"module_calls": {"nested": {"module": child}}}
        self.assert_denied(plan)
        plan["configuration"]["root_module"] = child
        self.assert_denied(plan)

    def test_prior_and_planned_values_ownership_without_changes(self):
        plan = fixture("oidc-prior-state-only")
        values = plan["prior_state"]["values"]
        for location in ("prior_state", "planned_values"):
            for nested in (False, True):
                with self.subTest(location=location, nested=nested):
                    candidate = deepcopy(values)
                    if not nested:
                        candidate["root_module"] = candidate["root_module"]["child_modules"][0]
                    plan = {location: {"values": candidate} if location == "prior_state" else candidate}
                    self.assert_denied(plan)

    def test_ownership_gate_precedes_vm_start_mode(self):
        for name in ("oidc-managed", "oidc-configuration-only", "oidc-prior-state-only"):
            with self.subTest(fixture=name):
                plan = fixture(name)
                if plan.get("resource_changes"):
                    plan["resource_changes"][0]["change"]["actions"] = ["no-op"]
                plan.setdefault("resource_changes", []).extend(fixture("vm-start-prerequisite")["resource_changes"])
                self.assert_denied(plan, mode="vm-start-prerequisite")

    def test_data_lookups_and_references_remain_allowed(self):
        for actions in (["read"], ["no-op"], []):
            plan = fixture("oidc-data")
            plan["resource_changes"][0]["change"]["actions"] = actions
            resource = plan["configuration"]["root_module"]["resources"][0]
            plan["configuration"]["root_module"]["outputs"] = {
                "provider": {"expression": {"references": [resource["address"]]}}}
            plan["configuration"]["root_module"]["module_calls"] = {
                "consumer": {"module": {"resources": [resource]}}}
            plan["planned_values"] = {"root_module": {"child_modules": [{"resources": [resource]}]}}
            plan["prior_state"] = {"values": plan["planned_values"]}
            with self.subTest(actions=actions):
                self.assert_passed(plan, allowed=False)
                plan["resource_changes"].extend(fixture("vm-start-prerequisite")["resource_changes"])
                self.assert_passed(plan, mode="vm-start-prerequisite")

    def test_non_oidc_controls_and_existing_guards(self):
        for name in ("noop", "import", "protection-enable"):
            self.assert_passed(fixture(name))
        self.assert_passed(fixture("vm-start-prerequisite"), mode="vm-start-prerequisite")
        plan = fixture("oidc-managed")
        plan["resource_changes"][0]["type"] = "aws_iam_role"
        # User/provider payloads describing a type are not resource envelopes.
        plan["resource_changes"][0]["change"]["after"]["description"] = {
            "type": OIDC_TYPE, "mode": "managed"}
        self.assert_passed(plan)
        for name in ("delete", "replace", "protection-disable", "import"):
            result = self.inspect(fixture(name), allowed=False)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        plan = fixture("import")
        plan["resource_changes"][0]["change"]["actions"] = ["update"]
        self.assertEqual(self.inspect(plan).returncode, 1)
        plan = fixture("vm-start-prerequisite")
        plan["resource_changes"][0]["change"]["after_unknown"]["boot_order"] = True
        self.assertEqual(self.inspect(plan).returncode, 1)


if __name__ == "__main__":
    unittest.main()
