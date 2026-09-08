#!/usr/bin/env python3
"""Synthetic plan-admission tests, not IAM evaluation or live provider validation."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
MODES = ("normal", "vm-start-prerequisite")
TYPES = ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment",
         "aws_iam_user", "aws_iam_user_policy", "aws_iam_access_key", "aws_iam_group",
         "aws_iam_service_linked_role", "aws_rolesanywhere_profile",
         "aws_rolesanywhere_trust_anchor", "aws_rolesanywhere_crl")
OIDC = "aws_iam_openid_connect_provider"


def resource(kind="aws_iam_role", actions=None, mode="managed"):
    return {"address": f"module.owner.module.nested.{kind}.renamed[0]", "type": kind,
            "mode": mode, "change": {"actions": ["no-op"] if actions is None else actions,
                                      "before": {"id": "synthetic"},
                                      "after": {"id": "synthetic"}}}


class ControllerIdentityGateTests(unittest.TestCase):
    inspections = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Synthetic plan inspector invocations: {cls.inspections}; no IAM evaluation.")

    def inspect(self, plan, mode, allow=True, raw=None):
        type(self).inspections += 1
        plan = deepcopy(plan)
        if mode == "vm-start-prerequisite" and isinstance(plan, dict) and isinstance(plan.get("resource_changes", []), list):
            vm = json.loads((ROOT / "fixtures/vm-start-prerequisite.json").read_text())
            plan.setdefault("resource_changes", []).extend(vm["resource_changes"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "plan.json").write_text(json.dumps(plan) if raw is None else raw)
            # Broad allowlist is intentionally not an identity authority boundary.
            def addresses(value):
                if isinstance(value, dict):
                    if isinstance(value.get("address"), str):
                        yield value["address"]
                    for child in value.values():
                        yield from addresses(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from addresses(child)
            (path / "allow.txt").write_text("\n".join(addresses(plan)) + "\n")
            args = [sys.executable, "-B", "-E", "-s", "-S", str(ROOT / "inspect-plan.py"),
                    str(path / "plan.json"), "--mode", mode]
            if allow:
                args += ["--allow-change-file", str(path / "allow.txt")]
            return subprocess.run(args, text=True, capture_output=True, timeout=10)

    def check(self, plan, denied=True, diagnostic="owner intervention required", allow=True):
        for mode in MODES:
            with self.subTest(mode=mode):
                result = self.inspect(plan, mode, allow)
                self.assertEqual(result.returncode, int(denied), result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                if denied:
                    self.assertIn(diagnostic, result.stderr)

    def test_mutations_all_identity_types_all_modes(self):
        for kind in TYPES:
            for actions in (["create"], ["update"], ["delete"], ["delete", "create"],
                            ["create", "delete"], ["forget"], ["future-action"]):
                with self.subTest(kind=kind, actions=actions):
                    self.check({"resource_changes": [resource(kind, actions)]})

    def test_imports_including_noop_read_empty_and_malformed_import(self):
        for kind in ("aws_iam_policy", "aws_rolesanywhere_profile"):
            for actions in (["no-op"], ["read"], [], ["create"], ["update"]):
                for importing in ({"id": "synthetic"}, {}, False, "unknown"):
                    item = resource(kind, actions)
                    item["change"]["importing"] = importing
                    with self.subTest(kind=kind, actions=actions, importing=importing):
                        self.check({"resource_changes": [item]})

    def test_identity_tracking_moves_are_not_safe_noops(self):
        for kind in TYPES:
            item = resource(kind)
            item["previous_address"] = f"{kind}.old"
            self.check({"resource_changes": [item]})

    def test_duplicate_json_keys_cannot_hide_identity_changes(self):
        for raw in ('{"resource_changes": [], "resource_changes": []}',
                    '{"resource_changes": [{"type": "aws_iam_role", "type": "example", '
                    '"change": {"actions": ["update"], "actions": ["no-op"]}}]}'):
            for mode in MODES:
                result = self.inspect({}, mode, raw=raw)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("duplicate JSON key", result.stderr)
                self.assertIn("owner intervention required", result.stderr)

    def test_safe_managed_noop_and_read_with_without_allowlist(self):
        for kind in TYPES:
            for actions in (["no-op"], ["read"]):
                for allow in (False, True):
                    with self.subTest(kind=kind, actions=actions, allow=allow):
                        self.check({"resource_changes": [resource(kind, actions)]}, denied=False, allow=allow)
        item = resource(actions=["read"])
        item["change"]["before"] = None
        item["change"]["after_unknown"] = {"tags": [False, {}]}
        self.check({"resource_changes": [item]}, denied=False)

    def test_identity_type_not_address_or_payload_controls_gate(self):
        item = resource(actions=["update"])
        item["address"] = "example.innocent"
        self.check({"resource_changes": [item]}, allow=False)
        item = resource("example", ["create"])
        item["change"]["after"]["payload"] = resource(actions=["update"])
        # General non-identity create is allowed only in normal mode (VM mode is stricter).
        result = self.inspect({"resource_changes": [item]}, "normal")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_malformed_identity_tracking_address(self):
        for address in (None, "", {}, [], 42):
            item = resource()
            item["address"] = address
            with self.subTest(address=address):
                self.check({"resource_changes": [item]})
        item.pop("address")
        self.check({"resource_changes": [item]})

    def test_missing_unknown_or_malformed_identity_mode(self):
        for mode in (None, "future", "MANAGED", "", {}, []):
            item = resource(mode=mode)
            with self.subTest(mode=mode):
                self.check({"resource_changes": [item]})
        item.pop("mode")
        self.check({"resource_changes": [item]})

    def test_retained_nested_identity_ownership_is_allowed_not_oidc(self):
        item = resource()
        item.pop("change")
        for location in ("configuration", "planned_values", "prior_state"):
            for nested in (False, True):
                values = {"root_module": {"resources": [item]}}
                if nested:
                    values = {"root_module": {"module_calls": {"outer": {"module": {
                        "child_modules": [values["root_module"]]}}}}}
                plan = {location: {"values": values} if location == "prior_state" else values}
                with self.subTest(location=location, nested=nested):
                    self.check(plan, denied=False)
                item["mode"] = "unknown"
                self.check(plan)
                item["mode"] = "managed"

    def test_drift_alone_and_with_proposed_noop(self):
        for kind in TYPES:
            for proposed in ([], [resource(kind)]):
                item = resource(kind, ["update"])
                item["change"]["after"]["policy"] = "owner-aligned-but-state-stale"
                with self.subTest(kind=kind, proposed=bool(proposed)):
                    self.check({"resource_drift": [item], "resource_changes": proposed}, diagnostic="resource_drift")
        self.check({"resource_drift": [resource()]}, denied=False)

    def test_deferred_identity_even_noop_and_missing_envelopes(self):
        for kind in ("aws_iam_role", "aws_rolesanywhere_profile"):
            for actions in (["update"], ["no-op"], ["read"]):
                self.check({"deferred_changes": [{"reason": "unknown", "resource_change": resource(kind, actions)}]})
        for deferred in (None, {}, [None], [{}], [{"resource_change": None}]):
            with self.subTest(deferred=deferred):
                self.check({"deferred_changes": deferred})

    def test_malformed_or_unknown_actions_and_change_envelopes(self):
        for location in ("resource_changes", "resource_drift"):
            for change in (None, [], "unknown", {}, {"actions": []}, {"actions": None},
                           {"actions": "no-op"}, {"actions": [None]}, {"actions": ["future"]}):
                item = resource()
                item["change"] = change
                with self.subTest(location=location, change=change):
                    self.check({location: [item]})
            item.pop("change")
            self.check({location: [item]})

    def test_unknown_or_inconsistent_safe_identity_results(self):
        for actions in (["no-op"], ["read"]):
            for unknown in (True, None, 0, "false", {"policy": True}, {"nested": [False, True]}, {"id": "unknown"}):
                item = resource(actions=actions)
                item["change"]["after_unknown"] = unknown
                with self.subTest(actions=actions, unknown=unknown):
                    self.check({"resource_changes": [item]})
            for after in (None, [], "unknown"):
                item = resource(actions=actions)
                item["change"]["after"] = after
                self.check({"resource_changes": [item]})
        item = resource(actions=["read"])
        item["change"].pop("before")
        self.check({"resource_changes": [item]})
        item = resource()
        item["change"]["after"] = {"policy": "changed despite no-op"}
        self.check({"resource_drift": [item]})
        self.check({"resource_changes": [item]})

    def test_malformed_container_or_type_cannot_hide_identity(self):
        cases = [None, [], {"resource_changes": None}, {"resource_changes": {}},
                 {"resource_changes": [None]}, {"resource_drift": {}},
                 {"configuration": None}, {"configuration": {"root_module": []}},
                 {"planned_values": {"root_module": {"resources": None}}},
                 {"prior_state": {"values": None}},
                 {"configuration": {"root_module": {"module_calls": {"nested": None}}}},
                 {"configuration": {"root_module": {"module_calls": {"nested": {}}}}},
                 {"planned_values": {"root_module": {"child_modules": [None]}}}]
        for kind in (None, [], {}, ""):
            item = resource()
            item["type"] = kind
            cases.append({"resource_changes": [item]})
        item = resource()
        item.pop("type")
        cases.append({"resource_changes": [item]})
        for plan in cases:
            with self.subTest(plan=plan):
                self.check(plan)

    def test_incomplete_or_errored_plans_fail_closed(self):
        for field, values in (("complete", [False, None, 0, "true"]),
                              ("errored", [True, None, 0, "false"])):
            for value in values:
                self.check({field: value, "resource_changes": [resource()]})
        self.check({"complete": True, "errored": False, "resource_changes": [resource()]}, denied=False)

    def test_explicit_data_and_nested_references_remain_legitimate(self):
        for kind in ("aws_iam_policy_document", "aws_iam_role", "aws_rolesanywhere_profile", OIDC):
            for actions in (["read"], ["no-op"], []):
                item = resource(kind, actions, "data")
                item["change"]["after_unknown"] = {"json": True}
                item["change"]["after"]["example"] = resource(OIDC, ["create"])
                self.check({"resource_changes": [item], "planned_values": {"root_module": {
                    "resources": [item], "outputs": {"reference": resource(OIDC)}}}}, denied=False, allow=False)

    def test_oidc_ownership_stays_unconditional_including_drift_deferred(self):
        for actions in (["no-op"], ["read"], [], ["update"]):
            for location in ("resource_changes", "resource_drift", "deferred_changes"):
                item = resource(OIDC, actions)
                envelope = {"resource_change": item} if location == "deferred_changes" else item
                self.check({location: [envelope]}, diagnostic="managed IAM OIDC provider ownership is forbidden")
        for location in ("configuration", "planned_values", "prior_state"):
            values = {"root_module": {"child_modules": [{"resources": [resource(OIDC)]}]}}
            self.check({location: {"values": values} if location == "prior_state" else values},
                       diagnostic="managed IAM OIDC provider ownership is forbidden")


if __name__ == "__main__":
    unittest.main()
