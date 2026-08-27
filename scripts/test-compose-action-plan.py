#!/usr/bin/env python3
"""Unit tests for guarded Compose operation argument construction."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "compose-action-plan.py"
SPEC = importlib.util.spec_from_file_location("compose_action_plan", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load compose-action-plan.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ComposeOperationArgumentsTests(unittest.TestCase):
    def test_create_defaults_to_complete_project_without_services(self) -> None:
        self.assertEqual(
            MODULE.compose_operation_arguments("create", False, []),
            ["create", "--no-build", "--pull", "never"],
        )

    def test_dependency_aware_up_preserves_exact_service_order(self) -> None:
        self.assertEqual(
            MODULE.compose_operation_arguments("up", False, ["alpha", "beta"]),
            ["up", "--detach", "--no-build", "--pull", "never", "alpha", "beta"],
        )

    def test_isolated_up_places_no_deps_before_exact_services(self) -> None:
        self.assertEqual(
            MODULE.compose_operation_arguments("up", True, ["alpha"]),
            ["up", "--detach", "--no-build", "--pull", "never", "--no-deps", "alpha"],
        )

    def test_up_requires_an_exact_service_boundary(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "requires at least one exact --service"):
            MODULE.compose_operation_arguments("up", False, [])

    def test_create_rejects_no_deps(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "valid only with --operation up"):
            MODULE.compose_operation_arguments("create", True, ["alpha"])

    def test_actions_are_canonicalized_without_losing_start_or_stop(self) -> None:
        self.assertEqual(
            MODULE.canonical_actions(
                [("alpha", "Recreated"), ("alpha", "Started"), ("beta", "Stopping")]
            ),
            [("alpha", "Recreate"), ("alpha", "Start"), ("beta", "Stop")],
        )


if __name__ == "__main__":
    unittest.main()
