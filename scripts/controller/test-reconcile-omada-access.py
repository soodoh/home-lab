#!/usr/bin/env python3
"""Regression tests for the temporary Omada controller access wiring."""

from pathlib import Path
import re
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
LOCAL_CONTROLLER = REPOSITORY / "scripts/local-controller"
RECONCILER = REPOSITORY / "scripts/reconcile-infrastructure"


class ReconcileOmadaAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.local_controller = LOCAL_CONTROLLER.read_text()
        cls.reconciler = RECONCILER.read_text()

    def test_public_operation_binds_flag_and_confirmation(self) -> None:
        operation = re.search(
            r"^  omada-controller-access\)\n(?P<body>.*?^    ;;)$",
            self.local_controller,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(operation)
        body = operation.group("body")
        self.assertIn("operation_args=(--phase steady --omada-controller-access)", body)
        self.assertIn("expected_confirmation=enable-reviewed-omada-controller-access", body)

    def test_operation_selects_only_tailscale_and_uses_exact_policy_mode(self) -> None:
        self.assertIn(
            "$tailscale_human_ssh_change == true || $omada_controller_access == true",
            self.reconciler,
        )
        self.assertIn('roots=(tailscale)', self.reconciler)
        self.assertIn('mode=omada-controller-access', self.reconciler)
        self.assertIn(
            "Omada controller access requires one changed Tailscale plan.",
            self.reconciler,
        )

    def test_manifest_binds_operation_and_rejects_absent_or_mismatched_field(self) -> None:
        self.assertIn(
            '--argjson omada_controller_access "$omada_controller_access"',
            self.reconciler,
        )
        self.assertIn(
            "omada_controller_access: $omada_controller_access",
            self.reconciler,
        )
        self.assertIn(
            '[[ $(jq -r .omada_controller_access "$manifest") == "$omada_controller_access" ]]',
            self.reconciler,
        )

    def test_tailscale_only_apply_reuses_exact_root_and_verification(self) -> None:
        function = re.search(
            r"^apply_tailscale_policy_only\(\) \{\n(?P<body>.*?)^\}$",
            self.reconciler,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(function)
        self.assertEqual(
            function.group("body").strip().splitlines(),
            ["apply_root tailscale", "  verify_all"],
        )
        self.assertIn(
            "$tailscale_controller_access == true || $omada_controller_access == true || "
            "$tailscale_human_ssh_change == true || $tailscale_controller_retirement == true",
            self.reconciler,
        )
        self.assertIn("apply_tailscale_policy_only", self.reconciler)

    def test_steady_plan_and_apply_verify_alias_but_bootstrap_does_not(self) -> None:
        helper = re.search(
            r"^prepare_steady_omada_input\(\) \{\n(?P<body>.*?)^\}$",
            self.local_controller,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(helper)
        self.assertIn("[[ $operation == steady ]]", helper.group("body"))
        self.assertIn("scripts/prepare-omada-plan-input prepare", helper.group("body"))
        self.assertEqual(self.local_controller.count("prepare_steady_omada_input"), 3)


if __name__ == "__main__":
    unittest.main()
