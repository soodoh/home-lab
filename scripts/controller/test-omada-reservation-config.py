#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
ENCRYPTED = REPOSITORY / "infrastructure/tofu/omada/reservation-config.sops.json"


class OmadaReservationConfigTests(unittest.TestCase):
    def test_requested_reservations_encrypt_all_sensitive_scalars(self) -> None:
        data = json.loads(ENCRYPTED.read_text())

        self.assertEqual(set(data), {"requested_reservations", "sops"})
        self.assertEqual(len(data["requested_reservations"]), 1)
        for item in data["requested_reservations"]:
            self.assertEqual(set(item), {"mac", "ip", "name", "enable"})
            self.assertTrue(all(value.startswith("ENC[AES256_GCM,") for value in item.values()))

        authorized = set(re.findall(r"age1[0-9a-z]+", (REPOSITORY / ".sops.yaml").read_text()))
        recipients = {entry["recipient"] for entry in data["sops"]["age"]}
        self.assertEqual(recipients, authorized)

    def test_client_alias_management_is_absent(self) -> None:
        main = (REPOSITORY / "infrastructure/tofu/omada/main.tf").read_text()
        variables = (REPOSITORY / "infrastructure/tofu/omada/variables.tf").read_text()
        prepare = (REPOSITORY / "scripts/prepare-omada-plan-input").read_text()
        reconcile = (REPOSITORY / "scripts/reconcile-infrastructure").read_text()

        self.assertNotIn("omada_client_alias", main)
        self.assertNotIn("client_aliases", main)
        self.assertNotIn("omada_client_config_path", variables)
        self.assertIn("omada_reservation_config_path", variables)
        self.assertIn("reservation-config.sops.json", prepare)
        self.assertIn("reservation-config.json", prepare)
        self.assertIn("omada_reservation_config_path=$repo_root/.local/omada/reservation-config.json", reconcile)
        self.assertFalse((REPOSITORY / "scripts/prepare-omada-provider-fork").exists())


if __name__ == "__main__":
    unittest.main()
