#!/usr/bin/env python3

import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "infrastructure" / "tofu" / "authentik"
DESIRED = json.loads((ROOT / "desired.json").read_text())
IMPORTS = json.loads(
    (REPO / "infrastructure" / "applications" / "vm-100-application-imports.json").read_text()
)


class AuthentikTofuFoundationTests(unittest.TestCase):
    def test_inventory_matches_approved_imports(self) -> None:
        authentik_imports = [item for item in IMPORTS["imports"] if item["root"] == "authentik"]
        application_imports = {
            item["importId"]: item for item in authentik_imports if item["class"] == "application"
        }
        proxy_imports = {
            item["importId"]: item for item in authentik_imports if item["class"] == "proxy-provider"
        }

        self.assertEqual(set(DESIRED["applications"]), set(application_imports))
        self.assertEqual(set(DESIRED["proxyProviders"]), set(proxy_imports))
        self.assertEqual(len(application_imports), 25)
        self.assertEqual(len(proxy_imports), 19)
        allow = set((REPO / "infrastructure" / "policy" / "allow" / "authentik.txt").read_text().splitlines())
        self.assertEqual(allow, {item["resourceAddress"] for item in authentik_imports})

        for slug, desired in DESIRED["applications"].items():
            self.assertEqual(desired["slug"], slug)
            self.assertEqual(desired["provider_id"], application_imports[slug]["providerId"])
            self.assertEqual(desired["provider_type"], application_imports[slug]["providerType"])
            self.assertEqual(
                application_imports[slug]["resourceAddress"],
                f'authentik_application.applications["{slug}"]',
            )

        for provider_id, desired in DESIRED["proxyProviders"].items():
            self.assertEqual(str(desired["pk"]), provider_id)
            self.assertEqual(
                proxy_imports[provider_id]["resourceAddress"],
                f'authentik_provider_proxy.providers["{provider_id}"]',
            )

    def test_proxy_provider_references_are_complete(self) -> None:
        managed_provider_ids = {int(value) for value in DESIRED["proxyProviders"]}
        referenced_proxy_ids = {
            application["provider_id"]
            for application in DESIRED["applications"].values()
            if application["provider_type"] == "proxy"
        }
        self.assertEqual(referenced_proxy_ids, managed_provider_ids)
        self.assertEqual(
            sum(application["provider_type"] == "oauth2" for application in DESIRED["applications"].values()),
            6,
        )

    def test_desired_json_excludes_secret_fields(self) -> None:
        forbidden_keys = {
            "api_key",
            "client_secret",
            "cookie_secret",
            "headers",
            "key",
            "password",
            "token",
        }

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(DESIRED)

    def test_source_hashes_match_inventory_manifest(self) -> None:
        source = DESIRED["sourceInventory"]
        evidence = IMPORTS["evidence"]
        self.assertEqual(source["applicationsSha256"], evidence["authentikApplicationInventorySha256"])
        self.assertEqual(source["proxyProvidersSha256"], evidence["authentikProxyInventorySha256"])

    def test_root_is_disabled_and_import_first(self) -> None:
        versions = (ROOT / "versions.tf").read_text()
        variables = (ROOT / "variables.tf").read_text()
        main = (ROOT / "main.tf").read_text()

        self.assertIn('version = "= 2026.5.1"', versions)
        self.assertIn('key          = "home-lab/authentik/tofu.tfstate"', versions)
        self.assertRegex(variables, r'variable "authentik_enable_management"[\s\S]+default\s+= false')
        self.assertEqual(main.count("prevent_destroy = true"), 2)
        self.assertEqual(main.count("import {"), 2)
        self.assertIn("var.authentik_enable_management ? local.desired.applications : {}", main)
        self.assertIn("var.authentik_enable_management ? local.desired.proxyProviders : {}", main)
        self.assertNotIn("client_secret", main)
        self.assertNotIn("cookie_secret", main)
        self.assertNotIn("property_mappings", main)
        self.assertIn("token    = var.authentik_token", main)
        self.assertEqual(variables.count("ephemeral = true"), 1)
        self.assertEqual(variables.count("sensitive = true"), 1)

    def test_bootstrap_is_guarded_and_least_privilege(self) -> None:
        bootstrap = (REPO / "scripts" / "controller" / "authentik-bootstrap-service-account.py").read_text()
        for permission in (
            "view_application",
            "change_application",
            "view_provider",
            "change_provider",
            "view_proxyprovider",
            "change_proxyprovider",
        ):
            self.assertIn(f'"{permission}"', bootstrap)
        for forbidden in ("add_application", "delete_application", "add_proxyprovider", "delete_proxyprovider"):
            self.assertNotIn(forbidden, bootstrap)
        self.assertIn("with transaction.atomic():", bootstrap)
        self.assertIn("HOME_LAB_AUTHENTIK_BOOTSTRAP_REQUEST_SHA256", bootstrap)
        self.assertIn("2026-11-12T00:00:00Z", bootstrap)
        self.assertNotIn("objects.delete", bootstrap)


if __name__ == "__main__":
    unittest.main()
