#!/usr/bin/env python3

import hashlib

import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "infrastructure" / "tofu" / "authentik"
DESIRED = json.loads((ROOT / "desired.json").read_text())
OAUTH_PROVIDER_IDS = {"15", "16", "21", "37", "47", "49"}


class AuthentikTofuFoundationTests(unittest.TestCase):
    def test_live_inventory_is_complete(self) -> None:
        self.assertEqual(DESIRED["schemaVersion"], 2)
        self.assertTrue(DESIRED["sourceInventory"]["complete"])
        self.assertEqual(len(DESIRED["applications"]), 25)
        self.assertEqual(len(DESIRED["proxyProviders"]), 19)
        self.assertEqual(set(DESIRED["oauthProviders"]), OAUTH_PROVIDER_IDS)
        self.assertEqual(len(DESIRED["applicationPolicyBindings"]), 30)
        self.assertEqual(set(DESIRED["authenticatorValidateStages"]), {"passwordless-webauthn"})
        self.assertEqual(set(DESIRED["customFlows"]), {"passwordless-authentication"})
        self.assertEqual(len(DESIRED["flowStageBindings"]), 2)
        self.assertEqual(set(DESIRED["scopeMappings"]), {"vaultwarden-email"})
        self.assertEqual(DESIRED["customBlueprints"], {})

        referenced_proxy_ids = {
            str(application["provider_id"])
            for application in DESIRED["applications"].values()
            if application["provider_type"] == "proxy"
        }
        referenced_oauth_ids = {
            str(application["provider_id"])
            for application in DESIRED["applications"].values()
            if application["provider_type"] == "oauth2"
        }
        self.assertEqual(referenced_proxy_ids, set(DESIRED["proxyProviders"]))
        self.assertEqual(referenced_oauth_ids, OAUTH_PROVIDER_IDS)
        self.assertEqual(
            {binding["application_slug"] for binding in DESIRED["applicationPolicyBindings"].values()},
            set(DESIRED["applications"]),
        )

    def test_source_inventory_hashes_bind_normalized_state(self) -> None:
        def digest(value: object) -> str:
            def canonical(item: object) -> object:
                if isinstance(item, dict):
                    keys = sorted(item, key=int) if item and all(key.isdigit() for key in item) else sorted(item)
                    return {key: canonical(item[key]) for key in keys}
                if isinstance(item, list):
                    return [canonical(nested) for nested in item]
                return item

            payload = json.dumps(canonical(value), separators=(",", ":")) + "\n"
            return hashlib.sha256(payload.encode()).hexdigest()

        source = DESIRED["sourceInventory"]
        self.assertEqual(source["applicationsSha256"], digest(DESIRED["applications"]))
        self.assertEqual(source["proxyProvidersSha256"], digest(DESIRED["proxyProviders"]))
        self.assertEqual(source["oauthProvidersSha256"], digest(DESIRED["oauthProviders"]))
        self.assertEqual(
            source["applicationPolicyBindingsSha256"],
            digest(DESIRED["applicationPolicyBindings"]),
        )
        self.assertEqual(
            source["customConfigurationSha256"],
            digest({
                "authenticatorValidateStages": DESIRED["authenticatorValidateStages"],
                "customFlows": DESIRED["customFlows"],
                "flowStageBindings": DESIRED["flowStageBindings"],
                "scopeMappings": DESIRED["scopeMappings"],
            }),
        )

    def test_nonsecret_desired_inventory_has_no_secret_fields(self) -> None:
        forbidden_keys = {"client_secret", "cookie_secret", "password", "token"}

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(DESIRED)

    def test_oauth_secrets_are_sops_ciphertext(self) -> None:
        encrypted_text = (ROOT / "client-secrets.sops.json").read_text()
        encrypted = json.loads(encrypted_text)
        self.assertEqual(set(encrypted["oauthProviders"]), OAUTH_PROVIDER_IDS)
        self.assertNotIn("REPLACE-DURING-BOOTSTRAP", encrypted_text)
        for provider in encrypted["oauthProviders"].values():
            self.assertEqual(set(provider), {"client_secret"})
            self.assertRegex(provider["client_secret"], r"^ENC\[AES256_GCM,")
        self.assertIn("sops", encrypted)
        self.assertEqual(len(encrypted["sops"]["age"]), 3)

    def test_root_is_import_first_and_secret_aware(self) -> None:
        versions = (ROOT / "versions.tf").read_text()
        variables = (ROOT / "variables.tf").read_text()
        main = (ROOT / "main.tf").read_text()

        self.assertIn('version = "= 2026.5.1"', versions)
        self.assertIn('key          = "home-lab/authentik/tofu.tfstate"', versions)
        self.assertRegex(variables, r'variable "authentik_enable_management"[\s\S]+default\s+= false')
        for resource in (
            "authentik_application",
            "authentik_blueprint",
            "authentik_flow",
            "authentik_flow_stage_binding",
            "authentik_policy_binding",
            "authentik_property_mapping_provider_scope",
            "authentik_provider_oauth2",
            "authentik_provider_proxy",
            "authentik_stage_authenticator_validate",
        ):
            self.assertIn(f'resource "{resource}"', main)
        self.assertEqual(main.count("prevent_destroy = true"), 9)
        self.assertEqual(main.count("import {"), 9)
        self.assertIn("to       = authentik_flow.custom[each.key]\n  id       = each.value.slug", main)
        self.assertIn("length(local.desired.applicationPolicyBindings) == 30", main)
        self.assertIn("data.authentik_stage.default_authentication_login", main)
        self.assertIn("data.authentik_stage.default_authenticator_webauthn_setup", main)
        self.assertIn("local.client_secrets.oauthProviders[each.key].client_secret", main)
        self.assertIn("authentik_property_mapping_provider_scope.scope_mappings", main)
        self.assertIn("url      = var.authentik_url", main)
        self.assertIn("token    = var.authentik_token", main)
        self.assertEqual(variables.count("ephemeral = true"), 1)
        self.assertEqual(variables.count("sensitive = true"), 1)

    def test_plan_policy_allowlist_is_exact_for_reviewed_addresses(self) -> None:
        allow = set((REPO / "infrastructure" / "policy" / "allow" / "authentik.txt").read_text().splitlines())
        expected = {
            *(f'authentik_application.applications["{key}"]' for key in DESIRED["applications"]),
            *(f'authentik_policy_binding.application_access["{key}"]' for key in DESIRED["applicationPolicyBindings"]),
            *(f'authentik_stage_authenticator_validate.custom["{key}"]' for key in DESIRED["authenticatorValidateStages"]),
            *(f'authentik_blueprint.custom["{key}"]' for key in DESIRED["customBlueprints"]),
            *(f'authentik_flow.custom["{key}"]' for key in DESIRED["customFlows"]),
            *(f'authentik_flow_stage_binding.custom["{key}"]' for key in DESIRED["flowStageBindings"]),
            *(f'authentik_provider_oauth2.providers["{key}"]' for key in DESIRED["oauthProviders"]),
            *(f'authentik_provider_proxy.providers["{key}"]' for key in DESIRED["proxyProviders"]),
            *(f'authentik_property_mapping_provider_scope.scope_mappings["{key}"]' for key in DESIRED["scopeMappings"]),
        }
        self.assertEqual(allow, expected)
        self.assertEqual(len(allow), 85)

    def test_prepare_and_normalize_steps_protect_sensitive_inputs(self) -> None:
        prepare = (REPO / "scripts" / "prepare-authentik-plan-input").read_text()
        normalizer = (REPO / "scripts" / "controller" / "authentik-normalize-inventory.mjs").read_text()
        for value in ("AUTHENTIK_URL", "AUTHENTIK_TOKEN", "SOPS_AGE_KEY_FILE", "chmod 0600"):
            self.assertIn(value, prepare)
        self.assertIn("path.is_symlink()", prepare)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", prepare)
        self.assertIn('assert(!serializedDesired.includes("client_secret")', normalizer)
        self.assertIn('writeFileSync(secretsPath', normalizer)
        self.assertIn('expected 30 application access bindings', normalizer)

    def test_bootstrap_separates_read_only_plan_and_apply_identities(self) -> None:
        bootstrap = (REPO / "scripts" / "controller" / "authentik-bootstrap-service-account.py").read_text()
        self.assertIn('"plan": {', bootstrap)
        self.assertIn('"apply": {', bootstrap)
        self.assertIn('"actions": ("view",)', bootstrap)
        self.assertIn('"actions": ("view", "add", "change")', bootstrap)
        for model in (
            "application",
            "authenticatorvalidatestage",
            "flow",
            "flowstagebinding",
            "oauth2provider",
            "policybinding",
            "proxyprovider",
            "scopemapping",
        ):
            self.assertIn(f'"{model}"', bootstrap)
        self.assertIn("with transaction.atomic():", bootstrap)
        self.assertIn("HOME_LAB_AUTHENTIK_BOOTSTRAP_REQUEST_SHA256", bootstrap)
        self.assertIn("HOME_LAB_AUTHENTIK_BOOTSTRAP_TOKEN_EXPIRES_AT", bootstrap)
        self.assertNotIn('"delete"', bootstrap)
        self.assertNotIn("objects.delete", bootstrap)


if __name__ == "__main__":
    unittest.main()
