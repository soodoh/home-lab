#!/usr/bin/env python3

import hashlib

import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "infrastructure" / "tofu" / "authentik"
DESIRED = json.loads((ROOT / "desired.json").read_text())
OAUTH_PROVIDER_IDS = {"15", "21", "37", "47", "49"}


class AuthentikTofuFoundationTests(unittest.TestCase):
    def test_live_inventory_is_complete(self) -> None:
        self.assertEqual(DESIRED["schemaVersion"], 3)
        self.assertTrue(DESIRED["sourceInventory"]["complete"])
        self.assertEqual(len(DESIRED["applications"]), 24)
        self.assertEqual(len(DESIRED["proxyProviders"]), 19)
        self.assertEqual(set(DESIRED["oauthProviders"]), OAUTH_PROVIDER_IDS)
        self.assertEqual(DESIRED["retainedOAuthProviders"], ["15"])
        self.assertEqual(len(DESIRED["applicationPolicyBindings"]), 28)
        self.assertEqual(set(DESIRED["authenticatorValidateStages"]), {"passwordless-webauthn"})
        self.assertEqual(
            set(DESIRED["customFlows"]),
            {"passwordless-authentication", "jellyfin-ldap-authentication"},
        )
        self.assertEqual(len(DESIRED["flowStageBindings"]), 5)
        self.assertEqual(set(DESIRED["scopeMappings"]), {"vaultwarden-email"})
        self.assertEqual(set(DESIRED["certificates"]), {"jellyfin-ldap"})
        self.assertEqual(set(DESIRED["ldapProviders"]), {"jellyfin"})
        self.assertEqual(
            set(DESIRED["outposts"]),
            {"authentik-embedded", "jellyfin-ldap"},
        )
        self.assertEqual(
            set(DESIRED["serviceAccounts"]),
            {"jellyfin-ldap-bind", "tailscale-control-proxy"},
        )
        self.assertEqual(
            DESIRED["ldapSearchPermissions"]["jellyfin"]["permission"],
            "authentik_providers_ldap.search_full_directory",
        )
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
        referenced_ldap_ids = {
            str(application["provider_id"])
            for application in DESIRED["applications"].values()
            if application["provider_type"] == "ldap"
        }
        self.assertEqual(referenced_proxy_ids, set(DESIRED["proxyProviders"]))
        self.assertEqual(
            referenced_oauth_ids | set(DESIRED["retainedOAuthProviders"]),
            OAUTH_PROVIDER_IDS,
        )
        self.assertEqual(referenced_ldap_ids, set(DESIRED["ldapProviders"]))
        self.assertTrue(
            all(
                application["import_existing"] == (application["uuid"] is not None)
                for application in DESIRED["applications"].values()
            )
        )
        self.assertTrue(
            all(
                provider["import_existing"] == (provider["pk"] is not None)
                for provider in DESIRED["proxyProviders"].values()
            )
        )
        self.assertEqual(DESIRED["applications"]["jellyfin"]["provider_id"], "jellyfin")
        bound_applications = {
            binding["application_slug"]
            for bindings in (
                DESIRED["applicationPolicyBindings"],
                DESIRED["serviceApplicationBindings"],
            )
            for binding in bindings.values()
        }
        self.assertEqual(bound_applications, set(DESIRED["applications"]))

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

    def test_omada_proxy_forces_http1_upstream(self) -> None:
        provider = DESIRED["proxyProviders"]["23"]
        self.assertEqual(provider["internal_host"], "http://caddy:18043")
        self.assertTrue(provider["internal_host_ssl_validation"])

        caddyfile = (REPO / "services" / "data" / "Caddyfile").read_text()
        self.assertIn(
            """http://:18043 {
\treverse_proxy https://172.23.0.1:8043 {
\t\ttransport http {
\t\t\ttls_insecure_skip_verify
\t\t\tversions 1.1
\t\t}
\t}
}
""",
            caddyfile,
        )

    def test_tailscale_control_proxy_is_private_and_destination_limited(self) -> None:
        provider = DESIRED["proxyProviders"]["tailscale-control"]
        application = DESIRED["applications"]["tailscale-control"]
        account = DESIRED["serviceAccounts"]["tailscale-control-proxy"]
        binding = DESIRED["serviceApplicationBindings"]["tailscale-control-proxy"]

        self.assertFalse(provider["import_existing"])
        self.assertTrue(provider["intercept_header_auth"])
        self.assertEqual(provider["internal_host"], "http://tailscale-control-proxy:8080")
        self.assertEqual(application["provider_id"], "tailscale-control")
        self.assertTrue(application["meta_hide"])
        self.assertIsNone(account["password_ref"])
        self.assertEqual(account["role_refs"], [])
        self.assertEqual(binding["application_slug"], "tailscale-control")
        self.assertEqual(binding["user_ref"], "tailscale-control-proxy")
        self.assertNotIn(
            "tailscale-control",
            {
                policy_binding["application_slug"]
                for policy_binding in DESIRED["applicationPolicyBindings"].values()
            },
        )
        self.assertEqual(
            sum(
                policy_binding["application_slug"] == "tailscale-control"
                for policy_binding in DESIRED["serviceApplicationBindings"].values()
            ),
            1,
        )

        embedded_outpost = DESIRED["outposts"]["authentik-embedded"]
        self.assertTrue(embedded_outpost["import_existing"])
        self.assertEqual(embedded_outpost["type"], "proxy")
        self.assertEqual(
            set(embedded_outpost["provider_refs"]),
            set(DESIRED["proxyProviders"]) - {"tailscale-control"},
        )

        infra = (REPO / "services" / "infra.yml").read_text()
        self.assertIn("gogost/gost:3.3.0@sha256:", infra)
        proxy_service = infra.split("  tailscale-control-proxy:", 1)[1].split("\n  caddy:", 1)[0]
        self.assertNotIn("\n    ports:", proxy_service)
        self.assertIn("      - proxy", proxy_service)

        gost = (REPO / "services" / "data" / "gost" / "tailscale-control.yml").read_text()
        self.assertIn('      - "*.tailscale.com:80"', gost)
        self.assertIn('      - "*.tailscale.com:443"', gost)
        self.assertNotIn("allow all", gost)

        caddyfile = (REPO / "services" / "data" / "Caddyfile").read_text()
        self.assertIn("ts-control.diloreto.com,", caddyfile)

    def test_jellyfin_ldap_runtime_is_private_and_pinned(self) -> None:
        authentik = (REPO / "services" / "authentik.yml").read_text()
        outpost = authentik.split("  authentik-ldap:", 1)[1].split("\nnetworks:", 1)[0]
        self.assertIn(
            "ghcr.io/goauthentik/ldap:2026.8.3@sha256:7114c560be4e24dc61080fe5bd7684cf0ebf4b0a6230a8247943ffa8957b73d4",
            outpost,
        )
        self.assertIn("AUTHENTIK_HOST: http://authentik-server:9000", outpost)
        self.assertIn("AUTHENTIK_TOKEN: ${AUTHENTIK_LDAP_TOKEN:?", outpost)
        self.assertIn("      - jellyfin-auth", outpost)
        self.assertNotIn("\n    ports:", outpost)
        self.assertIn("  jellyfin-auth:\n    internal: true", authentik)

        apps = (REPO / "services" / "apps.yml").read_text()
        jellyfin = apps.split("  jellyfin:", 1)[1].split("\n  calibre:", 1)[0]
        self.assertIn("source: ./data/authentik-ldap-ca.pem", jellyfin)
        self.assertIn("target: /etc/ssl/certs/authentik-ldap.pem", jellyfin)
        self.assertIn("      - jellyfin-auth", jellyfin)
        self.assertEqual(
            (REPO / "services" / "data" / "authentik-ldap-ca.pem").read_text(),
            (ROOT / "jellyfin-ldap.pem").read_text(),
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

    def test_authentik_secrets_are_sops_ciphertext(self) -> None:
        encrypted_text = (ROOT / "client-secrets.sops.json").read_text()
        encrypted = json.loads(encrypted_text)
        self.assertEqual(set(encrypted["oauthProviders"]), OAUTH_PROVIDER_IDS)
        self.assertNotIn("REPLACE-DURING-BOOTSTRAP", encrypted_text)
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", encrypted_text)
        for provider in encrypted["oauthProviders"].values():
            self.assertEqual(set(provider), {"client_secret"})
            self.assertRegex(provider["client_secret"], r"^ENC\[AES256_GCM,")
        self.assertEqual(set(encrypted["ldap"]), {"bind_password", "certificate_private_key"})
        self.assertRegex(encrypted["ldap"]["bind_password"], r"^ENC\[AES256_GCM,")
        self.assertRegex(encrypted["ldap"]["certificate_private_key"], r"^ENC\[AES256_GCM,")
        self.assertIn("sops", encrypted)
        self.assertEqual(len(encrypted["sops"]["age"]), 2)

        certificate = (ROOT / "jellyfin-ldap.pem").read_text()
        self.assertIn("-----BEGIN CERTIFICATE-----", certificate)
        self.assertNotIn("PRIVATE KEY", certificate)

    def test_root_is_import_first_and_secret_aware(self) -> None:
        versions = (ROOT / "versions.tf").read_text()
        variables = (ROOT / "variables.tf").read_text()
        main = (ROOT / "main.tf").read_text()

        self.assertIn('version = "= 2026.8.0"', versions)
        self.assertIn('key          = "home-lab/authentik/tofu.tfstate"', versions)
        self.assertRegex(variables, r'variable "authentik_enable_management"[\s\S]+default\s+= false')
        for resource in (
            "authentik_application",
            "authentik_blueprint",
            "authentik_certificate_key_pair",
            "authentik_flow",
            "authentik_flow_stage_binding",
            "authentik_outpost",
            "authentik_policy_binding",
            "authentik_property_mapping_provider_scope",
            "authentik_provider_ldap",
            "authentik_provider_oauth2",
            "authentik_provider_proxy",
            "authentik_rbac_permission_role",
            "authentik_rbac_role",
            "authentik_stage_authenticator_validate",
            "authentik_user",
        ):
            self.assertIn(f'resource "{resource}"', main)
        self.assertEqual(main.count("prevent_destroy = true"), 16)
        self.assertEqual(main.count("import {"), 10)
        self.assertIn("for_each = local.existing_custom_flows", main)
        self.assertIn("for_each = local.existing_flow_stage_bindings", main)
        self.assertIn("length(local.desired.applicationPolicyBindings) == 28", main)
        self.assertIn("for_each = local.existing_proxy_providers", main)
        self.assertIn("for_each = local.existing_applications", main)
        self.assertIn("data.authentik_stage.default_authentication_login", main)
        self.assertIn("data.authentik_stage.default_authenticator_webauthn_setup", main)
        self.assertIn("local.client_secrets.oauthProviders[each.key].client_secret", main)
        self.assertIn("authentik_property_mapping_provider_scope.scope_mappings", main)
        self.assertIn("local.client_secrets.ldap.certificate_private_key", main)
        self.assertIn("ignore_changes = [client_secret]", main)
        self.assertIn('permission = each.value.permission', main)
        self.assertIn("local.client_secrets.ldap.bind_password", main)
        proxy_block = main[main.index('resource "authentik_provider_proxy"'):main.index('resource "authentik_provider_oauth2"')]
        self.assertNotIn("property_mappings", proxy_block)
        self.assertIn("url      = var.authentik_url", main)
        self.assertIn("token    = var.authentik_token", main)
        self.assertEqual(variables.count("ephemeral = true"), 1)
        self.assertEqual(variables.count("sensitive = true"), 1)

    def test_plan_policy_allowlist_is_exact_for_reviewed_addresses(self) -> None:
        allow = set((REPO / "infrastructure" / "policy" / "allow" / "authentik.txt").read_text().splitlines())
        expected = {
            *(f'authentik_application.applications["{key}"]' for key in DESIRED["applications"]),
            *(f'authentik_certificate_key_pair.certificates["{key}"]' for key in DESIRED["certificates"]),
            *(f'authentik_outpost.outposts["{key}"]' for key in DESIRED["outposts"]),
            *(f'authentik_policy_binding.application_access["{key}"]' for key in DESIRED["applicationPolicyBindings"]),
            *(f'authentik_policy_binding.service_application_access["{key}"]' for key in DESIRED["serviceApplicationBindings"]),
            *(f'authentik_stage_authenticator_validate.custom["{key}"]' for key in DESIRED["authenticatorValidateStages"]),
            *(f'authentik_blueprint.custom["{key}"]' for key in DESIRED["customBlueprints"]),
            *(f'authentik_flow.custom["{key}"]' for key in DESIRED["customFlows"]),
            *(f'authentik_flow_stage_binding.custom["{key}"]' for key in DESIRED["flowStageBindings"]),
            *(f'authentik_provider_ldap.providers["{key}"]' for key in DESIRED["ldapProviders"]),
            *(f'authentik_provider_oauth2.providers["{key}"]' for key in DESIRED["oauthProviders"]),
            *(f'authentik_provider_proxy.providers["{key}"]' for key in DESIRED["proxyProviders"]),
            *(f'authentik_property_mapping_provider_scope.scope_mappings["{key}"]' for key in DESIRED["scopeMappings"]),
            *(f'authentik_rbac_permission_role.ldap_directory_search["{key}"]' for key in DESIRED["ldapSearchPermissions"]),
            *(f'authentik_rbac_role.roles["{key}"]' for key in DESIRED["rbacRoles"]),
            *(f'authentik_user.service_accounts["{key}"]' for key in DESIRED["serviceAccounts"]),
        }
        self.assertEqual(allow, expected)
        self.assertEqual(len(allow), 95)

    def test_prepare_step_protects_sensitive_inputs(self) -> None:
        prepare = (REPO / "scripts" / "prepare-authentik-plan-input").read_text()
        for value in ("AUTHENTIK_URL", "AUTHENTIK_TOKEN", "SOPS_AGE_KEY_FILE", "chmod 0600"):
            self.assertIn(value, prepare)
        self.assertIn("path.is_symlink()", prepare)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", prepare)


if __name__ == "__main__":
    unittest.main()
