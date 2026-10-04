#!/usr/bin/env python3

import copy
import json
from pathlib import Path
import subprocess
import unittest

from jsonschema import Draft202012Validator


REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "infrastructure" / "tofu" / "authentik"
DESIRED = json.loads((ROOT / "desired.json").read_text())
OAUTH_PROVIDER_IDS = {"15", "21", "37", "47", "grimmory"}


class AuthentikTofuFoundationTests(unittest.TestCase):
    def test_desired_inventory_is_complete(self) -> None:
        self.assertEqual(DESIRED["schemaVersion"], 6)
        self.assertNotIn("sourceInventory", DESIRED)
        self.assertEqual(len(DESIRED["applications"]), 23)
        self.assertEqual(len(DESIRED["proxyProviders"]), 18)
        self.assertEqual(set(DESIRED["oauthProviders"]), OAUTH_PROVIDER_IDS)
        self.assertEqual(DESIRED["retainedOAuthProviders"], ["15"])
        self.assertEqual(len(DESIRED["applicationPolicyBindings"]), 27)
        self.assertEqual(set(DESIRED["authenticatorValidateStages"]), {
            "passwordless-webauthn", "default-authentication-mfa-validation",
        })
        self.assertEqual(
            set(DESIRED["customFlows"]),
            {"passwordless-authentication", "jellyfin-ldap-authentication", "invitation-enrollment"},
        )
        self.assertEqual(len(DESIRED["flowStageBindings"]), 10)
        self.assertEqual(set(DESIRED["scopeMappings"]), {"vaultwarden-email"})
        self.assertEqual(set(DESIRED["certificates"]), {"jellyfin-ldap"})
        self.assertEqual(set(DESIRED["ldapProviders"]), {"jellyfin"})
        self.assertEqual(
            set(DESIRED["outposts"]),
            {"authentik-embedded", "jellyfin-ldap"},
        )
        self.assertEqual(
            set(DESIRED["serviceAccounts"]),
            {"jellyfin-ldap-bind", "gost-proxy-user"},
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
        self.assertEqual(
            DESIRED["applications"]["radarr-4k"]["meta_launch_url"],
            DESIRED["proxyProviders"]["8"]["external_host"],
        )
        bound_applications = {
            binding["application_slug"]
            for bindings in (
                DESIRED["applicationPolicyBindings"],
                DESIRED["serviceApplicationBindings"],
            )
            for binding in bindings.values()
        }
        self.assertEqual(bound_applications, set(DESIRED["applications"]))

    def test_desired_inventory_validates_against_native_json_schema(self) -> None:
        schema = json.loads((ROOT / "desired.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(DESIRED)
        elevated = copy.deepcopy(DESIRED)
        elevated["groups"]["jellyfin"]["is_superuser"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(elevated)))
        unowned_field = copy.deepcopy(DESIRED)
        unowned_field["systemSettings"]["default"]["base_url"] = "https://example.invalid"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(unowned_field)))

    def test_authentication_and_enrollment_preserve_reviewed_behavior(self) -> None:
        group = DESIRED["groups"]["jellyfin"]
        self.assertFalse(group["is_superuser"])
        members = DESIRED["membershipSets"][group["membership_set"]]
        self.assertEqual(len(members), 5)
        self.assertEqual(len(members), len(set(members)))
        identification = DESIRED["identificationStages"]["default-authentication-identification"]
        self.assertEqual(identification["webauthn_stage_ref"], "passwordless-webauthn")
        self.assertIsNone(identification["enrollment_flow"])
        webauthn = DESIRED["webauthnStages"]["default-authenticator-webauthn-setup"]
        self.assertEqual(webauthn["resident_key_requirement"], "required")
        self.assertEqual(webauthn["max_attempts"], 3)
        self.assertEqual(DESIRED["authenticatorValidateStages"]["default-authentication-mfa-validation"]["not_configured_action"], "skip")
        self.assertFalse(DESIRED["invitationStages"]["enrollment-invitation"]["continue_flow_without_invitation"])
        writer = DESIRED["userWriteStages"]["enrollment-write"]
        self.assertEqual(writer["create_users_group_ref"], "jellyfin")
        self.assertEqual(writer["user_creation_mode"], "always_create")
        self.assertFalse(writer["create_users_as_inactive"])
        bindings = sorted((b for b in DESIRED["flowStageBindings"].values()
                           if b["flow_ref"] == "invitation-enrollment"), key=lambda b: b["order"])
        self.assertEqual([b["stage_ref"] for b in bindings], [
            "enrollment-invitation", "enrollment-first", "enrollment-second", "enrollment-write", "enrollment-login",
        ])
        for stage in DESIRED["promptStages"].values():
            self.assertEqual(stage["validation_policy_refs"], [])
            self.assertTrue(set(stage["field_refs"]) <= set(DESIRED["promptFields"]))
        self.assertTrue(DESIRED["systemSettings"]["default"]["flags"]["core_default_app_access"])
        self.assertNotIn("eventRules", DESIRED)

    def test_access_entitlements_preserve_the_authorized_matrix(self) -> None:
        family = {"paul", "eabbado", "parents", "sarabeth", "carodilo"}
        expected = {
            "jellyfin": family, "seerr": family, "karaoke-eternal": family,
            "caro-tachidesk": {"carodilo", "eabbado"},
            "calibre-web-automated": {"paul", "sarabeth"},
            "grimmory": {"paul", "sarabeth"},
            "frigate": {"paul", "sarabeth"}, "vaultwarden": {"paul", "sarabeth"},
        }
        groups = {value["pk"]: value for value in DESIRED["groups"].values()}
        for slug, members in expected.items():
            bindings = [value for value in DESIRED["applicationPolicyBindings"].values()
                        if value["application_slug"] == slug]
            granted = set()
            for binding in bindings:
                self.assertTrue(binding["enabled"])
                self.assertFalse(binding["negate"])
                self.assertIsNone(binding["user"], "Direct-user grants bypass membership revocation")
                if binding["group"] in groups and binding["group"] != DESIRED["groups"]["app-operators"]["pk"]:
                    group = groups[binding["group"]]
                    granted.update(DESIRED["membershipSets"][group["membership_set"]])
            self.assertEqual(granted, members, slug)
            self.assertEqual(DESIRED["applications"][slug]["policy_engine_mode"], "any")
        for key, group in DESIRED["groups"].items():
            self.assertFalse(group["is_superuser"])
            self.assertEqual(group["parents"], [])
            if key != "jellyfin":
                self.assertEqual(group["roles"], [])
        self.assertEqual(DESIRED["groups"]["jellyfin"]["name"], "Jellyfin")
        self.assertEqual(DESIRED["groups"]["jellyfin"]["pk"], "7cc8f9fe-b4e6-4762-be05-263403a828e9")

    def test_operator_access_is_separate_from_authentik_administration(self) -> None:
        group = DESIRED["groups"]["app-operators"]
        self.assertEqual(group["name"], "App Operators")
        self.assertEqual(DESIRED["membershipSets"][group["membership_set"]], ["paul"])
        self.assertFalse(group["is_superuser"])
        self.assertEqual(group["parents"], [])
        self.assertEqual(group["roles"], [])
        self.assertEqual({binding["application_slug"] for binding in DESIRED["applicationPolicyBindings"].values()
                          if binding["group"] == group["pk"]}, {"calibre","calibre-web-automated","caro-tachidesk","ddns-updater","frigate","hass-oidc","karaoke-eternal","mindwtr","openfit","prowlarr","qbittorrent","radarr","radarr-4k","readarr","sabnzbd","sonarr","tachidesk","vaultwarden","zwave"})
        owned_groups = {value["pk"] for value in DESIRED["groups"].values()}
        self.assertTrue(all(binding["group"] in owned_groups and binding["user"] is None
                            for binding in DESIRED["applicationPolicyBindings"].values()))

    def test_mindwtr_remains_a_web_only_forward_auth_gate(self) -> None:
        app = DESIRED["applications"]["mindwtr"]
        provider = DESIRED["proxyProviders"]["mindwtr"]
        bindings = [v for v in DESIRED["applicationPolicyBindings"].values()
                    if v["application_slug"] == "mindwtr"]
        self.assertEqual(app["provider_id"], "mindwtr")
        self.assertFalse(app["import_existing"])
        self.assertTrue(app["meta_hide"])
        self.assertEqual(provider["mode"], "forward_single")
        self.assertEqual(provider["external_host"], "https://todo.diloreto.com")
        self.assertEqual(provider["internal_host"], "http://mindwtr-app:5173")
        self.assertTrue(provider["intercept_header_auth"])
        self.assertFalse(provider["import_existing"])
        self.assertEqual(DESIRED["outposts"]["authentik-embedded"]["provider_refs"].count("mindwtr"), 1)
        self.assertEqual(len(bindings), 1)
        self.assertEqual(
            {key for key, value in DESIRED["applicationPolicyBindings"].items() if value["pk"] is None and value["application_slug"] == "mindwtr"},
            {"e1f79e5c-85e3-47f1-b94c-c49cb4442f05"},
        )
        self.assertTrue(bindings[0]["group"])

    def test_omada_has_no_public_authentik_route(self) -> None:
        self.assertNotIn("omada", DESIRED["applications"])
        self.assertNotIn("23", DESIRED["proxyProviders"])
        self.assertNotIn("23", DESIRED["outposts"]["authentik-embedded"]["provider_refs"])
        self.assertFalse(any(
            binding["application_slug"] == "omada"
            for binding in DESIRED["applicationPolicyBindings"].values()
        ))

    def test_proxmox_is_not_an_authentik_app(self) -> None:
        self.assertNotIn("proxmox", DESIRED["applications"])
        self.assertNotIn("18", DESIRED["proxyProviders"])
        self.assertNotIn("18", DESIRED["outposts"]["authentik-embedded"]["provider_refs"])
        self.assertFalse(any(
            binding["application_slug"] == "proxmox"
            for binding in DESIRED["applicationPolicyBindings"].values()
        ))

    def test_zwave_keeps_its_access_policy_on_the_private_hostname(self) -> None:
        app = DESIRED["applications"]["zwave"]
        provider = DESIRED["proxyProviders"]["20"]
        self.assertEqual(app["provider_id"], 20)
        self.assertEqual(app["meta_launch_url"], "https://zwave.ts.diloreto.com")
        self.assertEqual(provider["external_host"], app["meta_launch_url"])
        self.assertEqual(provider["mode"], "proxy")
        self.assertEqual(provider["internal_host"], "http://zwave:8091")
        self.assertIn("20", DESIRED["outposts"]["authentik-embedded"]["provider_refs"])
        self.assertEqual(
            [binding["group"] for binding in DESIRED["applicationPolicyBindings"].values()
             if binding["application_slug"] == "zwave"],
            [DESIRED["groups"]["app-operators"]["pk"]],
        )

    def test_omada_bridge_advertises_reachable_host(self) -> None:
        network = json.loads((REPO / "infrastructure/tofu/omada/desired.json").read_text())["network"]
        self.assertEqual(network["dhcp_options"], [{"code": 138, "value": "192.168.0.100"}])
        infra = (REPO / "services/infra.yml").read_text()
        omada = infra.split("  omada:", 1)[1].split("\n  ddns-updater:", 1)[0]
        self.assertNotIn("network_mode: host", omada)
        self.assertIn("      - omada-backend", omada)
        self.assertNotIn("      - proxy", omada)
        self.assertIn("127.0.0.1:8043:8043", omada)
        self.assertIn("29810:29810/udp", omada)
        self.assertIn("29811-29817:29811-29817", omada)

    def test_tailscale_control_proxy_is_private_and_destination_limited(self) -> None:
        provider = DESIRED["proxyProviders"]["tailscale-control"]
        application = DESIRED["applications"]["tailscale-control"]
        account = DESIRED["serviceAccounts"]["gost-proxy-user"]
        binding = DESIRED["serviceApplicationBindings"]["gost-proxy-user"]

        self.assertFalse(provider["import_existing"])
        self.assertTrue(provider["intercept_header_auth"])
        self.assertEqual(provider["internal_host"], "http://tailscale-control-proxy:8080")
        self.assertEqual(provider["external_host"], "https://gost.diloreto.com")
        self.assertEqual(application["provider_id"], "tailscale-control")
        self.assertEqual(account["username"], "gost-proxy-user")
        self.assertTrue(application["meta_hide"])
        self.assertIsNone(account["password_ref"])
        self.assertEqual(account["role_refs"], [])
        self.assertEqual(binding["application_slug"], "tailscale-control")
        self.assertEqual(binding["user_ref"], "gost-proxy-user")
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
            set(DESIRED["proxyProviders"]),
        )

        infra = (REPO / "services" / "infra.yml").read_text()
        self.assertIn("gogost/gost:3.3.0@sha256:", infra)
        proxy_service = infra.split("  tailscale-control-proxy:", 1)[1].split("\n  traefik:", 1)[0]
        self.assertNotIn("\n    ports:", proxy_service)
        self.assertIn("      - proxy", proxy_service)

    def test_jellyfin_ldap_runtime_is_private_and_pinned(self) -> None:
        authentik = (REPO / "services" / "authentik.yml").read_text()
        outpost = authentik.split("  authentik-ldap:", 1)[1].split("\nnetworks:", 1)[0]
        self.assertIn(
            "ghcr.io/goauthentik/ldap:2026.8.3@sha256:7114c560be4e24dc61080fe5bd7684cf0ebf4b0a6230a8247943ffa8957b73d4",
            outpost,
        )
        self.assertIn("AUTHENTIK_HOST: http://authentik-server:9000", outpost)
        self.assertIn("AUTHENTIK_TOKEN: file:///run/secrets/authentik_ldap_token", outpost)
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

    def test_signing_material_has_separate_encrypted_custody(self) -> None:
        encrypted_text = (ROOT / "signing-keys.sops.json").read_text()
        encrypted = json.loads(encrypted_text)
        self.assertEqual(set(encrypted["certificates"]), set(DESIRED["signingCertificates"]))
        self.assertEqual(len(encrypted["sops"]["age"]), 2)
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", encrypted_text)
        self.assertNotIn("-----BEGIN RSA PRIVATE KEY-----", encrypted_text)
        for value in encrypted["certificates"].values():
            self.assertEqual(set(value), {"private_key"})
            self.assertRegex(value["private_key"], r"^ENC\[AES256_GCM,")
        for value in DESIRED["signingCertificates"].values():
            certificate = (ROOT / value["certificate_file"]).read_text()
            self.assertIn("-----BEGIN CERTIFICATE-----", certificate)
            self.assertNotIn("PRIVATE KEY", certificate)
        self.assertEqual(DESIRED["oauthProviders"]["15"]["signing_key"], DESIRED["signingCertificates"]["jellyfin-oidc"]["pk"])
        self.assertIsNone(DESIRED["signingCertificates"]["grimmory-oidc"]["pk"])
        self.assertIsNone(DESIRED["oauthProviders"]["grimmory"]["signing_key"])
        self.assertEqual(DESIRED["oauthProviders"]["grimmory"]["signing_certificate_ref"], "grimmory-oidc")
        self.assertNotIn(DESIRED["oauthProviders"]["47"]["signing_key"],
                         {value["pk"] for value in DESIRED["signingCertificates"].values()})

    def test_grimmory_signer_is_current_rsa_material_without_a_live_identity(self) -> None:
        certificate = ROOT / DESIRED["signingCertificates"]["grimmory-oidc"]["certificate_file"]
        validity = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "2592000"],
            capture_output=True,
        )
        self.assertEqual(validity.returncode, 0, "Prepare and review renewal before the dedicated signer expires.")
        public = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
            capture_output=True, check=True,
        ).stdout
        key = subprocess.run(
            ["openssl", "rsa", "-pubin", "-text", "-noout"], input=public,
            capture_output=True, check=True,
        ).stdout.decode()
        self.assertRegex(key, r"Public-Key: \(4096 bit\)")

    def test_root_is_import_first_and_secret_aware(self) -> None:
        versions = (ROOT / "versions.tf").read_text()
        variables = (ROOT / "variables.tf").read_text()
        main = "\n".join((ROOT / name).read_text() for name in ("main.tf", "authentication.tf", "imports.tf"))

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
        self.assertNotIn("prevent_destroy", main)
        self.assertEqual(main.count("import {"), 22)
        self.assertIn("for_each = local.existing_custom_flows", main)
        self.assertIn("for_each = local.existing_flow_stage_bindings", main)
        self.assertIn("length(local.desired.applicationPolicyBindings) == 27", main)
        self.assertIn("for_each = local.existing_application_policy_bindings", main)
        self.assertIn("for_each = local.existing_proxy_providers", main)
        self.assertIn("for_each = local.existing_applications", main)
        self.assertIn("data.authentik_stage.default_authentication_login", main)
        self.assertIn("authentik_stage_authenticator_webauthn.managed", main)
        self.assertIn("local.client_secrets.oauthProviders[each.key].client_secret", main)
        self.assertIn("authentik_property_mapping_provider_scope.scope_mappings", main)
        self.assertIn("local.client_secrets.ldap.certificate_private_key", main)
        self.assertNotIn("ignore_changes = [client_secret]", main)
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
        for resource_type, resource_name, desired_key in (
            ("authentik_group", "managed", "groups"),
            ("authentik_stage_identification", "managed", "identificationStages"),
            ("authentik_stage_authenticator_webauthn", "managed", "webauthnStages"),
            ("authentik_stage_invitation", "managed", "invitationStages"),
            ("authentik_stage_prompt_field", "managed", "promptFields"),
            ("authentik_stage_prompt", "managed", "promptStages"),
            ("authentik_stage_user_write", "managed", "userWriteStages"),
            ("authentik_stage_user_login", "managed", "userLoginStages"),
            ("authentik_policy_password", "managed", "passwordPolicies"),
            ("authentik_brand", "managed", "brands"),
            ("authentik_system_settings", "managed", "systemSettings"),
            ("authentik_certificate_key_pair", "signing", "signingCertificates"),
        ):
            expected.update(f'{resource_type}.{resource_name}["{key}"]' for key in DESIRED[desired_key])
        self.assertEqual(allow, expected)
        self.assertEqual(len(allow), 123)

    def test_prepare_step_protects_sensitive_inputs(self) -> None:
        prepare = (REPO / "scripts" / "prepare-authentik-plan-input").read_text()
        for value in ("AUTHENTIK_URL", "AUTHENTIK_TOKEN", "SOPS_AGE_KEY_FILE", "chmod 0600"):
            self.assertIn(value, prepare)
        self.assertIn("path.is_symlink()", prepare)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", prepare)


if __name__ == "__main__":
    unittest.main()
