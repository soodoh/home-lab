# Every operation, including imports and cleanup, uses a mocked provider.
# Fixtures contain deliberately invalid, synthetic secret material only.
mock_provider "authentik" {
  # Authentik's provider/user IDs are numeric strings, unlike mock defaults.
  mock_resource "authentik_provider_proxy" {
    defaults = { id = "1000" }
  }
  mock_resource "authentik_provider_oauth2" {
    defaults = { id = "2000" }
  }
  mock_resource "authentik_provider_ldap" {
    defaults = { id = "3000" }
  }
  mock_resource "authentik_user" {
    defaults = { id = "6000" }
  }
}

run "disabled_root_has_no_provider_objects" {
  command = plan

  variables {
    authentik_enable_management = false
  }

  assert {
    condition     = length(authentik_group.managed) == 0 && length(authentik_provider_oauth2.providers) == 0 && length(authentik_certificate_key_pair.signing) == 0
    error_message = "A disabled root must not read secret files or manage provider objects."
  }
}

run "authentication_and_onboarding_preserve_behavior" {
  command = apply

  variables {
    authentik_enable_management   = true
    authentik_client_secrets_path = "tests/fixtures/client-secrets.json"
    authentik_signing_keys_path   = "tests/fixtures/signing-keys.json"
  }

  override_data {
    target = data.authentik_user.group_members["carodilo"]
    values = { pk = 5000 }
  }

  override_data {
    target = data.authentik_user.group_members["eabbado"]
    values = { pk = 5001 }
  }

  override_data {
    target = data.authentik_user.group_members["parents"]
    values = { pk = 5002 }
  }

  override_data {
    target = data.authentik_user.group_members["paul"]
    values = { pk = 5003 }
  }

  override_data {
    target = data.authentik_user.group_members["sarabeth"]
    values = { pk = 5004 }
  }

  override_resource {
    target = authentik_certificate_key_pair.signing["grimmory-oidc"]
    values = { id = "synthetic-grimmory-signer" }
  }

  override_resource {
    target = authentik_certificate_key_pair.signing["jellyfin-oidc"]
    values = { id = "synthetic-existing-signer" }
  }

  assert {
    condition = (
      !contains(keys(local.existing_oauth_providers), "grimmory") &&
      tostring(authentik_application.applications["grimmory"].protocol_provider) == authentik_provider_oauth2.providers["grimmory"].id &&
      authentik_policy_binding.application_access["96719d44-e9d4-468b-8bc6-350014c4f846"].group == authentik_group.managed["cwa-users"].id &&
      authentik_provider_oauth2.providers["grimmory"].client_type == "confidential" &&
      authentik_provider_oauth2.providers["grimmory"].sub_mode == "user_uuid" &&
      !contains(keys(local.existing_signing_certificates), "grimmory-oidc") &&
      authentik_provider_oauth2.providers["grimmory"].signing_key == authentik_certificate_key_pair.signing["grimmory-oidc"].id &&
      toset(authentik_provider_oauth2.providers["grimmory"].grant_types) == toset(["authorization_code", "refresh_token"])
    )
    error_message = "Grimmory must create a separate signed OIDC client without importing an invented ID or widening membership."
  }

  assert {
    condition = (
      length(local.existing_signing_certificates) == 1 &&
      length(authentik_certificate_key_pair.signing) == 2 &&
      authentik_certificate_key_pair.signing["grimmory-oidc"].id != authentik_certificate_key_pair.signing["jellyfin-oidc"].id &&
      authentik_certificate_key_pair.signing["grimmory-oidc"].certificate_data == "${file("${path.module}/grimmory-oidc.pem")}\n" &&
      authentik_certificate_key_pair.signing["grimmory-oidc"].key_data == "${jsondecode(file(var.authentik_signing_keys_path)).certificates["grimmory-oidc"].private_key}\n"
    )
    error_message = "The new signer must remain separately owned, supplied from its matching encrypted authority, and excluded from imports."
  }

  assert {
    condition     = authentik_stage_identification.managed["default-authentication-identification"].webauthn_stage == authentik_stage_authenticator_validate.custom["passwordless-webauthn"].id
    error_message = "Identification must reference the owned passwordless validator."
  }

  assert {
    condition     = authentik_stage_identification.managed["default-authentication-identification"].passwordless_flow == authentik_flow.custom["passwordless-authentication"].uuid
    error_message = "Identification must preserve its existing passwordless flow selection."
  }

  assert {
    condition     = length(authentik_stage_authenticator_validate.custom["passwordless-webauthn"].configuration_stages) == 1 && toset(authentik_stage_authenticator_validate.custom["passwordless-webauthn"].configuration_stages) == toset([authentik_stage_authenticator_webauthn.managed["default-authenticator-webauthn-setup"].id])
    error_message = "Passwordless configuration must reference the owned WebAuthn setup stage."
  }

  assert {
    condition     = authentik_stage_authenticator_webauthn.managed["default-authenticator-webauthn-setup"].resident_key_requirement == "required" && authentik_stage_authenticator_webauthn.managed["default-authenticator-webauthn-setup"].max_attempts == 3
    error_message = "Passkey enrollment must retain resident keys and its attempt limit."
  }

  assert {
    condition     = authentik_stage_authenticator_validate.custom["default-authentication-mfa-validation"].not_configured_action == "skip" && length(authentik_stage_authenticator_validate.custom["default-authentication-mfa-validation"].configuration_stages) == 0
    error_message = "Adoption must not introduce mandatory MFA enrollment."
  }

  assert {
    condition     = !authentik_group.managed["jellyfin"].is_superuser && length(authentik_group.managed["jellyfin"].users) == 5 && toset(authentik_group.managed["jellyfin"].users) == toset([for username in local.group_usernames_by_key["jellyfin"] : data.authentik_user.group_members[username].pk])
    error_message = "Group membership must resolve all declared independent users without elevation."
  }

  assert {
    condition = alltrue([for key, members in {
      "jellyfin"           = [5000, 5001, 5002, 5003, 5004]
      "karaoke-users"      = [5000, 5001, 5002, 5003, 5004]
      "caro-library-users" = [5000, 5001]
      "cwa-users"          = [5003, 5004]
      "camera-viewers"     = [5003, 5004]
      "vaultwarden-users"  = [5003, 5004]
      "app-operators"      = [5003]
    } : toset(authentik_group.managed[key].users) == toset(members)])
    error_message = "Application entitlements must grant the exact reviewed user sets, including negative membership cases."
  }

  assert {
    condition = alltrue([for group_key, binding_key in {
      "karaoke-users"      = "b3104c79-adca-4847-b398-aaa7130cf25a"
      "caro-library-users" = "2cde7ad7-35ee-4ff2-8c90-1edcc83f3e89"
      "cwa-users"          = "cbbb8d4b-444e-4897-b915-2507a85334d4"
      "camera-viewers"     = "9fcefd65-0127-45d3-8d48-31e7e0804683"
      "vaultwarden-users"  = "182dbb79-78ab-4144-9625-8b042e985eaa"
    } : authentik_policy_binding.application_access[binding_key].group == authentik_group.managed[group_key].id && authentik_policy_binding.application_access[binding_key].user == null && !authentik_policy_binding.application_access[binding_key].negate])
    error_message = "New application grants must depend on the managed groups, not direct-user exceptions."
  }

  assert {
    condition     = alltrue([for key, group in authentik_group.managed : !group.is_superuser && length(group.parents) == 0 && (key == "jellyfin" || length(group.roles) == 0)])
    error_message = "Access groups must never inherit administrator privileges or acquire management roles."
  }

  assert {
    condition     = alltrue([for key in ["01d9c9fd-76de-4dc9-a0bf-01601f45fd40", "1176cdca-c642-4ab2-8fbb-b6eac0c6747b", "1997e1fe-2984-44b9-9bfe-db909b7f3460", "22bba89f-b249-414e-930a-a134dc186e32", "279dc5f4-217e-4e8b-a133-6574658c1c6d", "2d15e29a-fcae-4d1d-92ce-5a91ec3cd729", "34040ade-1660-472a-b829-b5312fafea04", "3907558a-efb8-4763-a976-6f2ebf335f81", "3fd79f0a-54bc-4e79-8f2d-1199d52319b9", "48004f36-36ef-45ac-9048-7cb2a67538bc", "51edd5fa-d699-4811-b67e-6d85356fc452", "55c6d390-dc40-49cf-b2a2-3a869a23b298", "7a201cfb-c8c5-422e-9804-9771e4827999", "a6a50029-e999-4bfa-8ece-737ed5ec8ebc", "c3c48745-5dd7-4325-a288-745b058442e8", "d10e3ec4-1aae-4df9-901b-807cc08eb100", "dd1bfef2-fc1c-4ada-adee-f7f0d242f0de", "e1f79e5c-85e3-47f1-b94c-c49cb4442f05", "e7747d8a-8153-49f0-948a-140bee74c6d1"] : authentik_policy_binding.application_access[key].group == authentik_group.managed["app-operators"].id])
    error_message = "Every reviewed operator application must use the Paul-only group without depending on Authentik administration."
  }

  assert {
    condition     = alltrue([for binding in authentik_policy_binding.application_access : contains([for group in authentik_group.managed : group.id], binding.group) && binding.user == null])
    error_message = "Human application access must depend only on owned non-superuser groups."
  }

  assert {
    condition     = !authentik_stage_invitation.managed["enrollment-invitation"].continue_flow_without_invitation && authentik_flow_stage_binding.custom["enrollment-invitation"].order == 1 && authentik_flow_stage_binding.custom["enrollment-login"].order == 100
    error_message = "Onboarding must start with a mandatory invitation and end with login."
  }

  assert {
    condition     = authentik_stage_user_write.managed["enrollment-write"].create_users_group == authentik_group.managed["jellyfin"].id && authentik_stage_user_write.managed["enrollment-write"].user_creation_mode == "always_create" && !authentik_stage_user_write.managed["enrollment-write"].create_users_as_inactive
    error_message = "Onboarding must create active users in the owned application group."
  }

  assert {
    condition     = alltrue([for stage in authentik_stage_prompt.managed : length(stage.validation_policies) == 0]) && authentik_policy_password.managed["password-change"].length_min == 8 && authentik_policy_password.managed["password-change"].check_zxcvbn
    error_message = "Adoption must preserve, not silently strengthen, existing password-policy attachment."
  }

  assert {
    condition     = jsondecode(authentik_system_settings.managed["default"].flags).core_default_app_access && authentik_brand.managed["default"].flow_authentication == data.authentik_flow.referenced["default-authentication-flow"].id
    error_message = "Effective system defaults and the brand's authentication selector must be preserved."
  }

  assert {
    condition     = authentik_provider_oauth2.providers["15"].signing_key == authentik_certificate_key_pair.signing["jellyfin-oidc"].id && authentik_provider_oauth2.providers["47"].signing_key == local.desired.oauthProviders["47"].signing_key
    error_message = "Only the independently adopted signing key becomes owned; discovery-owned signing material remains external."
  }

  assert {
    condition     = authentik_certificate_key_pair.signing["jellyfin-oidc"].certificate_data == "${file("${path.module}/jellyfin-oidc.pem")}\n" && authentik_certificate_key_pair.signing["jellyfin-oidc"].key_data == "${jsondecode(file(var.authentik_signing_keys_path)).certificates["jellyfin-oidc"].private_key}\n"
    error_message = "PEM comparison must match the pinned reader's appended newline without rotating material."
  }
}
