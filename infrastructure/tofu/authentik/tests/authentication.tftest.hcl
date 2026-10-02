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
