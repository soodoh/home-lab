locals {
  groups                = var.authentik_enable_management ? local.desired.groups : {}
  identification_stages = var.authentik_enable_management ? local.desired.identificationStages : {}
  webauthn_stages       = var.authentik_enable_management ? local.desired.webauthnStages : {}
  invitation_stages     = var.authentik_enable_management ? local.desired.invitationStages : {}
  prompt_fields         = var.authentik_enable_management ? local.desired.promptFields : {}
  prompt_stages         = var.authentik_enable_management ? local.desired.promptStages : {}
  user_write_stages     = var.authentik_enable_management ? local.desired.userWriteStages : {}
  user_login_stages     = var.authentik_enable_management ? local.desired.userLoginStages : {}
  password_policies     = var.authentik_enable_management ? local.desired.passwordPolicies : {}
  brands                = var.authentik_enable_management ? local.desired.brands : {}
  system_settings       = var.authentik_enable_management ? local.desired.systemSettings : {}
  signing_certificates  = var.authentik_enable_management ? local.desired.signingCertificates : {}
  signing_keys = var.authentik_enable_management ? jsondecode(file(var.authentik_signing_keys_path)) : {
    schemaVersion = 1
    certificates  = {}
  }

  group_member_usernames = toset(flatten([for group in values(local.groups) : group.member_usernames]))
  group_ids_by_pk        = { for key, group in local.groups : group.pk => authentik_group.managed[key].id }
  flow_ids_by_pk         = { for key, flow in local.custom_flows : flow.pk => authentik_flow.custom[key].uuid if try(flow.pk, null) != null }
  referenced_flow_slugs = toset(concat(
    [for stage in values(local.webauthn_stages) : stage.configure_flow_slug],
    flatten([for brand in values(local.brands) : [
      brand.flow_authentication_slug, brand.flow_invalidation_slug, brand.flow_user_settings_slug
    ]])
  ))
  managed_stage_ids = !var.authentik_enable_management ? {} : merge(
    {
      "passwordless-webauthn"                 = authentik_stage_authenticator_validate.custom["passwordless-webauthn"].id
      "default-authentication-identification" = authentik_stage_identification.managed["default-authentication-identification"].id
      "default-authentication-password"       = data.authentik_stage.default_authentication_password[0].id
      "default-authentication-login"          = data.authentik_stage.default_authentication_login[0].id
    },
    { for key, stage in authentik_stage_invitation.managed : key => stage.id },
    { for key, stage in authentik_stage_prompt.managed : key => stage.id },
    { for key, stage in authentik_stage_user_write.managed : key => stage.id },
    { for key, stage in authentik_stage_user_login.managed : key => stage.id }
  )
}

check "authentication_ownership" {
  assert {
    condition = (
      length(local.desired.groups) == 1 &&
      length(local.desired.identificationStages) == 1 &&
      length(local.desired.webauthnStages) == 1 &&
      length(local.desired.invitationStages) == 1 &&
      length(local.desired.promptFields) == 5 &&
      length(local.desired.promptStages) == 2 &&
      length(local.desired.userWriteStages) == 1 &&
      length(local.desired.userLoginStages) == 1 &&
      length(local.desired.passwordPolicies) == 1 &&
      length(local.desired.brands) == 1 &&
      length(local.desired.systemSettings) == 1 &&
      length(local.desired.signingCertificates) == 1 &&
      alltrue([for group in values(local.desired.groups) :
        !group.is_superuser && length(group.member_usernames) == length(distinct(group.member_usernames))
      ])
    )
    error_message = "Authentication ownership must include the reviewed group, onboarding path, passkey settings, security defaults and signing certificate; never elevate the application group."
  }
}

check "signing_key_custody" {
  assert {
    condition = !var.authentik_enable_management || (
      local.signing_keys.schemaVersion == 1 &&
      toset(keys(local.signing_keys.certificates)) == toset(keys(local.signing_certificates)) &&
      alltrue([for certificate in values(local.signing_keys.certificates) :
        startswith(certificate.private_key, "-----BEGIN ") && trimspace(certificate.private_key) != ""
      ])
    )
    error_message = "Every managed signing certificate must have private key material from the protected SOPS signing-key input."
  }
}

data "authentik_user" "group_members" {
  for_each = local.group_member_usernames
  username = each.key
}

data "authentik_flow" "referenced" {
  for_each = local.referenced_flow_slugs
  slug     = each.key
}

resource "authentik_group" "managed" {
  for_each = local.groups

  name         = each.value.name
  attributes   = jsonencode(each.value.attributes)
  is_superuser = each.value.is_superuser
  parents      = each.value.parents
  roles        = each.value.roles
  users        = [for username in each.value.member_usernames : data.authentik_user.group_members[username].pk]

  lifecycle {
    precondition {
      condition = length(distinct([
        for username in each.value.member_usernames : data.authentik_user.group_members[username].pk
      ])) == length(each.value.member_usernames)
      error_message = "Every declared application-group member must resolve to a distinct independently owned user."
    }
  }
}

resource "authentik_stage_identification" "managed" {
  for_each = local.identification_stages

  name                      = each.value.name
  user_fields               = each.value.user_fields
  password_stage            = each.value.password_stage
  captcha_stage             = each.value.captcha_stage
  webauthn_stage            = authentik_stage_authenticator_validate.custom[each.value.webauthn_stage_ref].id
  case_insensitive_matching = each.value.case_insensitive_matching
  show_matched_user         = each.value.show_matched_user
  pretend_user_exists       = each.value.pretend_user_exists
  enable_remember_me        = each.value.enable_remember_me
  show_source_labels        = each.value.show_source_labels
  enrollment_flow           = each.value.enrollment_flow
  recovery_flow             = each.value.recovery_flow
  passwordless_flow         = try(local.flow_ids_by_pk[each.value.passwordless_flow], each.value.passwordless_flow)
  sources                   = each.value.sources
}

resource "authentik_stage_authenticator_webauthn" "managed" {
  for_each = local.webauthn_stages

  name                     = each.value.name
  configure_flow           = data.authentik_flow.referenced[each.value.configure_flow_slug].id
  friendly_name            = each.value.friendly_name
  user_verification        = each.value.user_verification
  resident_key_requirement = each.value.resident_key_requirement
  authenticator_attachment = each.value.authenticator_attachment
  hints                    = each.value.hints
  max_attempts             = each.value.max_attempts
  device_type_restrictions = each.value.device_type_restrictions
}

resource "authentik_stage_invitation" "managed" {
  for_each = local.invitation_stages

  name                             = each.value.name
  continue_flow_without_invitation = each.value.continue_flow_without_invitation
}

resource "authentik_stage_prompt_field" "managed" {
  for_each = local.prompt_fields

  name                     = each.value.name
  field_key                = each.value.field_key
  label                    = each.value.label
  type                     = each.value.type
  required                 = each.value.required
  placeholder              = each.value.placeholder
  initial_value            = each.value.initial_value
  sub_text                 = each.value.sub_text
  order                    = each.value.order
  placeholder_expression   = each.value.placeholder_expression
  initial_value_expression = each.value.initial_value_expression
}

resource "authentik_stage_prompt" "managed" {
  for_each = local.prompt_stages

  name                = each.value.name
  fields              = [for field_ref in each.value.field_refs : authentik_stage_prompt_field.managed[field_ref].id]
  validation_policies = [for policy_ref in each.value.validation_policy_refs : authentik_policy_password.managed[policy_ref].id]
}

resource "authentik_stage_user_write" "managed" {
  for_each = local.user_write_stages

  name                     = each.value.name
  user_creation_mode       = each.value.user_creation_mode
  create_users_as_inactive = each.value.create_users_as_inactive
  create_users_group       = authentik_group.managed[each.value.create_users_group_ref].id
  user_type                = each.value.user_type
  user_path_template       = each.value.user_path_template
}

resource "authentik_stage_user_login" "managed" {
  for_each = local.user_login_stages

  name                     = each.value.name
  session_duration         = each.value.session_duration
  network_binding          = each.value.network_binding
  geoip_binding            = each.value.geoip_binding
  terminate_other_sessions = each.value.terminate_other_sessions
  remember_me_offset       = each.value.remember_me_offset
  remember_device          = each.value.remember_device

  lifecycle {
    # Provider 2026.8.0 writes these fields but does not read them. The plan
    # preflight independently checks them against desired state; do not hide drift.
    ignore_changes = [network_binding, geoip_binding]
  }
}

resource "authentik_policy_password" "managed" {
  for_each = local.password_policies

  name                    = each.value.name
  execution_logging       = each.value.execution_logging
  password_field          = each.value.password_field
  check_static_rules      = each.value.check_static_rules
  check_have_i_been_pwned = each.value.check_have_i_been_pwned
  check_zxcvbn            = each.value.check_zxcvbn
  amount_digits           = each.value.amount_digits
  amount_uppercase        = each.value.amount_uppercase
  amount_lowercase        = each.value.amount_lowercase
  amount_symbols          = each.value.amount_symbols
  length_min              = each.value.length_min
  symbol_charset          = each.value.symbol_charset
  error_message           = each.value.error_message
  hibp_allowed_count      = each.value.hibp_allowed_count
  zxcvbn_score_threshold  = each.value.zxcvbn_score_threshold
}

resource "authentik_brand" "managed" {
  for_each = local.brands

  domain                           = each.value.domain
  default                          = each.value.default
  branding_title                   = each.value.branding_title
  branding_logo                    = each.value.branding_logo
  branding_favicon                 = each.value.branding_favicon
  branding_custom_css              = each.value.branding_custom_css
  branding_default_flow_background = each.value.branding_default_flow_background
  attributes                       = jsonencode(each.value.attributes)
  client_certificates              = each.value.client_certificates
  flow_authentication              = data.authentik_flow.referenced[each.value.flow_authentication_slug].id
  flow_invalidation                = data.authentik_flow.referenced[each.value.flow_invalidation_slug].id
  flow_user_settings               = data.authentik_flow.referenced[each.value.flow_user_settings_slug].id
  flow_device_code                 = each.value.flow_device_code
  flow_lockdown                    = each.value.flow_lockdown
  flow_recovery                    = each.value.flow_recovery
  flow_unenrollment                = each.value.flow_unenrollment
  web_certificate                  = each.value.web_certificate
  default_application              = each.value.default_application
}

resource "authentik_system_settings" "managed" {
  for_each = local.system_settings

  avatars                      = each.value.avatars
  default_user_change_name     = each.value.default_user_change_name
  default_user_change_email    = each.value.default_user_change_email
  default_user_change_username = each.value.default_user_change_username
  default_token_duration       = each.value.default_token_duration
  default_token_length         = each.value.default_token_length
  event_retention              = each.value.event_retention
  footer_links                 = each.value.footer_links
  gdpr_compliance              = each.value.gdpr_compliance
  impersonation                = each.value.impersonation
  pagination_default_page_size = each.value.pagination_default_page_size
  pagination_max_page_size     = each.value.pagination_max_page_size
  reputation_lower_limit       = each.value.reputation_lower_limit
  reputation_upper_limit       = each.value.reputation_upper_limit
  flags                        = jsonencode(each.value.flags)
}

resource "authentik_certificate_key_pair" "signing" {
  for_each = local.signing_certificates

  name = each.value.name
  # The pinned reader appends a newline to both native PEM exports.
  certificate_data = "${file("${path.module}/${each.value.certificate_file}")}\n"
  key_data         = "${local.signing_keys.certificates[each.key].private_key}\n"
}
