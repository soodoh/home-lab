locals {
  desired = jsondecode(file("${path.module}/desired.json"))
  client_secrets = var.authentik_enable_management ? jsondecode(file(var.authentik_client_secrets_path)) : {
    schemaVersion  = 2
    oauthProviders = {}
    ldap           = {}
  }

  applications                  = var.authentik_enable_management ? local.desired.applications : {}
  application_policy_bindings   = var.authentik_enable_management ? local.desired.applicationPolicyBindings : {}
  authenticator_validate_stages = var.authentik_enable_management ? local.desired.authenticatorValidateStages : {}
  certificates                  = var.authentik_enable_management ? local.desired.certificates : {}
  custom_blueprints             = var.authentik_enable_management ? local.desired.customBlueprints : {}
  custom_flows                  = var.authentik_enable_management ? local.desired.customFlows : {}
  existing_custom_flows         = { for key, value in local.custom_flows : key => value if value.import_existing }
  flow_stage_bindings           = var.authentik_enable_management ? local.desired.flowStageBindings : {}
  existing_flow_stage_bindings  = { for key, value in local.flow_stage_bindings : key => value if value.import_existing }
  ldap_providers                = var.authentik_enable_management ? local.desired.ldapProviders : {}
  ldap_search_permissions       = var.authentik_enable_management ? local.desired.ldapSearchPermissions : {}
  oauth_providers               = var.authentik_enable_management ? local.desired.oauthProviders : {}
  outposts                      = var.authentik_enable_management ? local.desired.outposts : {}
  proxy_providers               = var.authentik_enable_management ? local.desired.proxyProviders : {}
  rbac_roles                    = var.authentik_enable_management ? local.desired.rbacRoles : {}
  scope_mappings                = var.authentik_enable_management ? local.desired.scopeMappings : {}
  service_accounts              = var.authentik_enable_management ? local.desired.serviceAccounts : {}
  service_application_bindings  = var.authentik_enable_management ? local.desired.serviceApplicationBindings : {}
}

provider "authentik" {
  url      = var.authentik_url
  token    = var.authentik_token
  insecure = false
}

check "desired_inventory" {
  assert {
    condition = (
      local.desired.schemaVersion == 3 &&
      length(local.desired.applications) == 23 &&
      length(local.desired.proxyProviders) == 18 &&
      (!var.authentik_enable_management || (
        local.desired.sourceInventory.complete &&
        length(local.desired.oauthProviders) == 5 &&
        length(local.desired.retainedOAuthProviders) == 1 &&
        length(local.desired.applicationPolicyBindings) == 28 &&
        length(local.desired.authenticatorValidateStages) == 1 &&
        length(local.desired.certificates) == 1 &&
        length(local.desired.customFlows) == 2 &&
        length(local.desired.flowStageBindings) == 5 &&
        length(local.desired.ldapProviders) == 1 &&
        length(local.desired.ldapSearchPermissions) == 1 &&
        length(local.desired.outposts) == 1 &&
        length(local.desired.rbacRoles) == 1 &&
        length(local.desired.scopeMappings) == 1 &&
        length(local.desired.serviceAccounts) == 1 &&
        length(local.desired.serviceApplicationBindings) == 1
      ))
    )
    error_message = "The enabled Authentik inventory must contain every reviewed application, provider, access binding, and custom flow object."
  }
}

check "provider_ownership" {
  assert {
    condition = !var.authentik_enable_management || alltrue([
      for application in values(local.applications) :
      application.provider_type == "proxy" ?
      contains(keys(local.proxy_providers), tostring(application.provider_id)) :
      application.provider_type == "oauth2" ?
      contains(keys(local.oauth_providers), tostring(application.provider_id)) :
      application.provider_type == "ldap" &&
      contains(keys(local.ldap_providers), tostring(application.provider_id))
    ])
    error_message = "Every managed application must reference a managed proxy, OAuth2, or LDAP provider."
  }
}

check "oauth_client_secrets" {
  assert {
    condition = !var.authentik_enable_management || (
      local.client_secrets.schemaVersion == 2 &&
      toset(keys(local.client_secrets.oauthProviders)) == toset(keys(local.oauth_providers)) &&
      alltrue([
        for provider in values(local.client_secrets.oauthProviders) :
        trimspace(provider.client_secret) != "" && provider.client_secret != "REPLACE-DURING-BOOTSTRAP"
      ]) &&
      trimspace(local.client_secrets.ldap.bind_password) != "" &&
      trimspace(local.client_secrets.ldap.certificate_private_key) != ""
    )
    error_message = "The decrypted SOPS input must contain one non-placeholder client_secret for every OAuth2 provider."
  }
}

data "authentik_stage" "default_authentication_identification" {
  count = var.authentik_enable_management ? 1 : 0
  name  = "default-authentication-identification"
}

data "authentik_stage" "default_authentication_login" {
  count = var.authentik_enable_management ? 1 : 0
  name  = "default-authentication-login"
}

data "authentik_stage" "default_authentication_password" {
  count = var.authentik_enable_management ? 1 : 0
  name  = "default-authentication-password"
}

data "authentik_flow" "default_provider_invalidation" {
  count = var.authentik_enable_management ? 1 : 0
  slug  = "default-provider-invalidation-flow"
}

data "authentik_stage" "default_authenticator_webauthn_setup" {
  count = var.authentik_enable_management ? 1 : 0
  name  = "default-authenticator-webauthn-setup"
}

resource "authentik_property_mapping_provider_scope" "scope_mappings" {
  for_each = local.scope_mappings

  name        = each.value.name
  scope_name  = each.value.scope_name
  description = each.value.description
  expression  = each.value.expression

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_provider_proxy" "providers" {
  for_each = local.proxy_providers

  name                          = each.value.name
  authentication_flow           = each.value.authentication_flow
  authorization_flow            = each.value.authorization_flow
  invalidation_flow             = each.value.invalidation_flow
  internal_host                 = each.value.internal_host
  external_host                 = each.value.external_host
  internal_host_ssl_validation  = each.value.internal_host_ssl_validation
  skip_path_regex               = each.value.skip_path_regex
  basic_auth_enabled            = each.value.basic_auth_enabled
  basic_auth_username_attribute = each.value.basic_auth_user_attribute
  basic_auth_password_attribute = each.value.basic_auth_password_attribute
  intercept_header_auth         = each.value.intercept_header_auth
  mode                          = each.value.mode
  cookie_domain                 = each.value.cookie_domain
  access_token_validity         = each.value.access_token_validity
  refresh_token_validity        = each.value.refresh_token_validity
  jwt_federation_sources        = each.value.jwt_federation_sources
  jwt_federation_providers      = each.value.jwt_federation_providers

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_provider_oauth2" "providers" {
  for_each = local.oauth_providers

  name                       = each.value.name
  authentication_flow        = each.value.authentication_flow
  authorization_flow         = each.value.authorization_flow
  invalidation_flow          = each.value.invalidation_flow
  client_id                  = each.value.client_id
  client_secret              = local.client_secrets.oauthProviders[each.key].client_secret
  client_type                = each.value.client_type
  allowed_redirect_uris      = each.value.allowed_redirect_uris
  access_code_validity       = each.value.access_code_validity
  access_token_validity      = each.value.access_token_validity
  refresh_token_validity     = each.value.refresh_token_validity
  refresh_token_threshold    = each.value.refresh_token_threshold
  include_claims_in_id_token = each.value.include_claims_in_id_token
  issuer_mode                = each.value.issuer_mode
  sub_mode                   = each.value.sub_mode
  property_mappings = [
    for mapping in each.value.property_mappings :
    mapping == local.desired.scopeMappings["vaultwarden-email"].pk ?
    authentik_property_mapping_provider_scope.scope_mappings["vaultwarden-email"].id : mapping
  ]
  signing_key              = each.value.signing_key
  encryption_key           = each.value.encryption_key
  grant_types              = each.value.grant_types
  logout_method            = each.value.logout_method
  logout_uri               = each.value.logout_uri
  jwt_federation_sources   = each.value.jwt_federation_sources
  jwt_federation_providers = each.value.jwt_federation_providers

  lifecycle {
    prevent_destroy = true
    # Authentik never returns OAuth client-secret material. Preserve the
    # separately encrypted source value without planning a rewrite on refresh.
    ignore_changes = [client_secret]
  }
}

resource "authentik_certificate_key_pair" "certificates" {
  for_each = local.certificates

  name             = each.value.name
  certificate_data = file("${path.module}/${each.value.certificate_file}")
  key_data         = local.client_secrets.ldap.certificate_private_key

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_provider_ldap" "providers" {
  for_each = local.ldap_providers

  name             = each.value.name
  base_dn          = each.value.base_dn
  bind_flow        = authentik_flow.custom[each.value.bind_flow_ref].uuid
  unbind_flow      = data.authentik_flow.default_provider_invalidation[0].id
  bind_mode        = each.value.bind_mode
  search_mode      = each.value.search_mode
  certificate      = authentik_certificate_key_pair.certificates[each.value.certificate_ref].id
  tls_server_name  = each.value.tls_server_name
  mfa_support      = each.value.mfa_support
  uid_start_number = each.value.uid_start_number
  gid_start_number = each.value.gid_start_number

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_application" "applications" {
  for_each = local.applications

  name  = each.value.name
  slug  = each.value.slug
  group = each.value.group
  protocol_provider = (
    each.value.provider_type == "proxy" ?
    authentik_provider_proxy.providers[tostring(each.value.provider_id)].id :
    each.value.provider_type == "oauth2" ?
    authentik_provider_oauth2.providers[tostring(each.value.provider_id)].id :
    authentik_provider_ldap.providers[tostring(each.value.provider_id)].id
  )
  backchannel_providers = each.value.backchannel_provider_ids
  meta_launch_url       = each.value.meta_launch_url
  meta_icon             = each.value.meta_icon
  meta_description      = each.value.meta_description
  meta_publisher        = each.value.meta_publisher
  policy_engine_mode    = each.value.policy_engine_mode
  open_in_new_tab       = each.value.open_in_new_tab
  meta_hide             = each.value.meta_hide

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_policy_binding" "application_access" {
  for_each = local.application_policy_bindings

  target         = authentik_application.applications[each.value.application_slug].uuid
  policy         = each.value.policy
  group          = each.value.group
  user           = each.value.user
  order          = each.value.order
  enabled        = each.value.enabled
  negate         = each.value.negate
  failure_result = each.value.failure_result
  timeout        = each.value.timeout

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_rbac_role" "roles" {
  for_each = local.rbac_roles

  name = each.value.name

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_user" "service_accounts" {
  for_each = local.service_accounts

  username  = each.value.username
  name      = each.value.name
  path      = each.value.path
  type      = each.value.type
  is_active = each.value.is_active
  roles     = [for role_ref in each.value.role_refs : authentik_rbac_role.roles[role_ref].id]
  password  = local.client_secrets.ldap.bind_password

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_rbac_permission_role" "ldap_directory_search" {
  for_each = local.ldap_search_permissions

  # The pinned provider cannot assign an object permission to the LDAP
  # provider's numeric primary key on Authentik 2026.8. This global permission
  # is held only by the dedicated bind role; Jellyfin is the only LDAP provider.
  role       = authentik_rbac_role.roles[each.value.role_ref].id
  permission = each.value.permission

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_policy_binding" "service_application_access" {
  for_each = local.service_application_bindings

  target         = authentik_application.applications[each.value.application_slug].uuid
  user           = authentik_user.service_accounts[each.value.user_ref].id
  order          = each.value.order
  enabled        = each.value.enabled
  negate         = each.value.negate
  failure_result = each.value.failure_result
  timeout        = each.value.timeout

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_outpost" "outposts" {
  for_each = local.outposts

  name               = each.value.name
  type               = each.value.type
  protocol_providers = [for provider_ref in each.value.provider_refs : authentik_provider_ldap.providers[provider_ref].id]
  config             = jsonencode(each.value.config)

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_flow" "custom" {
  for_each = local.custom_flows

  name               = each.value.name
  title              = each.value.title
  slug               = each.value.slug
  designation        = each.value.designation
  authentication     = each.value.authentication
  background         = each.value.background
  compatibility_mode = each.value.compatibility_mode
  denied_action      = each.value.denied_action
  layout             = each.value.layout
  policy_engine_mode = each.value.policy_engine_mode

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_stage_authenticator_validate" "custom" {
  for_each = local.authenticator_validate_stages

  name                          = each.value.name
  not_configured_action         = each.value.not_configured_action
  configuration_stages          = [data.authentik_stage.default_authenticator_webauthn_setup[0].id]
  device_classes                = each.value.device_classes
  email_otp_throttling_factor   = each.value.email_otp_throttling_factor
  last_auth_threshold           = each.value.last_auth_threshold
  sms_otp_throttling_factor     = each.value.sms_otp_throttling_factor
  static_otp_throttling_factor  = each.value.static_otp_throttling_factor
  totp_otp_throttling_factor    = each.value.totp_otp_throttling_factor
  webauthn_allowed_device_types = each.value.webauthn_allowed_device_types
  webauthn_hints                = each.value.webauthn_hints
  webauthn_user_verification    = each.value.webauthn_user_verification

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_flow_stage_binding" "custom" {
  for_each = local.flow_stage_bindings

  target = authentik_flow.custom[each.value.flow_ref].uuid
  stage = {
    "passwordless-webauthn"                 = authentik_stage_authenticator_validate.custom["passwordless-webauthn"].id
    "default-authentication-identification" = data.authentik_stage.default_authentication_identification[0].id
    "default-authentication-password"       = data.authentik_stage.default_authentication_password[0].id
    "default-authentication-login"          = data.authentik_stage.default_authentication_login[0].id
  }[each.value.stage_ref]
  order                   = each.value.order
  evaluate_on_plan        = each.value.evaluate_on_plan
  invalid_response_action = each.value.invalid_response_action
  policy_engine_mode      = each.value.policy_engine_mode
  re_evaluate_policies    = each.value.re_evaluate_policies

  lifecycle {
    prevent_destroy = true
  }
}

# Use database-backed blueprints only for custom configuration that has no
# typed provider resource. A blueprint must never overlap the resources above.
resource "authentik_blueprint" "custom" {
  for_each = local.custom_blueprints

  name    = each.value.name
  content = file("${path.module}/${each.value.content_file}")
  context = jsonencode(each.value.context)
  enabled = each.value.enabled

  lifecycle {
    prevent_destroy = true
  }
}

import {
  for_each = local.scope_mappings
  to       = authentik_property_mapping_provider_scope.scope_mappings[each.key]
  id       = each.value.pk
}

import {
  for_each = local.proxy_providers
  to       = authentik_provider_proxy.providers[each.key]
  id       = each.key
}

import {
  for_each = local.oauth_providers
  to       = authentik_provider_oauth2.providers[each.key]
  id       = each.key
}

import {
  for_each = local.applications
  to       = authentik_application.applications[each.key]
  id       = each.key
}

import {
  for_each = local.application_policy_bindings
  to       = authentik_policy_binding.application_access[each.key]
  id       = each.value.pk
}

import {
  for_each = local.existing_custom_flows
  to       = authentik_flow.custom[each.key]
  id       = each.value.slug
}

import {
  for_each = local.authenticator_validate_stages
  to       = authentik_stage_authenticator_validate.custom[each.key]
  id       = each.value.pk
}

import {
  for_each = local.existing_flow_stage_bindings
  to       = authentik_flow_stage_binding.custom[each.key]
  id       = each.value.pk
}

output "jellyfin_ldap_bind_password" {
  description = "Generated Authentik app password used only by Jellyfin for LDAP directory searches."
  value       = local.client_secrets.ldap.bind_password
  sensitive   = true
}

output "jellyfin_ldap_outpost_id" {
  description = "Authentik LDAP outpost identifier used to retrieve its deployment token without exposing it in plans."
  value       = authentik_outpost.outposts["jellyfin-ldap"].id
}

import {
  for_each = local.custom_blueprints
  to       = authentik_blueprint.custom[each.key]
  id       = each.value.id
}
