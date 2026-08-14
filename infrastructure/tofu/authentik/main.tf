locals {
  desired         = jsondecode(file("${path.module}/desired.json"))
  applications    = var.authentik_enable_management ? local.desired.applications : {}
  proxy_providers = var.authentik_enable_management ? local.desired.proxyProviders : {}
}

provider "authentik" {
  url      = var.authentik_enable_management ? null : "https://authentik.invalid"
  token    = var.authentik_enable_management ? null : "disabled-not-a-credential"
  insecure = false
}

check "desired_inventory" {
  assert {
    condition = (
      local.desired.schemaVersion == 1 &&
      length(local.desired.applications) == 25 &&
      length(local.desired.proxyProviders) == 19
    )
    error_message = "The checked Authentik desired inventory is incomplete or has an unsupported schema version."
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
  property_mappings             = each.value.property_mappings
  jwt_federation_sources        = each.value.jwt_federation_sources
  jwt_federation_providers      = each.value.jwt_federation_providers

  lifecycle {
    prevent_destroy = true
  }
}

resource "authentik_application" "applications" {
  for_each = local.applications

  name                  = each.value.name
  slug                  = each.value.slug
  group                 = each.value.group
  protocol_provider     = each.value.provider_id
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

import {
  for_each = local.proxy_providers
  to       = authentik_provider_proxy.providers[each.key]
  id       = each.key
}

import {
  for_each = local.applications
  to       = authentik_application.applications[each.key]
  id       = each.key
}
