# Keep declarative adoption separate from resource configuration.
# OpenTofu mock-provider tests cannot execute import operations.

import {
  for_each = local.scope_mappings
  to       = authentik_property_mapping_provider_scope.scope_mappings[each.key]
  id       = each.value.pk
}

import {
  for_each = local.existing_proxy_providers
  to       = authentik_provider_proxy.providers[each.key]
  id       = each.value.pk
}

import {
  for_each = local.oauth_providers
  to       = authentik_provider_oauth2.providers[each.key]
  id       = each.key
}

import {
  for_each = local.existing_applications
  to       = authentik_application.applications[each.key]
  id       = each.key
}

import {
  for_each = local.existing_application_policy_bindings
  to       = authentik_policy_binding.application_access[each.key]
  id       = each.value.pk
}

import {
  for_each = local.existing_outposts
  to       = authentik_outpost.outposts[each.value]
  id       = local.desired.outposts[each.value].pk
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

import {
  for_each = local.custom_blueprints
  to       = authentik_blueprint.custom[each.key]
  id       = each.value.id
}

import {
  for_each = local.groups
  to       = authentik_group.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.identification_stages
  to       = authentik_stage_identification.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.webauthn_stages
  to       = authentik_stage_authenticator_webauthn.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.invitation_stages
  to       = authentik_stage_invitation.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.prompt_fields
  to       = authentik_stage_prompt_field.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.prompt_stages
  to       = authentik_stage_prompt.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.user_write_stages
  to       = authentik_stage_user_write.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.user_login_stages
  to       = authentik_stage_user_login.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.password_policies
  to       = authentik_policy_password.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.brands
  to       = authentik_brand.managed[each.key]
  id       = each.value.pk
}

import {
  for_each = local.system_settings
  to       = authentik_system_settings.managed[each.key]
  id       = "system_settings"
}

import {
  for_each = local.signing_certificates
  to       = authentik_certificate_key_pair.signing[each.key]
  id       = each.value.pk
}
