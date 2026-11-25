mock_provider "authentik" {}

override_module {
  target = module.catalog
  outputs = {
    ids_by_role = { apply = [11, 12], refresh = [21, 22] }
  }
}

variables {
  authentik_access_owner_token = "synthetic-owner-token"
  authentik_access_adopted_object_ids = {
    "certificates/jellyfin-ldap" = "40000000-0000-4000-8000-000000000001"
    "ldapProviders/jellyfin"     = "975"
  }
}

run "grant_only_governed_lifecycle" {
  command = plan

  assert {
    condition = (
      authentik_rbac_role.controller["apply"].name == "home-lab-opentofu-authentik-apply" &&
      authentik_rbac_role.controller["refresh"].name == "home-lab-opentofu-managed-group-read" &&
      contains(keys(authentik_rbac_permission_role.global), "apply/authentik_core.add_group") &&
      contains(keys(authentik_rbac_permission_role.global), "apply/authentik_core.delete_application") &&
      alltrue([for grant in values(authentik_rbac_permission_role.global) : !contains([
        "authentik_core.change_user", "authentik_core.reset_user_password", "authentik_core.add_user_to_group",
        "authentik_core.change_group", "authentik_core.delete_group", "authentik_core.enable_group_superuser",
        "authentik_rbac.assign_role_permissions", "authentik_rbac.change_role", "authentik_blueprints.change_blueprintinstance",
        "authentik_providers_oauth2.change_oauth2provider", "authentik_crypto.view_certificatekeypair_key",
      ], grant.permission)])
    )
    error_message = "Scope sensitive writes and secret access; do not let controllers extend their own grants."
  }

  assert {
    condition = (
      authentik_rbac_permission_role.object["apply/groups/jellyfin/authentik_core.add_user_to_group"].object_id == local.desired.groups.jellyfin.pk &&
      authentik_rbac_permission_role.object["apply/ldapProviders/jellyfin/authentik_providers_ldap.change_ldapprovider"].object_id == "975" &&
      authentik_rbac_permission_role.object["refresh/certificates/jellyfin-ldap/authentik_crypto.view_certificatekeypair_key"].model == "authentik_crypto.certificatekeypair" &&
      authentik_rbac_permission_role.object["refresh/oauthProviders/15/authentik_providers_oauth2.change_oauth2provider"].object_id == "15" &&
      !contains(keys(local.scoped_objects), "signingCertificates/bookorbit-oidc")
    )
    error_message = "Attach scoped grants only to known IDs in the managed app declarations, not by guessing new IDs."
  }

  assert {
    condition = (
      local.initial.apply["authentik_core.delete_group"] == "authentik_core.group" &&
      local.initial.apply["authentik_policies.delete_policybinding"] == "authentik_policies.policybinding" &&
      local.initial.refresh["authentik_core.view_group"] == "authentik_core.group" &&
      local.initial.refresh["authentik_crypto.view_certificatekeypair_key"] == "authentik_crypto.certificatekeypair" &&
      local.initial.refresh["authentik_providers_oauth2.change_oauth2provider"] == "authentik_providers_oauth2.oauth2provider" &&
      !contains(keys(local.initial.apply), "authentik_core.reset_user_password") &&
      tolist(authentik_rbac_initial_permissions.controller["apply"].permissions) == tolist([11, 12]) &&
      tolist(authentik_rbac_initial_permissions.controller["refresh"].permissions) == tolist([21, 22])
    )
    error_message = "Native Initial Permissions should handle new managed objects without broadening global grants."
  }
}

run "reject_unowned_adoption" {
  command = plan

  variables {
    authentik_access_adopted_object_ids = { "groups/authentik-admins" = "40000000-0000-4000-8000-000000000004" }
  }

  expect_failures = [authentik_rbac_role.controller["apply"], authentik_rbac_role.controller["refresh"]]
}

run "reject_override_of_committed_identity" {
  command = plan

  variables {
    authentik_access_adopted_object_ids = { "groups/jellyfin" = "40000000-0000-4000-8000-000000000004" }
  }

  expect_failures = [authentik_rbac_role.controller["apply"], authentik_rbac_role.controller["refresh"]]
}

run "reject_duplicate_target" {
  command = plan

  variables {
    authentik_access_adopted_object_ids = { "oauthProviders/bookorbit" = "15" }
  }

  expect_failures = [authentik_rbac_role.controller["apply"], authentik_rbac_role.controller["refresh"]]
}
