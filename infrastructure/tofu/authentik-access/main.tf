locals {
  desired = jsondecode(file("${path.module}/../authentik/desired.json"))

  # Pin the object to the app root's declared identity, never to a name match.
  declarations = merge([
    for model, policy in local.models : merge([
      for collection in policy.collections : {
        for key, object in local.desired[collection] : "${collection}/${key}" => {
          model = model
          pk    = try(tostring(object.pk), null)
        }
      }
    ]...)
  ]...)
  scoped_objects = {
    for key, object in local.declarations : key => {
      model = object.model
      pk    = object.pk != null ? object.pk : var.authentik_access_adopted_object_ids[key]
    } if object.pk != null || contains(keys(var.authentik_access_adopted_object_ids), key)
  }

  object_permissions = {
    for model, policy in local.models : model => {
      apply = toset(concat(
        try(policy.create, false) ? ["change_${split(".", model)[1]}", "delete_${split(".", model)[1]}"] : [],
        try(tolist(policy.apply_extra), []),
      ))
      refresh = toset(concat(
        ["view_${split(".", model)[1]}"], try(tolist(policy.refresh_extra), []),
      ))
    }
  }
  global_grants = {
    for grant in flatten([
      for role, permissions in local.global_permissions : [
        for permission in concat(permissions, role == "apply" ? [
          for model, policy in local.models : "${split(".", model)[0]}.add_${split(".", model)[1]}" if try(policy.create, false)
        ] : []) : { role = role, permission = permission }
      ]
    ]) : "${grant.role}/${grant.permission}" => grant
  }
  object_grants = {
    for grant in flatten([
      for key, object in local.scoped_objects : [
        for role, permissions in local.object_permissions[object.model] : [
          for codename in permissions : {
            object_key = key
            role       = role
            model      = object.model
            object_id  = object.pk
            permission = "${split(".", object.model)[0]}.${codename}"
          }
        ]
      ]
    ]) : "${grant.role}/${grant.object_key}/${grant.permission}" => grant
  }
  initial = {
    for role in keys(local.roles) : role => merge([
      for model, policy in local.models : {
        for codename in local.object_permissions[model][role] : "${split(".", model)[0]}.${codename}" => model
      } if try(policy.create, false)
    ]...)
  }
}

resource "authentik_rbac_role" "controller" {
  for_each = local.roles
  name     = each.value

  lifecycle {
    # A mistaken import must not rename or claim someone else's role.
    ignore_changes = [name]
    postcondition {
      condition     = self.name == each.value
      error_message = "The live role name must match the dedicated controller role. Verify the import ID and role ownership."
    }
    precondition {
      condition = alltrue([
        for key in keys(var.authentik_access_adopted_object_ids) :
        try(contains(keys(local.declarations), key) && local.declarations[key].pk == null, false)
      ])
      error_message = "An adopted ID must reference a declared app object that has no committed primary key. Remove the ID when removing the app declaration."
    }
    precondition {
      condition = length(local.scoped_objects) == length(toset([
        for object in values(local.scoped_objects) : "${object.model}/${object.pk}"
      ]))
      error_message = "Multiple app declarations cannot grant permissions to the same Authentik object."
    }
  }
}

module "catalog" {
  source         = "./catalog"
  models_by_role = local.initial
}

resource "authentik_rbac_initial_permissions" "controller" {
  for_each    = local.initial
  name        = "${local.roles[each.key]}-initial"
  role        = authentik_rbac_role.controller[each.key].id
  permissions = module.catalog.ids_by_role[each.key]

  lifecycle {
    # A template owned by another role is not an adoption candidate.
    ignore_changes = [role]
    postcondition {
      # A state-only import runs with a partial graph before both roles exist in state.
      condition     = try(self.role == authentik_rbac_role.controller[each.key].id, true)
      error_message = "The Initial Permissions template must belong to this controller role. Verify the import ID."
    }
  }
}

resource "authentik_rbac_permission_role" "global" {
  for_each   = local.global_grants
  role       = authentik_rbac_role.controller[each.value.role].id
  permission = each.value.permission
}

# Native assignment is idempotent for an existing role/permission/object tuple.
# Declare grants for pinned and independently observed pre-existing objects.
# Initial Permissions is the writer for future unpinned objects, not this list.
resource "authentik_rbac_permission_role" "object" {
  for_each   = local.object_grants
  role       = authentik_rbac_role.controller[each.value.role].id
  permission = each.value.permission
  model      = each.value.model
  object_id  = each.value.object_id
}

resource "authentik_user" "controller" {
  for_each = local.controller_users

  username  = each.value.username
  name      = each.value.name
  path      = each.value.path
  type      = "service_account"
  is_active = true
  groups    = []
  roles     = [for role_key in each.value.roles : authentik_rbac_role.controller[role_key].id]

  lifecycle {
    # A mistaken import must not rename or claim someone else's account.
    ignore_changes = [username]
    postcondition {
      condition     = self.username == each.value.username
      error_message = "The live account username must match the dedicated controller account. Verify the import ID and account ownership."
    }
    postcondition {
      condition     = length(self.groups) == 0
      error_message = "Controller accounts must not belong to any Authentik group."
    }
  }
}
