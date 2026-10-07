# Discover live roles natively: scoped node/inspection roles can be created on
# their first owner-approved activation, or imported if they already exist.
data "proxmox_virtual_environment_roles" "existing" {}

import {
  for_each = {
    for name, privileges in local.access.roles : name => privileges
    if contains(data.proxmox_virtual_environment_roles.existing.role_ids, name)
  }
  to = proxmox_virtual_environment_role.automation[each.key]
  id = each.key
}

import {
  # The three original token bindings are adopted; scoped node/storage grants are
  # explicit creates requiring independent owner review, not guessed imports.
  for_each = {
    for name in ["apply", "plan", "plan_disk_inspect"] : name => local.access.acls[name]
  }
  to = proxmox_acl.automation[each.key]
  id = "${each.value.path}?${local.access.tokens[each.value.token].user_id}!${local.access.tokens[each.value.token].token_name}?${each.value.role_id}"
}

import {
  to = proxmox_cluster_options.cluster
  id = "cluster"
}
