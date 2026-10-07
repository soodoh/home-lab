locals {
  access = jsondecode(file("${path.module}/access.json"))
  token_ids = {
    for name, token in local.access.tokens : name => "${token.user_id}!${token.token_name}"
  }
}

resource "proxmox_virtual_environment_role" "automation" {
  for_each = local.access.roles

  role_id    = each.key
  privileges = each.value
}

# Users, token records and their secrets remain independently owned. Native
# token metadata reads require User.Modify; do not escalate the owner auditor
# merely to import them. The host observer verifies existing token separation.
resource "proxmox_acl" "automation" {
  for_each = local.access.acls

  path      = each.value.path
  role_id   = proxmox_virtual_environment_role.automation[each.value.role_id].role_id
  token_id  = local.token_ids[each.value.token]
  propagate = each.value.propagate
}
