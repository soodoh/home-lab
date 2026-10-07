locals {
  access = jsondecode(file("${path.module}/access.json"))
}

resource "proxmox_virtual_environment_role" "automation" {
  for_each = local.access.roles

  role_id    = each.key
  privileges = each.value
}

# root@pam is independently owned; this root manages only the two existing
# privilege-separated token records, never the privileged PAM account itself.
# Import does not recover token secrets; existing credentials stay in custody.
resource "proxmox_user_token" "automation" {
  for_each = local.access.tokens

  user_id               = each.value.user_id
  token_name            = each.value.token_name
  privileges_separation = true
}

resource "proxmox_acl" "automation" {
  for_each = local.access.acls

  path      = each.value.path
  role_id   = proxmox_virtual_environment_role.automation[each.value.role_id].role_id
  token_id  = proxmox_user_token.automation[each.value.token].id
  propagate = each.value.propagate
}
