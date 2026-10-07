locals {
  managed_servers = var.tailscale_enable_management ? var.tailscale_servers : {}
}

# This resource exclusively owns all tailnet DNS settings. Custom public records
# under ts.diloreto.com remain owned by the AWS foundation root.
resource "tailscale_dns_configuration" "tailnet" {
  count = var.tailscale_enable_management ? 1 : 0

  magic_dns          = true
  override_local_dns = false
  search_paths       = []
}

resource "tailscale_tailnet_settings" "tailnet" {
  count = var.tailscale_enable_management ? 1 : 0

  acls_externally_managed_on                  = var.tailscale_settings.acls_externally_managed_on
  acls_external_link                          = var.tailscale_settings.acls_external_link
  devices_approval_on                         = var.tailscale_settings.devices_approval_on
  devices_auto_updates_on                     = var.tailscale_settings.devices_auto_updates_on
  devices_key_duration_days                   = var.tailscale_settings.devices_key_duration_days
  users_approval_on                           = var.tailscale_settings.users_approval_on
  users_role_allowed_to_join_external_tailnet = var.tailscale_settings.users_role_allowed_to_join_external_tailnet
  regional_routing_on                         = var.tailscale_settings.regional_routing_on
  posture_identity_collection_on              = var.tailscale_settings.posture_identity_collection_on

  # HTTPS and flow logging are outside this resource's declared ownership until
  # their API reads and independently approved credential scopes are qualified.
  depends_on = [tailscale_acl.policy]
}

data "tailscale_device" "servers" {
  for_each = local.managed_servers

  name = each.value.name

  lifecycle {
    postcondition {
      condition     = self.node_id == each.value.node_id
      error_message = "The server name must resolve to its reviewed node ID; re-enrollment requires independent identity review."
    }
  }
}

resource "tailscale_device_tags" "servers" {
  for_each = local.managed_servers

  device_id = data.tailscale_device.servers[each.key].node_id
  tags      = [local.tags[each.key]]

  depends_on = [tailscale_acl.policy]
}
