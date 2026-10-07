mock_provider "tailscale" {}

variables {
  tailscale_enable_management = true
  tailscale_servers = {
    docker_host = { name = "docker-host.example.ts.net", node_id = "nDockerTestCNTRL" }
    proxmox     = { name = "proxmox.example.ts.net", node_id = "nProxmoxTestCNTRL" }
  }
}

override_data {
  target = data.tailscale_device.servers["docker_host"]
  values = { node_id = "nDockerTestCNTRL" }
}

override_data {
  target = data.tailscale_device.servers["proxmox"]
  values = { node_id = "nProxmoxTestCNTRL" }
}

run "magicdns_without_dns_takeover" {
  command = plan

  assert {
    condition = (
      tailscale_dns_configuration.tailnet[0].magic_dns &&
      !tailscale_dns_configuration.tailnet[0].override_local_dns &&
      length(tailscale_dns_configuration.tailnet[0].search_paths) == 0 &&
      try(length(tailscale_dns_configuration.tailnet[0].nameservers), 0) == 0 &&
      try(length(tailscale_dns_configuration.tailnet[0].split_dns), 0) == 0
    )
    error_message = "MagicDNS must stay enabled without taking over public or split DNS resolution."
  }
}

run "git_owned_policy_preserves_tailnet_preferences" {
  command = plan

  assert {
    condition = (
      tailscale_tailnet_settings.tailnet[0].acls_externally_managed_on &&
      tailscale_tailnet_settings.tailnet[0].acls_external_link == "https://github.com/soodoh/home-lab/blob/main/infrastructure/tofu/tailscale/main.tf"
    )
    error_message = "Policy editing must be external and link to its desired Git source."
  }

  assert {
    condition = (
      !tailscale_tailnet_settings.tailnet[0].devices_approval_on &&
      tailscale_tailnet_settings.tailnet[0].devices_auto_updates_on &&
      tailscale_tailnet_settings.tailnet[0].devices_key_duration_days == 180 &&
      tailscale_tailnet_settings.tailnet[0].users_approval_on &&
      tailscale_tailnet_settings.tailnet[0].users_role_allowed_to_join_external_tailnet == "admin" &&
      !tailscale_tailnet_settings.tailnet[0].regional_routing_on &&
      !tailscale_tailnet_settings.tailnet[0].posture_identity_collection_on
    )
    error_message = "External policy management must not change the reviewed tailnet approval, expiry, update, routing or posture settings."
  }
}

run "only_reviewed_servers_receive_their_policy_tags" {
  command = plan

  assert {
    condition = (
      toset(keys(tailscale_device_tags.servers)) == toset(["docker_host", "proxmox"]) &&
      tailscale_device_tags.servers["docker_host"].device_id == "nDockerTestCNTRL" &&
      tailscale_device_tags.servers["proxmox"].device_id == "nProxmoxTestCNTRL" &&
      tailscale_device_tags.servers["docker_host"].tags == toset([var.tailscale_policy_identity.tags.docker_host]) &&
      tailscale_device_tags.servers["proxmox"].tags == toset([var.tailscale_policy_identity.tags.proxmox])
    )
    error_message = "Only the two pinned permanent server identities may receive their respective policy tags; CI and personal nodes are not managed."
  }
}

run "same_name_replacement_is_refused" {
  command = plan

  variables {
    tailscale_servers = {
      docker_host = { name = "docker-host.example.ts.net", node_id = "nDockerTestCNTRL" }
      proxmox     = { name = "proxmox.example.ts.net", node_id = "nPreviouslyEnrolledCNTRL" }
    }
  }

  expect_failures = [data.tailscale_device.servers["proxmox"]]
}

run "duplicate_server_identity_is_refused" {
  command = plan

  variables {
    tailscale_servers = {
      docker_host = { name = "docker-host.example.ts.net", node_id = "nDuplicateCNTRL" }
      proxmox     = { name = "proxmox.example.ts.net", node_id = "nDuplicateCNTRL" }
    }
  }

  expect_failures = [var.tailscale_servers]
}

run "invalid_key_duration_is_refused" {
  command = plan

  variables {
    tailscale_settings = merge(var.tailscale_settings, { devices_key_duration_days = 0 })
  }

  expect_failures = [var.tailscale_settings]
}

run "management_disabled_has_no_resources" {
  command = plan

  variables {
    tailscale_enable_management = false
  }

  assert {
    condition = (
      length(tailscale_acl.policy) == 0 &&
      length(tailscale_federated_identity.ci_deploy) == 0 &&
      length(tailscale_dns_configuration.tailnet) == 0 &&
      length(tailscale_tailnet_settings.tailnet) == 0 &&
      length(tailscale_device_tags.servers) == 0 &&
      length(data.tailscale_device.servers) == 0
    )
    error_message = "The existing management gate must disable all provider ownership and server discovery."
  }
}
