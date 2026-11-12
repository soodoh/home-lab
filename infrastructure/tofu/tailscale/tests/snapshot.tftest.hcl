mock_provider "tailscale" {}

variables {
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

run "backup_host_receives_only_snapshot_rpc_not_ssh" {
  command = plan

  variables {
    tailscale_enable_management = true
  }

  assert {
    condition = length([
      for rule in jsondecode(tailscale_acl.policy[0].acl).ssh : rule
      if contains(rule.src, "tag:docker-host")
    ]) == 0
    error_message = "Snapshot RPC must not authorize any machine-originated SSH login."
  }

  assert {
    condition = length([
      for test in jsondecode(tailscale_acl.policy[0].acl).sshTests : test
      if test.src == "tag:docker-host" && test.dst == ["tag:proxmox"] &&
      toset(test.deny) == toset(["root", "ansible-deploy", "proxmox", "docker"])
    ]) == 1
    error_message = "Live policy validation must deny all SSH deployment identities from the backup host."
  }

  assert {
    condition = length([
      for grant in jsondecode(tailscale_acl.policy[0].acl).grants : grant
      if grant.src == ["tag:docker-host"] && grant.dst == ["tag:proxmox"] &&
      toset(grant.ip) == toset(["tcp:2444", "tcp:8006"])
    ]) == 1
    error_message = "The snapshot path may add only TCP 2444 alongside the existing PVE API grant."
  }

  assert {
    condition = length([
      for test in jsondecode(tailscale_acl.policy[0].acl).tests : test
      if test.src == "tag:docker-host" && contains(try(test.accept, []), "tag:proxmox:2444") &&
      contains(try(test.deny, []), "tag:proxmox:22") && contains(try(test.deny, []), "tag:proxmox:8007")
    ]) == 1
    error_message = "The live network policy must admit snapshot RPC while denying SSH and unrelated ports."
  }
}
