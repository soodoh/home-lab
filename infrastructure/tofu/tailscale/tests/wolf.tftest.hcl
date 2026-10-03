mock_provider "tailscale" {}

run "owner_only_wolf_ports" {
  command = plan

  variables {
    tailscale_enable_management = true
  }

  assert {
    condition = length([
      for grant in jsondecode(tailscale_acl.policy[0].acl).grants : grant
      if grant.src == ["autogroup:owner"] && grant.dst == ["tag:docker-host"] &&
      toset(grant.ip) == toset(["tcp:47984", "tcp:47989", "tcp:48010", "udp:47999", "udp:48100", "udp:48200"])
    ]) == 1
    error_message = "Exactly one owner-only grant must admit Wolf's six protocol ports."
  }

  assert {
    condition = alltrue([
      for grant in jsondecode(tailscale_acl.policy[0].acl).grants :
      grant.src == ["autogroup:owner"]
      if grant.dst == ["tag:docker-host"] && length(setintersection(
        toset(grant.ip),
        toset(["tcp:47984", "tcp:47989", "tcp:48010", "udp:47999", "udp:48100", "udp:48200"])
      )) > 0
    ])
    error_message = "Neither CI nor administrator-only identities may acquire Wolf protocol access."
  }

  assert {
    condition = length([
      for test in jsondecode(tailscale_acl.policy[0].acl).tests : test
      if test.src == "tag:ci-deploy" && test.proto == "udp" &&
      toset(test.deny) == toset(["tag:docker-host:47999", "tag:docker-host:48100", "tag:docker-host:48200"])
    ]) == 1
    error_message = "Policy admission must test CI refusal for every Wolf UDP port."
  }
}
