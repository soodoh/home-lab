variable "tailscale_enable_management" {
  type    = bool
  default = false
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  tags     = local.contract.tailscale.tags

  gateway_policy_stage = local.contract.tailscale.gateway_policy_stage

  active_policy = {
    tagOwners = {
      (local.tags.arch)         = ["autogroup:admin"]
      (local.tags.proxmox)      = ["autogroup:admin"]
      (local.tags.infra_router) = ["autogroup:admin"]
    }

    autoApprovers = {
      routes = {
        "192.168.0.100/32" = [local.tags.infra_router]
        "192.168.0.123/32" = [local.tags.infra_router]
      }
    }

    grants = [
      {
        src = ["autogroup:admin"]
        dst = [local.tags.infra_router]
        ip  = ["*"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = ["192.168.0.123"]
        ip  = ["tcp:8006"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = ["192.168.0.100"]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.arch]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner"]
        dst = ["autogroup:self"]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin", local.tags.arch]
        dst = [local.tags.proxmox]
        ip  = ["tcp:22", "tcp:8006"]
      },
    ]

    ssh = [
      {
        action = "accept"
        src    = ["autogroup:owner"]
        dst    = [local.tags.arch]
        users  = ["docker"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner", "autogroup:admin"]
        dst    = [local.tags.arch]
        users  = ["ansible-deploy"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner"]
        dst    = ["autogroup:self"]
        users  = ["pauldiloreto"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner", "autogroup:admin"]
        dst    = [local.tags.proxmox]
        users  = ["root", "tofu-plan", "tofu-apply"]
      },
      {
        action = "accept"
        src    = [local.tags.arch]
        dst    = [local.tags.proxmox]
        users  = ["root"]
      },
    ]

    tests = [
      {
        src   = local.tags.arch
        proto = "tcp"
        accept = [
          "${local.tags.proxmox}:22",
          "${local.tags.proxmox}:8006",
        ]
        deny = ["${local.tags.proxmox}:8007"]
      },
    ]

    sshTests = [
      {
        src    = local.tags.arch
        dst    = [local.tags.proxmox]
        accept = ["root"]
        deny   = ["tofu-plan", "tofu-apply"]
      },
    ]
  }

  detached_policy = {
    tagOwners = local.active_policy.tagOwners
    grants = [
      local.active_policy.grants[0],
      local.active_policy.grants[3],
      local.active_policy.grants[4],
      local.active_policy.grants[5],
    ]
    ssh      = local.active_policy.ssh
    tests    = local.active_policy.tests
    sshTests = local.active_policy.sshTests
  }

  retired_policy = merge(local.detached_policy, {
    tagOwners = {
      for tag, owners in local.detached_policy.tagOwners : tag => owners
      if tag != local.tags.infra_router
    }
    grants = slice(local.detached_policy.grants, 1, length(local.detached_policy.grants))
  })

  policy_json_by_stage = {
    active   = jsonencode(local.active_policy)
    detached = jsonencode(local.detached_policy)
    retired  = jsonencode(local.retired_policy)
  }
  policy_json = local.policy_json_by_stage[local.gateway_policy_stage]
}

resource "terraform_data" "tailscale_policy" {
  count = var.tailscale_enable_management ? 1 : 0

  input = {
    policy_json   = local.policy_json
    policy_sha256 = sha256(local.policy_json)
  }

  lifecycle {
    prevent_destroy = true
  }
}
