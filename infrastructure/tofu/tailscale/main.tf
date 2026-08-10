variable "tailscale_enable_management" {
  type    = bool
  default = false
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  tags     = local.contract.tailscale.tags

  gateway_policy_stage   = local.contract.tailscale.gateway_policy_stage
  human_ssh_policy_stage = local.contract.tailscale.human_ssh_policy_stage
  owner_identity         = local.contract.tailscale.owner_identity

  direct_proxmox_grants_by_stage = {
    transition = [
      {
        src = ["autogroup:owner", "autogroup:admin", local.tags.arch]
        dst = [local.tags.proxmox]
        ip  = ["tcp:22", "tcp:8006"]
      },
    ]
    final = [
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.proxmox]
        ip  = ["tcp:22", "tcp:8006"]
      },
      {
        src = [local.tags.arch]
        dst = [local.tags.proxmox]
        ip  = ["tcp:8006"]
      },
    ]
  }

  ssh_by_human_stage = {
    transition = [
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
        src    = ["autogroup:owner"]
        dst    = [local.tags.proxmox]
        users  = ["proxmox"]
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
    final = [
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
        src    = ["autogroup:owner"]
        dst    = [local.tags.proxmox]
        users  = ["proxmox", "tofu-plan", "tofu-apply"]
      },
      {
        action = "accept"
        src    = ["autogroup:admin"]
        dst    = [local.tags.proxmox]
        users  = ["tofu-plan", "tofu-apply"]
      },
    ]
  }

  omada_controller_access_test = {
    src    = local.owner_identity
    proto  = "tcp"
    accept = ["${local.tags.arch}:8043"]
  }

  tests_by_human_stage = {
    transition = [
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
    final = [
      {
        src   = local.tags.arch
        proto = "tcp"
        accept = [
          "${local.tags.proxmox}:8006",
        ]
        deny = [
          "${local.tags.proxmox}:22",
          "${local.tags.proxmox}:8007",
        ]
      },
    ]
  }

  ssh_tests_by_human_stage = {
    transition = [
      {
        src    = local.owner_identity
        dst    = [local.tags.arch]
        accept = ["docker", "ansible-deploy"]
        deny   = ["proxmox", "root"]
      },
      {
        src    = local.owner_identity
        dst    = [local.tags.proxmox]
        accept = ["proxmox", "root", "tofu-plan", "tofu-apply"]
        deny   = ["docker"]
      },
      {
        src    = local.tags.arch
        dst    = [local.tags.proxmox]
        accept = ["root"]
        deny   = ["docker", "proxmox", "tofu-plan", "tofu-apply"]
      },
    ]
    final = [
      {
        src    = local.owner_identity
        dst    = [local.tags.arch]
        accept = ["docker", "ansible-deploy"]
        deny   = ["proxmox", "root"]
      },
      {
        src    = local.owner_identity
        dst    = [local.tags.proxmox]
        accept = ["proxmox", "tofu-plan", "tofu-apply"]
        deny   = ["docker", "root"]
      },
    ]
  }

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

    grants = concat([
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
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.arch]
        ip  = ["tcp:8043"]
      },
      {
        src = ["autogroup:owner"]
        dst = ["autogroup:self"]
        ip  = ["tcp:22"]
      },
    ], local.direct_proxmox_grants_by_stage[local.human_ssh_policy_stage])

    ssh      = local.ssh_by_human_stage[local.human_ssh_policy_stage]
    tests    = concat(local.tests_by_human_stage[local.human_ssh_policy_stage], [local.omada_controller_access_test])
    sshTests = local.ssh_tests_by_human_stage[local.human_ssh_policy_stage]
  }

  detached_policy = {
    tagOwners = local.active_policy.tagOwners
    grants = concat(
      [local.active_policy.grants[0]],
      slice(local.active_policy.grants, 3, length(local.active_policy.grants)),
    )
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
