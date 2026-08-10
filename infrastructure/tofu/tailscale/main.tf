variable "tailscale_enable_management" {
  type    = bool
  default = false
}

locals {
  contract       = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  tags           = local.contract.tailscale.tags
  owner_identity = local.contract.tailscale.owner_identity

  policy = {
    tagOwners = {
      (local.tags.arch)    = ["autogroup:admin"]
      (local.tags.proxmox) = ["autogroup:admin"]
    }

    grants = [
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

    tests = [
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
      {
        src    = local.owner_identity
        proto  = "tcp"
        accept = ["${local.tags.arch}:8043"]
      },
    ]

    sshTests = [
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

  policy_json = jsonencode(local.policy)
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
