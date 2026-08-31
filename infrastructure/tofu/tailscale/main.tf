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
      (local.tags.docker_host) = ["autogroup:admin"]
      (local.tags.proxmox)     = ["autogroup:admin"]
    }

    grants = [
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.docker_host]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.docker_host]
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
        src = [local.tags.docker_host]
        dst = [local.tags.proxmox]
        ip  = ["tcp:8006"]
      },
    ]

    ssh = [
      {
        action = "accept"
        src    = ["autogroup:owner"]
        dst    = [local.tags.docker_host]
        users  = ["docker"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner", "autogroup:admin"]
        dst    = [local.tags.docker_host]
        users  = ["ansible-deploy"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner"]
        dst    = ["autogroup:self"]
        users  = ["pauldiloreto", "paul.diloreto"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner"]
        dst    = [local.tags.proxmox]
        users  = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply"]
      },
      {
        action = "accept"
        src    = ["autogroup:admin"]
        dst    = [local.tags.proxmox]
        users  = ["ansible-plan", "ansible-deploy", "firewall-apply"]
      },
    ]

    tests = [
      {
        src   = local.tags.docker_host
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
        src   = local.owner_identity
        proto = "tcp"
        accept = [
          "${local.owner_identity}:22",
          "${local.tags.docker_host}:8043",
        ]
      },
    ]

    sshTests = [
      {
        src    = local.owner_identity
        dst    = [local.tags.docker_host]
        accept = ["docker", "ansible-deploy"]
        deny   = ["proxmox", "root"]
      },
      {
        src    = local.owner_identity
        dst    = [local.owner_identity]
        accept = ["pauldiloreto", "paul.diloreto"]
        deny   = ["root"]
      },
      {
        src    = local.owner_identity
        dst    = [local.tags.proxmox]
        accept = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply"]
        deny   = ["docker", "root", "tofu-plan", "tofu-apply"]
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
