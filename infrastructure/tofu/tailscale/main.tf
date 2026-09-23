locals {
  tags           = var.tailscale_policy_identity.tags
  owner_identity = var.tailscale_policy_identity.owner_identity
  github_subject = "repo:${var.tailscale_policy_identity.github_repository}:environment:${var.tailscale_policy_identity.github_environment}"

  policy = {
    tagOwners = {
      (local.tags.docker_host) = ["autogroup:admin"]
      (local.tags.proxmox)     = ["autogroup:admin"]
      (local.tags.ci_deploy)   = ["autogroup:admin"]
    }

    grants = [
      {
        src = ["autogroup:owner", "autogroup:admin", local.tags.ci_deploy]
        dst = [local.tags.docker_host]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.docker_host]
        ip  = ["tcp:8043"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin", local.tags.ci_deploy]
        dst = [local.tags.docker_host]
        ip  = ["tcp:8443"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin"]
        dst = [local.tags.docker_host]
        ip  = ["tcp:8444"]
      },
      {
        src = ["autogroup:owner"]
        dst = ["autogroup:self"]
        ip  = ["tcp:22"]
      },
      {
        src = ["autogroup:owner", "autogroup:admin", local.tags.ci_deploy]
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
        src    = ["autogroup:owner", "autogroup:admin", local.tags.ci_deploy]
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
        users  = ["proxmox"]
      },
      {
        action = "accept"
        src    = ["autogroup:owner", "autogroup:admin", local.tags.ci_deploy]
        dst    = [local.tags.proxmox]
        users  = ["ansible-deploy"]
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
          "${local.tags.docker_host}:8443",
          "${local.tags.docker_host}:8444",
        ]
      },
      {
        src   = local.tags.ci_deploy
        proto = "tcp"
        accept = [
          "${local.tags.docker_host}:22",
          "${local.tags.docker_host}:8443",
          "${local.tags.proxmox}:22",
          "${local.tags.proxmox}:8006",
        ]
        deny = [
          "${local.tags.docker_host}:8088",
          "${local.tags.docker_host}:8043",
          "${local.tags.docker_host}:8444",
          "${local.tags.proxmox}:8007",
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
        accept = ["proxmox", "ansible-deploy"]
        deny   = ["docker", "root"]
      },
      {
        src    = local.tags.ci_deploy
        dst    = [local.tags.docker_host]
        accept = ["ansible-deploy"]
        deny   = ["docker", "proxmox", "root"]
      },
      {
        src    = local.tags.ci_deploy
        dst    = [local.tags.proxmox]
        accept = ["ansible-deploy"]
        deny   = ["docker", "proxmox", "root"]
      },
    ]
  }

  policy_json = jsonencode(local.policy)
}

resource "tailscale_acl" "policy" {
  count = var.tailscale_enable_management ? 1 : 0

  acl                        = local.policy_json
  overwrite_existing_content = false
  reset_acl_on_destroy       = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "tailscale_federated_identity" "ci_deploy" {
  count = var.tailscale_enable_management ? 1 : 0

  description = "home-lab GitHub deployment"
  issuer      = "https://token.actions.githubusercontent.com"
  subject     = local.github_subject
  custom_claim_rules = {
    repository_id       = var.tailscale_policy_identity.github_repository_id
    repository_owner_id = var.tailscale_policy_identity.github_owner_id
    ref                 = var.tailscale_policy_identity.github_ref
  }
  scopes = ["auth_keys"]
  tags   = [local.tags.ci_deploy]

  lifecycle {
    prevent_destroy = true
  }
}

output "ci_deploy_client_id" {
  value = try(tailscale_federated_identity.ci_deploy[0].id, null)
}

output "ci_deploy_audience" {
  value = try(tailscale_federated_identity.ci_deploy[0].audience, null)
}
