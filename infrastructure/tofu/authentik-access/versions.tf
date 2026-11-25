terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    authentik = {
      source  = "registry.terraform.io/goauthentik/authentik"
      version = "2026.8.2"
    }
  }

  # Independent bucket and principal: never initialize with ordinary controller
  # credentials. This key is not in aws-foundation's ordinary state-key grants.
  backend "s3" {
    key          = "home-lab/authentik-access/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "authentik" {
  url   = "https://auth.diloreto.com"
  token = var.authentik_access_owner_token
}

variable "authentik_access_owner_token" {
  type        = string
  description = "Independently held Authentik owner API token. Never use either ordinary controller token."
  sensitive   = true
  ephemeral   = true
  nullable    = false

  validation {
    condition     = length(trimspace(var.authentik_access_owner_token)) > 0
    error_message = "The independent Authentik owner token is required."
  }
}
