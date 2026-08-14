terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    authentik = {
      source  = "registry.terraform.io/goauthentik/authentik"
      version = "= 2026.5.1"
    }
  }

  backend "s3" {
    key          = "home-lab/authentik/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
