terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    sonarr = {
      source  = "registry.terraform.io/devopsarr/sonarr"
      version = "= 3.5.0"
    }
    radarr = {
      source  = "registry.terraform.io/devopsarr/radarr"
      version = "= 2.5.0"
    }
    prowlarr = {
      source  = "registry.terraform.io/devopsarr/prowlarr"
      version = "= 3.2.1"
    }
  }

  backend "s3" {
    key          = "home-lab/servarr/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
