terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    omada = {
      source  = "registry.terraform.io/wncservices/omada"
      version = "= 0.11.10"
    }
  }

  backend "s3" {
    key          = "home-lab/omada/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
