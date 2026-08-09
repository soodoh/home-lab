terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.58.0"
    }
  }

  backend "s3" {
    key          = "home-lab/aws-foundation/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
