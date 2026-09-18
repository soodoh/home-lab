terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  backend "s3" {
    key          = "home-lab/tailscale/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
