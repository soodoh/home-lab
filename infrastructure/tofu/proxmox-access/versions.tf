terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.116.0"
    }
  }

  # Independently owned bucket, supplied at init; never TF_BACKEND_BUCKET.
  # Normal controllers must have neither object-write nor bucket-policy authority
  # there. This key is also excluded from their active_state_keys grants.
  backend "s3" {
    key          = "home-lab/proxmox-access/tofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
