terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  backend "local" {
    path = ".local/nextcloud-recovery-qualification.tfstate"
  }

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.111.1"
    }
  }
}
