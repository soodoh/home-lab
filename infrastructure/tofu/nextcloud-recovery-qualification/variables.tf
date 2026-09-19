variable "proxmox_endpoint" {
  type    = string
  default = ""

  validation {
    condition     = var.proxmox_endpoint == "" || var.proxmox_endpoint == "https://proxmox:8006/api2/json"
    error_message = "Recovery foundation must use the exact reviewed Proxmox endpoint."
  }
}

variable "enable_foundation" {
  description = "Create only the stopped VM9000 recovery foundation."
  type        = bool
  default     = false
}

variable "retrieval_nic_enabled" {
  description = "Attach the firewall-confined retrieval NIC while the guest remains stopped."
  type        = bool
  default     = false
}

variable "controller_ipv4" {
  description = "Exact ephemeral controller IPv4 permitted to reach guest SSH during retrieval."
  type        = string
  default     = ""
}

variable "recovery_ssh_public_key" {
  description = "Single dedicated Ed25519 public key for the disposable guest."
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = var.recovery_ssh_public_key == "" || can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,2} nextcloud-recovery-[a-z0-9-]+$", var.recovery_ssh_public_key))
    error_message = "Recovery requires one dedicated Ed25519 key with a nextcloud-recovery-* comment."
  }
}

variable "recovery_ssh_public_key_sha256" {
  description = "SHA-256 of the exact public-key line."
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = var.recovery_ssh_public_key_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.recovery_ssh_public_key_sha256))
    error_message = "Recovery public-key identity must be a lowercase SHA-256 digest."
  }
}

variable "isolation_attestation_sha256" {
  description = "Identity of the separately reviewed target and isolation admission."
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = var.isolation_attestation_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.isolation_attestation_sha256))
    error_message = "Isolation admission identity must be a lowercase SHA-256 digest."
  }
}
