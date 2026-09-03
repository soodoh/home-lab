variable "proxmox_endpoint" {
  type = string
}

variable "enable_qualification" {
  type    = bool
  default = false
}

variable "qualification_ssh_public_key" {
  type      = string
  sensitive = true
  default   = ""

  validation {
    condition     = var.qualification_ssh_public_key == "" || can(regex("^ssh-ed25519 [A-Za-z0-9+/]+={0,2} qualification-[a-z0-9-]+$", var.qualification_ssh_public_key))
    error_message = "Qualification requires one single-line dedicated Ed25519 guest key with a qualification-* comment."
  }
}

variable "qualification_ssh_public_key_sha256" {
  type      = string
  sensitive = true
  default   = ""

  validation {
    condition     = var.qualification_ssh_public_key_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.qualification_ssh_public_key_sha256))
    error_message = "Qualification guest-key identity must be an exact SHA-256 digest."
  }
}

variable "controller_ipv4" {
  type    = string
  default = ""
}
variable "qualification_node_name" {
  type    = string
  default = "disabled-qualification"
}

variable "qualification_image_datastore_id" {
  type    = string
  default = ""
}

variable "qualification_disk_datastore_id" {
  type    = string
  default = ""
}

variable "qualification_bridge" {
  type    = string
  default = ""
}
variable "qualification_cloud_init_file_id" {
  type    = string
  default = ""
}

variable "isolation_attestation_sha256" {
  type      = string
  sensitive = true
  default   = ""

  validation {
    condition     = var.isolation_attestation_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.isolation_attestation_sha256))
    error_message = "Isolation attestation identity must be an exact SHA-256 digest."
  }
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  vm_id    = 9900
  cloud_init = templatefile("${path.module}/../../debian/cloud-init/qualification-user-data.tftpl", {
    locale                       = local.contract.debian.locale
    qualification_ssh_public_key = var.qualification_ssh_public_key
    timezone                     = local.contract.system_timezone
  })
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false
}
resource "proxmox_download_file" "qualification_image" {
  count              = var.enable_qualification ? 1 : 0
  content_type       = "import"
  datastore_id       = var.qualification_image_datastore_id
  node_name          = var.qualification_node_name
  url                = local.contract.debian.image.url
  file_name          = "debian-${local.contract.debian.build_id}-qualification.qcow2"
  checksum           = local.contract.debian.image.sha512
  checksum_algorithm = "sha512"
  overwrite          = false

  lifecycle {
    precondition {
      condition = (
        var.isolation_attestation_sha256 != "" &&
        var.qualification_node_name != "disabled-qualification" &&
        var.qualification_node_name != local.contract.proxmox.node &&
        var.qualification_image_datastore_id != "" &&
        var.qualification_disk_datastore_id != "" &&
        var.qualification_bridge != "" &&
        var.qualification_cloud_init_file_id == "local:snippets/home-lab-debian-lifecycle-qualification.yaml" &&
        !strcontains(lower(var.proxmox_endpoint), lower(local.contract.proxmox.node)) &&
        !strcontains(var.proxmox_endpoint, split("/", local.contract.network.proxmox.ipv4)[0])
      )
      error_message = "Enabled qualification requires an independently attested non-production PVE target and explicit isolated node, datastore, and bridge identities."
    }
  }
}


resource "proxmox_virtual_environment_vm" "qualification" {
  count       = var.enable_qualification ? 1 : 0
  node_name   = var.qualification_node_name
  vm_id       = local.vm_id
  name        = "home-lab-debian-lifecycle-qualification"
  description = "Disposable Debian lifecycle proof on independently attested isolated PVE target"
  tags        = ["qualification", "disposable", "debian-lifecycle"]

  machine       = "q35"
  scsi_hardware = "virtio-scsi-single"
  boot_order    = ["scsi0"]
  on_boot       = false
  started       = false
  protection    = false

  reboot_after_update                  = false
  stop_on_destroy                      = true
  purge_on_destroy                     = true
  delete_unreferenced_disks_on_destroy = true

  agent {
    enabled = true
    wait_for_ip {
      ipv4 = true
      ipv6 = false
    }
  }
  cpu {
    cores = 4
    type  = "host"
  }
  memory {
    dedicated = 8192
    floating  = 0
  }
  disk {
    datastore_id = var.qualification_disk_datastore_id
    import_from  = proxmox_download_file.qualification_image[0].id
    interface    = "scsi0"
    serial       = "DEB-LIFE-ROOT-32G"
    size         = 32
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }
  initialization {
    datastore_id      = var.qualification_disk_datastore_id
    upgrade           = false
    user_data_file_id = var.qualification_cloud_init_file_id
    dns {
      servers = ["1.1.1.1", "9.9.9.9"]
    }
    ip_config {
      ipv4 { address = "dhcp" }
    }
  }
  network_device {
    bridge   = var.qualification_bridge
    firewall = true
    model    = "virtio"
  }
  serial_device { device = "socket" }
  operating_system { type = "l26" }

  lifecycle {
    precondition {
      condition     = local.contract.proxmox.vm.vmid == 100 && local.vm_id == 9900 && var.controller_ipv4 != split("/", local.contract.vm_100.networking.ipv4)[0] && var.qualification_node_name != local.contract.proxmox.node && var.isolation_attestation_sha256 != ""
      error_message = "Disposable and production VM identities must remain distinct."
    }
    precondition {
      condition     = var.qualification_ssh_public_key != "" && sha256(var.qualification_ssh_public_key) == var.qualification_ssh_public_key_sha256
      error_message = "The dedicated guest first-contact key must match the admitted key identity."
    }
  }
}

resource "proxmox_virtual_environment_firewall_options" "qualification" {
  count         = var.enable_qualification ? 1 : 0
  node_name     = var.qualification_node_name
  vm_id         = proxmox_virtual_environment_vm.qualification[0].vm_id
  enabled       = true
  dhcp          = true
  input_policy  = "DROP"
  output_policy = "DROP"
  ipfilter      = false
  macfilter     = true
}

resource "proxmox_virtual_environment_firewall_rules" "qualification" {
  count     = var.enable_qualification ? 1 : 0
  node_name = var.qualification_node_name
  vm_id     = proxmox_virtual_environment_vm.qualification[0].vm_id

  rule {
    type    = "in"
    action  = "ACCEPT"
    source  = "${var.controller_ipv4}/32"
    proto   = "tcp"
    dport   = "22"
    log     = "nolog"
    comment = "bounded controller SSH"
  }
  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "${var.controller_ipv4}/32"
    proto   = "tcp"
    sport   = "22"
    dport   = "1024:65535"
    log     = "nolog"
    comment = "SSH replies only"
  }
  rule {
    type    = "out"
    action  = "DROP"
    dest    = "10.0.0.0/8"
    log     = "nolog"
    comment = "deny private production networks"
  }
  rule {
    type    = "out"
    action  = "DROP"
    dest    = "172.16.0.0/12"
    log     = "nolog"
    comment = "deny private production networks"
  }
  rule {
    type    = "out"
    action  = "DROP"
    dest    = "192.168.0.0/16"
    log     = "nolog"
    comment = "deny production LAN"
  }
  rule {
    type    = "out"
    action  = "DROP"
    dest    = "100.64.0.0/10"
    log     = "nolog"
    comment = "deny tailnet and CGNAT destinations"
  }
  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "0.0.0.0/0"
    log     = "nolog"
    comment = "public IPv4 egress after private and CGNAT denies"
  }

  lifecycle {
    precondition {
      condition     = can(cidrhost("${var.controller_ipv4}/32", 0)) && var.controller_ipv4 != split("/", local.contract.vm_100.networking.ipv4)[0] && var.controller_ipv4 != split("/", local.contract.network.proxmox.ipv4)[0]
      error_message = "Controller address must be exact and cannot equal a production host."
    }
  }
}

output "qualification" {
  sensitive = true
  value = var.enable_qualification ? {
    vmid               = proxmox_virtual_environment_vm.qualification[0].vm_id
    ipv4               = proxmox_virtual_environment_vm.qualification[0].ipv4_addresses
    cloud_init_sha256  = sha256(local.cloud_init)
    controller_ipv4    = var.controller_ipv4
    isolated_node_name = var.qualification_node_name
    image_sha512       = local.contract.debian.image.sha512
    isolation_evidence = var.isolation_attestation_sha256
    firewall_isolation = true
  } : null
}
