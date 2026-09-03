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
}

variable "controller_ipv4" {
  type    = string
  default = ""
}

locals {
  contract   = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  vm_id      = 9900
  cloud_init = <<-EOT
    #cloud-config
    hostname: debian-lifecycle-qualification
    manage_etc_hosts: true
    timezone: ${local.contract.system_timezone}
    locale: ${local.contract.debian.locale}
    package_update: false
    package_upgrade: false
    users:
      - name: ansible-deploy
        lock_passwd: true
        shell: /bin/bash
        sudo: ALL=(ALL) NOPASSWD:ALL
        ssh_authorized_keys:
          - ${var.qualification_ssh_public_key}
    packages:
      - qemu-guest-agent
    runcmd:
      - [systemctl, enable, --now, qemu-guest-agent.service]
  EOT
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false
}

resource "proxmox_virtual_environment_file" "cloud_init" {
  count        = var.enable_qualification ? 1 : 0
  content_type = "snippets"
  datastore_id = "local"
  node_name    = local.contract.proxmox.node
  overwrite    = false
  upload_mode  = "stream"
  source_raw {
    data      = local.cloud_init
    file_name = "home-lab-debian-lifecycle-qualification.yaml"
  }
  lifecycle {
    precondition {
      condition     = var.qualification_ssh_public_key != "" && can(cidrhost("0.0.0.0/0", 0))
      error_message = "Qualification requires a dedicated temporary SSH public key."
    }
  }
}

resource "proxmox_virtual_environment_vm" "qualification" {
  count       = var.enable_qualification ? 1 : 0
  node_name   = local.contract.proxmox.node
  vm_id       = local.vm_id
  name        = "home-lab-debian-lifecycle-qualification"
  description = "Disposable network-isolated Debian lifecycle proof; never production VM 100"
  tags        = ["qualification", "disposable", "debian-lifecycle"]

  machine       = "q35"
  scsi_hardware = "virtio-scsi-single"
  boot_order    = ["scsi0"]
  on_boot       = false
  started       = true
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
    datastore_id = "local-lvm"
    import_from  = "local:import/home-lab-restic-recovery-debian-${local.contract.debian.build_id}.qcow2"
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
    datastore_id      = "local-lvm"
    upgrade           = false
    user_data_file_id = proxmox_virtual_environment_file.cloud_init[0].id
    ip_config {
      ipv4 { address = "dhcp" }
    }
  }
  network_device {
    bridge   = local.contract.network.bridge
    firewall = true
    model    = "virtio"
  }
  serial_device { device = "socket" }
  operating_system { type = "l26" }

  lifecycle {
    precondition {
      condition     = local.contract.proxmox.vm.vmid == 100 && local.vm_id == 9900 && var.controller_ipv4 != split("/", local.contract.vm_100.networking.ipv4)[0]
      error_message = "Disposable and production VM identities must remain distinct."
    }
  }
}

resource "proxmox_virtual_environment_firewall_options" "qualification" {
  count         = var.enable_qualification ? 1 : 0
  node_name     = local.contract.proxmox.node
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
  node_name = local.contract.proxmox.node
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
    action  = "ACCEPT"
    dest    = "0.0.0.0/0"
    log     = "nolog"
    comment = "public package sources only"
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
    firewall_isolation = true
  } : null
}
