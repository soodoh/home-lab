locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))

  vm_id            = 9000
  node_name        = "proxmox"
  proxmox_endpoint = "https://proxmox:8006/api2/json"
  image_datastore  = "local"
  disk_datastore   = "local-lvm"
  retrieval_bridge = "vmbr0"
  memory_mb        = 6144
  disk_size_gb     = 64

  cloud_init = <<-EOT
    #cloud-config
    hostname: nextcloud-recovery-qualification
    manage_etc_hosts: true
    timezone: ${local.contract.lifecycle.maintenance.reboot_plan.debian_window.timezone}
    locale: ${local.contract.debian.locale}
    package_update: false
    package_upgrade: false
    ssh_pwauth: false
    disable_root: true
    users:
      - name: recovery-operator
        lock_passwd: true
        shell: /bin/bash
        sudo: ALL=(ALL) NOPASSWD:ALL
        ssh_authorized_keys:
          - ${jsonencode(var.recovery_ssh_public_key)}
    write_files:
      - path: /etc/sysctl.d/90-nextcloud-recovery-no-ipv6.conf
        owner: root:root
        permissions: '0644'
        content: |
          net.ipv6.conf.all.disable_ipv6=1
          net.ipv6.conf.default.disable_ipv6=1
    runcmd:
      - [sysctl, --system]
  EOT
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false

  # Snippet upload and image import require SSH. The existing bounded Proxmox
  # operator uses sudo for stream uploads; credentials remain in the agent.
  ssh {
    agent    = true
    username = "proxmox"

    node {
      name    = local.node_name
      address = "proxmox.tailea1a78.ts.net"
    }
  }
}

check "stopped_foundation_scope" {
  assert {
    condition     = !var.retrieval_nic_enabled || var.enable_foundation
    error_message = "The retrieval NIC cannot exist without the stopped foundation."
  }
}

resource "proxmox_download_file" "recovery_image" {
  count = var.enable_foundation ? 1 : 0

  content_type       = "import"
  datastore_id       = local.image_datastore
  node_name          = local.node_name
  url                = local.contract.debian.image.url
  file_name          = "debian-${local.contract.debian.build_id}-nextcloud-recovery.qcow2"
  checksum           = local.contract.debian.image.sha512
  checksum_algorithm = "sha512"
  overwrite          = false

  lifecycle {
    precondition {
      condition = (
        local.contract.proxmox.node == local.node_name &&
        local.contract.proxmox.vm.vmid == 100 &&
        var.proxmox_endpoint == local.proxmox_endpoint &&
        var.isolation_attestation_sha256 != ""
      )
      error_message = "Foundation enablement requires exact production-PVE identity and reviewed isolation admission."
    }
  }
}

resource "proxmox_virtual_environment_file" "cloud_init" {
  count = var.enable_foundation ? 1 : 0

  content_type = "snippets"
  datastore_id = local.image_datastore
  node_name    = local.node_name
  overwrite    = false
  upload_mode  = "stream"

  source_raw {
    data      = local.cloud_init
    file_name = "nextcloud-recovery-qualification.yaml"
  }

  lifecycle {
    precondition {
      condition = (
        var.recovery_ssh_public_key != "" &&
        sha256(var.recovery_ssh_public_key) == var.recovery_ssh_public_key_sha256
      )
      error_message = "The disposable guest key must match its reviewed identity."
    }
  }
}

resource "proxmox_virtual_environment_vm" "foundation" {
  count = var.enable_foundation ? 1 : 0

  node_name   = local.node_name
  vm_id       = local.vm_id
  name        = "nextcloud-recovery-qualification"
  description = "Stopped-only Nextcloud recovery foundation; never production VM100 or retired VM9900"
  tags        = ["qualification", "disposable", "nextcloud-recovery"]

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
    dedicated = local.memory_mb
    floating  = 0
  }

  disk {
    datastore_id = local.disk_datastore
    import_from  = proxmox_download_file.recovery_image[0].id
    interface    = "scsi0"
    serial       = "NEXTCLOUD-RECOVERY-64G"
    size         = local.disk_size_gb
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }

  initialization {
    datastore_id      = local.disk_datastore
    upgrade           = false
    user_data_file_id = proxmox_virtual_environment_file.cloud_init[0].id

    dns {
      servers = ["1.1.1.1", "9.9.9.9"]
    }

    ip_config {
      ipv4 { address = "dhcp" }
    }
  }

  # The pinned provider distinguishes an explicit [] from an omitted value. The
  # explicit empty list is required to delete net0 rather than merely stop
  # managing it when retrieval is complete.
  network_device = var.retrieval_nic_enabled ? [{
    bridge       = local.retrieval_bridge
    disconnected = null
    enabled      = null
    firewall     = true
    mac_address  = null
    model        = "virtio"
    mtu          = null
    queues       = null
    rate_limit   = null
    trunks       = null
    vlan_id      = null
  }] : []

  serial_device { device = "socket" }
  operating_system { type = "l26" }

  lifecycle {
    precondition {
      condition = (
        local.vm_id != local.contract.proxmox.vm.vmid &&
        local.vm_id != 9900 &&
        local.disk_datastore == "local-lvm" &&
        local.memory_mb == 6144 &&
        local.disk_size_gb == 64
      )
      error_message = "The stopped recovery foundation identity or admitted resource shape differs."
    }
    precondition {
      condition = (
        !var.retrieval_nic_enabled ||
        (
          can(cidrhost("${var.controller_ipv4}/32", 0)) &&
          var.controller_ipv4 != split("/", local.contract.vm_100.networking.ipv4)[0] &&
          var.controller_ipv4 != split("/", local.contract.network.proxmox.ipv4)[0] &&
          local.retrieval_bridge == local.contract.network.bridge
        )
      )
      error_message = "Retrieval NIC attachment requires one exact non-production controller IPv4 on the reviewed bridge."
    }
  }
}

resource "proxmox_virtual_environment_firewall_options" "foundation" {
  count = var.enable_foundation ? 1 : 0

  node_name     = local.node_name
  vm_id         = proxmox_virtual_environment_vm.foundation[0].vm_id
  enabled       = true
  dhcp          = true
  input_policy  = "DROP"
  output_policy = "DROP"
  ipfilter      = false
  macfilter     = true
}

resource "proxmox_virtual_environment_firewall_rules" "foundation" {
  count = var.enable_foundation ? 1 : 0

  node_name = local.node_name
  vm_id     = proxmox_virtual_environment_vm.foundation[0].vm_id

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "255.255.255.255/32"
    proto   = "udp"
    sport   = "68"
    dport   = "67"
    log     = "nolog"
    comment = "DHCP discovery"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    source  = "0.0.0.0/0"
    proto   = "udp"
    sport   = "67"
    dport   = "68"
    log     = "nolog"
    comment = "DHCP offer"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    source  = "${var.controller_ipv4}/32"
    proto   = "tcp"
    dport   = "22"
    log     = "nolog"
    comment = "ephemeral controller SSH"
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
    comment = "deny private networks"
  }

  rule {
    type    = "out"
    action  = "DROP"
    dest    = "172.16.0.0/12"
    log     = "nolog"
    comment = "deny private networks"
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
    comment = "deny tailnet and CGNAT"
  }

  rule {
    type    = "out"
    action  = "DROP"
    dest    = "169.254.0.0/16"
    log     = "nolog"
    comment = "deny link-local"
  }

  rule {
    type    = "out"
    action  = "DROP"
    dest    = "224.0.0.0/4"
    log     = "nolog"
    comment = "deny multicast"
  }

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "1.1.1.1/32"
    proto   = "udp"
    dport   = "53"
    log     = "nolog"
    comment = "reviewed DNS"
  }

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "9.9.9.9/32"
    proto   = "udp"
    dport   = "53"
    log     = "nolog"
    comment = "reviewed DNS fallback"
  }

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "1.1.1.1/32"
    proto   = "tcp"
    dport   = "53"
    log     = "nolog"
    comment = "reviewed DNS TCP fallback"
  }

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "9.9.9.9/32"
    proto   = "tcp"
    dport   = "53"
    log     = "nolog"
    comment = "reviewed DNS TCP fallback"
  }

  rule {
    type    = "out"
    action  = "ACCEPT"
    dest    = "0.0.0.0/0"
    proto   = "tcp"
    dport   = "443"
    log     = "nolog"
    comment = "public HTTPS retrieval after private denies"
  }

  lifecycle {
    precondition {
      condition     = can(cidrhost("${var.controller_ipv4}/32", 0))
      error_message = "Enabled foundation firewall rules require one exact controller IPv4."
    }
  }
}
