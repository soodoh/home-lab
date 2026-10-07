mock_provider "proxmox" {}

# Real provider file IDs have a datastore/content path, not random mock strings.
override_resource {
  target = proxmox_virtual_environment_file.cloud_init["meta"]
  values = { id = "local:snippets/vm-100-debian-meta.yaml" }
}

override_resource {
  target = proxmox_virtual_environment_file.cloud_init["network"]
  values = { id = "local:snippets/vm-100-debian-network.yaml" }
}

override_resource {
  target = proxmox_virtual_environment_file.cloud_init["user"]
  values = { id = "local:snippets/vm-100-debian-user.yaml" }
}

run "implicit_mtu_is_preserved_when_requested" {
  command = plan

  variables {
    proxmox_bridge_mtu = null
  }

  assert {
    condition = (
      proxmox_network_linux_bridge.lan.mtu == null &&
      proxmox_network_linux_bridge.lan.address == "192.168.0.123/24" &&
      proxmox_network_linux_bridge.lan.ports == tolist(["eno1"])
    )
    error_message = "Null MTU must preserve native implicit-default readback without changing the management path."
  }
}

run "plan_keeps_boot_inputs_known" {
  command = plan

  assert {
    condition = (
      proxmox_virtual_environment_vm.debian.initialization[0].user_data_file_id == "local:snippets/vm-100-debian-user.yaml" &&
      proxmox_virtual_environment_vm.debian.initialization[0].meta_data_file_id == "local:snippets/vm-100-debian-meta.yaml" &&
      proxmox_virtual_environment_vm.debian.initialization[0].network_data_file_id == "local:snippets/vm-100-debian-network.yaml" &&
      proxmox_virtual_environment_vm.debian.disk[2].file_format == "raw"
    )
    error_message = "Computed upload IDs must not make the saved-plan boot configuration unknown."
  }
}

run "native_vm_and_node_ownership" {
  command = apply

  assert {
    condition = (
      proxmox_virtual_environment_vm.debian.disk[0].interface == "scsi1" &&
      proxmox_virtual_environment_vm.debian.disk[1].interface == "scsi2" &&
      proxmox_virtual_environment_vm.debian.disk[2].interface == "scsi3" &&
      proxmox_virtual_environment_vm.debian.disk[2].path_in_datastore == "vm-100-disk-2" &&
      proxmox_virtual_environment_vm.debian.disk[2].serial == "HOME-LAB-DEBIAN-64G" &&
      proxmox_virtual_environment_vm.debian.disk[2].size == 64 &&
      length(proxmox_virtual_environment_vm.debian.disk) == 3 &&
      proxmox_virtual_environment_vm.debian.boot_order == tolist(["scsi3", "net0"])
    )
    error_message = "All existing attachments must match native import ordering without moving their bus slots."
  }

  assert {
    condition = (
      proxmox_virtual_environment_vm.debian.protection &&
      !proxmox_virtual_environment_vm.debian.delete_unreferenced_disks_on_destroy &&
      !proxmox_virtual_environment_vm.debian.purge_on_destroy &&
      !proxmox_virtual_environment_vm.debian.stop_on_destroy
    )
    error_message = "Adoption must preserve compute destruction safeguards."
  }

  assert {
    condition = (
      proxmox_storage_directory.local.path == "/var/lib/vz" &&
      toset(proxmox_storage_directory.local.content) == toset(["backup", "import", "iso", "snippets", "vztmpl"]) &&
      proxmox_storage_lvmthin.local.volume_group == "pve" &&
      proxmox_storage_lvmthin.local.thin_pool == "data" &&
      proxmox_storage_zfspool.storage.zfs_pool == "storage" &&
      toset(proxmox_storage_zfspool.storage.nodes) == toset(["proxmox"])
    )
    error_message = "Storage registrations must reference the existing pools and content types."
  }

  assert {
    condition = (
      proxmox_network_linux_bridge.lan.name == "vmbr0" &&
      proxmox_network_linux_bridge.lan.address == "192.168.0.123/24" &&
      proxmox_network_linux_bridge.lan.gateway == "192.168.0.1" &&
      proxmox_network_linux_bridge.lan.ports == tolist(["eno1"]) &&
      proxmox_network_linux_bridge.lan.mtu == 1500 &&
      proxmox_virtual_environment_dns.node.servers == tolist(["192.168.0.1", "192.168.0.1"]) &&
      proxmox_virtual_environment_time.node.time_zone == "America/Los_Angeles"
    )
    error_message = "Node adoption must preserve the management path and node settings."
  }

  assert {
    condition = (
      proxmox_virtual_environment_vm.debian.initialization[0].user_data_file_id == proxmox_virtual_environment_file.cloud_init["user"].id &&
      proxmox_virtual_environment_vm.debian.initialization[0].meta_data_file_id == proxmox_virtual_environment_file.cloud_init["meta"].id &&
      proxmox_virtual_environment_vm.debian.initialization[0].network_data_file_id == proxmox_virtual_environment_file.cloud_init["network"].id &&
      alltrue([for snippet in proxmox_virtual_environment_file.cloud_init :
        snippet.content_type == "snippets" && snippet.upload_mode == "stream" && !snippet.overwrite
      ])
    )
    error_message = "Cloud-init must reference native file resources without silently overwriting unowned files."
  }

  assert {
    condition = (
      yamldecode(proxmox_virtual_environment_file.cloud_init["meta"].source_raw[0].data)["instance-id"] == "vm-100-debian-13-20260810-2566-v1" &&
      yamldecode(proxmox_virtual_environment_file.cloud_init["network"].source_raw[0].data).ethernets.ens18.match.macaddress == lower(var.proxmox_vm.network.docker_host_mac) &&
      !yamldecode(proxmox_virtual_environment_file.cloud_init["user"].source_raw[0].data).ssh_pwauth &&
      alltrue([for user in yamldecode(proxmox_virtual_environment_file.cloud_init["user"].source_raw[0].data).users :
        !contains(keys(user), "ssh_authorized_keys") && user.lock_passwd
      ])
    )
    error_message = "First-boot identity/network must be preserved without legacy SSH credentials."
  }
}

run "reject_boot_volume_retargeting" {
  command = plan

  variables {
    proxmox_vm = merge(jsondecode(file("vm.auto.tfvars.json")).proxmox_vm, {
      vm = merge(jsondecode(file("vm.auto.tfvars.json")).proxmox_vm.vm, {
        boot_disk = merge(jsondecode(file("vm.auto.tfvars.json")).proxmox_vm.vm.boot_disk, {
          volume = "vm-100-unreviewed"
        })
      })
    })
  }

  expect_failures = [var.proxmox_vm]
}
