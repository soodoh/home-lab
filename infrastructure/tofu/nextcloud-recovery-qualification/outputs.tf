output "stopped_foundation" {
  description = "Non-secret identity of the stopped-only recovery foundation."
  value = var.enable_foundation ? {
    vmid                  = proxmox_virtual_environment_vm.foundation[0].vm_id
    node                  = local.node_name
    memory_mb             = local.memory_mb
    disk_size_gb          = local.disk_size_gb
    disk_datastore        = local.disk_datastore
    retrieval_nic_enabled = var.retrieval_nic_enabled
    started               = false
    cloud_init_sha256     = sha256(local.cloud_init)
    base_image_sha512     = local.contract.debian.image.sha512
  } : null
}
