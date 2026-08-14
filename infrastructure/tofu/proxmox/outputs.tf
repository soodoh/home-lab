output "arch_vm_id" {
  value = proxmox_virtual_environment_vm.arch_readopted.vm_id
}

output "arch_mac" {
  value = local.contract.network.arch.mac
}

output "qualification_vm_id" {
  value = try(proxmox_virtual_environment_vm.qualification[0].vm_id, null)
}
