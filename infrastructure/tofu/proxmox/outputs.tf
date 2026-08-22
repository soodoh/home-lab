output "docker_host_vm_id" {
  value = proxmox_virtual_environment_vm.debian.vm_id
}

output "docker_host_mac" {
  value = local.contract.network.docker_host.mac
}
