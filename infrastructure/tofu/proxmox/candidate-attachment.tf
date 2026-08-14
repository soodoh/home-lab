resource "terraform_data" "vm_100_candidate_disk_attachment" {
  input = {
    vm_id     = local.vm.vmid
    interface = local.vm.candidate_disk.interface
    datastore = local.vm.candidate_disk.datastore
    serial    = local.vm.candidate_disk.serial
    size_gb   = local.vm.candidate_disk.size_gb
  }

  provisioner "local-exec" {
    command = "${path.module}/../../../scripts/proxmox-vm-100-candidate-disk.py apply"

    environment = {
      HOMELAB_VM100_CANDIDATE_ATTACHMENT = "reviewed-opentofu-action"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}
