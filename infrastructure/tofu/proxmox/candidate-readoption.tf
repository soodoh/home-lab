removed {
  from = proxmox_virtual_environment_vm.arch

  lifecycle {
    destroy = false
  }
}

import {
  to = proxmox_virtual_environment_vm.arch_readopted
  id = "proxmox/100"
}
