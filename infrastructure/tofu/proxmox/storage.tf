# PVE storage registrations only. The underlying zpool, datasets and LVM pool
# are not created, reformatted or destroyed by these declarations.
resource "proxmox_storage_directory" "local" {
  id      = "local"
  path    = "/var/lib/vz"
  content = ["backup", "import", "iso", "snippets", "vztmpl"]
}

resource "proxmox_storage_lvmthin" "local" {
  id           = "local-lvm"
  volume_group = "pve"
  thin_pool    = "data"
  content      = ["images", "rootdir"]
}

resource "proxmox_storage_zfspool" "storage" {
  id       = "storage"
  zfs_pool = "storage"
  nodes    = [local.node]
  content  = ["images", "rootdir"]
}
