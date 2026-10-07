# PVE requires Sys.Modify at / for datacenter-option writes. That privilege
# also authorizes role edits at /access, so this is an independent owner writer.
resource "proxmox_cluster_options" "cluster" {
  keyboard   = "en-us"
  mac_prefix = "BC:24:11"
}
