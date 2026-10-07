locals {
  cloud_init_snippets = jsondecode(file("${path.module}/cloud-init/files.json"))
  # Keep the stable volume IDs known during file replacement. Reading each file
  # resource's input attributes retains upload dependencies without unknown .id
  # values obscuring the VM's boot configuration in its saved plan.
  cloud_init_file_ids = {
    for kind, snippet in proxmox_virtual_environment_file.cloud_init :
    kind => "${snippet.datastore_id}:snippets/${snippet.source_raw[0].file_name}"
  }
}

resource "proxmox_virtual_environment_file" "cloud_init" {
  for_each = local.cloud_init_snippets

  node_name    = local.node
  datastore_id = proxmox_storage_directory.local.id
  content_type = "snippets"
  upload_mode  = "stream"
  overwrite    = false

  source_raw {
    data      = file("${path.module}/cloud-init/${each.key}.yaml")
    file_name = each.value
  }
}
