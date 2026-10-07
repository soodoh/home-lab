mock_provider "proxmox" {}

variables {
  proxmox_access_api_token = "owner@pve!owner-plan=synthetic-test-token"
}

run "preserve_separated_access" {
  command = apply

  assert {
    condition = (
      length(proxmox_virtual_environment_role.automation) == 5 &&
      length(proxmox_acl.automation) == 7 &&
      local.token_ids.plan == "root@pam!tofu-plan" &&
      local.token_ids.apply == "root@pam!tofu-apply" &&
      proxmox_acl.automation["plan_disk_inspect"].path == "/vms/100" &&
      proxmox_acl.automation["plan_disk_inspect"].role_id == "HomeLabTofuPlanDiskInspect" &&
      proxmox_acl.automation["apply"].token_id == "root@pam!tofu-apply"
    )
    error_message = "Reference independently owned token identities and preserve original/scoped ACLs."
  }

  assert {
    condition = (
      alltrue([for privileges in local.access.roles :
        !contains(privileges, "Permissions.Modify") && !contains(privileges, "User.Modify")
      ]) &&
      toset(proxmox_virtual_environment_role.automation["HomeLabTofuPlanDiskInspect"].privileges) == toset(["VM.Audit", "VM.Config.Disk"]) &&
      toset(proxmox_virtual_environment_role.automation["HomeLabTofuPlanStorageInspect"].privileges) == toset(["Datastore.Allocate"]) &&
      !contains(proxmox_virtual_environment_role.automation["HomeLabTofuPlan"].privileges, "Datastore.Allocate") &&
      !contains(proxmox_virtual_environment_role.automation["HomeLabTofuApply"].privileges, "Sys.Modify") &&
      toset(proxmox_virtual_environment_role.automation["HomeLabTofuApplyNodeModify"].privileges) == toset(["Sys.Modify"]) &&
      proxmox_acl.automation["apply_node_modify"].path == "/nodes/proxmox" &&
      proxmox_acl.automation["apply_node_modify"].propagate &&
      proxmox_acl.automation["apply_node_modify"].token_id == "root@pam!tofu-apply" &&
      alltrue([for acl in proxmox_acl.automation :
        !contains(local.access.roles[acl.role_id], "Sys.Modify") ||
        (acl.path == "/nodes/proxmox" && acl.role_id == "HomeLabTofuApplyNodeModify")
      ]) &&
      toset([for name, acl in proxmox_acl.automation : acl.path if startswith(name, "plan_storage_")]) == toset([
        "/storage/local", "/storage/local-lvm", "/storage/storage"
      ]) &&
      alltrue([for name, acl in proxmox_acl.automation : !acl.propagate if startswith(name, "plan_storage_")])
    )
    error_message = "Managed automation must not gain direct API permission to change its own access."
  }

  assert {
    condition = (
      proxmox_cluster_options.cluster.keyboard == "en-us" &&
      proxmox_cluster_options.cluster.mac_prefix == "BC:24:11"
    )
    error_message = "Global cluster settings require the independent owner writer, not global Sys.Modify for automation."
  }
}

run "reject_managed_plan_identity" {
  command = plan

  variables {
    proxmox_access_api_token = "root@pam!tofu-plan=synthetic-test-token"
  }

  expect_failures = [var.proxmox_access_api_token]
}

run "reject_managed_apply_identity" {
  command = plan

  variables {
    proxmox_access_api_token = "root@pam!tofu-apply=synthetic-test-token"
  }

  expect_failures = [var.proxmox_access_api_token]
}

run "reject_malformed_owner_identity" {
  command = plan

  variables {
    proxmox_access_api_token = "not-a-token"
  }

  expect_failures = [var.proxmox_access_api_token]
}
