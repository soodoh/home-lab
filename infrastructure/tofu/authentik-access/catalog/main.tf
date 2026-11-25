terraform {
  required_providers {
    authentik = {
      source = "registry.terraform.io/goauthentik/authentik"
    }
  }
}

variable "models_by_role" {
  type = map(map(string))
}

# Authentik assigns the permission numbers. This data source filters only by
# codename, so pin and verify the complete native model before using the ID.
data "authentik_rbac_permission" "permission" {
  for_each = merge(values(var.models_by_role)...)
  codename = split(".", each.key)[1]

  lifecycle {
    postcondition {
      condition     = "${self.app}.${self.model}" == each.value
      error_message = "The Authentik permission catalog did not return the declared app/model for this codename."
    }
  }
}

output "ids_by_role" {
  value = {
    for role, permissions in var.models_by_role : role => [
      for permission in sort(keys(permissions)) : tonumber(data.authentik_rbac_permission.permission[permission].id)
    ]
  }
}
