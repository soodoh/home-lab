variable "omada_export_path" {
  type    = string
  default = ""
}

variable "omada_enable_management" {
  type    = bool
  default = false
}

variable "omada_domain" {
  type = object({
    controller_version = string
    endpoint           = string
    site_name          = string
    network_name       = string
  })

  validation {
    condition = (
      var.omada_domain.controller_version != "" &&
      startswith(var.omada_domain.endpoint, "https://") &&
      trimspace(var.omada_domain.site_name) != "" &&
      trimspace(var.omada_domain.network_name) != ""
    )
    error_message = "The Omada domain requires a controller version, HTTPS endpoint, site, and network."
  }
}
