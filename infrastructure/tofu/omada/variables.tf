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
  })

  validation {
    condition = (
      var.omada_domain.controller_version != "" &&
      startswith(var.omada_domain.endpoint, "https://")
    )
    error_message = "The Omada domain requires a controller version and HTTPS endpoint."
  }
}
