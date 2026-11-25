variable "authentik_access_adopted_object_ids" {
  type        = map(string)
  default     = {}
  nullable    = false
  description = "Verified IDs keyed by app desired collection/key for existing objects without a pinned primary key. Keep admitted IDs in Git, not in per-run options."

  validation {
    condition = alltrue([
      for pk in values(var.authentik_access_adopted_object_ids) :
      can(regex("^([1-9][0-9]*|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})$", pk))
    ])
    error_message = "Adopted Authentik IDs must be native UUIDs or positive integer IDs."
  }
}
