# Keep the existing Authentik user and binding IDs while renaming their state
# addresses. The live plan must update the username in place, never replace it.
moved {
  from = authentik_user.service_accounts["tailscale-control-proxy"]
  to   = authentik_user.service_accounts["gost-proxy-user"]
}

moved {
  from = authentik_policy_binding.service_application_access["tailscale-control-proxy"]
  to   = authentik_policy_binding.service_application_access["gost-proxy-user"]
}
