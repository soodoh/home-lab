provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false

  # Tailscale SSH admits this account through SSH's initial "none" handshake.
  # No conventional SSH key, password or agent is added. Pre-pin the node FQDN
  # in the controller's known_hosts: this provider accepts unknown host keys.
  ssh {
    username         = "ansible-deploy"
    agent            = false
    agent_forwarding = false

    node {
      name    = "proxmox"
      address = "proxmox.mora-rattlesnake.ts.net"
    }
  }
}
