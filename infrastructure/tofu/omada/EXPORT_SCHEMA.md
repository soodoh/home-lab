# Omada live export input

This root owns its non-secret controller version and endpoint in
`domain.auto.tfvars.json`, including the exact site and network selectors.
`omada_export_path` is an explicit absolute path to a
mode-0600 JSON export created from the current controller session in a new private
temporary directory. The export includes every port-forwarding rule in the selected
site so existing rules can be adopted without recreation.
[`scripts/prepare-omada-plan-input`](../../../scripts/prepare-omada-plan-input) uses
the read-only provider identity to fetch it directly from the live controller.
Delete it after the plan/apply session; never retain the export in controller
credential files.

The required shape is:

```json
{
  "exported_at": "RFC3339",
  "controller_version": "6.3.0.45",
  "site": { "id": "controller-id", "name": "site-name" },
  "network": {
    "id": "network-id",
    "name": "LAN",
    "vlan_id": 1,
    "gateway_subnet": "192.168.0.1/24",
    "dhcp_enabled": true,
    "dhcp_start": "192.168.0.10",
    "dhcp_end": "192.168.0.99"
  },
  "reservations": [
    { "name": "arch", "mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.0.100", "enable": true }
  ],
  "port_forwards": [
    {
      "id": "controller-rule-id",
      "name": "https-ingress",
      "enable": true,
      "external_port": "443",
      "forward_ip": "192.168.0.100",
      "forward_port": "443",
      "protocol": "tcp",
      "wan_port_ids": ["controller-wan-port-id"],
      "dmz": false
    }
  ]
}
```

Values above are synthetic. The preparation helper requires
`TF_VAR_omada_export_path` to name a nonexistent file in a mode-0700 directory,
verifies the tailnet-only Tailscale Serve endpoint through the system trust store and
creates the export without replacement. Never carry the export into another session.
