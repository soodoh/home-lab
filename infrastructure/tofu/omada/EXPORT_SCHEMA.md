# Omada live export input

This root owns its non-secret controller version and endpoint in
`domain.auto.tfvars.json`. `omada_export_path` is an explicit absolute path to a
mode-0600 JSON export created from the current controller session in a new private
temporary directory. Delete it after the plan/apply session.

The required shape is:

```json
{
  "exported_at": "RFC3339",
  "controller_version": "6.2.14.11",
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
  ]
}
```

Values above are synthetic. [`scripts/prepare-omada-plan-input`](../../../scripts/prepare-omada-plan-input)
requires `TF_VAR_omada_export_path` to name a nonexistent file in a mode-0700
directory and creates it without replacement. Never carry the export into another
session.
