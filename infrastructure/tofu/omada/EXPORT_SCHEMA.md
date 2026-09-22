# Omada live export input

This root owns its non-secret controller version and endpoint in
`domain.auto.tfvars.json`, including the exact site, network and UI-bootstrapped
VPN selectors.
`omada_export_path` is an explicit absolute path to a
mode-0600 JSON export created from the current controller session in a new private
temporary directory. [`scripts/prepare-omada-plan-input`](../../../scripts/prepare-omada-plan-input)
uses the read-only provider identity to fetch it directly from the live controller.
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
  "vpn": {
    "id": "vpn-id",
    "name": "home_lab_deploy",
    "enable": true,
    "purpose": 4
  },
  "reservations": [
    { "name": "arch", "mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.0.100", "enable": true }
  ]
}
```

Values above are synthetic. The preparation helper requires
`TF_VAR_omada_export_path` to name a nonexistent file in a mode-0700 directory,
verifies the managed `Omada` host alias and private CA, and creates the export
without replacement. The provider can preserve and import the selected VPN, but
models only its name, enabled state and read-only purpose. It does not prove or
manage the WireGuard protocol, keys, port, pool or clients. Never carry the
export into another session.
