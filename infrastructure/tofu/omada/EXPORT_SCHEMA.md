# Required ignored Omada export

`omada_export_path` must point to a root-only, ignored JSON file with this shape.
Values below are synthetic examples, not desired reservation identities:

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

Do not add import blocks until this export is supplied and reviewed. Import the network by its confirmed ID first, then each reservation as `<site>/<MAC>`.
