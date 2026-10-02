# Omada ownership and live export input

`domain.auto.tfvars.json` selects the controller, site and LAN.
`desired.json` is the reviewed Git authority; never regenerate it as a routine
planning step. Resource settings come from Git, not the live export. Unexpected
settings produce a drift plan to investigate, not permission to copy them into Git.

## Selective ownership

The selected site owns the LAN, every DHCP reservation and port forward, and the
listed SSIDs. SSID IDs, reservation MACs and port-forward IDs are stable resource
address keys. Changing a key or WLAN-group identity needs a reviewed migration,
not an accidental replacement. The gateway is bound to its reviewed device MAC.

The root also manages these explicitly configured settings:

- LAN isolation, IPv6 enablement, IGMP snooping, DHCP DNS mode and lease duration.
- Wi-Fi bands, security mode/version/encryption, visibility, VLAN/guest status,
  roaming/PMF and multicast behavior. The untagged SSID reports VLAN ID `0` through
  the provider; do not substitute its default `1` during adoption.
- Disabled UPnP, managed-device SSH/cross-subnet access, and both SNMP versions.
- Automatic firmware upgrades, mesh and fast-roaming site policy.
- Existing enabled attack-defense controls, including the existing WAN-ping
  response. Adoption is not a security-policy change; do not invert that setting.
- Gateway hardware offload and LLDP. Do not configure the gateway's IGMP attributes:
  site proxy/IGMP ownership belongs to `omada_iptv` alone.
- Site IGMP proxy/version and disabled IPTV. The controller reports selected IPTV
  port flags even while IPTV is disabled; preserve those latent IDs, not an empty
  list. They do not activate IPTV while `enable` is false.
- Global alert/event email, batching delays and webhook delivery controls.

Unset optional/computed attributes are not desired authority. Provider defaults
still apply where documented; require an import-only plan with **zero** controller
updates before adopting resources. Wi-Fi `psk` is deliberately omitted: updates
preserve the existing key, but its write-only interface cannot detect password
drift. Do not export or put Wi-Fi/SNMP credentials in Git.

Individual alert/event selector maps are intentionally not declared here. Provider
v0.11.10 refreshes only selector keys already in state; declaring even matching
sparse maps during import causes an update. Review any future selector adoption
separately instead of calling it a no-op import. Unlisted selectors remain intact.
SMTP belongs to [native Ansible](../../../docs/omada-mail.md), not this root.
Recipients are a read-only projection of independently owned administrator account
email/alert subscriptions, checked as a prerequisite by Ansible. Provider
notification writes do not establish recipient configuration. Serialize notification
applies, SMTP convergence, account changes and manual edits; rereading cannot
eliminate a concurrent-edit race.

Other sites/networks, WLAN-group configuration, WAN configuration, AP names/radios
and switch configuration remain outside this ownership boundary.

## Fresh identity export

`omada_export_path` is an explicit absolute path to a mode-0600 JSON export in a
new private current-run directory. The preparation helper requires a nonexistent
file in a mode-0700 directory, verifies the tailnet-only HTTPS endpoint with system
trust, and uses the read-only provider identity. Delete the export after the
session; never store it in controller credentials or Git.

The export inventories every reservation, port forward and SSID in the selected
site, including each SSID's WLAN group, plus exactly one gateway. Missing or extra
identities, changed groups/MAC, wrong controller version or an export older than
15 minutes refuse management. Resource preconditions enforce this boundary;
the check block alone is not an apply gate. Native bare and paginated list shapes
are supported. Credential-bearing WLAN/device objects are reduced to identities
before export. Existing DHCP option values must remain private and preserved in
Git's reviewed DHCP-options configuration.

The required shape is shown with synthetic values:

```json
{
  "exported_at": "RFC3339",
  "controller_version": "6.3.0.45",
  "site": { "id": "site-id", "name": "site-name" },
  "network": {
    "id": "network-id",
    "name": "LAN",
    "vlan_id": 1,
    "gateway_subnet": "192.168.0.1/24",
    "dhcp_enabled": true,
    "dhcp_start": "192.168.0.10",
    "dhcp_end": "192.168.0.99",
    "dhcp_options": [{ "code": 138, "type": 1, "value": "192.168.0.100" }]
  },
  "reservations": [
    { "name": "arch", "mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.0.100", "enable": true }
  ],
  "port_forwards": [
    {
      "id": "rule-id",
      "name": "https-ingress",
      "enable": true,
      "external_port": "443",
      "forward_ip": "192.168.0.100",
      "forward_port": "443",
      "protocol": "tcp",
      "wan_port_ids": ["wan-port-id"],
      "dmz": false
    }
  ],
  "wireless_networks": [
    { "id": "ssid-id", "wlan_group_id": "group-id", "name": "Home" }
  ],
  "gateway": { "mac": "AA-BB-CC-DD-EE-FF" }
}
```

[`scripts/prepare-omada-plan-input`](../../../scripts/prepare-omada-plan-input)
creates this observation afresh. Follow [operations](../../../docs/operations.md)
for clean-checkout review, private credentials, remote state, plan inspection and
separate apply confirmation. An import-only policy entry admits ownership only;
it does not authorize a controller update or an apply. Remove transition-only
import allowances after verified adoption and a fresh no-op plan.
