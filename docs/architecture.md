# Architecture and authority

## Sources of truth

| Concern | Authority |
| --- | --- |
| Desired resources and host configuration | Reviewed Git source |
| Current host and application state | Fresh Proxmox/Docker-host observation |
| Current provider state | Fresh provider reads and plans |
| Provider-resource ownership | OpenTofu remote state |
| Active mutation or recovery | Host-local lock, journal and before-image |
| Secrets and recovery payloads | SOPS or independent protected storage |
| Historical explanation | Git, review and CI history |

Observation output is transient. It may authorize only the run that produced it,
and mutation must revalidate relevant conditions after acquiring ownership.

## Boundaries

### Git

Git contains declarative configuration, version/digest pins, policy, schemas for
reusable interfaces, and synthetic tests. It does not contain saved plans, state,
receipts, historical observations or completed transaction records.

A digest in Git identifies desired bytes. It does not prove those bytes are live.

### Controllers

A controller checkout and its caches are disposable. A valid workflow works from a
fresh clone with current credentials and network access. `.local/`, `.reconcile/`,
provider caches and captured browser output are never inputs to another run.

### Managed hosts

A host may retain state needed to make an interrupted mutation safe. A nonterminal
owner, journal or before-image remains authoritative until an operator observes and
resolves it. Terminal records receive bounded retention and are not copied into Git.

### OpenTofu

Every active provider root uses a remote backend. Planning refreshes that state
against the provider. Saved plans are short-lived private files bound to one reviewed
run; they are destroyed after apply, refusal or abandonment.

### Recovery

Git defines recovery groups and recovery tooling. Snapshot IDs, repository IDs,
current artifact identities and tool identities are discovered live. Recovery
credentials and encrypted bundles live outside Git.

## Durable design decisions

- The existing hosts are adopted through Tailscale SSH and Ansible privilege
  escalation; there is no custom controller state machine or native deployment key.
  GitHub workload identity federation can create a narrowly tagged ephemeral CI node
  without a reusable Tailscale credential.
- Compose convergence archives committed Git source and reconciles the complete
  project with the native Compose module. Git revert followed by convergence is
  configuration rollback.
- Omada remote state owns the default LAN, its DHCP reservations and all
  port-forwarding rules in the selected site. Reviewed `desired.json` supplies
  their settings; a fresh private controller export supplies import identities and
  checks completeness, never desired settings. Declarative import blocks preserve
  bootstrap from an empty state without imperative state scripts. Local and CI
  controllers use one tailnet-only Tailscale Serve endpoint with public TLS trust;
  Ansible owns its exact node-level proxy to the
  Omada loopback HTTPS listener. Omada's forced HTTPS redirect requires that one
  encrypted loopback hop to accept the private certificate without authentication.
- Proxmox remote state owns the adopted VM, its managed disks and its PCI and USB
  hardware mappings. The inert first disk block preserves provider list indexes after
  retirement of its former bus slot; changing that tombstone requires an explicit
  provider/state migration. Native Proxmox services persist the firewall policy; the
  observer reads the API and requires the reviewed policy, exact rule order, default
  forward policy and both backends to match. A separate `proxmox-firewall` OpenTofu
  root stages ownership without inheriting the VM/hardware root's provider-planned
  updates. It remains disabled until the new remote state key is authorized and the
  pinned provider imports both cluster resources with a no-op plan. The provider
  does not round-trip PVE's omitted default forward policy, so only that attribute
  is ignored by OpenTofu and independently enforced by the host observer. Ansible
  is never a second firewall writer.
- Data recovery stages into a new private directory before any production decision.
- External Nextcloud user data is outside the managed Restic recovery group and must
  be handled independently.
- Host-side autonomous rollback may outlive a controller only where loss of
  connectivity could otherwise strand the host.
- `gost.diloreto.com` is an authenticated WebSocket transport for the
  work Mac's Tailscale coordination and CLIProxyAPI traffic. Caddy terminates
  public TLS, Authentik admits only the `gost-proxy-user` service account,
  and the private GOST service permits `tailscale.com` on TCP 80/443 plus
  `*.mora-rattlesnake.ts.net` on any TCP port. This owner-approved expansion
  exposes all host-reachable tailnet peers and ports to the relay credential;
  Tailscale evaluates relay egress as the Docker-host node, not the work Mac.
  GOST alone uses the host-observed MagicDNS and public resolvers because Docker's
  default DNS cannot resolve tailnet peers. Other Internet destinations remain
  denied by the remote relay; the work-Mac client dials nonmatches locally.
