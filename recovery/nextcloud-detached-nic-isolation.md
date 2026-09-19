# Nextcloud detached-NIC isolation design

## Decision

A temporary firewall-confined NIC on `vmbr0`, followed by removal of the virtual NIC
before any database or application startup, is a conditionally viable alternative to
creating a new Proxmox bridge. This is a design only. It does not authorize an
OpenTofu root, provider initialization or planning, VM/disk/firewall creation, guest
startup, credential handling, repository access, data transfer or cleanup.

The September 19 survey found no isolated bridge. Historical VM9900 evidence proves
that this Proxmox host previously enforced a firewall-enabled `vmbr0` NIC with DROP
input/output policies and ordered private-network denies. That source and authority
were deliberately retired. Treat it as design evidence, not a callable recovery path
or authorization to recreate VM9900.

This design narrows the claim:

- network access exists only during operating-system/input retrieval;
- recovery services never start while a virtual NIC is attached; and
- offline checks use the Proxmox serial console or QEMU guest-agent channel, not IP.

It still shares the production hypervisor and `local-lvm` fault domain and therefore
is not independent infrastructure.

## Fixed candidate

| Property | Candidate |
| --- | --- |
| VMID | `9000`, currently absent |
| Node | `proxmox` |
| Root/work disk | New blank 64 GiB disk on `local-lvm` |
| Bridge during retrieval | Existing `vmbr0` only |
| NIC during service proof | Absent from PVE configuration |
| Production VM | VM100, never modified |
| Retired identity | VM9900, never reused |
| Snapshot original | Games `abbf7d3543bb031ab80d97b69dde24de3b8c1a23ad47e4bb8c471a8dbbde128f` |
| Remote copied snapshot | Proton `800594c2d00bcc8281dc22e46b846991370fba2a6b700b19d12740d0f148b557` |

The copied Proton snapshot must retain `original=abbf7d…`, the exact policy tag and
the accepted `2f12e384…` artifact tag. Never select `latest`.

## Lifecycle states

Use explicit stop/go boundaries rather than one automatic transaction:

1. **Absent:** VMID 9000, its disks, firewall options/rules, cloud-init snippet and
   dedicated state are absent.
2. **Stopped foundation:** the blank disk, stopped VM, cloud-init and VM firewall
   exist. The VM has never started.
3. **Retrieval online:** the VM starts with one firewall-enabled `vmbr0` NIC solely
   to obtain and verify fixed inputs.
4. **Retrieval complete and stopped:** all fixed inputs are local and verified; no
   MariaDB, Redis, Nextcloud, cron or Caddy process has run.
5. **Offline ready:** while stopped, a separately reviewed provider change removes
   the NIC from PVE configuration. Firewall resources may remain as defense in depth.
6. **Offline recovery proof:** the VM starts with no NIC and performs the database
   and application-control-plane phases through serial/guest-agent control.
7. **Stopped evidence:** containers and VM are stopped; disks and bounded evidence
   remain for review.
8. **Destroyed:** a separately approved destroy removes only VMID 9000 and its exact
   disks, snippet, firewall resources and ephemeral access material.

Never skip directly from foundation creation to a running guest. Every transition
requires fresh observation and separate authorization.

## Foundation and ownership requirements

A new narrow provider root would be required. Do not add the recovery guest to the
VM100 root, reuse retired VM9900 state, adopt historical local state, or issue direct
`qm`/`pvesh` mutations around provider ownership.

Before any provider plan, define and review:

- exact resource addresses for one stopped VM, one blank disk, one cloud-init snippet,
  one NIC, VM firewall options and fixed ordered rules;
- a dedicated state backend and ownership marker with no overlap with production or
  retired qualification roots;
- one ephemeral guest SSH key and exact controller IPv4, neither equal to VM100 or
  the Proxmox host;
- CPU/RAM allocation plus a required post-allocation host-memory reserve; the survey's
  13,829,181,440 free bytes does not itself admit an allocation;
- `on_boot=false`, `protection=false`, no production pool, no backup/replication,
  unique disk serials and destroy limited to the admitted resources; and
- creation stopped by default, with starting controlled by a separate explicit input
  and plan.

The first apply, if ever authorized, must create only the stopped foundation. A
second fresh plan must report zero drift before startup can be considered.

## Retrieval firewall

The VM NIC must set Proxmox `firewall=true` before first boot. VM firewall options
must be enabled with input and output policy `DROP`, DHCP explicitly bounded,
MAC filtering enabled and IPv6 unavailable or independently denied.

Ordered rules must provide only:

1. DHCP discovery/offer needed to obtain the temporary address;
2. inbound SSH from one exact ephemeral controller IPv4, if serial/guest-agent
   transfer cannot replace SSH;
3. SSH reply traffic to that controller only;
4. explicit outbound drops for `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, multicast and any
   additional local routes;
5. DNS and clock traffic only to fixed reviewed public resolvers/time sources; and
6. public IPv4 TCP/443 egress required for retrieval, after all denies.

Do not permit broad inbound LAN access, NFS, SMB, Docker APIs, Tailscale, Proxmox API,
VM100, SMTP, DDNS, webhooks or public ingress. Avoid package installation during this
phase: use a checksum-pinned base image containing the reviewed container runtime,
Restic/rclone and QEMU guest agent, or make those fixed archives explicit inputs.

A provider plan is insufficient firewall proof. Before transferring secrets or
repository credentials, observe exact live VM options/rules and run bounded negative
probes from the guest to VM100, Proxmox management, NFS, RFC1918 ranges and tailnet
ranges. Only declared public retrieval endpoints may succeed. Record destinations as
policy classes and counts, not credentials or URLs carrying tokens.

## Retrieval inputs

The current recovery bundles are bound to an older chain. Before execution, build
and independently review a new encrypted recovery bundle bound to Proton snapshot
`800594c2…` and original games snapshot `abbf7d35…`. Bundle construction,
publication, retrieval and decryption each retain their existing separate approvals.

During retrieval, obtain and verify:

- the exact recovery bundle, pinned Restic/rclone binaries and repository identities;
- Proton snapshot `800594c2…` with exact copied ancestry and tags;
- the artifact/image-lock generation needed for Nextcloud, MariaDB and Redis;
- digest-pinned container images saved into local guest storage; and
- SOPS-backed Nextcloud database secrets re-encrypted or transferred into target-only
  tmpfs through the independent recovery path.

Do not copy VM100's credential directory, Docker cache, host keys, Tailscale state,
production environment file or restored staging tree into the guest.

Complete native `restic restore --verify` and immutable input manifest checks during
the retrieval-online state. Restoration is allowed; database/application startup is
not.

## NIC-removal barrier

After retrieval:

1. stop the guest and require PVE status `stopped`;
2. preserve exact restore and input-manifest evidence;
3. obtain a fresh provider plan whose only intended mutation removes the VM network
   device;
4. apply only under separate authorization;
5. require PVE current and pending configuration to contain no `netN` device;
6. require no virtual NIC MAC remains in the VM configuration or firewall identity;
7. start through console/guest-agent control only;
8. before Docker starts, require `/sys/class/net` to contain only `lo`, no default or
   non-loopback route, no DHCP client, and no listening TCP/UDP socket outside
   loopback; and
9. after Docker creates internal bridges, require no route or interface capable of
   leaving the guest.

Link-down, guest firewall rules, unplugging inside the guest, deleting a DHCP lease,
or stopping networking is not equivalent to removing the PVE NIC.

## Offline control and recovery proof

The QEMU guest-agent channel uses the hypervisor transport rather than IP. Admit it
only for fixed, bounded commands and outputs. Do not expose a generic guest shell or
forward production credentials through logs.

With the NIC absent, follow
[`nextcloud-isolated-recovery-plan.md`](nextcloud-isolated-recovery-plan.md):

- retain immutable restored input;
- start MariaDB only against a writable copy;
- perform logical database checks and clean shutdown;
- reconstruct the application root from the pinned image;
- start MariaDB, ephemeral Redis and Nextcloud without cron or public ports; and
- report external user data unavailable rather than mounting production NFS.

Any command that requires network access after the NIC-removal barrier is a design
failure. Stop rather than reattach the NIC to a running recovery stack.

## Remaining blockers

The detached-NIC design is not executable until all of these are closed:

- no new provider root, state ownership or reviewed stopped-foundation source exists;
- no RAM allocation and host reserve are admitted;
- no current bundle is bound to the September 19 copied snapshot;
- the exact base image/runtime/tool input and independent application-artifact path
  are not assembled;
- the ephemeral controller identity and address are not admitted;
- VM-firewall ordering, IPv6 denial and negative probes lack current source tests;
- no reviewed provider-only NIC-removal plan or post-detach observer exists; and
- external Nextcloud user data remains outside Restic.

Closing these blockers requires source design and local tests first. It does not
implicitly authorize provider init/plan, guest creation or live firewall changes.
