# Tailscale gateway LXC specification

## Status and purpose

This is a repository-only design for a future Proxmox LXC. It does **not** authorize downloading a template,
creating or starting a container, changing Proxmox networking, enabling IP forwarding, installing Tailscale,
advertising routes, or changing tailnet policy.

The gateway remains an independent recovery path for the trusted MacBook controller; no hosted workload identity or CI tag is retained.

```text
Recovery path:
trusted MacBook controller
  -> operator Tailscale identity
  -> unprivileged gateway LXC (`tag:infra-router`)
  -> Proxmox API and Docker LAN OpenSSH

Normal Docker management:
trusted MacBook controller
  -> operator Tailscale identity
  -> direct Tailscale SSH
  -> Docker VM (`tag:docker-host`, local user `ansible-deploy`)
```

The routed path provides connectivity only. OpenTofu still requires its separated API token, and routed OpenSSH still requires an SSH credential. Direct Tailscale SSH remains the normal identity path.

## Observed Proxmox baseline

Read-only observations supplied from the Proxmox node:

- Proxmox VE `9.2.3`, running kernel `7.0.6-2-pve`.
- Proxmox LAN address `192.168.0.123/24` on `vmbr0`; gateway `192.168.0.1`.
- Docker VM 100 remains running at LAN address `192.168.0.100`.
- Protected CT 101 now exists on `local-lvm` and remains stopped.
- CT 101 has one core, 512 MiB memory, 256 MiB swap, a 4 GiB rootfs, DHCP on `vmbr0`, and native
  `/dev/net/tun` passthrough.
- Generated MAC `BC:24:11:FD:4C:5C` has confirmed router DHCP reservation `192.168.0.122`.
- `debian-13-standard_13.6-1_amd64.tar.zst` is downloaded in `local`.
- Creation warned that systemd 257 may require nesting; no nesting or start has occurred.
- `pve-firewall` reports `disabled/running`; cluster and node firewall option objects are empty.
- Proxmox serial recovery for VM 100 remains verified through `serial0: socket` and `qm terminal 100`.

## Approved design inputs

| Setting | Planned value |
|---|---|
| CT ID | `101` |
| Hostname | `tailscale-gateway` |
| Container type | Unprivileged LXC system container with `nesting=1` for systemd 257 |
| OS | `debian-13-standard_13.6-1_amd64.tar.zst` |
| Root storage | `local-lvm` |
| Root disk | 4 GiB |
| CPU | 1 core |
| Memory | 512 MiB |
| Swap | 256 MiB |
| Bridge | `vmbr0` |
| LAN address | Confirmed DHCP reservation `192.168.0.122` for MAC `BC:24:11:FD:4C:5C` |
| Proxmox firewall flag | Disabled on `net0` initially; global policy is disabled/unconfigured and needs a separate plan |
| Start at boot | Enabled, startup order 1 |
| Tailscale tag | `tag:infra-router` |
| Tailscale DNS acceptance | Disabled initially |
| Tailscale route acceptance | Disabled initially |
| Subnet-route SNAT | Keep Tailscale's default SNAT behavior initially |

The router-side reservation is confirmed; CT 101 has not yet made its first DHCP request.

## Security boundaries

- Keep the container unprivileged. Do not convert it to privileged.
- Debian 13 systemd 257 requires `nesting=1` for reliable boot/console behavior on this Proxmox version. This
  increases proc/sys namespace exposure, so keep the gateway minimal and trusted.
- Do not enable keyctl, FUSE, an unconfined AppArmor profile, or any feature beyond nesting.
- Pass through only `/dev/net/tun`; do not bind-mount host filesystems or the Proxmox API socket.
- Do not run Docker or Headscale in this container.
- Do not expose a public inbound port. Tailscale and package access are outbound.
- Enable only IPv4 forwarding needed for the two approved host routes.
- Advertise `/32` routes, not the entire `192.168.0.0/24` subnet.
- Keep route approval and traffic grants separate and deny by default.
- Back up the LXC configuration/rootfs, but never include auth keys in backups or configuration files.
- Treat this LXC as bootstrap infrastructure. It must not be destroyed by the same future OpenTofu stack that
  depends on it to reach Proxmox.

Tailscale requires `/dev/net/tun` in an unprivileged LXC. Proxmox 9.2 supports native device passthrough, so the
plan uses this managed CT property instead of raw LXC cgroup/config lines:

```text
dev0: /dev/net/tun
```

The corresponding creation option is `--dev0 path=/dev/net/tun`. No manual edit under `/etc/pve/lxc` is planned.

## Scoped routes and ports

Initially advertise only:

```text
192.168.0.123/32  # Proxmox host
192.168.0.100/32  # Docker VM
```

Minimum future CI grants:

| Source | Destination | Port | Purpose |
|---|---|---:|---|
| `tag:ci` | `192.168.0.123` | TCP 8006 | OpenTofu Proxmox API |
| `tag:ci` | `192.168.0.100` | TCP 22 | Docker OpenSSH bootstrap/recovery only |
| `tag:ci` | `tag:docker-host` | TCP 22 | Normal direct Tailscale SSH |

Do not grant CI Proxmox SSH or the entire LAN unless a later Ansible-on-Proxmox requirement is separately designed.
OpenTofu API authentication remains a separate least-privilege Proxmox API token stored only in an approved GitHub
Environment secret or equivalent secret manager.

## Conceptual tailnet policy merge

Merge this with the actual tailnet policy; never replace unrelated rules wholesale:

```json
{
  "tagOwners": {
    "tag:infra-router": ["autogroup:admin"],
    "tag:docker-host": ["autogroup:admin"],
    "tag:ci": ["autogroup:admin"]
  },
  "autoApprovers": {
    "routes": {
      "192.168.0.123/32": ["tag:infra-router"],
      "192.168.0.100/32": ["tag:infra-router"]
    }
  },
  "grants": [
    {
      "src": ["tag:ci"],
      "dst": ["192.168.0.123"],
      "ip": ["tcp:8006"]
    },
    {
      "src": ["tag:ci"],
      "dst": ["192.168.0.100"],
      "ip": ["tcp:22"]
    },
    {
      "src": ["tag:ci"],
      "dst": ["tag:docker-host"],
      "ip": ["tcp:22"]
    }
  ],
  "ssh": [
    {
      "action": "accept",
      "src": ["tag:ci"],
      "dst": ["tag:docker-host"],
      "users": ["ansible-deploy"]
    }
  ]
}
```

Add separately reviewed administrator grants for gateway and Docker testing. CI must not receive root Tailscale SSH.
Validate policy tests and effective grants in the hosted Tailscale admin console before enrolling either node.

## Current gateway state and gated bootstrap

The approved template download and stopped-container creation completed successfully. Observed configuration:

```text
arch: amd64
cores: 1
dev0: path=/dev/net/tun
hostname: tailscale-gateway
memory: 512
net0: name=eth0,bridge=vmbr0,firewall=0,hwaddr=BC:24:11:FD:4C:5C,ip=dhcp,type=veth
onboot: 1
ostype: debian
protection: 1
rootfs: local-lvm:vm-101-disk-0,size=4G
startup: order=1,up=30,down=60
swap: 256
unprivileged: 1
```

CT 101 completed its first start and remains running. Verified baseline:

- Debian 13.6 with systemd `running` and no failed units.
- DHCP address `192.168.0.122/24` and default route through `192.168.0.1`.
- `/dev/net/tun` is a character device with mode `0666`.
- DNS resolves `login.tailscale.com`.
- IPv4 and IPv6 forwarding remain disabled.
- Tailscale is absent.
- nftables is enabled/active with accept policies only.
- Root password is locked, no non-root login account exists, and root `authorized_keys` is absent or empty.
- OpenSSH socket/service and Postfix are disabled/inactive; their packages remain installed.
- The only listener is DHCP client UDP/68.

Gateway recovery remains available through Proxmox `pct exec` and `pct console`. Baseline hardening changed no
package, firewall, forwarding, network, CT, or Tailscale state.

APT inspection found only Debian Trixie, Trixie updates, and Trixie security sources; no held packages. `wget` and
`ca-certificates` are installed/current; `curl`, `gnupg`, and Tailscale are absent. No extra downloader is needed.

The official stable repository metadata currently resolves to:

```text
Key fingerprint: 2596 A99E AAB3 3821 893C 0A79 458C A832 957F 5868
Key SHA-256: 3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39
List SHA-256: 5a1b21b30892bf22fb5d7c4f52fefe9b65efda2100e82abba2e0849da2a2264b
Repository: deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian trixie main
```

The corrected repository-only mutation succeeded. Both installed files match the hashes above, and the source content
is exactly the stable Trixie definition. APT metadata refresh then completed without package changes.

The exact seven-package transaction completed: no upgrades/removals and eight unrelated updates remained untouched.
Package integrity is clean; the key is package-owned and unchanged. `tailscaled` 1.98.10 is enabled/active but logged
out, with `tailscale0` and UDP/41641 present. Forwarding remains disabled and no Tailscale netfilter chains exist yet.

The persistent nftables file now matches SHA-256
`f5aab15bafc7a7cef806c47a543f08423323e93add959810486fe29b35144d31`. Runtime forward policy is `drop` with only:

- established/related replies;
- `tailscale0` to `192.168.0.123` TCP/8006; and
- `tailscale0` to `192.168.0.100` TCP/22.

Two copy-altered firewall candidates were safely rejected before the validated short-line ruleset applied. The
IPv4-only sysctl file now matches SHA-256
`bb6438589918b8623e78eab154b537a10768a6e013b47185a54add4a25992487`; IPv4 forwarding is 1 and IPv6 forwarding is 0.
Tailscale remains logged out and advertises no routes.

Route-free enrollment completed using a one-off, pre-approved, non-ephemeral key scoped to `tag:infra-router`. The key
was supplied from a root-only temporary file with terminal echo disabled, then deleted. No key or private key was
recorded in Git/chat/history; zero-valued private fields in `tailscale debug prefs` are CLI redactions.

Verified enrollment state:

- Tailscale 1.98.10 is Running at `100.67.24.7` as `tailscale-gateway`.
- `tag:infra-router` and hostname `tailscale-gateway` are requested.
- Advertised routes remain empty.
- DNS/route acceptance and Tailscale SSH remain disabled.
- Default subnet-route SNAT and stateful filtering are enabled.
- `pauls-macbook` is visible as a peer.
- Tailscale's iptables-nft chains coexist with the stricter persistent `inet filter` forward chain.
- IPv4 forwarding remains 1 and IPv6 forwarding remains 0.

The unused IPv6 NAT warning has no tailscaled health impact: backend Running, node key present, empty health list, and
no warning-priority journal entries. IPv6 forwarding/routes remain disabled. The administrator Mac reached the gateway
directly over WireGuard at `192.168.0.122:41641` in 11 ms.

The gateway now advertises exactly `192.168.0.123/32` and `192.168.0.100/32`; the saved `autoApprovers` policy made
them usable on the administrator Mac through `utun13`.

Verification passed:

- Proxmox API through `192.168.0.123:8006` returned HTTP 200.
- Docker OpenSSH through `192.168.0.100:22` accepted a TCP connection.
- Unapproved Proxmox SSH at `192.168.0.123:22` timed out.
- The two allow rules each counted one initial packet; established/related reply traffic counted separately.
- No `/24`, exit-node, IPv6, or additional route was requested.

The subnet-router recovery path is operational. Reconfirm VM 100 serial and direct LAN recovery before authorizing
direct Docker Tailscale bootstrap.

## Verification gates

Before declaring the gateway usable:

- CT 101 remains unprivileged; nesting is the sole additional feature and no unrelated device/mount/capability exists.
- `/dev/net/tun` exists only as the planned device passthrough.
- The LXC starts automatically and obtains its reserved DHCP address.
- IP forwarding is enabled only for IPv4.
- Tailscale reports Running with `tag:infra-router`.
- Only the two `/32` routes are advertised and approved.
- `tag:ci` effective access is limited to the three documented destination/port combinations.
- Proxmox API responds through the subnet route without public exposure.
- Docker LAN SSH responds through the subnet route, but authentication still enforces OpenSSH credentials.
- The Proxmox serial console and direct LAN recovery paths still work.
- Docker has 41 running services and 33 project volumes; no Docker runtime action occurred.

## Failure and rollback policy

There is no automatic rollback. Keep Proxmox node shell and VM serial-console access available.

- If the LXC fails before enrollment, stop and inspect it; do not alter Proxmox or Docker networking.
- If route advertisement fails, do not broaden to `/24` as a workaround.
- Route unapproval, `tailscale down`, LXC stop/disable, TUN removal, and LXC deletion each require explicit approval.
- Never destroy the gateway until an alternate management path is verified.
- Do not import CT 101 into the main OpenTofu state until the Docker host is converged and bootstrap dependencies are
  explicitly separated.

## Deferred OpenTofu adoption

No OpenTofu code is added in this phase. Later, either:

- import CT 101 into a dedicated bootstrap/management state with destruction protection; or
- keep it manually managed as root-of-trust infrastructure.

The main Proxmox workload stack must consume the gateway path but must never be able to destroy the gateway that
provides access to the Proxmox API.
