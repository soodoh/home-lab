# Proxmox Nix apply-engine retirement assessment

The retained Nix engine is now an audit and recovery boundary, not the package owner. Read-only observation uses the fixed `ansible-plan@proxmox` Tailscale transport. The local `tofu-plan` LAN SSH identity is no longer used by live planning.

## Mutation closure

All currently projected Nix action policies are frozen:

- managed files are individually nonautomatic after the APT, boot, storage, network, and access freezes;
- managed fragments are nonautomatic after boot transfer;
- package, service, account, Tailscale, PVE access, PVE storage, and PVE firewall domains are nonautomatic; and
- managed artifacts are now nonautomatic because all projected artifacts are APT keyrings already transferred with `apt_repositories`.

Historical apply and bootstrap tests explicitly opt their fixtures back into one automatic artifact action. Production projection tests require the transferred APT handoff to freeze artifacts and require a pending handoff to retain the historical policy. This keeps recovery semantics tested without leaving a production action path open.

## Remaining `tofu-apply` dependency

The controller still contains two fixed conventional-LAN apply calls:

- `nix/proxmox/prepare.py` invokes `proxmox-private-preparer prepare` as `tofu-apply`;
- `nix/proxmox/apply.py` invokes `proxmox-activator session` as `tofu-apply`.

The private preparer validates protected hardware inventory, both tofu authorized-key sets, firewall keys, token escrows, access files, and other root-only attestations. Removing either local tofu account, key, sudo rule, helper, or protected input before replacing this evidence model would make protected facts unverifiable and would damage recovery.

The new projection was installed in observer `2ea47661a7f8ea0e286048abdfeae7354e22023f1a9d8375913ddc2e2936875c` through guarded observer plan `c2feed3774ddc86df39e9e01f66e7b31872c7399cc0f488b29a54cac0d118744`. The first canary failed on an incorrect field name and rolled back to the exact prior observer. The corrected transaction committed with a root-owned mode-`0600` journal.

## Current fail-closed result

Live observation succeeds over `ansible-plan`, protocol 4, with all public domains complete. Protected access and hardware attestations are unavailable because the existing private attestation is bound to the earlier bundle. The Nix planner therefore produces zero actions but remains blocked by exactly:

- `protected-access/observation-unavailable`; and
- `protected-hardware/observation-unavailable`.

This is intentional fail-closed behavior, not a no-op authorization. It must not be weakened or reclassified as ready.

## Required replacement before retirement

Before retiring `tofu-apply`, implement a separately authorized protected-evidence capability that:

1. runs only from the physical console or an equivalently bounded fixed capability;
2. reads root-only protected inputs without exporting values;
3. binds the exact clean pushed contract, projection, observer, schemas, installed access metadata, and current bundle;
4. emits only reduced match/count/hash evidence;
5. uses root-owned, mode-`0600`, regular, single-link, fsynced state under an exclusive lock;
6. cannot prepare or execute Nix actions, mutate accounts, keys, tokens, hardware, firewall, storage, services, or packages; and
7. preserves a durable recovery path for the historical protected inputs until final Nix retirement.

Only after fresh protected evidence makes the zero-action plan ready may the Nix prepare/apply entry points be frozen. Local tofu accounts and conventional recovery assets still require their own exact access-critical retirement transactions and physical-console rollback.