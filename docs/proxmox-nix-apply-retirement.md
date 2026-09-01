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

## Protected evidence restored

The initial observer-only transition failed closed with `protected-access/observation-unavailable` and `protected-hardware/observation-unavailable` because the observer required the projection-bound private-preparer hash. No blocker was weakened or reclassified.

A separate physical-console protected-evidence transaction then installed only private preparer `b0dc55397d228345a0725e8e9de6ad6443d196c76c83cb2a7cc850d2a53eeefb` under authorized plan `46dc9e6ce9f2e495a01a778599d617d6a86133fff8b6f7f383413c8aaab528a2`. It read existing protected inputs in place, exported no protected values, required complete reduced access/hardware summaries, ran an `ansible-plan` observer canary, retained the prior helper for rollback, and wrote a root-owned mode-`0600`, regular, single-link, fsynced journal.

Fresh live observation now reports protected access `6/6` and protected hardware `3/3`, both complete and matching. The guarded Nix steady plan has zero actions, zero blockers, zero findings, and `privatePreconditionsRequired: false`; plan SHA-256 is `663da14e8413734b0194d29b7bbf84824c2e8a649fa370f6739e474e84a556b0`.

The Nix mutation engine is now `ready` and source-frozen. Projection field `nixMutationFrozen: true` is schema-bound; both controller `prepare` and `apply` reject before reading a plan sidecar, taking a controller lock, or contacting `tofu-apply`. Historical recovery tests explicitly set the field false while production projection tests require it true. Live rejection canaries returned nonzero with `Nix protected preparation is frozen by lifecycle policy` and `Nix apply is frozen by lifecycle policy`.

After the freeze, guarded plan `b3d4fe84856858cc0aeea36804b983e5204f6f9848c2047b73b865a9d1cf7261` remained ready with zero actions, blockers, and findings and fresh complete protected evidence. Local tofu accounts, conventional keys, sudo rules, helpers, protected inputs, tokens, and recovery assets remain unchanged. Their retirement must first revise protected-access evidence so intentionally removed tofu keys/accounts no longer create a mismatch, then use separate access-critical transactions with physical-console rollback.