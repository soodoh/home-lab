# Proxmox Nix-to-Ansible migration matrix

This is the Phase 0 retirement plan for the protocol-v4 Proxmox host bundle. Nix remains production authority until each row has an accepted Ansible replacement and an explicit ownership handoff. Adding an Ansible task does not transfer authority.

## Parity rule

A domain can move only when the replacement:

1. reads `infrastructure/contract/home-lab.yml` directly;
2. produces deterministic, normalized check-mode evidence;
3. refuses unknown, unavailable, protected, or changed preconditions;
4. participates in the controller descriptor lock and host owner lock;
5. has capture-before-mutate, rollback, ambiguous-transport recovery, and post-observation appropriate to its safety class;
6. preserves strict host-key verification and excludes protected values from plans/logs; and
7. disables the same Nix mutation domain in the same reviewed change, so dual writers never exist.

The installed observer currently matches the neutral contract-rendered artifact byte-for-byte and reports all 17 domains complete. Public-domain parity is independently validated by Ansible; protected access and hardware summaries still depend on the exact transitional private preparer and therefore remain a Gate 3 blocker. Retained rollback sessions remain terminal `released-committed`; none has a pending transition or active lock.

## Domain matrix

| Nix area/domain | Current implementation | Target Ansible implementation | Handoff/retirement gate |
|---|---|---|---|
| Projection | `scripts/controller/proxmox-host-projection.js`, `nix/proxmox/projection.json`, schemas | Shared direct contract mapping consumed by transitional Nix and final Ansible artifacts, without a second policy authority | Every projected field has one role/audit owner; contract schema tests reject omissions and unknowns |
| Bundle and source isolation | `nix/flake.nix`, `flake.lock`, `bundle.py`, Nix-store leak scans | Implemented neutral observer source/schema and controller-built, hash-bound artifact; tracked Nix files are byte-identical compatibility mirrors | Protected preparer and remaining mutation helpers move to the neutral boundary in Gate 3; installed-byte replacement requires separate authorization |
| Observation | Fixed `ansible-plan` transport invokes the installed observer | Implemented `proxmox-production.yml`, `proxmox-audit.yml`, and complete local validator against direct contract mapping | All 17 domains pass through strict pinned host keys; protected summaries remain explicitly marked `transitional-exact-helper` until Gate 3 |
| Planning | `planner.py`, `plan.schema.json`, 30-minute freshness, ordered findings/actions/blockers | Reproducible Ansible check plan plus normalized action manifest bound into the controller saved-plan manifest | Same commit/tree, contract, inventory, role, artifact, live-observation, freshness, and action-order bindings; apply cannot replan |
| Protected preparation | `prepare.py`, private preparer, MAC-bound protected sidecar | Root-only Ansible preflight that emits only counts/booleans or opaque attestations | Hardware/access/token checks remain non-exportable; exact plan and operator gates are bound before mutation |
| Activation/rollback | `apply.py`, activator, per-action journal and rollback tree | Lifecycle transaction role/action plugin with durable owner journal and captured before-state | Lost-response recovery, per-step idempotence, rollback, postcheck, and lock release have adversarial tests |
| Managed files | 16 projected files including APT, exports, network, SSH, sudoers, ZFS, VFIO | Existing shared file patterns plus Proxmox-specific templates/validation | Transfer one safety class at a time; validate with `visudo`, `sshd -t`, `ifreload --syntax-check` or equivalent; preserve file metadata/no-follow checks |
| Managed fragment | Required GRUB command line in `/etc/default/grub` | Reboot-bound Ansible kernel role | Exact old/new line capture, `update-grub` evidence, no reboot in ordinary apply, separately reviewed reboot |
| Managed artifacts | Debian, Proxmox, and Tailscale archive keyrings | Checksum-pinned Ansible artifacts | Source/checksum/provenance and installed bytes match; no network fetch during apply unless present in reviewed plan |
| Packages | Exact 1,355-record manifest and solver provenance; apply currently nonautomatic | Ansible package-plan/apply roles with a reviewed candidate manifest | Never use a generic `state: latest`; preserve installed/candidate delta, repo identity, holds, PVE/ZFS compatibility, saved plan, and separate reboot |
| Services | chrony, NFS server, OpenSSH, tailscaled | Shared systemd role with safety-class handlers | Ordinary services first; NFS and access services require data/access canaries and rollback/watchdog |
| Timezone | Nix retains read-only observer parity but no projection, planner, catalog, activator, or rollback mutation surface | Shared Ansible base role, gated on transferred contract ownership | Saved handoff authorization binds exact live parity and source exclusion; `America/Los_Angeles` remains unchanged while Ansible becomes the sole writer |
| Accounts | `tofu-plan`, `tofu-apply`, `firewall-apply`, human `proxmox` | Human `proxmox`, automation `ansible-plan` and `ansible-deploy`; keep `firewall-apply` isolated | Create/prove replacements before retiring tofu accounts; password locks, groups, shells, sudo and session termination are checked |
| Conventional SSH keys | Three forced-command files, the root symlink to the six-key PVE authorized-key set, and controller private keys | Tailscale SSH only; conventional files absent; OpenSSH pubkey auth/root login disabled | Attribute every root key, replace recovery/provider consumers, pass tailnet positive/negative tests, use MagicDNS transports with strict host keys, preserve console recovery, and close the rollback window |
| Tailscale host | Nix package/config/health domain | Shared Ansible Tailscale role | Never restart during access cutover; prove node ID, tag, MagicDNS, SSH preference, version, and a second live session |
| PVE API access | Nix-projected PVE roles, ACLs, API tokens and escrow metadata | OpenTofu remains resource owner where modeled; Ansible audits host escrow metadata and bounded helpers | Do not expose token values; plan/apply capabilities stay distinct; remove Nix token rotation tools only after replacement rotation/recovery |
| PVE storage registration | Nix intent and protected observation | Ansible audit/convergence for registration metadata; ZFS pool itself remains protected host storage | Pool GUID/member proof, ONLINE health, NFS canary, no create/import/destroy ambiguity |
| Host storage/NFS/ZFS | Nix files, exports, services and health checks | Data-critical Ansible storage role | Existing pool/datasets/exports are adopted, never recreated; exact before-state and rollback; VM 100 remains running unless a reviewed maintenance operation says otherwise |
| Networking | Nix owns `/etc/network/interfaces` | Access-critical Ansible network role | Physical console and LAN rollback confirmed; staged config validation; watchdog; tailnet and PVE UI canaries before commit |
| OpenSSH | Nix SSH file and forced identities | Ansible SSH role with Tailscale-only steady-state invariant | `sshd -t`, independent host keys, live replacement sessions, delayed old-session termination, conventional-file absence |
| VFIO recovery | Nix deploys helper/policy; manual helper locks host and VM | Ansible deploys/audits the exact helper and policy; OpenTofu keeps PCI mapping ownership | Preserve exact confirmation, `/run/lock/home-lab-vfio-recovery.lock`, VM lock, device/IOMMU checks and recovery tests |
| PVE firewall | Nix bootstrap installs assets; separate transaction mutates policy | Ansible installs/audits assets only; separate transaction continues to mutate policy | Keep console authorization, canary catalogue, CAS digest, watchdog/timer rollback, terminal journal, and shared mutex |
| VM 100 observation | Nix blocks on OpenTofu drift | OpenTofu saved plan plus Ansible read-only cross-check | VM resource remains `.debian`; protected disk/boot/hardware mismatch blocks host apply |
| Health and audit absence | Observer summaries and explicit absence records | Ansible audit role, including forbidden files/lines, locks, host lifecycle, Tailscale-only access and PVE/ZFS health | Full audit passes twice around every handoff; unavailable facts block rather than skip |
| Controller integration | `local-controller` invokes Nix plan/prepare/apply and imports planner validation | Controller invokes saved OpenTofu plans then lifecycle-aware Ansible plans/applies | Manifest version transition is atomic; old and new manifests cannot be cross-applied; one-tag applies and exact confirmations remain |
| Schemas/tests | Seven Nix schemas and broad adversarial tests | Contract schema, Ansible argument tests, transaction tests, fixtures and controller security tests | Port failure modes before deleting their tests: interrupted bootstrap, stale locks, transport loss, rollback, source leaks, malformed protected evidence |
| Bootstrap/recovery tools | Console Nix access/host bootstrap, protected input/session rotation | Minimal console/bootstrap Ansible and documented break-glass recovery | Interrupted bootstrap adoption and rollback are proven; installed copies and external callers are inventoried before retirement |
| Documentation | Proxmox bootstrap/guarded-apply/maintenance docs declare Nix authority | Lifecycle and ADR documents declare Ansible authority after cutover | Update authority wording only with the operational handoff; retain dated recovery history where required |

## Gate 2 repository and read-only evidence

At repository revision `e2ecbec`, `scripts/controller/build-proxmox-ansible-observer.js` rendered the neutral observer from the direct contract mapping without invoking Nix. The installed observer reported the same SHA-256, `5a4e18d1b33fd58c7554b89cee74d83c9ae016401a2cf5584c6178070f39fbb7`.

A production read-only run through `ansible-plan@proxmox` and `ansible/playbooks/proxmox-audit.yml` returned 17 complete domains, zero Ansible changes, and exact contract parity. Its raw observation SHA-256 was `0d68ddf9b574e53373db4fc27d9dc22f446ea3758eca1d684bcfa29ef3d16a57`. The raw observation is locally protected and not committed; the repository fixture contains the same schema-valid redacted values for adversarial validation.

This does not transfer mutation ownership, install bytes, widen sudo, or authorize an apply. The protected summaries are bound to private-preparer SHA-256 `6ef3889b97beed58139510e50d5703c7b7f5f044402caf4a95395e8b9c4ccd58` and remain an explicit Gate 3 dependency.

## Safe handoff order

1. **Freeze and observe:** keep Nix mutation authority; add Ansible read-only parity and lifecycle audit.
2. **Low-risk files/services:** transfer timezone, keyring/repository files and chrony individually. Remove each from Nix policy at handoff.
3. **Reboot-bound host policy:** transfer ZFS/VFIO module files and GRUB, but do not reboot in the ownership change.
4. **Data-critical storage:** adopt NFS exports, registration and ZFS assertions with exact pool/dataset protection.
5. **Access-critical networking/Tailscale/SSH:** create and test Ansible identities and tailnet policy first; preserve console and old sessions; remove conventional keys last.
6. **Packages:** replace the package manifest workflow and run an independently reviewed package transaction/reboot rehearsal.
7. **Controller engine:** switch saved-plan manifest ownership from Nix actions to Ansible actions after every domain has moved.
8. **Retire Nix:** retain terminal rollback evidence for the agreed window, remove installed helpers/accounts/keys in dependency order, then remove Nix build/controller code and its now-replaced tests.

## Rollback and coexistence rules

- During migration, Nix may remain installed for evidence and rollback, but it must not mutate a domain already assigned to Ansible.
- Ansible must reject active Nix/firewall/VFIO/controller/host locks and retained nonterminal journals.
- A failed ownership handoff restores the captured host state and the prior authority declaration together; it never leaves both writers enabled.
- The firewall transaction, OpenTofu, Compose, Restic and SOPS/age are not absorbed into ordinary host convergence.
- No helper, account, key, schema, test or rollback tree is deleted merely because static caller count is zero. See `docs/script-retirement-matrix.md`.
