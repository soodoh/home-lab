# VM 100 Arch-to-NixOS migration architecture

Status: Phase 1 architecture approved. Implementation and every production action remain gated by the milestones and acceptance evidence below.

## Repository reconciliation

- `nix/flake.nix` is an isolated controller-side flake pinned by `nix/flake.lock` to `nixos-26.05`; it currently exports only the Proxmox host bundle/app/check and no `nixosConfigurations`.
- OpenTofu resource `proxmox_virtual_environment_vm.arch` is the protected authority for VMID 100 and materializes the fixed MAC, SMBIOS UUID, CPU/memory, q35 machine, scsi0 root, scsi1 games disk, PCI/USB mappings, protection, startup and lifecycle.
- Compose has 41 services, 30 declared volumes and 3 retained undeclared legacy volumes. It uses NFS and games-disk binds plus root-disk named volumes. Existing deployment stages a deterministic artifact into `/srv/docker-compose`, decrypts SOPS on-host, captures image locks, uses reviewed dry-run plans, and has a separately reviewed non-stateful rollback.
- Ansible owns all Arch guest state, guest identities, host hardware setup, Coral DKMS, Compose transaction orchestration, audit, image-prune scheduling and recovery. The controller invokes it in both steady and recovery paths.
- There are no Authentik or Servarr OpenTofu roots.
- The only tracked SOPS rule has one age recipient. Repository evidence does not prove whether that recipient is the Arch host, the recovery identity, or both.
- Prerequisite defect found during architecture review: `scripts/reconcile-infrastructure` created `.reconcile/controller-apply.lock` as a directory while `nix/proxmox/apply.py` opened the same pathname as a regular flock file. Commit `8d4fa48` replaced both plus the firewall path with one inherited descriptor/token protocol; live steady no-op qualification remains required before extending the controller.

## 1. Ansible ownership migration matrix

| Current behavior | Current owner | Proposed owner | Activation | Validation | Rollback |
|---|---|---|---|---|---|
| Arch snapshot/package/kernel management | Ansible `arch_packages`, `pacman_packages`, `base`, `maintenance` | NixOS host modules and pinned flake inputs | Exact NixOS toplevel activation; risky kernel via `boot`/test-boot first | Flake checks, toplevel build, package/kernel assertions, cold boot | Previous NixOS generation; old Arch disk until retirement |
| Static guest network, hostname and DNS | Ansible `arch_network` | `nix/hosts/vm-100/networking.nix` | NixOS systemd-networkd generation | expected address/MAC/route/DNS, SSH and Tailscale reachability | prior generation plus PVE console; Arch disk before write-commit |
| Root partition/boot filesystem | Arch image/OpenTofu scsi0 | Disko for fresh NixOS disk; OpenTofu for PVE attachment/interface/boot order | Explicit destructive install app only against an approved fresh disk | disk identity/capacity guard, Disko dry-run, mount/boot checks | boot preserved Arch root disk; never reformat either retained disk |
| VM 100 compute, MAC, SMBIOS UUID, protection, disks and passthrough | PVE OpenTofu | PVE OpenTofu unchanged as authority | Exact saved migration/steady plans | application policy plus PVE plan/no-op | reviewed reverse PVE plan; no manual PVE drift |
| NFS and games mounts | Ansible `arch_mounts`, `storage`, `backup_storage` | NixOS storage module | systemd mounts before Docker | exact UUID/server/export/fs/options/capacity and no-format checks | prior generation; detach new root and boot Arch if no writes |
| `docker` workload user, groups and access | Ansible `arch_hardware`, `human_access` | NixOS users/access module | generation activation | live UID/GID/group and file-ownership compatibility | generation rollback; numeric IDs remain fixed |
| `ansible-plan` / `ansible-deploy` accounts and sudo | Ansible bootstrap roles | replacement `nix-plan` observer and `nix-apply` forced transport, narrowly scoped | bootstrap from console/temporary installer, then NixOS modules | arbitrary-command denial, exact envelope/path checks | console/root recovery; do not retain broad Ansible sudo |
| SSH host keys and policy | Ansible `ssh` | NixOS OpenSSH module; new host keys | boot/activation only after access preflight | key-only auth, allowed principals, second-session proof | console and previous generation |
| Tailscale daemon/preferences | Ansible `tailscale` | NixOS module for daemon/static preferences; guarded one-use enrollment app | generation plus parent-supplied short-lived key | backend running, intended hostname/tag/routes/DNS | LAN/console; tailnet policy remains separate Tailscale OpenTofu |
| Docker engine and Compose CLI | Ansible `docker` | NixOS Docker module and pinned package set | generation; Docker ordered after required mounts/devices | daemon/version/storage-driver/UID checks | previous generation; mutable Docker data is not reverted |
| Compose service/network/volume topology | Compose YAML | Compose unchanged | guarded generation-bound Compose activator | canonical config, service set, health, dry-run/no-op | previous generation’s artifact/image document; no data rollback claim |
| Compose artifact staging/deploy/rollback | Ansible Compose roles | packaged guarded Nix applications plus NixOS systemd units | exact embedded artifact selected by exact toplevel | hashes, repeated action plan, image availability, post-activation no-op | explicit previous-generation activation; mutable data/API state separate |
| SOPS/age tooling and runtime env | Ansible `sops_age` / Compose stage | `sops-nix` and guarded controller provider env wrappers | activation-time `/run` materialization only | recipient/decrypt test, owner/mode/order, closure/log/plan scans | prior encrypted generation plus escrowed recovery identity |
| uinput/uhid/TUN/GPU/USB rules/sysctls/qemu agent | Ansible `arch_hardware`, `hardware`, host files | NixOS hardware module | generation and boot | device nodes, udev permissions, GPU binding/VAAPI, input smoke tests | previous generation; PVE mappings remain OpenTofu |
| Coral source/build/install | Ansible DKMS + Arch package | Nix kernel-module derivation and `coral.nix` | built in exact toplevel, loaded at boot; never built in activation | source hash, patches, module names, vermagic/srcversion, PCI binding, `/dev/apex_0`, Frigate inference | previous kernel+module generation |
| Wolf tracked host config | Ansible `host_files` | `/etc` files in NixOS; games-disk files represented as explicit generation activation copies with no ownership of Wolf mutable state | guarded preflight after games mount | byte hashes, ownership/mode, Wolf child-container/input/GPU smoke tests | previous files via previous generation; pairings/profiles remain mutable |
| Backup schedules and replica capacity | Compose backup services + Ansible assertions | Compose still runs backup containers; NixOS owns ordering/timers only where host-side; NixOS health owns capacity assertions | Compose activation and systemd checks | actual local 3-copy run, remote run, checksums, RPO/capacity | backup history remains independent mutable state |
| Safe image pruning/current+previous locks | Ansible `maintenance` + helper | NixOS timer and packaged guarded helper; deterministic expected image docs embedded per generation; live evidence outside store | timer under shared mutation lock | both current/previous generation digests local/registry available; no unrestricted prune | disable timer; retain images referenced by current/previous generations |
| Host/controller mutation locks | Ansible role + outer controller + Proxmox Nix app | one shared, tested lock protocol used by controller, VM apply, Compose and recovery apps | acquired by exact apply/recovery only | contention, stale-owner, failure-retention and clearance tests | explicit inspected clearance app only |
| Audit/health | Ansible audit/health | `vm-verify` plus NixOS health units and controller no-op checks | after host/Compose/app OpenTofu phases and on timer/boot | host, storage, hardware, Compose, backups and all control-plane no-op | observation only |
| Disaster-recovery archive selection/extraction/activation | Ansible recovery playbooks plus Python/shell tools | guarded `recovery` Nix app reusing/refactoring existing safe tools | explicit plan then restore of reviewed backup into approved isolated/fresh targets | backup ID/checksum/version, traversal/device/hardlink/symlink/nonempty rejection, post-health | never automatic; no destructive overwrite |
| Normal migration data transfer | no current implementation | guarded `vm-cutover` Nix app and manifest-driven rsync | only after complete quiescence proof | per-path stats, metadata, final checksum dry-run with no unexplained output | old Arch disk stays unchanged; post-write rollback needs explicit divergence decision |
| Authentik API desired state | restored DB / manual configuration | isolated Authentik OpenTofu root only for imported/explicit supported resources | only after Compose health | plan/apply/no-op and API checks | reviewed Git revert and reverse plan; data restore separate |
| Sonarr/Radarr/Prowlarr API desired state | restored DB, env API keys, Recyclarr/manual config | isolated media-app OpenTofu root for non-overlapping supported resources | only after Compose health and Authentik phase | imports, plan/apply/no-op and API checks | reviewed reverse plan; never claim DB rollback |
| Unsupported SAB/qBittorrent/app settings | restored app files/DB/manual | retain restored state initially; later SOPS-backed file or narrow idempotent packaged API script per setting | explicit app phase | setting-specific GET/compare/no-op | reverse script/config commit; mutable data separate |
| Retired Proxmox/CT transition logic | historical Ansible/docs already removed or tombstoned | obsolete; do not translate | none | absence/tombstone tests | separate backend-retirement design only |

Duplicated desired state to eliminate: Arch package/network/users/SSH/Tailscale/Docker/hardware versus NixOS; Ansible Compose deploy versus generation activator; Recyclarr versus any OpenTofu quality-profile ownership; Compose environment/API keys versus provider-managed credential resources; restored databases versus newly declared API settings; old and new mutation-lock implementations.

State not to model as configuration: named-volume contents, databases, media, Wolf-generated containers/pairings/profiles, Docker image/overlay/build cache, backup archives/history, runtime sockets/PIDs, decrypted SOPS material, saved plan files, quiescence/rsync evidence.

Historical logic not to translate: pacman/snapshot mechanics, DKMS activation, Arch initramfs handlers, Ansible check-mode/recap normalization as an engine contract, retired CT 101/gateway/Proxmox Ansible paths, legacy checkout migration, unrestricted prune cleanup mechanics. Preserve only the safety invariants.

## 2. Proposed NixOS module structure

```text
nix/
  flake.nix
  flake.lock
  hosts/vm-100/
    default.nix
    disko.nix
    hardware.nix
    networking.nix
    access.nix
    storage.nix
    docker.nix
    compose.nix
    secrets.nix
    backup.nix
    health.nix
    qualification.nix
  modules/
    coral.nix
  packages/
    coral-driver/default.nix
    compose-artifact/default.nix
  apps/
    # add vm-plan, vm-apply, vm-verify, vm-install, vm-cutover,
    # recovery and app-tofu only in their implementing milestones
  vm-100/
    projection.json
    projection.schema.json
  compose/
    # generated from the existing compose-artifact selector's Nix profile;
    # never maintained by a second path list
```

Keep the existing isolated flake so the approved Proxmox host bundle does not ingest the whole repository. Extend the existing contract projector to emit a closed, secret-free VM projection. Extend `scripts/compose-artifact.py` as the single authoritative selector/hash implementation with distinct profiles: (1) the existing full deployment input and (2) a secret-free Nix topology/runtime-asset input. Regenerate a tracked `nix/compose/` mirror from profile 2 and require exact path/content equality, no extras and freshness in validation. Hash and bind the encrypted SOPS/runtime-input manifest separately; it cannot share the topology artifact hash. Do not create a second path list, repository-root flake or weakened Proxmox closure.

Use NixOS 26.05 because the existing input already selects the current stable release, with the exact revision held in `flake.lock`. Add Disko and sops-nix as locked inputs following the same nixpkgs. Begin with cohesive VM-100 modules; extract generic option-bearing modules only after production and qualification have a demonstrated shared consumer. Expose production and transfer-inhibited configurations/specialisations from the same modules; only production is the VM 100 final toplevel.

## 3. Compose activation design

- Build a derivation containing only the exact secret-free Compose topology/runtime assets, topology manifest/hash, deterministic expected image document, host-side Wolf tracked files, expected application OpenTofu revisions and packaged helper binaries. Separately bind the SOPS ciphertext/runtime-input manifest hash.
- Keep `secrets/production.sops.env` as the single encrypted authority but outside the topology artifact hash. It may be a sops-nix ciphertext input in the closure; plaintext is materialized only under `/run`.
- `sops-nix` renders the exact runtime dotenv at `/run/home-lab/compose/production.env` with `root:root 0400`; Compose and providers consume runtime paths, never Nix strings.
- Preserve and attest `project-name=docker-compose`, runtime project directory `/srv/docker-compose/current`, explicit compose/env paths and `HOME=/home/docker` in projection, plan, preflight, activation, rollback and cold boot. This preserves engine volume names and the `${HOME}/.ssh` backup bind.
- Docker is ordered after local filesystems, games and NFS mounts, required device preflight and the transfer-inhibit guard, so restart policies cannot start containers before storage/hardware is ready.
- `home-lab-compose-preflight.service` validates mount identities/capacity, sops template metadata, device availability, topology/runtime-input/image hashes, complete service/image/reference set and canonical Compose config.
- `home-lab-compose.service` is boot-enabled but is not restarted merely because a generation switched. Normal deployment explicitly invokes the guarded activator after exact toplevel activation. On cold boot it selects the artifact embedded in the booted generation.
- The activator uses no build, no orphan removal, no volume removal and only reviewed image pulls/recreations. It recomputes a secret-free action plan immediately before apply and requires post-activation no-op and health.
- Use two schemas: the deterministic embedded expected document maps project and every service to its exact pinned reference/manifest digest plus artifact/toplevel hashes; live evidence separately records local image IDs, RepoDigests and capture time. Require exact equality only for the expected mapping, then prove every observed local image resolves to that pinned digest. Update current/previous live evidence transactionally only after convergence.
- Generation rollback selects the previous toplevel’s artifact and image document. It does not revert volumes, binds, databases, external APIs or schema changes.
- Transfer mode masks Docker/Compose and leaves a persistent inhibitor. It is verify-only on reused NFS/games mounts: no Wolf/game file activation occurs before the explicit write-commit gate.

## 4. Exact-generation plan/apply model

`nix run path:./nix#vm-plan` evaluates/builds once, creates plan-bound indirect GC roots, and writes a canonical mode-0600 plan containing only secret-free/protected identities:

- exact local `main` commit and proof it equals `origin/main`;
- contract, VM projection and `flake.lock` hashes;
- exact planner/apply program store paths;
- exact toplevel store path and a sorted recursive closure manifest containing every store path and NAR hash;
- active toplevel and closure difference;
- separate Compose topology, encrypted runtime-input and expected image-document hashes;
- SOPS recipient-set identities without plaintext values;
- expected Authentik/media root revisions;
- kernel/bootloader/module/mount/network restart/reboot classification;
- applicable protected saved PVE/application plan file hashes.

`vm-apply --plan <file> --generation /nix/store/...` executes the GC-rooted apply program directly, never `nix run`:

1. requires clean local `main`, fetches origin and verifies exact equality with `origin/main`;
2. verifies every plan hash, recursive closure entry and exact store path using query-only operations—no evaluate, build or replan;
3. copies the already-built closure through a distinct restricted `nix-copy` forced-command identity with a unique key, no general shell/sudo/groups/TTY/forwarding and exact closure authorization/resource limits. A dedicated protected signing key signs the planned closure and only its public key is trusted by the guest importer; the private key never reaches the guest. After import, verify remote recursive closure-set equality and every NAR hash before creating a temporary remote GC root or activating anything;
4. acquires one outer controller transaction lock spanning PVE, closure copy, host activation, Compose, Authentik/media apply and final no-op; host-operation and per-root S3 locks nest in a documented fixed order. The prerequisite fix makes this one regular-file flock acquired once by the outer process; nested tools receive and validate an inherited lock FD/token and never reacquire it. Tests cover contention, invalid inheritance, nested success, cleanup and exact live no-op;
5. invokes a separate forced `nix-apply` transport accepting only a canonical envelope and exact toplevel;
6. for risky changes, runs the selected path’s `switch-to-configuration test`; after success atomically sets `/nix/var/nix/profiles/system` to the exact path without evaluation and invokes that same path’s `switch-to-configuration boot|switch`;
7. verifies `/run/current-system`, the system profile and bootloader selected generation all resolve to the planned toplevel;
8. runs host preflight, explicitly activates the embedded Compose artifact, applies application roots in required order, verifies health/no-op, replaces temporary GC roots with retained profile/pre-copied-generation roots and releases the lock only after success.

The active generation writes safe build metadata under `/etc/home-lab/generation.json`; `vm-verify` compares it to the booted profile and `origin/main`. Retain the prior profile and explicit GC roots until qualification. Before retiring a SOPS private identity, enumerate all retained rollback generations’ ciphertext recipients and prove each remains decryptable or build and qualify replacement rollback generations.

## 5. Application OpenTofu ownership table

| Domain/application | Initial managed surface | Owner/credential source | Bootstrap/import | Drift and rollback | State sensitivity |
|---|---|---|---|---|---|
| Authentik | only explicitly inventoried supported applications, providers, mappings, policies, groups/outposts chosen after export | `goauthentik/authentik`, API URL/token supplied ephemerally from SOPS | use a manually created non-self-rotating bootstrap token; define desired resources; import existing IDs before first apply | fail on unimported existing objects; Git revert + reviewed reverse plan | inspect every schema; avoid client secrets/resources that persist secrets until protected-state threat review |
| Sonarr | root folders, download clients, indexer/proxy/application links or other supported settings that do not overlap Recyclarr/restored config | pinned `devopsarr/sonarr`; API key from SOPS only | live inventory, define/import existing resources | API plan/apply/no-op; reverse plan | connection passwords/keys may enter state; defer those resources until schema review |
| Radarr and Radarr 4K | same bounded classes, separate provider aliases/endpoints | pinned `devopsarr/radarr`; SOPS API keys | inventory and imports per instance | same | same |
| Prowlarr | supported indexers/proxies/settings not duplicated by restored DB or app links | pinned `devopsarr/prowlarr`; SOPS API key | inventory/import | same | application links can contain downstream API keys; defer unless schema/state threat model accepted |
| Recyclarr | retain ownership of synced quality profiles/custom formats initially | Compose/restored data + SOPS API keys | no OpenTofu adoption of overlapping profiles | its own idempotent sync and explicit verification | avoids dual ownership |
| SABnzbd/qBittorrent | restored files/databases initially | mutable app state | no automatic rewrite during migration | later one-setting-at-a-time SOPS file or packaged idempotent API script | keep values out of logs/store; do not build a provider by default |
| Other apps | remain restored/manual until provider maturity and ownership are proven | existing owner | explicit future adoption only | explicit | explicit review |

Use separate S3 keys for `authentik` and `media-apps`, exact provider pins and lockfiles. Before initializing them, extend the AWS-foundation least-privilege state/lock allowlist and verify KMS encryption, versioning, public-access blocking and lock behavior. Extend plan policy with application-specific allowlists. Treat binary saved plans, state, apply logs, crash files and any JSON rendering as secret-bearing: protected fixed directories, mode 0600/single-link checks, `TF_LOG` disabled, bounded retention through exact apply, cleanup after verification and secret-free evidence only. Roots run only after Compose health. State remains sensitive even when UI output is redacted.

Because saved application plans do not refresh APIs at delayed apply, each plan also binds a secret-free canonical hash of every adopted resource field read during planning and blocks setting changes after capture. Immediately before applying the saved plan, GET the same fields from the newly restored live application and require exact hash equality; mismatch aborts and requires a fresh reviewed plan. Never serialize secret fields into this evidence hash.

## 6. SOPS credential-flow design

- Keep one encrypted authority for shared credentials. First classify the current single recipient; add independent recovery and new NixOS guest recipients before removing anything.
- Parent generates a standalone NixOS age identity outside Git/store/logs, escrows it offline, adds only its recipient, and runs `sops updatekeys`. Qualification installs it only through a protected channel; no subagent sees it.
- `sops.age.keyFile` points to a persisted root-only path outside the store. Disable implicit generation because rotation and escrow are explicit.
- Separate guest Compose materialization from controller provider execution. The guest alone renders `/run/home-lab/compose/production.env`. The controller uses its own protected, escrowed age identity outside Git/store/logs; a root-owned Nix wrapper starts each OpenTofu provider from `env -i` (or equivalent), decrypts only that root’s allowlist into ephemeral credentials, and adds only fixed reviewed non-secret variables plus required endpoint/API/backend values. Unrelated shared names are tested absent.
- Authentik uses a dedicated least-privilege provider service account where supported. Bootstrap token creation, expiry/revocation and dual-token operator rotation are explicit; the provider never manages the credential required for its own active session.
- Never interpolate secret placeholders into derivations, store files, command arguments, plan metadata or logs.
- Tests cover recipient rotation/recovery, retained-generation decryption, path/owner/mode/order, template regeneration, closure/store scans, clean provider environments and protected plan/log handling.
- Remove the old host recipient only after live/cold-boot/no-op/recovery success; retain the independent recovery recipient.

## 7. Coral derivation design

- `fetchFromGitHub` the archived `google/gasket-driver` commit `5815ee3908a46a415aac616ac7b9aedcb98a504c` with a fixed Nix source hash. Keep and apply the three tracked compatibility patches; remove Arch PKGBUILD/DKMS packaging only after the Nix derivation is qualified.
- Define a function parameterized by `kernel`/`kernel.dev`; build through kbuild against the selected NixOS kernel build tree and `Module.symvers`, not DKMS and not activation.
- Install `gasket.ko` and `apex.ko` under `$out/lib/modules/${kernel.modDirVersion}/extra`, run module fixup/compression as required by Nixpkgs, and expose the package through `boot.extraModulePackages` with `boot.kernelModules = [ "gasket" "apex" ]`.
- `coral.nix` defines group `apex`, stable udev rule for `/dev/apex_0` mode `0660`, module order and workload group membership.
- Build checks require both modules, `modinfo` metadata, exact vermagic match to the selected kernel and source/patch identity. NixOS VM tests can prove build/load failure handling only if virtual hardware permits; real PCI binding and inference remain Gate D/E physical checks.
- The upstream repository was archived 2026-04-18. Treat external GitHub availability and ongoing kernel compatibility as accepted but high operational risk; fail clearly if the fixed source/hash disappears or stops building.

## 8. Temporary-VM qualification procedure

1. Create a separate OpenTofu root/state for disposable VMID 9900, use DHCP with a proven non-production address (never VM100’s `192.168.0.100`), q35/host CPU, 8 vCPU, 16 GiB RAM, 32 GiB simulated source root, 32 GiB simulated games disk and 128 GiB candidate disk, with no exclusive production hardware.
2. Build installer/transfer/production closures from pushed `main` and bind their hashes in schema-validated evidence.
3. Exercise provider create, update, start/stop, protection/unprotection, mapping behavior, delete/absence and final empty/no-op state under qualification policy; none of these actions authorizes VM 100 cutover.
4. Install with Disko on a disposable disk; bind a unique PVE disk serial/by-id and capacity, reject known Arch/games identities, prove destructive-target guards and repeatability.
5. Exercise exact plan/copy/test/boot/switch, system-profile identity, GC roots, no reevaluation and previous-generation rollback.
6. Parent installs protected qualification credentials; prove SOPS materialization, clean provider environments and recipient recovery without logging values.
7. Exercise Docker and exact Compose topology/config using isolated fixtures for production secrets/data/hardware; do not call this full production health.
8. Test recovery into isolated empty targets plus all rejection cases. Separately rehearse simulated writes, divergence classification and every permitted post-write rollback outcome.
9. Test Authentik/media plan/apply/no-op against isolated instances where safe, including protected plans/state.
10. Test sequencing, lock contention/failure retention, health and cold reboot.
11. Record pre-destruction evidence, destroy the VM, verify absence and empty/no-op state, then commit/push the complete qualification evidence.
12. Defer GPU, Coral, Zigbee, Z-Wave, Bluetooth, games disk, production NFS, USB and virtual input behavior to final VM 100 qualification.

## 9. Physical cutover procedure

Preparation:

- Live-no-op-qualify the controller lock fix before any later implementation milestone.
- Land an explicit host-authority state machine: `arch`, `migration-in-progress`, `nixos`. Existing steady behavior remains `arch`; while migration is active ordinary steady/recovery guest mutation refuses to run; only the exact migration app is permitted; after cutover a pushed authority-flip commit enables NixOS steady paths. Dual/ambiguous authority is invalid. Preserve OpenTofu state address `proxmox_virtual_environment_vm.arch` unless a separately reviewed `moved` block proves no VM create/delete/replace or identity change.
- Capture read-only production inventory: all containers, volumes/engine paths, binds, Docker data root, UID/GID/modes, filesystem/capacity/features, writers/timers, mappings, backups, current/previous artifacts and images.
- Generate a reviewed manifest from canonical Compose plus live Docker. Include all 30 declared project volumes (including `openfit-data`), explicitly allowlist/create/transfer the 3 retained undeclared legacy engine volumes without attaching or pruning them, and include required host paths and persistent non-Compose/Wolf state. Mark NFS/games as reused, not copied. Exclude images/overlay/build cache, sockets/PIDs, runtime SOPS, regenerated identities and `/var/lib/docker` wholesale. Gate C rejects any hardlink spanning transfer roots; preservation requires a separately reviewed grouped-transfer design and inode/link-count verification.
- Recommended topology, subject to provider qualification: OpenTofu adds a fresh uniquely serialized VM100 candidate disk as `scsi2`, retaining Arch `scsi0` and games `scsi1`. A guarded installer running on Arch rejects the known Arch/games identities, partitions/formats only that by-id disk, installs the exact NixOS closure and mounts it at a dedicated target. A separate isolated target dockerd uses candidate-only socket, `data-root`, `exec-root`, PID file and managed-containerd/runtime state under the mounted candidate; disables bridge, iptables/ip6tables, forwarding, masquerade and userland proxy; and is selected by explicit `DOCKER_HOST` for every command. It creates all 30 declared and 3 protected legacy destination volumes, preserves their required metadata, then stops and remains inhibited. Attest the source daemon inventory is unchanged; start no application container. If provider or installer qualification cannot prove this safe, Gate C remains blocked rather than falling back to manual PVE drift.
- Every manifest entry binds canonical source/destination, expected device/filesystem/mount ID, Docker volume engine name/mountpoint/labels/creation identity and permitted deletion root. Reject symlinks, source/destination overlap, nested destination mounts and unexpected devices before copy.
- Use exact reviewed write argv `rsync -aHAXSx --numeric-ids --delete --delete-delay --itemize-changes -- SOURCE/ DEST/`; `--delete` is permitted only inside a dedicated approved destination root.
- Produce a fresh checksum-bound off-host recovery point or explicitly accept its RPO, restore it successfully to an isolated target, and fix OpenFit backup coverage (or explicitly accept its loss) before cutover. Local replicas are useful but not collectively independent of this migration.
- Pre-review one operational plan for each permitted post-write outcome: reverse transfer by data class, approved recovery point, or accepted data loss; include application version/schema compatibility. Rehearse simulated writes/divergence in the disposable VM.
- After all preparation commits are pushed and reviewed but before any workload stop, push the explicit `migration-in-progress` authority selection. It disables/refuses every ordinary Arch/Ansible and NixOS steady/recovery mutation path while leaving the currently running Arch workload untouched; only the exact cutover app can proceed. Regenerate all Gate C plans/evidence against that final pushed commit. Do not commit again until the cutover outcome selects `nixos` or rollback selects `arch`.

Outage:

1. Verify pushed-main identities, exact GC-rooted generation, off-host and local backup evidence, PVE/application plans, console and rollback commands. Start the approved outage clock: an 8-hour scheduled maintenance window, 6-hour maximum service unavailability and mandatory pre-write no-go/reverse transition by T+4h if the write-commit prerequisites have not passed.
2. Enter maintenance/block external writers. Disable Compose/Wolf/container producers, restart mechanisms, timers and backup jobs.
3. Inventory all running and stopped containers; stop every container; stop/mask source `docker.socket`, `docker.service` and runtime; prove no container, database, backup or other writer has any manifest source open.
4. With Arch still booted but quiescent and target dockerd stopped, execute each exact per-path rsync directly to the mounted candidate root. Copy only named-volume `_data` into its already-created destination; never engine metadata.
5. Repeat each transfer exactly as `rsync -aHAXSx --numeric-ids --delete --delete-delay --dry-run --checksum --itemize-changes -- SOURCE/ DEST/`. Require exit 0 and zero itemized changes—not merely explained differences. Bind evidence to manifest/argv hash, rsync version, source/destination mount identities, quiescence timestamp, counts, bytes, UID/GID/mode/ACL/xattr checks, critical checksums and stdout/stderr hashes.
6. Keep Arch Docker stopped. Apply the exact reviewed OpenTofu boot-order/disk plan while its observed state still has VM100 running; OpenTofu/provider owns the required controlled reboot into candidate `scsi2`. No manual PVE power mutation is allowed. The saved plan must prove update-in-place with protection, VMID, MAC, SMBIOS, disks and mappings preserved and no intermediate Arch workload restart. If the provider cannot prove/perform that state machine, stop and use a separately designed/reviewed provider-qualified transition.
7. NixOS boots transfer-inhibited and verify-only on reused mounts. Before any destination or games/NFS write, verify all transferred roots, profile/generation, network/access, external mounts and GPU/Coral/USB/Bluetooth/input/TUN. Against the now-updated PVE state, select the pre-reviewed reverse desired-input/configuration, generate and review/hash an exact reverse saved plan restoring Arch boot order, and prove it is update-in-place. Docker remains inhibited; any later PVE state mutation invalidates this reverse plan and blocks write-commit.
8. Pass the explicit write-commit gate only after that reverse plan is retained. Then materialize any changed Wolf/game files, remove the inhibitor and activate the exact Compose artifact. Prove application data equals the latest Arch state at quiescence, complete service/image identity and health.
9. Apply exact reviewed Authentik, then media OpenTofu plans, then approved unsupported-setting tools, all under the outer transaction lock; require each post-apply no-op.
10. Verify backups/maintenance and the complete no-op manifest; perform a controlled power-off/start and repeat the cold-boot evidence manifest.

Write-commit point: before step 8, rollback may use the preserved Arch disk because NixOS has made no writes to transferred or reused production data. After step 8, stop NixOS containers/daemon, compare every mutable class and require explicit approval for the pre-reviewed reverse-transfer/recovery/data-loss outcome. Never boot both stacks concurrently.

## 10. Rollback and recovery model

- Before cutover: remove qualification resources only after recording delete/absence/no-op evidence; revert unapplied code.
- Before write-commit: apply the exact reverse OpenTofu plan generated/reviewed after the forward transition and against its updated state; restore Arch boot order, boot Arch with Docker inhibited until storage/hardware checks pass, then start the exact pre-migration Compose artifact.
- After write-commit: quiesce NixOS, classify divergence using the manifest and execute only an explicitly approved pre-reviewed outcome. Never automatic.
- Nix generation rollback: exact previous profile/toplevel plus previous embedded Compose artifact/image document; it does not revert mutable data or APIs.
- Application rollback: Git revert, new reviewed reverse plan, apply and verify; mutable restore separately approved.
- Disaster recovery: separate `recovery plan/restore/verify`, exact backup identity/checksum/S3 version, empty targets and unsafe archive rejection; never migration source and never overwrite games/ZFS data.
- Retain Arch disk through live/cold boot, successful backup, recovery preflight, no-op, Ansible removal and separate user retirement approval.

## 11. Granular milestone and commit sequence

Each substantial milestone follows understand → decide → design → one-writer implement → parallel fresh review → fix → validate → commit → fetch/reconcile → fast-forward push → live apply/verify when applicable.

1. `docs(architecture): design vm 100 nixos migration` (after approval).
2. `fix(controller): unify production mutation locking` — regression fix; push and exact live steady no-op.
3. `chore(nix): add vm 100 flake scaffolding` — locked inputs, closed projection, NixOS skeleton.
4. `feat(nixos): define vm 100 base system and access`.
5. `feat(nixos): configure vm networking and storage`.
6. `feat(nixos): configure vm hardware`.
7. `feat(nixos): package coral kernel modules`.
8. `feat(nixos): manage vm runtime secrets with sops` — parent performs rotation; encrypted data only.
9. `feat(nixos): embed and activate compose artifact` — selector profile/mirror, separate manifests, expected images, preflight.
10. `feat(nixos): add backup maintenance and health services`.
11. `feat(controller): deploy exact nixos generations` — GC roots, recursive closure, copy/apply identities, profile activation.
12. `feat(controller): add guest authority state machine` — existing Arch default, migration refusal mode, NixOS path; no dual authority.
13. `feat(recovery): add guarded nix recovery application`.
14. `feat(migration): add guarded vm data cutover tooling`.
15. `feat(tofu): add vm 100 qualification root` — separate state/policy.
16. `feat(aws): authorize application tofu state` — least-privilege Authentik/media state/lock keys.
17. `feat(tofu): scaffold authentik application configuration` — disabled, inventory/import-first, protected state review.
18. `feat(tofu): scaffold media application configuration` — disabled, non-overlap policy, protected state review.
19. `test(nixos): qualify vm 100 migration` — qualify the exact pinned application roots plus provider lifecycle and post-destroy evidence.
20. `feat(tofu): prepare vm 100 candidate root` — only after provider and disk-identity proof.
21. `chore(controller): enter vm 100 migration` — only after review/approval of the cutover package; atomically select `migration-in-progress`, push, and leave the running Arch workload untouched.
22. Regenerate the exact closure and PVE/application plans from that pushed `main`; pass Gate C without another commit.
23. Parent executes the production cutover from pushed `main`; no commit substitutes for live evidence.
24. `feat(controller): select nixos guest authority` — pushed after successful boot/write gates; exact final-generation deploy/no-op.
25. `docs(qualification): record vm 100 live and cold-boot evidence` — Gate D/E plus backup/recovery evidence; no calendar soak is required.
26. Remove Ansible in vertical, internally valid slices: each commit removes one controller call path, its validation/tests, playbook and exclusively owned roles together; then remove remaining inventories/config/dependencies/identities and docs. Example subjects remain `refactor(ansible): ...` and `chore(controller): remove ansible dependencies`.
27. `docs(qualification): record final nixos convergence` — Gate F and final origin/main-equivalent active closure.

Application roots are implemented and production-imported/planned before cutover because the fixed workflow requires their post-Compose apply. Desired scope remains minimal/import-first; no setting is adopted without explicit ownership and protected-state review.

Split or reorder only to keep every commit safe on `main`. Never let ordinary steady target NixOS while Arch is active, or Arch while NixOS is active; migration mode refuses both. A pre-write rollback selects and pushes `arch` authority only after the reverse PVE transition and inhibited Arch verification; successful cutover selects and pushes `nixos` only after the write/health gates.

## 12. Subagent orchestration plan

- Parent owns every decision, commit, push, secret operation, live mutation, rollback and completion judgment.
- At each milestone, parent reads load-bearing files and writes a validation contract.
- Recon: read-only `scout` lanes for local seams, `researcher` for current official docs, `oracle` for drift/risk.
- Implementation: exactly one `worker` writer in the active checkout, with approved files/scope/non-goals/checks/stop rules and required handoff (files, behavior, unfinished work, commands/exit codes, evidence, risks, discoveries, decisions, Git state). Ordinary children cannot launch subagents.
- Review: fresh-context read-only reviewers in parallel for correctness/regressions; tests/acceptance; simplicity/maintainability; security/secrets; operations/rollback/DR; Nix reproducibility/closure as relevant. They inspect actual files/diff.
- Parent classifies every finding blocker/fix-now/deferred/rejected. One fix worker applies accepted findings. Up to three rounds unless a concrete blocker persists.
- No subagent receives decrypted secrets, identities, tokens, provider credentials, recovery URLs/keys or production environment files. Subagents may prepare commands and inspect redacted evidence only.
- Parent alone runs production read/mutation commands and interprets results. One writer per checkout; parallel writers only in isolated worktrees if ever explicitly needed.

## Acceptance gate matrix

| Gate | Required evidence and pass criteria | Unlocks |
|---|---|---|
| A — Nix foundation | `nix flake check`, exact VM toplevel build, deterministic eval, secret/store scan, UID/GID and mount-policy tests, Coral build metadata where introduced, independent review, pushed clean `main` | qualification infrastructure and secret qualification |
| B — temporary VM | created from pushed commit; provider lifecycle matrix; install; exact copy/profile/test/boot/switch; rollback; SOPS; isolated Compose/recovery/app-provider tests; lock tests; cold boot; destroy/absence/final no-op; no review blockers | Gate C planning |
| C — cutover approval | complete live manifest; all 30 declared + 3 allowlisted legacy destinations; no cross-root hardlinks; fresh off-host/local backup evidence; isolated restore; capacity/fs/ID/mount checks; exact rsync argv/dry-runs; inhibitor/quiescence procedures; rollback outcomes and pre-reviewed reverse PVE config/commands; exact GC-rooted closure; forward PVE and application saved plans; application before-state hashes; outage/console; parent approval | stopping all Arch containers |
| D — live VM100 | NixOS exact pushed generation; clean final checksum transfer; latest Arch state; storage/no-format; access; GPU/Coral/USB/input; exact Compose and complete health; PVE/Auth/media/Nix no-op; backup/maintenance active | cold boot |
| E — cold boot | controlled power-off/start timestamps; booted toplevel/profile/bootloader identity; network/SSH/Tailscale; mounts before Docker; SOPS; all devices; Compose order/health; timers; repeated complete no-op manifest | Ansible removal |
| F — Ansible removal/final | no executable/reference/dependency paths except explicitly justified history; repository checks; recovery preflight; all removal commits on origin/main; final active closure from final origin/main; all control planes no-op; clean checkout | completion report |

Each gate has a schema-validated secret-free evidence manifest listing exact command/argv, timestamp, exit code, action count/result hash, commit, toplevel, artifact/image hashes and pass/fail. The final no-op manifest enumerates every enabled OpenTofu root (AWS, Proxmox legacy tombstone where applicable, PVE, Omada, Tailscale, Authentik, media), Tailscale live/state equality, Proxmox host Nix, VM host Nix, Compose action plan/health and recovery preflight both before and after cold boot. Gate failure blocks the next milestone; it is never converted into documentation-only acceptance.

## 13. Risks and unresolved decisions

### Blockers before implementation beyond docs

1. The controller lock protocol landed in `8d4fa48`; exact live steady no-op qualification remains the blocker before NixOS scaffolding.
2. The approved VM100 `scsi2` NixOS root + retained `scsi0` Arch topology remains blocked on provider qualification. A saved live plan must prove update, not replacement/destruction.
3. Current single SOPS recipient role is unknown; independent recovery and new guest recipient design needs live/public identity evidence.
4. Numeric UID/GID and complete mutable root-path inventory need read-only production evidence.
5. Application desired resources/import IDs and overlaps (especially Recyclarr) require live API inventory before any application root can be authored.

### High risks

- Coral upstream is archived and lacks a modern-kernel compatibility guarantee; real hardware is a cutover blocker.
- A temporary VM cannot qualify exclusive passthrough, production IP-bound NFS or games disk.
- Compose restart policies can violate mount/secret ordering unless Docker itself is gated.
- Post-write rollback can lose or corrupt state; application backward schema compatibility is unknown.
- Existing artifact includes encrypted secrets and helper scripts; migration must define and validate a narrower secret-free artifact without breaking exact topology/path semantics.
- OpenTofu saved plans and state may contain sensitive values; provider schema review and protected state are mandatory.
- OpenFit declares `openfit-data` but current backup volume lists omit it; migration manifest must include it and backup coverage needs a separate decision/fix.
- Only Gluetun and Seerr are current required-health assertions despite more healthchecks; final required service-health baseline must be explicitly expanded/approved.
- The candidate-root preparation depends on running Nix installation/Disko and an isolated target dockerd from Arch; this exact environment must be qualified before it is accepted as the production topology.
- The PVE provider’s controlled reboot semantics for a running protected VM with a boot-order change are unknown until an exact disposable/live-safe qualification plan proves them.

### Approved architecture decisions

A. Use `nixos-26.05` at the exact locked revision; retain `docker-host` as network/Tailscale identity; use OS-neutral contract field names where safe; permanently preserve historical OpenTofu address `proxmox_virtual_environment_vm.arch` unless a later moved-state migration is explicitly approved.
B. Use the provider-qualified candidate topology: OpenTofu adds uniquely serialized `scsi2`; the guarded Arch-side installer and isolated target dockerd prepare only it; Arch `scsi0` and games `scsi1` remain; the exact PVE plan owns the controlled reboot.
C. Use `nix-plan`, a restricted signed-closure `nix-copy` importer and `nix-apply`, each with unique keys/forced transports; retain `docker` at its live-attested UID/GID; use an offline-protected closure signing key and guest-trusted public key.
D. Extend the existing Compose artifact selector with a secret-free Nix profile and generated tracked `nix/compose/` mirror; preserve the isolated nested flake.
E. Before any NixOS data write, rollback uses the exact OpenTofu disk/boot reverse plan. Afterward, require an explicit pre-reviewed divergence/reverse-transfer/recovery/data-loss decision.
F. Qualification envelope: VMID 9900; DHCP with proven non-production address; 8 vCPU; 16 GiB RAM; 32 GiB source, 32 GiB simulated games and 128 GiB candidate disks. Cutover envelope: separately scheduled 8-hour window, 6-hour maximum outage and mandatory pre-write no-go/reverse by T+4h.
G. Initial application scope is import-first, excluding Recyclarr-owned profiles and every resource whose secret schema/state handling has not passed review.
H. Add OpenFit to migration/off-host backup coverage and require every explicit Compose healthcheck plus application-specific smoke tests.
I. No calendar soak is required before production cutover or Ansible removal. Gate B parity authorizes Gate C planning; after cutover, successful Gates D and E, a successful off-host backup and one timed isolated recovery are the evidence threshold. Any unresolved parity or safety check still blocks progression.

## Sources

- NixOS 26.05 manual: https://nixos.org/manual/nixos/stable/
- Disko project/reference: https://github.com/nix-community/disko and https://github.com/nix-community/disko/blob/master/docs/reference.md
- sops-nix: https://github.com/Mic92/sops-nix
- Docker Compose config/interpolation: https://docs.docker.com/reference/cli/docker/compose/config/ and https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/
- Linux external modules: https://docs.kernel.org/kbuild/modules.html
- Google gasket driver (archived): https://github.com/google/gasket-driver
- OpenTofu saved apply/state/locks: https://opentofu.org/docs/cli/commands/apply/ , https://opentofu.org/docs/language/state/sensitive-data/ , https://opentofu.org/docs/language/files/dependency-lock/
- Authentik provider: https://github.com/goauthentik/terraform-provider-authentik
- DevOpsArr providers: https://github.com/devopsarr/terraform-provider-sonarr , https://github.com/devopsarr/terraform-provider-radarr , https://github.com/devopsarr/terraform-provider-prowlarr
