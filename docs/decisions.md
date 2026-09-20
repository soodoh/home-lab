# Decisions and deliberate exceptions

## Approved direction

Manage existing infrastructure with native OpenTofu, hosts with standard
SSH/Ansible become, and applications with Compose. Adopt the existing server
before expanding rebuild coverage. Keep high-risk storage, access, firewall,
reboot, database migration and recovery operations explicit and separate.
This supersedes the old controller/admission ADRs. There is no requirement to
finish their deferred successor before simplifying unrelated source.

Source cleanup removes universal launchers, abandoned admission/reporting machinery,
inert experiments and isolated unconsumed helpers/schema definitions. Published
forward recipes remain in Git, not current setup guidance. Retained evidence records
and installed/recovery consumers are a separate boundary; no new universal manifest,
launcher or qualification platform replaces the old controller.

## Disposable controllers and live validation

New native workflows must work from a fresh checkout on a disposable runner.
Desired configuration and repeatable checks belong in source; current readiness
comes from fresh host observations and operation-specific postconditions, not
agent-session inventories, developer-local plans or committed success receipts.
CI logs are diagnostic history, not authorization inputs. Missing historical
completion records do not by themselves block unrelated source retirement.

Keep recovery state separate from validation results. Required interruption
journals, ownership, before-images and autonomous rollback belong durably on the
host or in independently available protected storage. Remote OpenTofu state and
reviewed saved-plan handling remain native tool responsibilities. Runner loss
must not lose recovery intent or disable watchdogs. Fresh observation is not
exclusive ownership: recheck preconditions under the operation's coordination.

This direction does not waive surviving legacy consumer checks, resolve a live
interruption, prove backup restorability or authorize artifact deletion. Migrate
those consumers deliberately rather than fabricating receipts, pinning new checks
to old observations, or introducing another admission framework. Production CI
needs trusted workflows, protected approval, reviewed short-lived access and
coordination with host-local writers; none is configured by this decision.

## Built-in-first Nix retirement

Preserve useful package, reboot and low-risk operations, not the legacy planning
framework or its exact CLI. Prefer core Ansible package facts/APT, copy/template,
service and reboot modules. Native check/review/apply replaces the custom saved
solver-plan model; it is not an immutable transaction. No custom APT display-output
parser, redacted production transition or replacement receipt system is required.

Keep inventory separate from mutation previews: even Ansible APT check mode can
repair missing/corrupt metadata. Retain operation-specific host coordination and
necessary interruption recovery, but do not reconstruct a universal controller
around built-ins. Durable native tool state may support forward repair; it is not
proof of automatic rollback. Autonomous firewall recovery and genuine hardware
safety functions remain narrow exceptions, not reasons to preserve unused writers.
Existing capabilities/recovery stay until replacements are qualified. Source work
and the checkpoint commit do not approve package actions, reboots or access changes.

## First native adoption

Native SSH/become deliberately reuses Tailscale access, accounts and keys.
Manual-install policy is independent of the legacy contract: the old unattended
retirement (disable timers/list updates) and cloud-init automatic-install defaults
must not undo it.

`configure-backups.yml` owns narrowly guarded existing-host configuration, not
bootstrap or activation. Native variables own unit inputs and tool pins; shared
render/install/account/copy declarations keep legacy entrypoint guards intact.
The `restic_systemd_legacy_contract` bridge remains necessary for legacy convergence
and the bounded post-NFS single-unit repair. Byte parity is not a permanent
obligation to match old receipt hashes.
Runtime policy, backup scope and retained-journal reconciliation remain legacy
responsibilities: tool upgrades and content rollout need coordinated policy/journal
review, not independent pin bumps or receipt regeneration.

[Operations](operations.md#latest-host-configuration-deployment) is canonical for
dated outcomes and supported scope, including
[unit-state exclusions](operations.md#backup-unit-definitions),
[existing-account refusal](operations.md#confined-backup-account) and
[same-content metadata limits](operations.md#same-content-backup-runtime-files).
These adoptions confer no general host convergence, upgrade, restart, reboot,
firewall, data migration or backup-health authority. The
[native Proxmox capability observation](operations.md#native-proxmox-capability-observation)
now checks protected identities without installed Nix helpers or prior runner
artifacts. Native maintenance variables also replace selected Nix data reads in
current source, but that activator change is not deployed and the wider legacy
audit/maintenance/recovery consumers remain.

Historically, the first
[native Compose workflow](operations.md#native-compose-qualification) slice used
fresh tracked source plus actual remote state and limited mutation to an explicit
`flaresolverr` canary. That canary-only service scope is superseded by the
bounded ordinary lane described below. Its host-side SOPS decryption, production
ownership and current/previous artifact/environment publication remain; the current
lane no longer uses image locks. It creates no approval receipt and consumes no
previous runner result. After exact forward recovery closed the interrupted publication, commit
`b93919a3` passed the repaired reusable role's corrected same-commit check, separately
authorized normal canary activation and zero-change post-observation. Only
`flaresolverr` was recreated; the exact Compose 2.26 replacement pair was settled
through dependency-aware automatic convergence, and no database, Restic policy,
secret or artifact generation changed. The later image-lock simplification exposed
that dependency-isolated **automatic** convergence can leave the same pair as forced
convergence. Current generation activation therefore guards the exact requested
container action shape and settles all requested services—not only the forced subset—
through dependency-aware automatic convergence before the final zero-change preview.
The exact-owner recovery advanced artifact `d35539c7…`, released the retained owner,
and was removed after use. At that point this qualified the exact
canary mechanism, not a general deployment lane or other service scope. The later
ordinary-lane qualification supersedes that service-scope limit without authorizing
unrestricted convergence. The canary result was sufficient to refuse the legacy
**general** deployment lane, but not to remove operation-specific migration/recovery
code. A later live read found no installed image-pruning helper or scheduler consumer.

Tracked repository digests are the native runtime image authority. A September 19
read first proved the former override's 37 local image-ID entries resolved to the same
images as all 38 tracked references. After two safe check refusals corrected an
unstable raw action count and the historical unit dependency order, commit `6efbec4`
passed same-commit check mode and the separately authorized normal all-service
cutover. The normal run reported `ok=117 changed=11 failed=0 unreachable=0`; it wrote
the source-only unit with a host-local before-image, converged all 38 services,
required zero post-preview actions, consumed its checkpoint and released ownership.
Immediate ordinary observation reported `ok=40 changed=0 failed=0 unreachable=0`.
No image identity, database, environment, secret, topology, volume, Restic policy or
artifact generation changed. The former override and image locks remain recovery
evidence but the override is no longer a runtime input. The consumed cutover play and
transitional comparison/preinstalled-image branches are removed rather than retained
as a second authority. Commit `0e3c018` passed the simplified ordinary observation
with `ok=35 changed=0 failed=0 unreachable=0` and tracked-digest authority.

The bounded ordinary lane is now qualified for existing-service forward changes,
not unrestricted convergence. Commit `ba998f2` recreated only stateless/dependent
`flaresolverr`; commit `7e64899` published one exact bind-file change and forcibly
recreated only Caddy; commit `233a582` pulled and automatically activated only the
reviewed Recyclarr 8.7.2 repository digest. Their normal runs passed respectively
`ok=100 changed=10`, `ok=133 changed=24`, and `ok=134 changed=25`; each ended with
38 running services, zero full-project actions, consumed checkpoint and released
owner. Caddy config validation, Recyclarr's running version and zero-change ordinary
observations passed. The decision remains explicit-subset deployment with exact
reviewed paths, immutable service set/protected topology and separate production
authorization. Approved environment changes use the same native resolved-model
mechanics but require a separate explicit confirmation. Database/storage/secret and
Restic operations remain outside this qualification.

Ordinary rollback is a Git revert followed by the latest reviewed
`ansible/playbooks/deploy-compose.yml` forward path. Tracked repository digests are
the sole image authority; an absent old image is repulled by exact digest and
registry/network access is an accepted rollback dependency. The generic
previous-artifact rollback play, image checkpoints, image-lock rotation and
registry-independent guarantee are retired. Current/previous artifact/environment
pointers remain only because Nextcloud migration and archive recovery still consume
them. The former override and host image-lock files remain untouched evidence.

## Why legacy code remains

| Retained source | Actual reason / retirement boundary |
| --- | --- |
| `infrastructure/contract/`, schema, renderers and validators | OpenTofu roots now own typed root-local inputs and Omada has left the contract. Retained host lifecycle, Restic, Compose/Nextcloud recovery and whole-document plan bindings still consume the compatibility document. Follow the [consumer inventory and deletion gate](contract-ownership.md) rather than adding another global field. |
| Compose artifact/model/action/diff/image helpers, operation-specific staging/deploy/rollback roles | Legacy migration and archive recovery remain. General staging/deployment and generic rollback are refused/removed. `compose-action-plan.py` and `compose-image-lock.py` remain only for Nextcloud migration/rollback and archive recovery; image-lock pruning is retired. September 19 restore evidence closed the stale Calibre NFS-to-local lane without deleting either data generation. The coupled Calibre/Caro preserved-data play remains blocked pending separate review. |
| Restic runner, bootstrap/init/first-run/qualification helpers and recovery plays | Writer quiescence, interrupted-backup recovery, repository identity, pending-copy retention and retained operation journals remain real dependencies. |
| Proxmox deploy activator/transport | The final read found all boot/network/storage/NFS/Tailscale/package ownership journals committed. The retained prepared package record is preserved as historical evidence. The installed activator was removed in the approved September 17 cleanup; the later VM9900 closure retired the remaining Restic-only deploy transport, account capability and source. |
| Installed Proxmox observer/private preparer/plan transport | Active source callers and installed helper/access generations are retired. The approved cleanup preserved root-only before-images, removed obsolete helpers/sudo, disabled obsolete shells and passed a zero-change second normal run. The known PVE root key remains inert behind the checked root-specific effective sshd public-key/root-login refusals and is checked by native observation. |
| Firewall transaction, boot recovery and persistent watchdog | Autonomous rollback must survive controller/network loss; Ansible rescue cannot provide that. Its source/runtime is independent of the removed Nix tree. |
| Historical Nix recovery material | Active `nix/`, bundle/planner/bootstrap and protected-input writer source is retired. Preserve the old host checkout, previous generation, install manifest, sealed inputs and historical Git checkpoint until their explicit disposition; do not reintroduce them as current automation. |
| VM9900 qualification and recovery roots/helpers | Live provider and host capability retirement is complete; callable source is removed. Preserve ignored state/cache generations, journals, plans, receipts, diagnostics and capability evidence as historical lineage. |
| JS dependencies and provider locks | Contract and policy consumers still need AJV/js-yaml. Retiring the Proxmox projection does not eliminate Node/Bun dependencies. |

### Qualification and provider-adoption retirement boundary

The September 18 source and live audit established the exact Debian and Restic
VM9900 ownership lineages before retirement. Separately approved saved plans then
deleted the stopped Debian VM, its two LVs, firewall resources and Debian image, and
deleted the Restic root's sole indexed image. Both preserved local states now contain
no resources. PVE removed `/vms/9900` with the VM. A later bounded host phase locked
the two dedicated Proxmox accounts, removed the seven exact capability files and
preserved homes, diagnostics, capability evidence and before-images. A guarded native
Tailscale full-policy update removed the two retired Proxmox SSH users; immediate
live-before body/ETag comparison, planned-after comparison and a fresh zero-change
plan passed.

Callable VM9900 roots, controllers, plan inspectors, fixtures, setup/retirement
plays and dedicated tests are removed. The disposable Debian `qualification-canary`
transaction route and its now-unneeded retained-lock recovery are also removed;
production lifecycle recovery operations remain. The
[VM9900 retirement assessment](vm9900-retirement-assessment.md) records exact plan,
state, policy and preservation evidence. Keep every ignored `.local`, `.reconcile`
and `.terraform` generation, journal, plan, receipt, diagnostic and evidence record;
source deletion is not permission to erase them or reuse VMID 9900.

The disposable disk-adoption source is retired. Its current local state is empty;
the immediately preceding state generation records VM9951 and four disks on the
`qual-lvmthin` datastore. A bounded live read found VM9951 absent, no matching ACL,
and the qualification datastore itself absent. The ignored provider cache and both
state generations remain as historical evidence; no VM, disk or datastore was
changed.

The production Proxmox candidate move is also retired after remote state showed the
sole VM address as `proxmox_virtual_environment_vm.debian`, with no
`proxmox_virtual_environment_vm.debian_readopted` or `arch` address; a fresh
provider-backed plan then reported zero changes. VM100's disk tombstone, imports and
resource address are unchanged. Tailscale remote state now binds only
`tailscale_acl.policy[0]`, the native complete policy-file owner. Import used the
separately provisioned least-privileged OAuth client and changed state only;
protected reads confirmed the live policy body and ETag were unchanged. The
separately authorized apply used a fresh inspected two-update saved plan, with the
live policy re-read and matched to the planned-before value immediately before
apply. It removed the retired `ansible-plan` identity from two SSH grants and moved
its policy test from accept to deny. Protected post-apply reads matched the
planned-after policy and the ETag changed. After that convergence, the now-redundant
`terraform_data.tailscale_policy[0]` placeholder was explicitly removed from state
and its source/policy fixtures were retired; before/after reads again proved no live
policy change, and a fresh native-only provider plan reported zero changes. The old
custom ETag evidence helpers remain retired. The later VM9900 closure update used the
same guarded procedure: one native policy update, exactly four SSH/test list changes,
immediate planned-before/body/ETag equality and exact planned-after live equality.
It removed only the retired Proxmox `ansible-deploy` and `qualification-apply` users;
Docker-host `ansible-deploy`, `proxmox`, `firewall-apply`, grants and network tests
remain. Provider updates overwrite the complete policy without an ETag precondition,
so future changes still require a fresh pre-apply comparison, separate authorization
and frozen dashboard edits.

Omada remote state exactly matches its one network and eight reservations, and
Authentik remote state exactly matches all 79 declared managed addresses plus two
data lookups. Fresh provider-backed plans for both roots reported zero changes.
Their roots, imports, encrypted inputs and preparation tooling remain active. Only
Authentik's one-shot account-creation bootstrap and hard-coded inventory normalizer
were removed: neither was a state, rotation or recovery consumer. Omada's export
and hostname-alias tooling still feed its retained root.

An exact state-bucket inventory found zero versions or delete markers for every
formerly retired key. Those five entries and their expired-object lifecycle-rule
scaffolding are removed from desired source. The external owner subsequently created
distinct plan/apply boundary policies with explicit action ceilings, attached them to
the two Roles Anywhere controller roles and reduced the apply identity policy from
version 13 to version 14 by removing the reviewed 20 IAM/Roles Anywhere mutation
action patterns. The complete prior version set was archived before oldest
nondefault version 9 was deleted to free AWS's fifth version slot. A refresh-only
owner plan contained exactly the two role boundary changes and apply-policy change;
its exact saved plan was applied to state without another AWS resource mutation.
The reviewed non-secret manifest is controller-local, both Roles Anywhere identities
work under the boundaries, and independent live readback matches the reviewed hashes.

The AWS foundation root is the first isolated provider leaf removed from the
global contract seam. It owns the fixed one-day incomplete multipart-upload cleanup
as a local safety invariant. Active state-object retention and resource addresses
remain unchanged. The separately authorized lifecycle apply removed the ten live
rules for the five already absent retired keys and retained all five active
lock-history rules unchanged. A post-apply state-object audit found no unexpected
versions or delete markers, and a fresh provider plan reported zero changes. The
legacy Offen field remains because recovery-hold proof and first-run recovery still
consume it; this change is not authority to prune that contract subtree.

Do not regenerate historical hashes, fabricate receipts, clear journals, stop
watchdogs or erase locks to make the reduced source pass legacy admission. A
persistent lock inode is not necessarily contention; its owner/journal and actual
flock state matter. Deleting an installer does not retire its installed copy.
Unknown operation state requires inspection and a specific recovery decision.

Backup schedule activation still checks the exact Restic restore-proof hash and
terminal Offen receipt. Keep those evidence files and the retirement manifest.
The contract also references `infrastructure/evidence/restic-first-run-aws.json`,
which is excluded by `.git/info/exclude` locally and untracked. `validate-contract`
no longer reads this receipt or any other historical inputs: its historical modes
were removed, and both retired flags fail explicitly rather than silently selecting
[offline source validation](operations.md#offline-contract-source-validation).
The pre-removal tracked-caller recheck found only documentation, not operational
callers; the isolated regression test covers flag rejection. First-run run/resume/finalize
playbooks separately produce or verify this receipt; their requirements, shared
policy validators and runtime/recovery gates are unchanged. Do not publish it
blindly or substitute a fake proof. Source tests are not current backup health.

## Custody is separate from receipt cleanup

The read-only custody audit is closed. Ordinary provider state is remote in the
five configured S3 backends, not dependent on developer-local state copies.
Remote object/version metadata establishes existence, not correct contents,
decryptability or successful recovery. Bundle B's restricted HEAD access is not
absence. Current state objects use SSE-S3 despite KMS bucket defaults; this is
not authorization to rewrite encryption or a prerequisite for safe source work.

The two former local qualification-state dependencies are now closed but remain
preserved: Debian lifecycle's
`.local/qualification-route/clean-first-boot-foundation-final/state.tfstate` and
Restic recovery's `.reconcile/restic-recovery-vm/09d091e5c9f44eafaf5a8b89576c9929e1fa5644/tofu.tfstate`
contain no resources after exact separately authorized deletes. Preserve both states,
their preceding generations and all recovery inputs. Do not apply historical plans,
remove state, erase lineage or treat closure as permission to reuse VMID 9900; see
the [retirement assessment](vm9900-retirement-assessment.md).

The recovery key remains on this developer machine and in the home Vaultwarden
service, but neither location is an independent recovery boundary. On September 19
the operator confirmed an exact plaintext copy on an offline USB stored securely
offsite. That closes the age-key location-custody gap without placing key material
or its physical location in Git. Historical GPG ciphertext remains preserved as an
optional legacy envelope; it is not a required recovery dependency and its separate
decryptability is not implied by the USB confirmation.

The separately authorized September 19
[read-only retrieval drill](../recovery/aws-bundle-retrieval.md) used the
controller-local identity after the operator accepted it as an exact equivalent of
the confirmed USB copy. It proved publication-credential decryption, the expected
AWS caller, KMS-backed retrieval of the exact historical current bundle version,
ciphertext identity and cleanup. It did not literally read the USB, establish an
independent repository checkout, decrypt the bundle or restore data. Future
credential use, cloud reads, bundle decryption and recovery exercises require
separate approval.

Keep working logging and backup configuration unchanged. Explicit journald policy
is optional follow-up. These remaining recovery gaps, further historical evidence
collection and KMS changes are **not prerequisites for receipt-dependency source cleanup**.
Such cleanup must still preserve operational guards and supported scope.

## Ownership and evidence limits

- The shared AWS GitHub OIDC provider
  `arn:aws:iam::658271954302:oidc-provider/token.actions.githubusercontent.com`
  belongs to websites' CloudFormation stack `diloreto-amplify-hosting`, logical
  resource `GitHubOidcProvider`. Home-lab must not manage/import an OIDC provider.
  The prior foundation serial 43 observation had zero OIDC entries, not proof
  about every backend. No deletion principal was established by that history.
- Roles Anywhere IAM resources remain useful native credential infrastructure;
  names containing `local_controller` are not permission to delete them. External
  boundary ARNs do not establish the deployed policy contents or custody.
- `state-objects.json` drives exact active backend IAM keys and noncurrent lock
  lifecycle prefixes. Active state history remains retained. The September 18
  exact-key inventory proved every formerly retired version and delete marker
  absent before their entries were removed from source. Prefix matching is not
  equality; any future retirement needs the same exact inventory gate. No
  bucket-wide expiration or state deletion.
- Historical aggregate Ansible ownership and bounded Nix-runtime retirement
  (2026-09-11, no removals) did not qualify clean boot, new-source convergence or
  universal recovery. Completed key/domain handoffs are not repeatable setup steps.
- A saved OpenTofu plan is not a cross-system transaction. `prevent_destroy` does
  not prevent every in-place data loss or external action. Ansible check mode is
  a preview, and Compose cannot reverse database migrations.

Retain `.local`, `.reconcile`, `.terraform`, recovery bundles, state, credentials,
images, failed plans and lock/journal artifacts. No ignored operational artifacts
were cleaned during this source pass. Live retirement and native replacement
require separate review; see [migrations](migrations.md) and
[recovery](../recovery/README.md).
