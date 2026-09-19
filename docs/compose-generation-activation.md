# Compose generation activation

## Purpose and boundary

Compose delivery is moving toward one native Ansible activation seam, not a new
controller. Operation-specific workflows remain responsible for selecting and
preparing an artifact and environment, validating service/data changes, coordinating
writers, and performing any database or filesystem migration. The small
`compose_native` generation input starts only after those checks.

The first slice extracts the already check-qualified canary's activation mechanics
into `ansible/roles/compose_native/tasks/generation.yml`. It accepts one prepared
`compose_native_generation` mapping containing:

- an operation name and exact candidate/current artifact hashes;
- the hash-addressed staged artifact, environment and interruption-image paths;
- the explicit service and forced-recreation sets; and
- the complete expected service set/count and required healthy containers.

The task file rejects paths that do not derive from the supplied artifact hash. It
then captures a durable pre-change image checkpoint, rechecks the backup mutex,
preserves older hash-addressed artifact/environment/image generations, publishes
`current` and `previous`, pulls only the requested missing images, previews the
complete published project with `community.docker.docker_compose_v2`, converges only
the requested services, waits for health, requires a zero-change full-project
post-preview, verifies the complete running set, rotates image locks, publishes the
active artifact identity, and consumes the checkpoint only after full success.
Builds, orphan removal, anonymous-volume replacement and automatic rollback remain
disabled.

This is a refactor of the existing canary behavior, not a new deployment approval or
a universal manifest, launcher, plan, or receipt. `deploy.yml` still owns source
selection, SOPS handling, normalized-model comparison, canary scope and all
operation authorization. The activation task is not a public standalone playbook.

## Retained caller and recovery inventory

| Path | What it prepares or owns | Current activation boundary |
| --- | --- | --- |
| `deploy-compose.yml` / `compose_native:deploy` | Clean committed source, deterministic hash-addressed artifact, host-only environment decryption, same-content environment check, normalized topology/service comparison and explicit canary recreation scope | Uses the extracted native generation interface. This is the only migrated caller in the first slice. |
| `stage-compose.yml`, `review-compose-stage.yml` / `compose_stage` | Exact legacy artifact/environment, Nextcloud secret files and protected desired/runtime inventories for four allowlisted retained operations | Retained unchanged. General staging remains refused. Its inventories still feed legacy deployment and archive-recovery preflight. |
| `deploy-nextcloud-migration.yml` / `compose_deploy` | Nextcloud writer ordering and path migration, or the latent exact Restic-policy and interrupted Calibre recovery lanes, including filesystem/SQLite/policy work | Retained unchanged. Database/filesystem and timer work must be split from Compose activation before this caller can use the native seam. There is no general deploy entrypoint. |
| `rollback-compose.yml`, `rollback-nextcloud-migration.yml` / `compose_rollback` | Exact reviewed previous artifact/environment/image locks, optional historical Nextcloud service removal and rollback action identity | Retained unchanged. Both plays still depend on the custom action-plan and image-lock helpers until a native preview can preserve their exact service-removal and pre-publication recovery semantics. |
| `plan-compose-recovery.yml`, `recover-compose.yml` / `compose_recovery` | Selected archive identity, empty recovery target, first-host path/volume admission, explicit recovered-data activation, host-file reconciliation and ordered Nextcloud startup | Retained unchanged. It still consumes `compose_recovery_preflight`, `prepare-recovery-volumes.py`, `activate-recovered-data.py`, `host_files`, `health`, staging inventories and image locks. It accepts the older `backup/` archive layout only; it must never consume a Restic staging tree. |
| `compose-artifact.py`, `compose-image-lock.py` and installed safe-image-prune | Deterministic generation identity and retained/interrupted rollback-image protection | Retained. The native slice calls them for identities and image generations; the installed prune consumer remains supported. |

Current/previous artifacts and environments, hash-addressed staging, current/previous/
retained image locks, interruption checkpoints, production ownership, Restic mutex
and journal, migration journals, rollback inputs and installed recovery consumers
remain intact. No helper is retired by this slice.

## Local controller capability

A fresh local controller can perform the bounded native path when it has the reviewed
Ansible Core 2.21.x line, pinned `community.docker` collection, explicit inventory,
trusted Docker-host key, Tailscale connectivity and the exact clean source commit.
The host retains the SOPS age identity; the controller does not need the production
private key. Check mode deliberately reports the source/active generation boundary
without staging or decrypting protected inputs. A normal run still requires explicit
operation confirmation and separate authorization, and repeats live coordination and
model checks before activation.

Controller-local source tests parse the role and verify the generation input/path
contract, native Compose preview/convergence, health/idempotence checks, retained
publication/image state and the untouched recovery callers. On September 19, 2026,
the local controller reported Ansible Core 2.21.2 and the pinned `community.docker`
5.3.0 collection; syntax checks for both `deploy-compose.yml` and
`observe-compose.yml` passed without contacting a host. This confirms the bounded
controller toolchain and playbook parsing only—not SSH connectivity, live check-mode
behavior or deployment readiness. Neither check decrypts a secret, initializes a
provider or authorizes deployment.

No GitHub deployment workflow is included. Short-lived Tailscale identity,
authoritative SSH host-key custody, protected-environment approval and production
coordination remain unresolved prerequisites.

## Next slices

Migrate one recovery caller at a time only after its operation-specific preparation
can hand the activation seam a complete, validated generation. Preserve explicit
Nextcloud, Calibre and archive-recovery data logic outside the seam. A later slice
may add narrowly reviewed publication strategies for previous-generation rollback or
fresh-host recovery; it must not generalize database migration, data activation,
locks, journals or approval into a universal transaction format.
