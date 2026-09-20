# Compose generation activation

## Purpose and boundary

Ordinary Compose delivery uses one native Ansible activation seam, not a custom
transaction controller. `ansible/playbooks/deploy-compose.yml` selects and validates
an exact clean Git commit, stages immutable source inputs, decrypts the environment on
the host, validates the resolved model and then calls
`ansible/roles/compose_native/tasks/generation.yml`.

The prepared `compose_native_generation` mapping contains only:

- an operation name and exact candidate/current artifact hashes;
- the hash-addressed staged artifact and environment paths;
- explicit requested and forced-recreation service sets; and
- the complete expected service set/count and required healthy containers.

It does **not** contain an image checkpoint. Tracked repository digest references are
the sole ordinary image authority. The activation task pulls missing requested images
with `community.docker.docker_compose_v2_pull` and `policy: missing`; every preview and
convergence call then uses `pull: never`. Native Compose automatically recreates
services whose resolved models changed, including image digest or approved environment
value changes. Explicit `recreate: always` is reserved for requested services whose
exact bind-mounted files changed. Either automatic or forced dependency-isolated
convergence may leave Compose 2.26 replacement metadata pending. The activation seam
admits only the exact requested-container recreate/start pairs, settles requested
services through dependency-aware automatic convergence, and then requires zero drift.

A full-project preview before convergence may act only on explicitly requested
container identities. The final full-project preview must be zero-change. Builds,
orphan removal, anonymous-volume renewal and automatic rollback remain disabled.

## Publication and authorization

The caller requires an exact clean source commit, unique requested services, exact
reviewed changed paths and an optional forced-recreation subset. It refuses mutable
images, service-set changes, top-level network/volume/config/secret changes, protected
per-service topology changes, non-requested service-model changes and unreviewed paths.
A separately approved plaintext environment difference additionally requires
`compose_native_environment_change_confirmed=true`; unused broad confirmation is
refused. File-backed secret publication remains outside this ordinary entrypoint.

Immutable staging and `current` publication remain necessary because Compose resolves
relative bind mounts from a stable project path. The `previous` artifact and decrypted
environment pointers, plus older hash-addressed artifacts/environments, remain because
the explicit Nextcloud migration rollback and archive recovery callers still consume
them. Their retention is not a generic rollback interface.

Current/previous/retained image locks, the former host override and historical
interruption checkpoints are not read, written, rotated, activated or verified by the
native deploy or observe paths. Existing host files remain historical/recovery evidence
until separately authorized cleanup.

## Rollback model

Generic Compose rollback is an ordinary forward deployment:

1. Create and review a new Git revert commit for the undesired Compose, image,
   environment or bind-file change.
2. Keep deployment automation at the latest reviewed version.
3. Run `ansible/playbooks/deploy-compose.yml` against that exact clean revert commit,
   naming only the affected services and reviewed paths.
4. Pull a missing old image by its exact tracked repository digest.
5. Let native Compose identify resolved-model recreation; explicitly force only
   unchanged-path content cases such as bind-mounted files.
6. Require the same running-service, health and zero-change full-project checks.

There is no ordinary “activate previous artifact” action and no registry-independent
rollback promise. Registry/network access is an accepted dependency when an exact old
digest is absent locally.

## Interrupted deployment

The durable production owner and Restic mutex checks remain the coordination boundary.
Failure leaves ownership in place. No image checkpoint is created. Do not clear the
owner, watchdogs or host evidence to retry.

After a failure following artifact publication or partial container convergence:

1. stop and inspect the exact owner, source commit, `current`/`previous` and staged
   artifact/environment identities, running containers, full-project native preview,
   health and Restic state;
2. decide whether the exact committed desired state can be safely completed with the
   latest automation;
3. if adoption is needed, create a narrow reviewed recovery entrypoint using the
   existing `apply_lock` `adopt` semantics, bound to the exact owner SHA-256,
   operation, controller and source/artifact identities;
4. converge only the explicitly affected services, then require complete health and a
   zero-change full-project preview before releasing that exact owner.

Do not add image retention checkpoints or a generalized resume/receipt framework.
No standing resume entrypoint exists because production currently has no unresolved
owner.

## Retained caller and recovery inventory

| Path | Current boundary |
| --- | --- |
| `deploy-compose.yml` / `compose_native:deploy` | Ordinary bounded forward deployment using tracked digests and native recreation. |
| `stage-compose.yml`, `review-compose-stage.yml` / `compose_stage` | Retained only for allowlisted Nextcloud/Restic/archive recovery preparation; general staging is refused. |
| `deploy-nextcloud-migration.yml` / `compose_deploy` | Historical Nextcloud migration and latent exact Restic-policy recovery semantics; general deployment is refused. |
| `rollback-nextcloud-migration.yml` / `compose_rollback` | Operation-specific Nextcloud migration rollback. It still consumes previous artifact/environment pointers, `compose-action-plan.py` and image locks. It is not the ordinary rollback model. |
| `plan-compose-recovery.yml`, `recover-compose.yml` / `compose_recovery` | Archive recovery with explicit recovered-data activation and ordered startup. It still seeds recovery image locks and must never consume a Restic staging tree. |
| `compose-artifact.py` | Deterministic artifact identity and publication. |
| `compose-image-lock.py` | Retained only for explicit migration/recovery capture, verification, difference and local-ID activation consumers. Its generic prune command is retired. |
| `compose-action-plan.py` | Retained only for explicit migration/recovery planning consumers. The generic rollback playbook is removed. |

The consumed failed-canary release play and generic `rollback-compose.yml` entrypoint
are removed from callable source. Nextcloud/database/storage/archive recovery semantics
remain unchanged pending separate review.

## Safe prune boundary

The historical maintenance role has no active playbook caller. Its source now installs
a narrow `docker image prune --all --filter until=168h` wrapper under the existing production
coordination lock. It does not inspect image locks, create protection containers or
query registries. Docker naturally preserves images referenced by containers; unused
historical images may be removed and later repulled by digest.

A live read on September 19 found `/usr/local/sbin/home-lab-safe-image-prune`, the
`crontab` binary and installed systemd/cron/helper references absent on `docker-host`.
No installed prune behavior or host file was changed. Any future installation remains
a separate production mutation requiring authorization.

## Qualification status

The historical canary, image-authority cutover, Caddy bind-file publication and
Recyclarr digest deployment outcomes remain recorded in
[operations](operations.md#native-compose-qualification). At the start of this
simplification, live check-mode observation again reported 38 declared/running
services, 38 digest-pinned images, required health, no owner/interruption and zero
Compose drift; the active artifact was `57c7326a463a560fee93fb45b729552fa8a9181d01b1f5292b2756558b21aa0d`
and Recyclarr reported v8.7.2.

The first authorized simplification deployment published artifact `d35539c7…` and
converged `flaresolverr`, then correctly retained production ownership when the
post-preview exposed the automatic isolated-convergence variant of the known Compose
2.26 recreate/start pair. The guard had incorrectly enabled settlement only when the
forced-recreation subset was non-empty. Commit `f7cdd91` generalized the exact action
guard and dependency-aware settlement to every requested service. The exact-owner
recovery initially settled the pair but stopped before marker publication and owner
release because its temporary health list was wrong; commit `c8dd472` made that
one-off recovery resumable from the already-settled state and reused the authoritative
`compose_native_required_healthy_containers` list. Its check passed with zero changes,
the normal recovery passed `ok=24 changed=1 failed=0`, advanced the marker, and
released only the retained owner. The consumed recovery play was then removed.

Fresh observation passed `ok=34 changed=0 failed=0`: all 38 services were running,
all 38 images were digest pinned, both required health checks passed, backup writers
were inactive, ownership/interruption state was absent, and the full preview was
zero-change. A source-bound check at `c8dd472` reported candidate and active artifact
`d35539c7…` with `ok=45 changed=0 failed=0`.

No GitHub deployment workflow is included. Short-lived Tailscale identity,
authoritative SSH host-key custody, protected-environment approval and production
coordination remain unresolved prerequisites.
