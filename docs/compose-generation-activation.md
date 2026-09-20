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

This began as a refactor of the qualified canary behavior. The current source now
uses the same seam for an explicit subset of any service already present in both the
active and candidate models; it does not carry a separate service catalogue or
canary-specific mount manifest. `deploy.yml` still owns source selection, SOPS
handling, normalized-model comparison and operation authorization. It requires an
exact reviewed changed-path list, refuses service-set and top-level topology changes,
keeps the decrypted environment byte-identical, derives container names from native
`docker compose config --format json`, and requires source images to be repository
digest pinned. Native pull fetches only missing requested-service images before all
previews and convergence switch to `pull: never`. Bind-file changes require the
operator to include their services in the explicit forced-recreation subset.

This is not a universal manifest, launcher, plan, receipt, database migration path or
new deployment approval. The activation task is not a public standalone playbook.

## Retained caller and recovery inventory

| Path | What it prepares or owns | Current activation boundary |
| --- | --- | --- |
| `deploy-compose.yml` / `compose_native:deploy` | Clean committed source, exact reviewed artifact paths and requested/forced-recreation service subsets, host-only environment decryption, same-content environment check and native normalized-model comparison | Uses the extracted native generation interface. The all-service reference cutover qualified activation of all existing services; representative ordinary config, bind-file and image changes remain pending. |
| `stage-compose.yml`, `review-compose-stage.yml` / `compose_stage` | Exact legacy artifact/environment, Nextcloud secret files and protected desired/runtime inventories for three allowlisted retained operations | General staging remains refused. The obsolete Calibre operation is no longer allowlisted; retained inventories still feed Nextcloud/Restic deployment and archive-recovery preflight. |
| `deploy-nextcloud-migration.yml` / `compose_deploy` | Historical Nextcloud writer/path migration and latent exact Restic-policy recovery | Retained pending caller-by-caller retirement. The applied Nextcloud migration must not be rerun. The obsolete Calibre authorization/resume and NFS-to-local reconciliation branch was removed after verified private-staging restore. There is no general deploy entrypoint. |
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
behavior or deployment readiness. Neither check initializes a provider or authorizes
deployment. The separately authorized live attempt documented in
[operations](operations.md#native-compose-qualification) reached this interface but
failed its immediate full-project idempotence assertion after publication and the
bounded canary recreation. A disposable Compose 2.26.1 regression isolated the
`--force-recreate --no-deps` interaction with a named service that has a dependency.
The interface now permits only the exact requested replacement actions and settles
them through dependency-aware automatic convergence before requiring a final
zero-change preview. Commit `bc870b8e` bound an exact forward completion to the
retained owner and generations. Its separately authorized normal run completed the
interrupted publication, preserved rollback image generations, advanced the marker,
consumed the checkpoint and released ownership; fresh native observation then passed
with 38 running services and a zero-change preview. That operation-specific recovery
authorization is consumed. Commit `b93919a3` then passed the reusable role's corrected
same-commit check and separately authorized normal canary run. The role recreated only
`flaresolverr`, admitted the exact replacement action pair, settled it without
dependency recreation, consumed its fresh checkpoint and finished with zero-change
observation. That live qualification covers only the exact historical canary scope. The later
general-caller refactor is source-only: no broader service deployment is authorized
or qualified yet. At commit `0b75750d`, fresh native observation and a same-commit
check passed with zero changes and equal candidate/active artifact identity. Check
mode intentionally skipped normal staging, decryption, model comparison and
activation, so it did not qualify those generalized branches. Native inspection later
proved the retained host override semantically image-neutral for all 38 services, but
a source-only Compose preview proposed 76 container actions because its image-ID
references differ textually from tracked repository digests.

The one-time image-authority cutover at commit `6efbec4` passed same-commit check
mode (`ok=63 changed=2 failed=0 unreachable=0`) and its separately authorized normal
run (`ok=117 changed=11 failed=0 unreachable=0`). It published the source-only unit
with a host-local before-image, converged all 38 existing services without changing
image identity or data/topology, required a zero-change post-preview, consumed the
checkpoint and released ownership. Immediate ordinary observation passed
`ok=40 changed=0 failed=0 unreachable=0`. Tracked repository digests are now the
runtime image authority. The former host override and all image locks remain recovery
evidence but are not Compose inputs. The consumed cutover play, exact before-unit
fixture, duplicate model comparison and local-image precondition are removed from
callable source. Commit `0e3c018` then passed the simplified ordinary observation
with `ok=35 changed=0 failed=0 unreachable=0` and explicit tracked-digest authority.

No GitHub deployment workflow is included. Short-lived Tailscale identity,
authoritative SSH host-key custody, protected-environment approval and production
coordination remain unresolved prerequisites.

## Next slices

Qualify the ordinary general caller without expanding its boundary: same environment,
same service set, unchanged top-level topology, exact reviewed paths and explicit
service/recreation sets. Start with one stateless service, one bind-file recreation
and one digest-pinned image update.

Migrate recovery callers only after the general forward path is qualified and each
operation-specific preparation can hand the activation seam a complete validated
generation. Preserve explicit Nextcloud and archive-recovery data logic outside the
seam. The separate historical Calibre/Caro preserved-data play remains blocked
pending its own recovery review. Any later rollback or fresh-host slice must not
generalize database migration, data activation, locks, journals or approval into a
universal transaction format.
