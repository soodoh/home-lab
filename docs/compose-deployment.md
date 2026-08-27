# Repository-driven Compose deployment

## Phase 3 staging design

The deployment artifact is selected by `scripts/compose-artifact.py` from the exact Git checkout. It includes only:

- `docker-compose.yml`;
- the eight `services/*.yml` stack files;
- tracked `services/data/**` files;
- `.sops.yaml` and the encrypted production environment manifests; and
- the deployment-only validation and layout helpers required on the host.

Git metadata, documentation, worktrees, plaintext environment files, recovery keys, and unrelated repository files are excluded. A plaintext `*.env` path or private-key candidate inside the selection is a hard failure.

The canonical artifact hash is SHA-256 over a version marker followed by each sorted UTF-8 filename and its raw bytes, both length-delimited. File timestamps, checkout paths, archive metadata, and runner-specific state do not affect the hash. CI proves that the source, copied artifact, and no-Git staged tree produce the same hash.

## Stable host paths

```text
/srv/docker-compose/current
/srv/docker-compose/staging/<artifact-sha256>
/srv/docker-compose/previous
/etc/docker-compose/production.env
/etc/docker-compose/staging/<artifact-sha256>.env
/etc/docker-compose/previous.env
```

`current` is the only live project directory and its recomputed artifact hash is the deployment identity. Staging directories are immutable and hash-addressed, while `previous` and `previous.env` retain one separately reviewed rollback generation. The trusted local checkout is a controller input only; no live bind, audit, health check, or rollback operation depends on a host Git checkout.

## Staging workflow

The trusted local controller stages only the exact committed Compose artifact after manifest review and interactive apply confirmation. Host-side apply locks serialize it with other production work.

1. checks out the exact `main` commit;
2. computes and copies the deterministic artifact on the controller;
3. reviews `stage-compose.yml --check --diff`;
4. copies only that artifact into a root-owned incoming host directory;
5. recomputes the hash before atomically publishing `staging/<hash>`;
6. decrypts SOPS only on the host through `/etc/sops/age/keys.txt`;
7. restores the non-secret dotenv layout in a root-only temporary directory;
8. atomically installs an inactive `/etc/docker-compose/staging/<artifact-sha256>.env` as `root:root 0600` with `no_log: true`;
9. validates with explicit project name, immutable staging project directory, candidate environment file, and `docker compose config --quiet`;
10. writes root-owned secret-free desired and runtime inventories;
11. runs `docker compose --dry-run create --no-build --pull never`; and
12. requires a zero-change staging post-check and complete read-only audit.

This workflow does not run Compose pull, build, create, up, restart, removal, orphan removal, or volume operations. The normal staging execution is separately confirmation-gated even after entering the protected apply environment.

### Completed staging evidence

Manual run [`30850160213`](https://github.com/soodoh/home-lab/actions/runs/30850160213) staged and reviewed artifact `533ed4a14fce8a811a41ff0a3fe5e6b182fe485f965499d80d8f0c27cf79b357`. Its post-stage check reported `ok=5 changed=0 unreachable=0 failed=0`, the guarded model review reported `ok=7 changed=0 unreachable=0 failed=0`, and the complete audit reported `ok=45 changed=0 unreachable=0 failed=0` with all 41 containers still running.

The normalized model has identical service names, images, ports, volumes, devices, network modes, and network memberships. Five intentional bind-source changes remain for the stable-root migration: Caddy, Gluetun, LiteLLM, and the two backup services. The backup SSH source was explicitly preserved as `/home/docker/.ssh`; the two backup environment mounts change from the untouched checkout `.env` to the byte-verified root-only production environment file.

The exact no-pull/no-build dry run schedules recreation of those five services plus the eleven services sharing Gluetun's network namespace. It schedules no creates, removals, or volume operations. Ten health-check identity differences remain visible as hashed diagnostics; nine do not schedule any Compose action, while Gluetun is already accounted for by its bind-source migration. Nothing in this evidence authorizes the cutover.

## Secret-free model evidence

`scripts/compose-model-inventory.py` captures resolved Compose JSON and Docker inspection data only in process memory, then emits a restricted model containing:

- project name and service/volume counts;
- image references and current image IDs;
- published ports;
- bind and named-volume sources and targets;
- devices;
- network modes and network names; and
- SHA-256 identities of health-check definitions.

It never emits environment values, resolved commands, labels, or the complete Compose model. Compose resolves and dry-runs the immutable staged tree so every include and helper exists; the sanitized desired inventory then translates artifact-relative bind sources to `/srv/docker-compose/current`, never a temporary staging or GitHub checkout.

## Backup environment mount

The backup services declare `/etc/docker-compose/production.env:/backup/.env:ro`; active containers use the root-only production environment rather than a repository checkout.

## Backup temporary storage

Both backup services bind `/mnt/games/backups/.tmp` to container `/tmp` with automatic host-path creation disabled. `scripts/prepare-debian-production-automation` is the physical-console boundary that verifies the exact games UUID at `/mnt/games`, `rw`, at least 100 GiB available, and the completed Debian production journal before installing `/mnt/games/backups/.tmp` as `root:root` mode `0700`. It also installs the dedicated, password-locked `ansible-deploy` controller account outside the Docker group. Staging and deployment repeat the read-only mount, capacity, metadata, non-symlink, and device checks and fail if any differ. This keeps large plaintext working archives off the 64 GiB Debian root filesystem while preserving the existing encrypted archive and replica paths. Backup discovery and pruning remain limited to their existing top-level encrypted filename patterns.

During the Debian rollback-retention period, staging and deployment merge the root-owned `/var/lib/home-lab/production-image-override.json` captured by the production cutover. This preserves the exact transferred image IDs, disables staging pulls, and prevents unrelated image recreation. The first deployment accepts only the pinned legacy `current` symlink target, materializes and hash-verifies it as `previous`, then converts `current` to the normal directory-backed artifact layout before converging reviewed services.

## Cutover boundary

Staging may populate hash-addressed artifacts and inactive root-only candidate environment files. It never overwrites the active `/etc/docker-compose/production.env`, synchronizes an artifact into `current`, changes runtime Compose labels, pulls images, or converges containers.

The Phase 4 cutover used a temporary, fail-closed workflow requiring the protected environment, exact staged artifact, typed confirmation, and a zero-change audit. It copied the immutable artifact into the previously empty `current` directory and converged the exact 16 reviewed recreations without pulls, builds, removals, orphan removal, or volume operations.

That one-time cutover workflow and role were retired after successful adoption. The ongoing rollback workflow operates only on the hash-verified `current` and `previous` artifacts and requires their root-only environments to have the same private SHA-256 identity; an environment change requires a separate recovery plan. It requires distinct exact artifact hashes, typed confirmation, protected-environment approval, a deterministic private plan hash reproduced immediately before apply, an unchanged 41-service set, and zero create/removal actions. Docker converges only the reviewed services against a root-only normalized target with `--no-build --pull never --no-deps` while `current` remains unchanged and retryable. After idempotence is proved, GNU `mv --exchange` atomically swaps the two artifact directories. A plan-only mode uses typed `plan-rollback:<current>:to:<target>` confirmation and never converges or exchanges artifacts. Failures retain the production lock; there is no automatic stateful rollback.

## Completed initial cutover

The first authorized attempt, run [`30853421473`](https://github.com/soodoh/home-lab/actions/runs/30853421473), stopped immediately after creating the production lock because its owner metadata referenced an unavailable Ansible variable. It executed no Docker command. Independent audit [`30853571318`](https://github.com/soodoh/home-lab/actions/runs/30853571318) then reported `ok=45 changed=0 unreachable=0 failed=0`. The empty lock remained fail-closed until separately authorized clearance run [`30853977059`](https://github.com/soodoh/home-lab/actions/runs/30853977059) inspected and removed only that directory.

Authorized retry [`30854028095`](https://github.com/soodoh/home-lab/actions/runs/30854028095) deployed artifact `533ed4a14fce8a811a41ff0a3fe5e6b182fe485f965499d80d8f0c27cf79b357`:

- pre-cutover audit: `ok=45 changed=0 unreachable=0 failed=0`;
- exact plan: `ok=22 changed=1 unreachable=0 failed=0`, with the expected 16 recreations and zero forbidden create/remove actions;
- cutover and health verification: `ok=35 changed=3 unreachable=0 failed=0`;
- post-cutover action plan: no further convergence proposed;
- post-cutover audit: `ok=45 changed=0 unreachable=0 failed=0`.

The initial cutover, failed-lock clearance, and rollback enable variables were removed after use. `/srv/docker-compose/current` and `/etc/docker-compose/production.env` are active. Ongoing deployments preserve one exact previous artifact and environment for separately approved rollback; the initial legacy-checkout rollback has been retired.

## Protected ongoing deployment

`scripts/local-controller` is the deployment path. It validates and hashes the exact candidate, stores the saved manifest locally, uses separate plan/apply credentials, stages the exact artifact and isolated candidate environment, displays restricted model differences, and produces a hash-locked check-mode deployment plan before activation.

The apply job is independently disabled unless `COMPOSE_AUTO_APPLY_ENABLED=true`. A changed merged plan must still match the current `main` tip and reproduce the deterministic secret-free deployment-plan hash. Deployment refuses service additions/removals, Docker create/remove actions, and `services/data/**` changes that lack an explicit restart decision. It pulls only services whose reviewed image reference changed, preserves current as `previous` plus a root-only previous environment, and rotates the hash-verified artifact. Immediately before convergence it dry-runs the exact dependency-aware `up` command and requires its recreate, start, stop, and complete action service sets to remain within the reviewed recreation set, with no creates or removals. Only then does it converge that exact service set without builds or orphan removal; the post-check uses the same dependency model and must be action-free. No image or volume pruning occurs.

The two exact host-consumed Restic policy files, `services/data/restic/excludes` and `services/data/restic/files-from`, may accompany a reviewed Compose artifact only through `deploy-reviewed-restic-policy:<artifact-hash>` authorization. That lane requires active Restic, terminal Offen retirement, the exact two-file manual-only set, unchanged service membership, and zero create/remove actions; all ordinary recreation guards still apply.

The one-time Calibre local rollback is additionally bound to `rollback-calibre-to-local:<artifact-hash>`. It requires exactly the three Calibre consumers and the two Restic policy files, proves canonical endpoint and filesystem identities, stops both Restic timers, holds the Restic mutex while reconciling NFS into the retained local library with checksum/delete semantics, requires zero-difference and SQLite integrity checks, atomically activates the new Restic policy, and only then permits dependency-aware Compose convergence onto local mounts. An interrupted run may adopt only the exact retained owner and must repeat every data/integrity guard before convergence. The transition completed on 2026-08-27; the NFS source remains intact as rollback input.

Reviewed changes limited to host-executed helper files selected by `scripts/compose-artifact.py` may use the separate `COMPOSE_ARTIFACT_PROMOTION_ENABLED=true` gate, exact candidate hash, and typed `promote-artifact:<hash>` confirmation. Controller-only planning helpers do not alter the artifact identity. This artifact-only lane requires zero image differences, recreations, service-set changes, and forbidden actions; it rotates the artifact and environment but executes no Compose pull or `up` command.

Every apply attempt retains the production lock on failure. Success requires an idempotent post-deployment Compose action plan, all 40 configured services running, healthy Gluetun and Seerr, a zero-change deployment post-check, and a zero-change complete audit. There is no automatic stateful rollback; the tracked previous artifact and unchanged previous environment are recovery inputs for a separately reviewed rollback. A failed pre-apply canary may be retried manually only with the exact candidate hash, typed confirmation for that exact candidate, the same canary-only policy, and `COMPOSE_AUTO_APPLY_ENABLED=true`.

### Host-checkout independence

Active audit, health, Compose preflight, Wolf-file comparison, deployment, and rollback operations all resolve the exact stable artifact with explicit project name, project directory, environment file, and Compose file arguments. The production environment metadata gate requires `root:root 0600`. No workflow runs `git pull` on the server or reads a host checkout. A merge from any machine therefore follows the same GitHub-controlled artifact path.

The Debian production endpoint is `docker-host` with dedicated deployment identity `ansible-deploy`; the `docker` workload account is reserved for interactive administration. Both identities authenticate through Tailscale SSH under the tailnet SSH policy, without conventional `authorized_keys`. Strict SSH host-key checking remains mandatory for the Tailscale SSH endpoint. `infrastructure/evidence/vm-100-debian-ssh-host-key.json` records the guest OpenSSH ED25519 key independently read through Proxmox QGA and remains the trusted key for LAN recovery access.

PR [#219](https://github.com/soodoh/home-lab/pull/219) retired the one-time cutover code, initial legacy rollback, recorded-hash side metadata, and every tracked host-checkout path. It also changed rollback to converge the exact normalized previous model before an atomic artifact exchange, privately binds the plan to both artifact hashes and the unchanged environment hash, and ensures plan-only normalized configuration is passed through standard input rather than written to disk.

Checkout-retirement proof was performed before the repository rename, with `/home/docker/Projects/docker-compose` moved out of the path and replaced temporarily by an empty directory:

- full audit [`30863883940`](https://github.com/soodoh/home-lab/actions/runs/30863883940): `ok=45 changed=0 unreachable=0 failed=0`;
- exact Compose plan [`30863947303`](https://github.com/soodoh/home-lab/actions/runs/30863947303): both plans `ok=24 changed=0 unreachable=0 failed=0`; apply skipped;
- previous-artifact rollback plan [`30864021531`](https://github.com/soodoh/home-lab/actions/runs/30864021531): pre-audit `ok=45 changed=0`, two identical private plan hashes, each `ok=26 changed=1`, unchanged environment identity, zero forbidden actions, and only Flaresolverr in the reviewed recreation set; apply skipped.

The retired checkout and its inactive plaintext `.env` were then removed. Runtime artifacts, root-only environments, images, containers, volumes, and the production lock were unchanged throughout this proof.

### Renovate canary lane

The automatic apply lane is initially restricted to `flaresolverr`, a stateless service without a Compose-managed volume. A candidate is canary-eligible only when all checks agree that:

- the candidate changes exactly `services/servarr.yml`;
- `flaresolverr` is the only image-reference difference;
- `flaresolverr` is the only proposed recreation;
- no stateful service, service-set change, create/remove action, secret file, or `services/data/**` path is involved; and
- the candidate and active artifact identities are exact.

All other Compose changes still produce a protected plan but report zero effective automatic changes, so the apply job cannot start. Renovate Docker updates are ungrouped, have a minimum release age, and default to `automerge: false`; the Flaresolverr package receives the `compose-canary` label and a seven-day release age.

The canary lane was explicitly authorized. Flaresolverr alone may use platform PR automerge, including pinning its readable tag to an immutable digest, but the default-branch ruleset requires the repository's `Hash and copy exact Compose artifact` status first. That unprivileged check now runs on every pull request, so path filtering cannot leave the required status absent. `COMPOSE_AUTO_PLAN_ENABLED=true` stages and plans trusted merged commits; `COMPOSE_AUTO_APPLY_ENABLED=true` permits only candidates that pass the hard-coded canary policy above. No other Renovate or human Compose change can enter the automatic apply block.

### Completed Renovate canary proof

Renovate PR [#214](https://github.com/soodoh/home-lab/pull/214) changed only `services/servarr.yml`, received the `dependencies` and `compose-canary` labels, passed the required deterministic-artifact check, and squash-merged commit `8a5a8166eb905f3a6ff117ab0b945356c6237638`. It pinned only `ghcr.io/flaresolverr/flaresolverr` to digest `sha256:139dfee…`.

The first merge-triggered attempt, run [`30857616854`](https://github.com/soodoh/home-lab/actions/runs/30857616854), failed closed while revalidating the plan because it compared the complete Ansible logs, which contain nondeterministic output. The deployment step and both post-apply steps were skipped. `COMPOSE_AUTO_APPLY_ENABLED` was immediately removed, and no pull, lock acquisition, artifact rotation, or container recreation occurred. PR [#216](https://github.com/soodoh/home-lab/pull/216) replaced the full-log identity with a SHA-256 over the canonical secret-free deployment-plan object and added an immediate second check-mode plan; runs [`30859720774`](https://github.com/soodoh/home-lab/actions/runs/30859720774) and [`30859890365`](https://github.com/soodoh/home-lab/actions/runs/30859890365) reproduced that identity while apply remained disabled.

After PR [#217](https://github.com/soodoh/home-lab/pull/217) added the exact-hash and typed-confirmation retry path, authorized run [`30859967393`](https://github.com/soodoh/home-lab/actions/runs/30859967393) deployed artifact `199f446bc918683947c844217bbf0efe927155e46c606e1ddf6fbfd511c03ea2`:

- the initial plan, immediate repeated plan, and protected apply revalidation each reported `ok=25 changed=1 unreachable=0 failed=0` and the same deterministic plan identity;
- the guarded model reported only the Flaresolverr image reference and recreation, no stateful recreation, and no service-set, create/remove, secret, or data-file change;
- deployment and health verification reported `ok=45 changed=9 unreachable=0 failed=0`;
- the post-deployment plan reported `ok=25 changed=0 unreachable=0 failed=0`;
- the complete post-deployment audit reported `ok=45 changed=0 unreachable=0 failed=0`.

All 41 services remained running, Gluetun and Seerr remained healthy, and the former active artifact `533ed4a14fce8a811a41ff0a3fe5e6b182fe485f965499d80d8f0c27cf79b357` is retained as the previous rollback input. `COMPOSE_AUTO_PLAN_ENABLED=true` and `COMPOSE_AUTO_APPLY_ENABLED=true` now leave the proven lane active, but the hard-coded Flaresolverr-only policy remains the authorization boundary; every non-canary change stays plan-only.
