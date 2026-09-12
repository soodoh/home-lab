# Attended LiteLLM config-only deployment

This is a dedicated application operation, **not** adoption or invocation of the deferred controller. [Ordinary Compose deployment](compose-deployment.md) keeps its existing manual-data guard. The [operator command](../scripts/litellm-deployment.py) and [dedicated playbook](../ansible/playbooks/deploy-litellm.yml) admit only a change to `services/data/litellm/config.yaml`. File equality is refused as unnecessary deployment, not reported as process adoption.

## Authority and commands

Use reviewed, clean, published `main`; the command compares local `HEAD` with `origin/main` but does not fetch or certify remote publication. Establish publication and the quiet operational window separately. Have independent recovery access and exclude other administrators, queued work and recovery operations throughout. Use an existing mode-0700 private directory, with mode-0600 JSON inputs. No source/test fixture is a live observation.

All commands below use the existing Python executable. `request`, `approval-template`, and `plan` are offline and load no administrative credentials:

```sh
python3 -I -B scripts/litellm-deployment.py request --known-hosts /absolute/pre-established/known-hosts --output /private/run/request.json
python3 -I -B scripts/litellm-deployment.py approval-template --input /private/run/request.json --output /private/run/capture-approval-template.json
```

The owner must separately approve the **exact JSON template**, through an attended operator or the approval-file harness, before supplying it as `/private/run/capture-approved.json`. Generating a template or knowing its digest is not permission. Approval names operation, whole-document digest, source commit and artifact hash. A genuine terminal can instead require typing the entire confirmation; no forged TTY is needed.

```sh
python3 -I -B scripts/litellm-deployment.py capture --request /private/run/request.json --approval-file /private/run/capture-approved.json --known-hosts /absolute/pre-established/known-hosts --output /private/run/capture.json
python3 -I -B scripts/litellm-deployment.py plan --capture /private/run/capture.json --output /private/run/plan.json
python3 -I -B scripts/litellm-deployment.py approval-template --input /private/run/plan.json --output /private/run/apply-approval-template.json
```

Capture honestly uses **admin-capable `ansible-deploy` via existing Tailscale SSH**, not `ansible-plan` or imaginary read-only credentials. It checks Docker's running systemd state before Docker access. It writes a retained protected Ansible transport workspace and a one-shot capture-attempt record, holds existing native descriptor locks, and runs bounded inspection, resolved Compose configuration/dry-run and container-local passive liveness. It neither publishes a production owner nor stages a candidate, decrypts secrets, installs helpers or changes containers. Strict existing production inventory host-key policy remains; the known-hosts bytes are bound into the request.

Review the complete private plan and its effects. Separate **apply** approval is mandatory:

```sh
python3 -I -B scripts/litellm-deployment.py apply --plan /private/run/plan.json --approval-file /private/run/apply-approved.json --known-hosts /absolute/pre-established/known-hosts --output /private/run/result.json
```

The request expires 30 minutes after creation; it is not a lease. Stale/partial observations require a newly approved capture, never rewritten timestamps. Each capture/apply consumes a local attempt before privileged transport and a distinct host nonce attempt. Before scheduling any host (including implicit fact gathering under task selection), Ansible's target expression rechecks clean source, the prepared attempt, approved known-hosts bytes and the effective fixed SSH/sudo transport, including connection arguments and aliases. Successful target admission is read-only and returns only `docker-host-production`; rejection raises and retains a bounded private rejection receipt. Fixed play transport variables override inventory settings, while contradictory extra-vars refuse. Every remote action also requires a fresh ordered one-shot admission receipt bound to its actual content/destination or argv. Module arguments are returned directly by that validated phase, not by overrideable workspace/argv/output variables. Those legacy effect overrides refuse. Fact modules are explicitly empty, including if Ansible replays its setup task under `--start-at-task`. SSH connection multiplexing is disabled. Known-hosts paths must be absolute and contain only letters, digits, `_`, `.`, `/` and `-`; altered transport settings refuse even with a prepared bundle. Direct playbook invocation supplies no Boolean bypass. There are no SSH retries, helper installations, provider credential loaders or implicit fallback identities.

## Native guards and admitted effects

The host must already have the declared state mount, root-protected current/previous artifacts and environments, both locally available retained image sets, installed image-ID override, existing Restic `root:restic-proton 0660` mutex, running Docker, Python/PyYAML, compatible Compose `config --hash`/dry-run and the existing Ansible/sudo/Tailscale route. Missing prerequisites refuse; source fixtures do not qualify these native behaviors.

Every Docker/Compose call explicitly selects `unix:///var/run/docker.sock`, uses an empty CLI configuration directory retained inside its protected workspace and a sanitized environment rather than `/home/docker`'s context. The dispatcher reads the existing `ansible-playbook` absolute Python shebang and launches that same interpreter with `-I -B` and `PYTHONNOUSERSITE=1`; unsupported launchers refuse without a fallback or installation. Python entrypoints and the container probe use `-I -B`: system dependencies remain available, but user-site, current-directory and `PYTHONPATH` startup imports are excluded. Existing system-installed Docker CLI/Compose and PyYAML must already work under these constraints.

The controller validates the complete prepared file set, modes and exact collector/contract/artifact/envelope bytes through no-follow directory/file descriptors. A bounded base64 representation is handed directly to Ansible `copy.content`, never independently reread from a mutable source pathname. The deterministic `/var/lib/docker-compose/.litellm-<document-sha256>` namespace is exclusively created; a collision refuses. The reviewed inline pre-execution program receives the independently validated payload digest in its bound argv, reads and verifies one buffer before parsing/extraction, and executes those same main/helper byte buffers without filesystem import fallback. No transferred verifier authenticates itself. Duplicate keys/files, unexpected paths/modes, links and oversized inputs refuse. Total encoded transport and decoded file bytes are each capped at 8 MiB, with at most 4,096 entries. The controller checkout and installed isolated interpreters remain trusted execution inputs; quarantine payload paths are not code authority.

Discovery refuses incrementally above 4,096 artifact entries, depth 16, 8 MiB per file or 64 MiB per artifact; token data is limited to 1,000 entries, depth 16, 1 MiB per file and 16 MiB total. Command stdout/stderr together are drained with a 16 MiB ceiling and a timeout, not accumulated without limits. Overflow is a failed/unknown attempt, never permission to truncate evidence or continue.

Directory-backed `current` is normal. The deterministic [artifact selection/hash](../scripts/compose-artifact.py) is unchanged; this operation additionally checks file modes, rejects linked/special/unselected artifact files, and compares the entire exact delta. The installed override must contain only image-ID selections agreeing with actual containers. It is preserved, not regenerated. The [committed retention lock](../infrastructure/debian/production-image-lock.json) associates the unchanged LiteLLM 1.94.0 reference with its accepted image ID; literal `Config.Image` need not equal the public pinned reference. This association is not OCI/source-byte certification. The complete previous service set is independently resolved from `previous` with unchanged `previous.env`, **without** the current override. Every previous lock entry must bind its declared image to the locally inspected retained ID; immutable IDs/RepoDigests establish exact associations without depending on a moved mutable tag. Missing or ambiguous bindings refuse without pulling, retagging or changing recovery inputs.

Before mutation, under the existing backup/native descriptor exclusion and newly owned production marker, recheck the exact captured host/boot, artifact, model, runtime environment/startup, image, network, token-tree and recovery identities. Only the config path may differ. Other service identities must remain unchanged. Admission explicitly accounts for Jellyfin's source-less tmpfs (including size/mode), Nextcloud's existing file-secret bind paths without reading/materializing their contents, and Wolf's image-declared anonymous volume with its local volume identity. Only a verified Docker-generated ID-prefix hostname is separated from invariant configuration during recreation; explicit hostnames and all unrelated container identities remain guarded. Declaration-backed host-network containers instead retain the verified host hostname as invariant configuration. No current/previous secret refresh, decryption, image pull/tag/build/prune, database migration, controller or host-infrastructure operation is invoked.

Apply retains the older `previous` and `previous.env` **untouched**. It preserves `current`, active/previous env files, image locks, override, old artifact marker and private plan under exclusive `/srv/docker-compose/.litellm-<plan-sha256>/`, publishes a verified incoming directory as `current`, updates its artifact marker and executes exactly:

```text
[explicit existing Compose project/env/current/override arguments]
up --detach --no-build --pull never --no-deps --force-recreate litellm
```

Only LiteLLM has planned downtime/session loss. Bind-file content is invisible to ordinary Compose model differences, so recreation is explicit even when the model hash is unchanged. Token contents are hashed privately, never exported; no token file is written by the transaction. Unexpected application-generated token changes fail postchecks rather than being silently accepted or undone.

## Adoption, stability and recovery

Verification is intentionally **startup-file-read adoption plus liveness**, not model inventory, every YAML field's semantics, readiness or external provider functionality. It uses the accepted pinned startup path, exact stable mounted config/callback bytes and effective startup selectors, a newly identified container/serving process, and one container-local `/health/liveliness` request per observation. No model/provider request or metadata-enrichment endpoint is used.

The probe requires exactly one listening process with the ordinary LiteLLM CLI arguments, installed version 1.94.0 and explicit `LITELLM_MODE=PRODUCTION`; alternate config/cloud/DB/worker selectors, includes, dynamic config keys and development dotenv loading are not admitted. It permits only the existing callback/settings shape. Native process/environment shape remains a real capture prerequisite, not a source-test receipt. Startup waits once for 20 seconds, then checks again after 10 seconds for stable identities, unchanged inputs and zero restart count. LiteLLM can ignore invalid model deployments during startup: these checks do **not** certify provider/model usability.

Result protection occurs only in the local dispatcher, never a delegated Ansible task inheriting production connection variables. It reserves an exclusive mode-0600 output descriptor, creates/pins a private incoming directory, and uses bounded no-follow reads plus descriptor-based metadata/permission checks to protect and validate the fetched result's exact operation binding. Only that validated byte buffer is written to the reserved descriptor; substituted output/directory identities refuse. Existing evidence is never overwritten.

Any stale state, failed command, failed liveness/adoption, changed unrelated container or lost connection is a failed/unknown **one-shot attempt**. Delivery failure does not establish host failure: the host may have completed and released its owner before the result was lost. Retain transport/delivery evidence and inspect actual host/process/ownership and recovery inputs; do not retry, adopt or clear ownership, overwrite evidence, prune recovery, or automatically compensate. On success only the exact owned marker is released, while recovery inputs remain. A failure after artifact publication can leave new files and old/failed process state; the artifact marker is not a success receipt. Recovery requires a new attended decision and exact current observations; this command deliberately has no rollback/resume lane.

Offline tests substitute external OS/Docker/Ansible effects at the operator and guarded-transaction seams; they neither run Ansible against a host nor qualify its native execution:

```sh
LITELLM_TEST_SCRATCH=/private/mode-0700-tests python3 -I -B -S scripts/test-litellm-deployment.py
```

Test directories are exclusively created and retained. Separately authorized, opt-in `LITELLM_TEST_ANSIBLE=1` cases exercise real installed Ansible task/target selection using a private inert connection plugin and no host transport; they do not qualify a successful native production invocation. Source review, installed prerequisites, operational approval and deployed verification are separate acceptance states.
