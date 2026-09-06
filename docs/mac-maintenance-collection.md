# Existing Mac: read-only maintenance collection

Status: **repository implementation; installation, publication trust and live qualification gated**. This does not complete host-lifecycle acceptance. Current ADR applies: no automatic metadata refresh, package installation, reboot, enrollment, recovery or failed-qualification retry. VM100, disks, production state, backup/rollback receipts and credentials are not rehearsal inputs.

## Boundaries

- `scripts/maintenance-launcher.py` is a standard-library bootstrap, copied as reviewed bytes **outside** the checkout. LaunchAgent executes a pinned absolute Python with `-I`; the launcher verifies its own hash, pinned real Node/Python binaries, protected config, clean exact reviewed commit, contract/inventory hashes and executable dependency blobs **before** executing repository code. Git status alone is insufficient: the executable closure is compared directly with committed blobs, preventing clean-filter/skip-worktree substitution. Never point the agent at a PR checkout or auto-update its approved commit.
- Config, known-hosts, attestations and local inputs are canonical JSON (where applicable), single-link regular files, mode 0600; output/input directories are 0700. Paths are absolute, with no symlink or untrusted writable ancestors. Root-owned sticky temporary ancestors are allowed for isolated tests; production setup belongs in protected controller storage, not `/tmp`. Node/Python paths must be real regular executables, not version-manager symlinks. These are cooperating trusted-user/root boundaries, not protection against a compromised controller owner or root.
- `controller-apply-lock.py` acquires/retains the actual shared controller descriptor lock. The launcher verifies inherited FD/token ownership; it never treats PID text or an existing lock file as a held lock and never unlinks it. The executable closure now binds `scripts/controller/controller_lock.py`, which the runner compiles directly from reviewed source instead of importing ignored bytecode. A real unchecked-hash cache regression exercises this boundary. This collection path grants no new host mutation or rollback authority.
- Each host collection is one fixed command with a 120-second controller deadline and 1 MiB combined stdout/stderr bound. Child stderr is never forwarded. No retries, shell, SSH config, agent, conventional-key/password fallback, environment credentials, generic sudo, Ansible deploy, or host credentials in GitHub. The report is not a host lock lease or a saved mutation plan.

## Capability paths and exact wire

Preferred new account: `ansible-maintenance-plan@proxmox` or `ansible-maintenance-plan@docker-host`. The **only** remote command is:

```
observe <nonce64hex> <reviewed-commit40hex> <contract-sha25664hex>
```

Parent owns the reserved producer/transport/role and attended installation. This lane does not install them. The root-owned installed policy independently binds host machine identity and exact producer/package/transport bytes; requested source/contract must match that policy, not merely be echoed. Canonical JSON plus newline, at most 1 MiB:

```json
{"format":"home-lab-maintenance-observation-v1","host":"debian","nonce":"<64hex>","source_commit":"<40hex>","contract_sha256":"<64hex>","observed_at":"<UTC-seconds>","producer_sha256":"<64hex>","package_sha256":"<64hex>","transport_sha256":"<64hex>","package":{"proposal":"<existing exact v2 package proposal object>"},"reboot":{"required":null,"backup_proven":false},"active_locks":[],"authorized":false,"automatic_apply":false,"automatic_reboot":false,"automatic_retry_allowed":false}
```

The displayed JSON is explanatory; actual JSON is key-sorted and `proposal` is an object. Controller requires request-start <= original package timestamp <= wire completion timestamp <= controller-finish, total <=120 seconds; it never rewrites either timestamp. Strict SSH known-host bytes independently match the configured ED25519 fingerprint. Nonce, host, source, contract and installed producer hash must match exactly. All nonempty/unknown lock observations reject the whole host collection. `required:null` is explicitly unknown, not a clean reboot observation. `backup_proven` must be false; a reporting observation cannot prove reboot admission.

Each configured challenge capability names `known_hosts`, a protected `attestation`, and the protected mode-0755 `package_artifact` containing the independently reviewed rendered package observer bytes. The latter is canonical `home-lab-maintenance-challenge-installation-v1` with exactly:

- `source_commit`, `contract_sha256`, `host`, `host_key_fingerprint`;
- `observed_at`, `expires_at` (fresh, no future observation, at most 24 hours);
- `producer_sha256`, `package_sha256`, `transport_sha256`, `audit_sha256`;
- `complete_audit:true`, `active_locks:[]`.

All three wire component hashes must match the protected installation evidence. Producer/transport hashes must also match reviewed repository bytes; package hash must match the protected reviewed rendered artifact. The parent producer independently checks all three installed bytes through root-owned policy. The full audit and installed-policy inspection are separate protected evidence, not report-generated assertions. Changing source requires a separately reviewed policy/capability update, not automatic installation. A missing/stale attestation is a setup failure, never permission to use another identity.

**No automatic attestation/audit renewal exists in this candidate.** Neither fixed observation command performs a complete host audit or renews the <=24-hour installation/audit receipt. The Mac schedule therefore fails closed after those prerequisites expire; a one-time installation receipt is not a complete autonomous schedule. Parent must integrate a fixed, non-authorizing fresh-audit renewal capability, or separately decide to distinguish enduring installation identity from informational audit staleness. Until that reviewed integration, renewal is attended and this remains a setup-gated source candidate.

An explicit `null` challenge config permits only the legacy Proxmox `ansible-plan@proxmox observe-package` path, requiring fresh `home-lab-maintenance-capability-attestation-v1` bound to source/contract/host/key, exact producer/transport/audit hashes, 17 domains, parity true, changed zero and no active locks. Its provenance is **attestation-only**, not challenge-verified. Its fields are enforced in `capability()`. Legacy Debian/package and both reboot paths produce `capability-unavailable`; generic `packages-plan.yml` become/Python is forbidden. Configured challenge failure never falls back to legacy.

## Setup / installer dry run — no installation performed here

1. Review a clean committed source and the producer/transport/identity installation independently. Prepare verified host keys and fresh complete-audit/installation attestations. Do not reuse guest or production credentials in a test VM.
2. Through an attended local setup, copy exact reviewed launcher bytes to protected controller storage outside the repository, mode 0755. Record that hash and the actual Node/Python executable hashes in a protected canonical copy of `infrastructure/maintenance/mac/controller.example.json`. Its sentinel paths/digests deliberately cannot run. Pin the real inventory/contract hashes and reviewed commit. Inputs/receipts directories must already exist at 0700. No token is a config field.
3. Installer dry-run path (checks protected config/source; prints plist only):

   ```sh
   /ABSOLUTE/REVIEWED/python3 -I /PROTECTED/maintenance-launcher.py --config /PROTECTED/controller.json --dry-run
   ```

   It neither writes a LaunchAgent nor calls launchctl, contacts a host, loads credentials or creates a lock. The template schedules daily at 06:17 local Mac time. No KeepAlive, RunAtLoad or retry loop. Operator must separately review/install the rendered plist; that action was not performed in this lane.
4. Only after capability/trust setup, `--collect` takes the shared controller lock and makes the fixed read-only observations. Each new schedule is a new read-only observation, never a retry of any failed qualification or mutation. Attestation expiration stops collection until reviewed evidence is renewed.

Sleeping/offline Macs do not produce fresh evidence. Original input times survive aggregation; the publisher recomputes stale state from its own consumption clock. A signed report expires in at most 24h. Scheduled publication is **not enabled** here, so no claim is made that an existing issue changes while the Mac is asleep; issue automation must later consume/re-evaluate the last authenticated report or publish an explicit missing heartbeat. Timestamp-free stable issue content is for dedup, not evidence freshness authority.

## Aggregation and retained receipts

`maintenance-report.js` aggregates ten bounded host/topic slots: package, reboot, release, pins and migrations for Debian/Proxmox, plus at most twenty major-migration entries per host. Every input binds source, contract, host/key, original timestamps, payload hash, evidence hash and provenance. The launcher retains exact validated challenge wires and package candidates privately as content-addressed mode-0600 files, plus started/finished attempts and failed input receipts. Unknown/raw diagnostics never cross the public boundary. Invalid input hashes remain visible but raw malicious values do not. No receipt is overwritten or automatically purged; a 5,000-file budget fails closed for attended retention review. An unmatched started attempt means interrupted/unfinished, not success.

The package bridge independently validates the existing v2 proposal and reconstructs the exact existing candidate lock. Wrong candidate digest, inventory/host/source/contract mismatch, unknown fields and secret-like values are refused. Metadata age is recomputed from original mtime; stale metadata remains `apt-metadata-stale`, never an APT refresh trigger. Full candidate content stays private; public summaries contain only bounded counts, hashes and booleans. `complete` means fresh slot coverage, not readiness. Every authorization, automatic apply/reboot/retry field is false, including healthy/unknown/failed states.

Local release/pin/migration inputs are read from six exact `<host>-<topic>.json` paths under the protected inputs directory. Missing files remain missing, invalid files become failed receipts, and expired inputs are never restamped. `maintenance-local-inputs.js` is an offline adapter for the existing dashboard/release outputs plus source/contract/time-bound migration descriptors `{major,issue_number}` (no titles, URLs or bodies). It emits the six strict envelopes; a separately reviewed local preparer writes them to the protected paths. Release input source hashes/age, pin coverage/hash and each migration major remain in the aggregate. Raw GitHub workflow artifacts are **not** trusted local preparer inputs.

Both existing GitHub workflows remain credential-free artifact-only jobs. The coverage dashboard now explicitly reports missing host collection and prohibits workflow-artifact promotion. It is not relabeled as fresh host data. Fixed fixture suites run before artifact upload.

## Separate publication boundary — narrow explicit setup gate

`maintenance-publish.js --trust <protected-json> --input <bounded-json>` verifies an Ed25519 signature against an independently protected public key and emits **offline issue requests only**. It contains no network/gh/token/signing client and cannot send them. It must run separately from the host collector. Trust config has exactly `repository` (`soodoh/home-lab`), `source_commit`, `contract_sha256`, `public_key_pem`, `public_key_sha256`.

Input contains `report`, `registry`, `provenance`, `signature`. The detached base64 signature covers canonical provenance with exactly format `home-lab-maintenance-publication-provenance-v1`, repository/source/contract, `issued_at`/`expires_at` (<=24h), `collector:"existing-mac"`, `workflow_artifact:false`, SHA-256 of the full report bytes, SHA-256 of registry bytes. Registry is at most fifty `{dedup_key,issue_number,content_sha256}` entries. It must come from the same authenticated publication authority, not user issue text. Signature is verified before consumption; report hash/shape/flags are independently revalidated. Repository/event strings without a valid pinned signature confer no trust. PR/workflow artifact promotion is refused even if signed with `workflow_artifact:true`.

The planner emits bounded fixed `POST /repos/soodoh/home-lab/issues` or `PATCH /repos/soodoh/home-lab/issues/<positive-integer>` requests with generated titles/bodies only. No caller-supplied argv, path, markdown, mentions, links or issue body is forwarded. Keys hash fixed repository/host/topic identities; major OS migrations include target major. Same key updates the same registered issue; identical semantic content emits no request. New keys must be registered after a confirmed single creation; ambiguous send is a manual reconciliation gate, never an automatic retry. Stale source suppresses old candidate values.

**Remaining setup choice/gate:** parent must select/provision a reviewed signing identity and a separate issues-only publisher token/runner, protect approved revisions, and durably authenticate/update the issue registry and heartbeat. Neither signing keys nor tokens are created/read here. No issue-write workflow, untrusted workflow-run artifact handoff or live sending is enabled. This source candidate is not operational publication completion.

## Focused suites and parent integration

```sh
node scripts/controller/test-maintenance-report.js
node scripts/controller/test-maintenance-publish.js
node scripts/controller/test-maintenance-local-inputs.js
PYTHONDONTWRITEBYTECODE=1 python3 scripts/controller/test-maintenance-launcher.py
node scripts/controller/test-maintenance-dashboard.js
node scripts/controller/test-release-eol-report.js
```

Python fixtures exercise mocked fixed SSH for both hosts, wrong nonce/source/contract/host/producer/time/locks/authority, unknown reboot, strict files, deadlines/output bounds, partial failures, retention, dry-run, reviewed executable blobs and the real inherited controller-lock runner on a temporary repository. JS fixtures cover fresh/missing/stale/invalid/partial inputs, existing candidate hashes, malicious/oversized input, deterministic migration keys, signed provenance, signed-registry dedup and stale consumption. None is a live qualification claim.

Parent authoritative validation now registers the report, local-input, publication, launcher and read-only capability suites, alongside descriptor-lock and explicit controller-generation tests. The combined Nix-free entry point passes in the parent checkout. Installation/qualification of Debian/PVE capabilities, policy renewal, local input preparation, signing, issues-only sending and durable registry/heartbeat setup remain parent-owned operational gates; passing source tests does not enable them.
