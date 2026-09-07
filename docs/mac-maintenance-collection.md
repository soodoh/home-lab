# Mac maintenance reporting: ordinary advisories

Status: **offline presentation implemented for optional manual use; collection installation, scheduling, issue sending and missed-report monitoring are deferred—not migration or acceptance blockers**. Daily collection is not a requirement. No replacement collector profile is being implemented; resuming reporting automation requires a separate decision. [ADR 0002](adr/0002-advisory-maintenance-reporting.md) supersedes the selected high-assurance reporting design only. [ADR 0001](adr/0001-ansible-host-lifecycle.md) still governs mutation/recovery. No report authorizes deployment, metadata refresh, package installation, reboot, enrollment, recovery, credential/ownership changes or failed-qualification retry. VM 100, protected disks, production state, backups/rollback receipts and credentials are not rehearsal inputs.

## Useful offline interface

`scripts/controller/maintenance-advisory.js` exports `renderAdvisory(report, now)` returning fixed human-readable text. `report` is an existing parsed `home-lab-maintenance-collection-v1` report or explicit `null`; `now` is ordinary UTC at seconds precision (`YYYY-MM-DDTHH:mm:ssZ`), defaulting to OS time. Deterministic tests inject `now`. The CLI reads canonical JSON plus newline on stdin (the existing report serialization), with no arguments:

```sh
node scripts/controller/maintenance-advisory.js < /PATH/TO/LOCAL/collection.json
printf 'null\n' | node scripts/controller/maintenance-advisory.js
```

These examples only render local input. The command uses standard-library dependencies; no credentials, host commands, network, writes, signing/registry clients or live sender. Input is bounded to 256 KiB. Malformed, noncanonical (including duplicate keys), oversized or structurally invalid input is rejected with the constant `maintenance advisory input rejected` diagnostic and CLI exit 65. The API throws the same constant error without raw exceptions/input. Missing input must be explicit `null`, not an empty stream.

The existing report validator checks shape, self-hash and false action flags; its signed publication planner is **not executed**. The hash is structural integrity plumbing, not authenticated source authority. Only fixed labels, bounded numbers, checked booleans and timestamps are displayed, not private payloads, hashes, free-form strings, markdown, URLs or exception messages. Ten host/topic lines show package counts, reboot observations, release comparison, pin coverage and migration counts. Individual migration issue references and raw versions are deliberately omitted.

### Status and time meanings

- **needs-review / observation-only:** a current, usable observation, never host health or authorization. Zero upgrades are not a complete health claim. A reboot-required=false observation does not admit a reboot; backup remains unknown.
- **unknown:** missing/null, failed, invalid, incomplete, stale or future data. Partial reports retain useful current topics but cannot promote missing topics. Partial pin coverage and unknown reboot information stay unknown; candidate values are suppressed for unavailable topics.
- Generated OS time and original report aggregation time are distinct from each topic's original observed/expiry times. All are labelled; original times survive stale display. Freshness is reevaluated at every read, including exact expiry (unknown), future observations/visible clock rollback and package metadata age. Re-rendering an old success does not renew it. Report expiry also suppresses all candidates.

Existing at-most-24-hour bounds are display-freshness heuristics using ordinary OS-managed UTC, not a requirement to collect daily. It is acceptable to have no current report; the display remains unknown rather than blocking the migration. The owner accepts platform/time trust: no protection against compromised owner/root, adversarial clock freezing or malicious storage rollback. Ordinary clock rollback that puts observations in the future makes them unknown; this is not a durable anti-rollback service.

## Existing collection path: unchanged and setup-gated

This slice does **not** replace collectors, launchers, report/wire formats or their admission/expiry checks. In particular, it does not accept expired attestations. The old selected daily COMPLETE-AUDIT renewal requirement is superseded as a *target reporting requirement*, not bypassed in existing code. A separately reviewed installation-identity/read-only collection design must precede replacement. Full audits required for mutation/recovery remain unchanged.

Important current runtime boundaries:

- `scripts/maintenance-launcher.py` is copied as reviewed bytes outside the checkout. LaunchAgent invokes pinned absolute Python with `-I`; the launcher verifies itself, real Node/Python binaries, protected config, a clean exact reviewed commit, contract/inventory hashes and executable dependency blobs before repository execution. Never point it at a PR checkout or auto-update the approved commit; Git status alone is insufficient. Real binaries, not version-manager symlinks, are required.
- Protected config, known-hosts, attestations and local inputs are canonical JSON where applicable, single-link regular files at 0600; input/output directories are 0700. Use absolute paths without symlinks or untrusted writable ancestors. Root-owned sticky temporary ancestors are a fixture exception, not a production storage recommendation. These are trusted-user/root boundaries, not compromised-owner protection.
- `controller-apply-lock.py` retains the actual shared descriptor lock; inherited FD/token ownership is checked. PID text or a lock file is not a lease; the lock is never unlinked. The reviewed lock-source bytes are used instead of ignored bytecode. Reporting grants no host mutation/rollback authority.
- Each host observation is one fixed read-only command, a 120-second controller deadline and a 1 MiB combined output bound. Child stderr is not forwarded. No shell, automatic retries, SSH config/agent, conventional-key/password fallback, environment credentials, generic sudo or Ansible deploy. Host credentials stay on the Mac, never GitHub.

Preferred challenge accounts are `ansible-maintenance-plan@proxmox` and `ansible-maintenance-plan@docker-host`; the sole remote command is `observe <nonce64hex> <reviewed-commit40hex> <contract-sha25664hex>`. The root-owned installed policy independently binds host identity and exact producer/package/transport bytes. Strict known-host bytes must match the configured ED25519 fingerprint. Host/source/contract/nonce/hash mismatches or nonempty/unknown locks reject collection. Original package time must lie between request start and wire completion, completion no later than controller finish, all within 120 seconds. `required:null` is unknown and `backup_proven` must be false.

Configured challenge capabilities require protected known-hosts, fresh installation/audit attestation (no future timestamp, at most 24 hours), and the reviewed rendered mode-0755 package artifact. Evidence binds source/contract/host/key, producer/package/transport/audit hashes, complete audit and empty active locks; requested strings alone are insufficient. Repository producer/transport bytes and the reviewed rendered package artifact must match. Changing source requires separate review, not automatic installation. No automatic attestation renewal exists; expiration stops the old schedule until reviewed evidence is renewed. A one-time receipt does not enable autonomous daily collection.

Explicit null challenge configuration permits only legacy Proxmox `ansible-plan@proxmox observe-package`, with its fresh source/contract/host/key-bound capability attestation, exact producer/transport/audit hashes, 17-domain parity, zero changes and no locks. Its provenance remains attestation-only. Legacy Debian/package and both reboot paths are unavailable; configured challenge failure never falls back to legacy or generic become/Python package planning.

### Future installation work — deferred, not performed here

The following is reference guidance only if collection is resumed, not a current task list. An attended operator must independently review clean committed source, host keys, producer/transport/identity installation and required fresh evidence. Copy reviewed launcher bytes to protected controller storage at 0755; pin launcher/runtime binaries, commit and inventory/contract hashes in a protected canonical copy of `infrastructure/maintenance/mac/controller.example.json`. Sentinel example paths/digests cannot run. Prepare protected inputs/receipts directories; tokens are not config fields. Do not reuse production credentials in a test VM.

The legacy launcher `--dry-run` with a protected `--config` checks config/source and prints a plist only: no launchctl, host contact, credentials, lock or installation. Its template is daily 06:17 local Mac time, without KeepAlive, RunAtLoad or retry loop. Plist installation is separately reviewed work. Only after capability setup does `--collect` take the shared lock and issue fixed observations. Each schedule is a new read-only check, never a retry of a failed qualification/mutation. No installation/dry-run/collection commands were executed for this source slice.

## Existing inputs and attempts

`maintenance-report.js` still aggregates package/reboot/release/pins/migrations for Debian and Proxmox, with up to twenty individual migrations per host. Source/contract/host/key, original times, hashes and provenance are bound in existing inputs. Package bridging validates the existing v2 proposal and exact candidate lock; full candidates stay private. Stale metadata never triggers refresh. `complete` describes slot coverage, not readiness; every action flag remains false.

The launcher retains exact validated wires/candidates privately as content-addressed 0600 files, plus started/finished attempts and failed receipts. An unmatched start is interrupted/unfinished, not success. Files are not overwritten or automatically purged; the 5,000-file budget requires attended retention review. Invalid hashes may exist in reports, but raw diagnostics must not cross the public boundary.

Six exact `<host>-<topic>.json` local release/pins/migrations files are prepared separately in the protected input directory. `maintenance-local-inputs.js` is an offline adapter, not a scheduled preparer. Missing files remain missing, invalid files become failed receipts and expired inputs are not restamped. Raw GitHub workflow artifacts are not trusted preparer/host inputs. Existing weekly release/EOL and monthly coverage workflows remain credential-free, artifact-only; missing host collection is not relabelled as fresh host data.

## Deferred automation — not migration blockers

The old `maintenance-publish.js` signed offline issue planner and `maintenance-publication-state.js` synthetic in-memory trace model remain unchanged historical/offline alternatives. The advisory uses only the planner module's structural `verifyReport` function. Neither signed planning nor model execution is required or invoked. Old code still enforces its own signatures, trusted registry, expiry and synthetic time/intent rules; it has no live sender. Synthetic fixtures are not operational receipts.

ADR 0002 drops Roughtime/qualified `[L,U]` time, separate signing custody/purpose keys, authenticated CAS/append-only journals/Object Lock, durable time floors, retained publication intents and exactly-once delivery as reporting requirements. They are not hidden setup blockers for this advisory.

If separately resumed, best-effort publication can update a known issue with a stable key and least-privilege issues-only token, isolated from host credentials. Duplicates, ambiguous sends and lost updates are ordinary reconciliation problems, not permanent global publication locks. No sender, token, provider, issue, registry service or schedule is selected/provisioned here.

If scheduling is resumed, preserve scheduled-check attempts separately from the last successful collection. A failed/missed check must not restamp the old success; display its original deadline and unknown/stale status. External missed-report alerting is also deferred; if resumed, it needs separate configuration because a Mac-only timer cannot alert when the Mac is off. No trusted-time service is required and no alert currently exists in this slice.

## Bounded source validation

```sh
node scripts/controller/test-maintenance-report.js
node scripts/controller/test-maintenance-publish.js
node --check scripts/controller/maintenance-advisory.js
node --check scripts/controller/test-maintenance-report.js
docker compose --env-file /dev/null config --no-interpolate --no-env-resolution --quiet
```

These are offline source/mock/config checks, not host, native, installed, scheduler or live-publication qualification. The report suite exercises the real advisory interface and CLI alongside existing aggregation fixtures; the publication suite checks unchanged legacy behavior using synthetic keys only. Full reconcile remains **NOT RUN / not waived**. Broader migration and all operational acceptance remain incomplete; frozen failure/no-retry and VM 9900 boundaries are unchanged.
