# Package transaction candidate locks

Package maintenance remains candidate-only until an exact transaction receives separate review and authorization. Debian Security updates are not exempt from this rule, and neither a Renovate PR nor a merged candidate lock authorizes installation.

`ansible/playbooks/packages-plan.yml` invokes the read-only `package_lifecycle` role. It does not refresh APT metadata and never invokes an install command. The observer records:

- the installed package-set hash and exact Proxmox manifest comparison;
- APT source, keyring, preference, and configuration tree hashes;
- the full simulated dependency-coordinated transition with current version, candidate version, origin, and security classification;
- additions, removals, downgrades, holds, and kept-back packages;
- simulated download and disk-size requirements; and
- the exact solver output hashes.

The version-2 observer is a single immutable Python source shared by the Debian role and generated Proxmox artifact. It reads regular APT state through `O_NOFOLLOW`, compares descriptor metadata, rejects unsafe ownership/mode/link count/size, and permits only same-directory basename symlinks whose root-owned target is independently descriptor-verified and content-bound. Every changed package also binds the exact `apt-cache policy` output hash for its candidate version. Nonempty transactions with unrecognized download or disk summaries retain `null` sizes and the `package-size-evidence-incomplete` blocker rather than reporting false zeroes.

`scripts/controller/save-host-maintenance-plan.js` independently verifies the proposal hash and embeds `home-lab-package-transaction-lock-v1`, validated by `infrastructure/maintenance/package-transaction-lock.schema.json`. The candidate binds the host, production lifecycle, clean base commit, generation and expiry, contract, inventory, installed package set, APT state, exact proposal, and every `name=version` installation specification.

Candidate observation cannot safely determine post-install service impact or `needrestart` output. Those fields therefore remain `null`, the safety classification remains `impact-review-required`, and every lock includes both `impact-review-required` and `separate-exact-authorization-required`. Package plans remain `actionable: false` and `authorized: false`. Removals, downgrades, holds, kept-back packages, manifest drift, and an empty transaction add explicit blockers rather than silently widening authority.

An operator impact review uses `home-lab-package-impact-review-v1` and binds the candidate transaction, exact change hash, additions, normalized version-policy identities, affected and protected services, `needrestart` assessment, reboot decision, lane, reviewer, and short expiry. `scripts/controller/promote-package-transaction.js` independently recomputes every derived value. It rejects removals, downgrades, stale or altered reviews, origin drift, unresolved candidate blockers, incomplete sizes, unsafe APT state, and a no-restart lane that touches a protected service or indicates reboot. A successful promotion emits `home-lab-package-transaction-final-v1` with `actionable: true` but still `authorized: false`, `automatic_apply: false`, `automatic_reboot: false`, and the sole blocker `separate-exact-authorization-required`.

A future apply transaction must use a separate fixed package capability, re-observe the exact installed and APT hashes, re-simulate without selecting newer candidates, require byte-equivalent transaction content, consume one fresh exact authorization, preserve controller and host locks, and run post-apply health checks. The general `ansible-deploy` identity and the release-monitor workflow must never provide unattended package authority.

## Production read-only qualification

At commit `8e4c64a41c6a7df0c407238f8c2818548af2af04` on 2026-09-03, the Debian planner ran over a dedicated single-link mode-0600 known-hosts file whose ED25519 fingerprint matched independently recorded fingerprint `SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ`. The play completed with `changed=0`, no active lifecycle locks, fresh metadata age 8,337 seconds, 373 installed package records, no holds, no kept-back packages, and zero additions, upgrades, downgrades, or removals.

Proposal `ec234701ee68e7d154c480d6915f44c75b5a8ba490c1f38831036bae15dac7ed` produced protected local plan `bed805a54db85c58013dd82ce4b9658fd71d8545d0424ca623123cdd408b541b` and embedded transaction `19a3ebe95a9235a028427ce8aff8dba7935fc8a66ac36c02eaa9321ffc13a2a3`. The plan is intentionally non-actionable and unauthorized, with `no-package-changes`, impact-review, saved-plan, and separate-authorization blockers. No APT refresh, package download, install, service restart, reboot, or other production mutation occurred.

Repository Proxmox package planning uses `ansible/playbooks/proxmox-packages-plan.yml` with the local `proxmox-production.yml` inventory. It first requires the complete 17-domain audit, validates the generated package observer against the artifact, contract, and exact PVE manifest hashes, and then invokes only literal `observe-package` through `ansible-plan@proxmox`. The required production capability upgrade remains a separate saved mutation; fallback to the generic human inventory is prohibited.

## Dedicated Debian application boundary

Final Debian locks are consumed only through `ansible-package-apply@docker-host`. The contracted account has no supplementary groups or conventional keys, and its only sudo rule invokes `debian-package-transaction`. The fixed transport accepts only stage, inspect, prepare, apply, and recover with one 64-character digest. The host executor revalidates the installed package set, all APT source/keyring/configuration hashes, the exact simulation, locks, holds, kept-back state, and every `name=version` before download and again before apply. It uses `--no-remove`, never replans, never reboots, durably journals failure for manual recovery, and the controller requires the complete production audit before reporting success.

Installing this identity is itself a separate `maintenance-capability-activation.py` saved-plan transaction. The Proxmox generated package observer similarly requires `proxmox-package-observer-capability.py`, which binds the generated manifest, transport, sudo rule, prior host bytes, clean pushed commit, strict known-host file, fresh observation, and exact confirmation. Neither capability is installed by repository validation.
