# Package transaction candidate locks

Package maintenance remains candidate-only until an exact transaction receives separate review and authorization. Debian Security updates are not exempt from this rule, and neither a Renovate PR nor a merged candidate lock authorizes installation.

`ansible/playbooks/packages-plan.yml` invokes the read-only `package_lifecycle` role. It does not refresh APT metadata and never invokes an install command. The observer records:

- the installed package-set hash and exact Proxmox manifest comparison;
- APT source, keyring, preference, and configuration tree hashes;
- the full simulated dependency-coordinated transition with current version, candidate version, origin, and security classification;
- additions, removals, downgrades, holds, and kept-back packages;
- simulated download and disk-size requirements; and
- the exact solver output hashes.

`scripts/controller/save-host-maintenance-plan.js` independently verifies the proposal hash and embeds `home-lab-package-transaction-lock-v1`, validated by `infrastructure/maintenance/package-transaction-lock.schema.json`. The candidate binds the host, production lifecycle, clean base commit, generation and expiry, contract, inventory, installed package set, APT state, exact proposal, and every `name=version` installation specification.

Candidate observation cannot safely determine post-install service impact or `needrestart` output. Those fields therefore remain `null`, the safety classification remains `impact-review-required`, and every lock includes both `impact-review-required` and `separate-exact-authorization-required`. Package plans remain `actionable: false` and `authorized: false`. Removals, downgrades, holds, kept-back packages, manifest drift, and an empty transaction add explicit blockers rather than silently widening authority.

A future apply transaction must use a separate fixed package capability, re-observe the exact installed and APT hashes, re-simulate without selecting newer candidates, require byte-equivalent transaction content, consume one fresh exact authorization, preserve controller and host locks, and run post-apply health checks. The general `ansible-deploy` identity and the release-monitor workflow must never provide unattended package authority.

## Production read-only qualification

At commit `8e4c64a41c6a7df0c407238f8c2818548af2af04` on 2026-09-03, the Debian planner ran over a dedicated single-link mode-0600 known-hosts file whose ED25519 fingerprint matched independently recorded fingerprint `SHA256:7GYR95H1ybocMXsvjw0qAaiDiW3OQXcaZDU+oO5cOsQ`. The play completed with `changed=0`, no active lifecycle locks, fresh metadata age 8,337 seconds, 373 installed package records, no holds, no kept-back packages, and zero additions, upgrades, downgrades, or removals.

Proposal `ec234701ee68e7d154c480d6915f44c75b5a8ba490c1f38831036bae15dac7ed` produced protected local plan `bed805a54db85c58013dd82ce4b9658fd71d8545d0424ca623123cdd408b541b` and embedded transaction `19a3ebe95a9235a028427ce8aff8dba7935fc8a66ac36c02eaa9321ffc13a2a3`. The plan is intentionally non-actionable and unauthorized, with `no-package-changes`, impact-review, saved-plan, and separate-authorization blockers. No APT refresh, package download, install, service restart, reboot, or other production mutation occurred.

Proxmox candidate generation remains blocked from this generic playbook: production observation must use the fixed `ansible-plan@proxmox` transport rather than the transitional human SSH inventory. The existing attended Proxmox package transaction remains separate until that observer is adapted and disposable parity is proven.
