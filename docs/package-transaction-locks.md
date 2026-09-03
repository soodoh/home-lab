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
