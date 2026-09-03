# Unattended-upgrade retirement

Every Debian package mutation, including a security-origin update, requires an exact reviewed package transaction. The live unattended-upgrade schedule is therefore policy drift, not an exception to package authorization.

The direct contract keeps `unattended-upgrades` installed but requires these units to become inactive and masked:

- `apt-daily.timer`
- `apt-daily-upgrade.timer`
- `unattended-upgrades.service`

It also requires `/etc/apt/apt.conf.d/20auto-upgrades` to set both periodic package-list refresh and unattended upgrade to `0`. Package removal is explicitly outside this transaction.

`ansible/playbooks/unattended-retirement-plan.yml` is read-only. Its immutable observer uses no-follow descriptor reads for both relevant APT policy files, records their exact content and metadata for rollback, inventories unit state, and checks exact APT/dpkg processes and lock holders. It refuses unsafe files and does not stop, disable, mask, rewrite, remove, or install anything.

`scripts/controller/save-unattended-retirement-plan.js` binds a clean pushed commit, contract, production inventory, independently verified host key, fresh observation, exact before state, desired state, and rollback material into an exclusive mode-0600 local artifact. An active package process, active package lock, unavailable unit, or missing drift blocks action. Even a safe plan remains `authorized: false` and requires a separate exact authorization.

The 2026-09-03 read-only production observation found no APT/dpkg process or lock and canonical root-owned mode-0644 policy files. All three units were active and enabled, and periodic update and unattended-upgrade values were both `1`. The play reported `changed=0`; no unit or file was changed. At pushed commit `3a12f3b`, it produced plan `f6e231c4a7ba7ae3ec6826dfa310cc756ada05c7268f7b797f224fe902405578`, which remained `authorized: false` and has expired.

`infrastructure/maintenance/host/unattended-retirement-transaction` now implements the host-side exact-plan boundary. It validates canonical root-only plans and expiry, acquires a nonblocking host lock, rechecks byte-equivalent live state, writes an exclusive fsynced `applying` journal before mutation, stops and masks only the three reviewed units, atomically writes only the reviewed periodic file, verifies postconditions, and durably commits. Any handled failure restores the exact file and unit states and records `rolled-back`; `recover` is inspection-only and never retries mutation. The executor and observer are not installed in production. Their installation requires a new separately authorized capability plan, after which the live retirement observation and transaction plan must be regenerated.
The observer and executor are installed only through the separate `unattended-retirement` mode of `maintenance-capability-activation.py`. Its protected plan binds the clean pushed commit, contract, inventory, and both executable hashes, expires after 30 minutes, remains `authorized: false`, requires an exact confirmation, and reruns Ansible check mode immediately before one apply. Repository validation does not install or execute the retirement capability.
