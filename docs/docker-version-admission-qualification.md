# Docker version-admission regression

## Scope

The production Docker role first gathers native service facts, refusing a
Docker service not observed running under systemd **before contacting its
socket**. It then admits the recorded client/server versions **before** its
package and service tasks. The comparison, controller branch conditions,
exact-package-lock dependency and service settings remain unchanged.
Preparation/startup needs its own approved route.

This is a sampled native precondition under the cooperative, attended model,
not an atomic fence against a concurrent daemon crash, stop or privileged
configuration change. Existing exclusion and startup controls remain necessary;
this slice does not replace or qualify them.

The opt-in [native test](../ansible/tests/docker-version-admission.yml) invokes
that real role and its real `apt_packages` dependency. It observes systemd and
dpkg, not a replacement role or simulated service manager. It requires a
separately approved, empty disposable Debian guest with native systemd, root,
Ansible, Python-APT and all three Docker packages already installed.

**Do not run it on production.** Its hostname/consent checks and refusal of
`/etc/home-lab` are accident guards, not proof of disposability or operational
authorization. The defective role intentionally changes boot enablement during
RED. The playbook does not prepare, stop, restart, clean up or install anything
itself; the invoked role remains capable of its normal mutations.

## Running the cases

Copy only these public inputs into an isolated fixture directory, preserving
contents and layout:

- `ansible/roles/docker/tasks/main.yml`
- `ansible/roles/apt_packages/tasks/main.yml`
- `ansible/roles/apt_packages/defaults/main.yml`
- `ansible/tests/docker-version-admission.yml`

Use a private `ansible.cfg` pointing `roles_path` at that copy, an isolated HOME
and environment, `/usr/bin/python3`, and inline `localhost,` inventory. Do not
load production inventory, credentials, callbacks or configuration. Confirm the
actual hostname explicitly rather than deriving the consent value from the
machine being tested.

Invocation shape, inside the approved guest:

```sh
ansible-playbook -i localhost, ansible/tests/docker-version-admission.yml \
  -e disposable_docker_test=true \
  -e disposable_docker_test_hostname=YOUR_APPROVED_FIXTURE
```

The default case is `mismatch`. Docker must already be running but boot-disabled;
only separately approved fixture setup may disable it (without `--now`). The
case requires the specific version-refusal message, unchanged service activity,
PID/invocation, boot enablement and installed package inventory.

Then invoke the same playbook with:

1. `-e docker_admission_case=match`, from running/disabled state; supply
   `docker_test_matching_client_version` and `docker_test_matching_server_version`
   at the independently observed/approved versions. Boot enablement must become
   enabled without changing daemon identity or packages.
2. `-e docker_admission_case=steady`, with the same matching-version inputs and
   running/enabled state. State must remain identical. Check that the actual
   Ansible recap also reports `changed=0`, `failed=0`, `unreachable=0`.

The separately approved `stopped` case requires Docker boot-enabled but stopped,
with its socket still active/listening. First verify the runtime is empty while
Docker is running, then stop only the daemon through the approved fixture
procedure. Invoke with `-e docker_admission_case=stopped` and
`-e docker_test_stopped_fixture_prepared=true`. This extra flag records operator
preparation, not independent proof of it. The test uses only non-activating
systemd/dpkg observations before the role; it must get the specific running-state
refusal while Docker remains stopped. Restore the daemon only through the
separately approved fixture procedure. No timer or failed-unit reset is needed.

A setup error, unexpected refusal, missing executable or unsupported platform
is not a causal RED. Do not install dependencies automatically or weaken the
assertions to obtain a pass.

## Native evidence — 2026-09-10

The local `dkr-role` fixture used Debian 13 ARM64, systemd 257.13-1~deb13u1,
Ansible Core 2.19.4 and Docker client/server 26.1.5+dfsg1. The exact fourteen
setup packages were installed once from verified Debian archives, with no
upgrades/removals. Docker had no containers, images or volumes.

Independent review found that the reorder-only candidate could still activate
stopped Docker via its listening socket. A separately approved native RED proved
this happened even with Ansible reporting `changed=0`. The native running-state
guard was added only after that RED, and the test's own state check was moved
before its Docker API queries.

The **same final test bytes** were exercised in all six cases, against original,
reorder-only and final guarded role bytes:

| Case | Actual result |
| --- | --- |
| Original role, mismatch | Causal RED: exact version refusal followed by failed invariant; disabled → enabled, Ansible exit 2 / changed 1 |
| Corrected role, mismatch | GREEN: refusal preserved disabled state; exit 0 / changed 0 |
| Corrected role, matching versions | Enabled boot without restart; exit 0 / changed 1 |
| Corrected role, second matching convergence | No change; exit 0 / changed 0 |
| Reorder-only candidate, stopped daemon / listening socket | Causal RED: Docker became active via observation; test exit 2 despite Ansible changed 0 |
| Final guarded role, stopped daemon / listening socket | GREEN: specific running-state refusal, daemon remained inactive/PID0; exit 0 / changed 0 |

Daemon PID/invocation were unchanged across each of the four running-daemon
cases. The stopped cases used two explicitly approved fixture stops and an
approved final restoration; they do not claim an uninterrupted daemon session.
Package inventory was unchanged in all six cases. Frozen SHA256 identities:

- Original role: `7bb9af685b1c9f81d94475b6cd28d6224bdb14738f9684ed9349079b67e3eb19`
- Reorder-only candidate: `93ccd9f93ae34deff43231da12e01f89aa6a367146535fb3deca099300e0e8bf`
- Final guarded role: `07dab6ecb1121fca1f3d5ce81178abecca7bee4483fa296b05dc8bbf15aece77`
- Final test: `e7cbfea76877bb8bc3c5e5b8e156306b0e73439146822a7eb9403df27533fcac`

Private packet `local-debian-docker-role-3491395-01` retains the exact inputs,
commands, raw Ansible/systemd observations, original `final-native-cases.json`
and superseding `review-fix-native-cases.json` (running cases `r2-*`, socket
cases `socket-red`/`socket-green`, and `socket-test-restoration.stdout`).
Earlier cloud-init deprecation, keyring-alias probe and timer-state check
failures remain recorded; none were labeled Docker-role RED or erased.

This qualifies only the packages-present **direct-controller role branch** on
this fixture: running-daemon admission and refusal of an observed stopped daemon
with a listening socket. It does not qualify missing-package installation,
the fixed read-only helper, the Ubuntu x86_64 / Ansible2.21.2 controller lock,
production startup/activation, VM9900 first boot, recovery or the whole migration.
The fixture remains running; automatic APT units remain runtime-masked (cleared
by reboot), with the diagnosed failed timer state retained. No production
operation, commit or publication was performed by this slice.
