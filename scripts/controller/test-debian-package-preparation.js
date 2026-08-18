#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "infrastructure/debian/prepare-packages.sh"), "utf8");

assert.equal(contract.debian.cutover.stage, "qualified");
assert.equal(contract.debian.cutover.package_source, "debian-stable");
assert.ok(script.includes(`readonly PACKAGES=(${contract.debian.cutover.docker_package} ${contract.debian.cutover.compose_package})`));
assert.match(script, /os_id == debian && \$os_version == 13/);
assert.match(script, /debian-inert-provisioned/);
assert.match(script, /verify_protected_mounts_inactive/);
assert.match(script, /findmnt -rn --target "\$target"/);
assert.doesNotMatch(script, /findmnt -rn \/srv\/home-lab-state \/mnt\/games/);
assert.match(script, /policy-rc\.d/);
assert.match(script, /exit 101/);
assert.match(script, /apt-get install --no-install-recommends --yes/);
assert.match(script, /systemctl disable --now "\$\{SERVICES\[@\]\}"/);
assert.match(script, /systemctl mask "\$\{SERVICES\[@\]\}"/);
assert.match(script, /systemctl unmask "\$\{SERVICES\[@\]\}"/);
assert.match(script, /trap cleanup EXIT/);
assert.match(script, /trap 'exit 130' INT/);
assert.ok(script.indexOf('systemctl mask "${SERVICES[@]}"') < script.indexOf('apt-get install --no-install-recommends --yes'));
assert.match(script, /docker compose version --short/);
assert.match(script, /\[\[ ! -S \/run\/docker\.sock \]\]/);
assert.match(script, /verify_credentials_and_tailscale_absent/);
assert.match(script, /\/var\/lib\/tailscale/);
assert.match(script, /systemctl list-unit-files.*tailscaled/);
assert.match(script, /verify_docker_objects_absent/);
assert.match(script, /\/var\/lib\/docker\/containers/);
assert.match(script, /write_live_evidence/);
assert.match(script, /cmp -s "\$live_marker" "\$MARKER"/);
assert.doesNotMatch(script, /docker compose (?:up|create|start)|mount .*home-lab-state|tailscale up|sops decrypt/);
assert.equal(contract.debian.cutover.credentials, "deferred");
assert.equal(contract.debian.cutover.tailscale_enrollment, "deferred");
assert.deepEqual(contract.debian.cutover.rollback_boot_order, ["scsi0", "net0"]);
assert.equal(contract.debian.cutover.transition_restore, "physical-host-reboot");
assert.equal(contract.debian.cutover.package_evidence, "post-reboot-arch-verified");

process.stdout.write("debian package preparation tests passed\n");
