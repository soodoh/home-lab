#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const prepare = fs.readFileSync(path.join(root, "infrastructure/debian/prepare-openfit-canary-from-arch.sh"), "utf8");
const canaryScript = fs.readFileSync(path.join(root, "infrastructure/debian/run-openfit-production-canary.sh"), "utf8");
const coordinator = fs.readFileSync(path.join(root, "scripts/qualify-debian-inert"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-debian-production-canary"), "utf8");
const finalizer = fs.readFileSync(path.join(root, "scripts/finalize-debian-production-canary"), "utf8");
const canary = contract.debian.cutover.production_canary;

assert.equal(contract.debian.cutover.stage, "credentials-staged");
assert.equal(canary.phase, "not-run");
assert.equal(canary.service, "openfit");
assert.equal(canary.state_bind, "/srv/home-lab-state/openfit-data");
assert.equal(canary.state_metadata, "root:root:755");
assert.equal(canary.backup_max_age_hours, 24);
assert.equal(canary.backup_replica_count, 3);
assert.equal(canary.pulls, "disabled");
assert.equal(canary.runtime_environment, "staged-only");
assert.equal(canary.production_boot, false);
assert.ok(prepare.includes(`readonly IMAGE='${canary.image}'`));
assert.ok(prepare.includes(`readonly TRANSFER=${canary.image_transfer_path}`));
assert.match(prepare, /timeout 7200 docker exec daily-local-backup/);
assert.match(prepare, /for root in \$BACKUP_ROOTS/);
assert.match(prepare, /actual_sha=\$\(sha256sum "\$archive"/);
assert.match(prepare, /backupReplicaCount:3/);
assert.match(prepare, /openfitStoppedForSnapshot:true/);
assert.match(prepare, /CONTAINER_BACKUP_PID/);
assert.match(prepare, /stop_container_backup/);
assert.match(prepare, /docker image save --output/);
assert.match(prepare, /privateDataExported:false/);
assert.match(prepare, /openfitState:"0:0:755"/);

assert.ok(canaryScript.includes(`readonly ARTIFACT_SHA256=${canary.artifact_sha256}`));
assert.ok(canaryScript.includes(`readonly IMAGE='${canary.image}'`));
assert.match(canaryScript, /systemctl start "\$STATE_UNIT"[\s\S]*systemctl start "\$GAMES_UNIT"[\s\S]*systemctl start "\$NFS_UNIT"/);
assert.match(canaryScript, /docker load --input "\$TRANSFER"/);
assert.match(canaryScript, /CANARY_OVERRIDE/);
assert.match(canaryScript, /docker image tag "\$loaded_image_id"/);
assert.match(canaryScript, /docker inspect openfit --format '\{\{\.Image\}\}'/);
assert.match(canaryScript, /up --detach --no-deps --pull never openfit/);
assert.match(canaryScript, /State\.Health[\s\S]*healthy/);
assert.match(canaryScript, /Source == "\/srv\/home-lab-state\/openfit-data"/);
assert.match(canaryScript, /docker image rm --force/);
assert.match(canaryScript, /systemctl mask containerd\.service/);
assert.match(canaryScript, /trap '' INT TERM HUP/);
assert.match(canaryScript, /protectedMountsUnmounted:true/);
assert.match(canaryScript, /runtimeEnvironmentInstalled:false/);
assert.doesNotMatch(canaryScript, /tailscale up|docker compose.*pull|--pull always|\/etc\/docker-compose\/production\.env.*install/);

assert.ok(coordinator.includes("canary_prepare_sha=94b89943009a6c76c8215b147777ed00942e4f2f846e25448c59190a82635849"));
assert.ok(coordinator.includes("canary_sha=f814ae02d8600788d32f655c8a4f02f1ad0d429384b814c9983c030528a03093"));
assert.match(coordinator, /setsid \/bin\/bash \/run\/home-lab-arch-canary-prepare\.runner/);
assert.match(coordinator, /setsid \/bin\/bash \/run\/home-lab-debian-canary-run\.runner/);
assert.match(coordinator, /cancel_guest_operation/);
assert.match(coordinator, /\$rehearsal_mode == true \|\| \$canary_mode == true/);
assert.match(coordinator, /write_canary_transfer_pending_evidence "\$canary_transfer_marker"/);
assert.match(coordinator, /mark_failed_canary_evidence_awaiting_reboot/);
assert.match(coordinator, /transitionState == "failed-awaiting-host-reboot"/);
assert.match(coordinator, /CANARY_ABORTED_LOG/);
assert.match(coordinator, /write_canary_pending_evidence "\$canary_marker"/);
assert.match(coordinator, /mark_canary_evidence_awaiting_reboot "\$arch_reboot_config_sha"/);
assert.match(coordinator, /finalize_canary_mode == true/);
assert.match(coordinator, /verify_arch_post_restore[\s\S]*mv -T "\$finalize_evidence" "\$CANARY_LOG"/);
assert.ok(runner.includes("readonly CONFIRMATION=run-reviewed-vm-100-debian-openfit-canary"));
assert.ok(finalizer.includes("readonly CONFIRMATION=finalize-reviewed-vm-100-debian-canary-after-reboot"));
for (const wrapper of [runner, finalizer]) {
  assert.match(wrapper, /\[\[ -t 0 \]\]/);
  assert.match(wrapper, /exec "\$root\/scripts\/qualify-debian-inert"/);
}

process.stdout.write("debian production canary tests passed\n");
