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
const promoter = fs.readFileSync(path.join(root, "scripts/promote-recovered-debian-production-canary"), "utf8");
const evidence = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/evidence/vm-100-debian-production-canary.json"), "utf8"));
const canary = contract.debian.cutover.production_canary;

assert.equal(contract.debian.cutover.stage, "production-canary");
assert.equal(canary.phase, "verified");
assert.equal(canary.service, "openfit");
assert.equal(canary.state_bind, "/srv/home-lab-state/openfit-data");
assert.equal(canary.state_metadata, "root:root:755");
assert.equal(canary.backup_max_age_hours, 168);
assert.equal(canary.backup_replica_count, 3);
assert.equal(canary.backup_validation, "existing-local-replicas-sidecar-and-sample");
assert.equal(canary.s3_checked, false);
assert.equal(canary.pulls, "disabled");
assert.equal(canary.runtime_environment, "staged-only");
assert.equal(canary.production_boot, false);
assert.equal(evidence.stage, "production-canary");
assert.equal(evidence.canaryEvidence.canaryHealthy, true);
assert.equal(evidence.canaryEvidence.cleanupComplete, true);
assert.equal(evidence.canaryEvidence.transitionState, "complete");
assert.equal(evidence.canaryEvidence.forensicPromotion.basis, "exact-source-control-flow-plus-post-reboot-cleanup");
assert.equal(evidence.postRebootArch.runningContainers, 41);
assert.equal(evidence.postRebootArch.unhealthyContainers, 0);
assert.equal(evidence.authorization.productionCutover, false);
assert.ok(prepare.includes(`readonly IMAGE='${canary.image}'`));
assert.ok(prepare.includes(`readonly TRANSFER=${canary.image_transfer_path}`));
assert.match(prepare, /for root in \$BACKUP_ROOTS/);
assert.match(prepare, /backupSampleSha256/);
assert.match(prepare, /backupReplicaCount:3/);
assert.match(prepare, /backupValidation:"existing-local-replicas-sidecar-and-sample"/);
assert.match(prepare, /openfitStoppedForSnapshot:false/);
assert.match(prepare, /s3Checked:false/);
assert.match(prepare, /docker image save --output/);
assert.match(prepare, /privateDataExported:false/);
assert.doesNotMatch(prepare, /docker exec daily-local-backup backup|AWS_|S3_BUCKET|timeout 7200/);
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

assert.ok(coordinator.includes("canary_prepare_sha=2ca4fc66a62da672b33f8463a77bcf313f43a4e5c20735037b25f6f604edface"));
assert.ok(coordinator.includes("canary_sha=7c6f909a924e9d234be0fa6ce770b68c2bf6c268666a73c446c3ad5d7351c924"));
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
assert.match(coordinator, /promote_canary_mode == true/);
assert.match(coordinator, /FORENSIC_ABORTED_SHA256=029cbf14b1a4df986c6b063c8a132d37d9d1d09c759eef48385cd59bcc597ab1/);
assert.match(coordinator, /FORENSIC_RUN_LOG_SHA256=be25a98c60d2b7fa43b7317acade8e3d29e666f2015b69329e0b854eb986835e/);
assert.match(coordinator, /FORENSIC_JOURNAL_SHA256=30a93a4584d2261031ffc3ad22724746f1d3b75356ffaac315f88f861594fe1b/);
assert.match(coordinator, /exact-source-control-flow-plus-post-reboot-cleanup/);
assert.match(coordinator, /originalAttemptOutcome:"failed"/);
assert.ok(runner.includes("readonly CONFIRMATION=run-reviewed-vm-100-debian-openfit-canary"));
assert.ok(finalizer.includes("readonly CONFIRMATION=finalize-reviewed-vm-100-debian-canary-after-reboot"));
assert.ok(promoter.includes("readonly CONFIRMATION=promote-reviewed-vm-100-debian-canary-forensic-evidence"));
for (const wrapper of [runner, finalizer, promoter]) {
  assert.match(wrapper, /\[\[ -t 0 \]\]/);
  assert.match(wrapper, /exec "\$root\/scripts\/qualify-debian-inert"/);
}

process.stdout.write("debian production canary tests passed\n");
