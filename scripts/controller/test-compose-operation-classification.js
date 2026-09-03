#!/usr/bin/env node
"use strict";
const fs=require("fs"),path=require("path"),Ajv=require("ajv/dist/2020");
const root=path.resolve(__dirname,"../..");
const manifest=JSON.parse(fs.readFileSync(path.join(root,"infrastructure/retirement/compose-operation-classification.json"),"utf8"));
const schema=JSON.parse(fs.readFileSync(path.join(root,"infrastructure/retirement/compose-operation-classification.schema.json"),"utf8"));
const validate=new Ajv({strict:true}).compile(schema);
if(!validate(manifest)) throw new Error(JSON.stringify(validate.errors));
const byComponent=new Map();
for(const entry of manifest.entries){
 if(byComponent.has(entry.component)) throw new Error(`duplicate component ${entry.component}`);
 byComponent.set(entry.component,entry);
 for(const file of entry.paths) if(!fs.existsSync(path.join(root,file))) throw new Error(`classified path absent ${file}`);
}
const expected={
 "compose-artifact-lifecycle":"durable-runtime",
 "compose-rollback-and-recovery":"durable-recovery",
 "nextcloud-steady-configuration":"durable-policy",
 "nextcloud-five-mount-migration":"pending-migration",
 "nextcloud-migration-rollback":"conditional-recovery",
 "calibre-local-rollback-lane":"conditional-recovery",
 "preserved-calibre-caro-forward-migration":"retire-after-proof",
 "restic-steady-backup-retry":"durable-recovery",
 "restic-restore-boundary":"durable-recovery",
 "restic-first-run-transaction":"retire-after-proof",
 "restic-repository-initialization":"retire-after-proof",
 "compose-health-and-artifact-canaries":"durable-validation",
 "pve-firewall-nfs-canary":"conditional-recovery",
};
for(const [component,classification] of Object.entries(expected)) if(byComponent.get(component)?.class!==classification) throw new Error(`classification drift ${component}`);
const protectedPaths=new Set(["scripts/compose-artifact.py","scripts/compose-image-lock.py","scripts/compose-recovery-plan.py","scripts/restic-backup","scripts/build-restic-recovery-bundle","scripts/run-restic-recovery-bundle"]);
for(const entry of manifest.entries.filter(item=>item.class==="retire-after-proof")) for(const file of entry.paths) if(protectedPaths.has(file)) throw new Error(`core recovery path marked for retirement ${file}`);
const site=fs.readFileSync(path.join(root,"ansible/playbooks/site.yml"),"utf8");
for(const forbidden of ("nextcloud_path_migration migrate-preserved-backup-data run-first-restic-backup initialize-restic-repositories").split(" ")) if(site.includes(forbidden)) throw new Error(`ordinary convergence invokes operation-specific path ${forbidden}`);
console.log(`compose_operation_classification=verified components=${manifest.entries.length}`);
