#!/usr/bin/env node
"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto"),cp=require("child_process"),net=require("net"),Ajv=require("ajv/dist/2020"),yaml=require("js-yaml");
const ROOT=path.resolve(__dirname,"../..");
function fail(message){throw new Error(message);}
function protectedRead(file,maxBytes){
 if(!path.isAbsolute(file)) fail("protected artifact path must be absolute");
 let fd; try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_CLOEXEC)}catch{fail("unsafe protected artifact metadata")}
 let before,after,raw;
 try{
  before=fs.fstatSync(fd); const mode=before.mode&0o777;
  if(!before.isFile()||before.nlink!==1||before.uid!==process.getuid()||before.gid!==process.getgid()||mode!==0o600||before.size>maxBytes) fail("unsafe protected artifact metadata");
  raw=fs.readFileSync(fd); after=fs.fstatSync(fd);
  if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.nlink!==after.nlink||raw.length!==before.size) fail("protected artifact changed during read");
 }finally{fs.closeSync(fd)}
 const current=fs.lstatSync(file);
 if(!current.isFile()||current.isSymbolicLink()||current.dev!==after.dev||current.ino!==after.ino||current.size!==after.size||current.nlink!==1) fail("protected artifact path changed during read");
 return raw;
}
function stable(value){
 if(Array.isArray(value)) return value.map(stable);
 if(value&&typeof value==="object") return Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])]));
 return value;
}
function sha(raw){return crypto.createHash("sha256").update(raw).digest("hex")}
function main(){
 let evidencePath="",knownHostsPath="";
 for(let i=2;i<process.argv.length;i+=2){if(process.argv[i]==="--evidence") evidencePath=process.argv[i+1]||""; else if(process.argv[i]==="--known-hosts") knownHostsPath=process.argv[i+1]||""; else fail("usage: validate-disposable-pve-target.js --evidence ABSOLUTE_PATH --known-hosts ABSOLUTE_PATH");}
 if(!evidencePath||!knownHostsPath) fail("usage: validate-disposable-pve-target.js --evidence ABSOLUTE_PATH --known-hosts ABSOLUTE_PATH");
 const raw=protectedRead(evidencePath,65536), knownHosts=protectedRead(knownHostsPath,16384);
 let evidence; try{evidence=JSON.parse(raw.toString("utf8"))}catch{fail("admission evidence is not JSON")}
 const canonical=Buffer.from(JSON.stringify(stable(evidence))+"\n");
 if(!raw.equals(canonical)) fail("admission evidence must be canonical JSON");
 const schema=JSON.parse(fs.readFileSync(path.join(ROOT,"infrastructure/evidence/disposable-pve-target-admission.schema.json"),"utf8"));
 const validate=new Ajv({strict:true,formats:{"date-time":true}}).compile(schema);
 if(!validate(evidence)) fail(`admission schema violation: ${JSON.stringify(validate.errors)}`);
 const observed=Date.parse(evidence.observed_at), expires=Date.parse(evidence.expires_at), now=Date.now();
 if(!Number.isFinite(observed)||!Number.isFinite(expires)||observed>now+5000||observed<now-1800000||expires<=now||expires-observed>1800000) fail("admission evidence is stale or has an unsafe validity window");
 const contract=yaml.load(fs.readFileSync(path.join(ROOT,"infrastructure/contract/home-lab.yml"),"utf8"));
 const endpoint=new URL(evidence.endpoint), productionPve=contract.network.proxmox.ipv4.split("/")[0], productionVm=contract.vm_100.networking.ipv4.split("/")[0];
 if(evidence.node_name===contract.proxmox.node||evidence.target_id===contract.proxmox.node||endpoint.hostname===contract.proxmox.node||endpoint.hostname===productionPve||endpoint.hostname===productionVm||evidence.host_key.ssh_address===productionPve||evidence.host_key.ssh_address===productionVm||evidence.host_key.ssh_address===contract.proxmox.node) fail("production endpoint or identity is not admissible");
 if(net.isIP(evidence.network.controller_ipv4)!==4||evidence.network.controller_ipv4===productionPve||evidence.network.controller_ipv4===productionVm) fail("controller address is invalid or aliases a production managed host");
 const {plan_principal:plan,apply_principal:apply,ssh_principal:sshPrincipal}=evidence.credentials;
 const productionPrincipals=new Set((contract.proxmox.access.pve.accounts||[]).map(account=>`${account.user}!${account.token_name}`));
 const productionSshUsers=new Set(["root",...(contract.proxmox.access.service_accounts||[]).map(account=>account.name),...(contract.proxmox.access.human_accounts||[]).map(account=>account.name)]);
 if(plan===apply||productionPrincipals.has(plan)||productionPrincipals.has(apply)||productionSshUsers.has(sshPrincipal)) fail("qualification credentials are not independent");
 if(evidence.credentials.ssh_agent_public_key_sha256===evidence.credentials.guest_ssh_public_key_sha256) fail("guest and PVE SSH keys must differ");
 if(sha(knownHosts)!==evidence.host_key.known_hosts_sha256) fail("known-hosts digest mismatch");
 const lines=knownHosts.toString("utf8").trim().split("\n");
 if(lines.length!==1||lines[0].startsWith("#")) fail("known-hosts file must contain exactly one host key");
 const fields=lines[0].trim().split(/\s+/); if(fields.length<3||fields[1]!==evidence.host_key.algorithm) fail("known-hosts algorithm mismatch");
 const hostNames=fields[0].split(","); if(!hostNames.includes(evidence.host_key.ssh_address)&&!hostNames.includes(`[${evidence.host_key.ssh_address}]:22`)) fail("known-hosts endpoint mismatch");
 const fingerprint=cp.execFileSync("ssh-keygen",["-E","sha256","-lf","-"],{encoding:"utf8",input:knownHosts,stdio:["pipe","pipe","ignore"]}).trim().split(/\s+/)[1];
 if(fingerprint!==evidence.host_key.fingerprint) fail("known-hosts fingerprint mismatch");
 process.stdout.write(JSON.stringify({admitted:true,api_ca_sha256:evidence.api_ca_sha256,apply_principal:apply,bridge:evidence.network.bridge,controller_ipv4:evidence.network.controller_ipv4,disk_datastore_id:evidence.storage.disk_datastore_id,endpoint:evidence.endpoint,guest_ssh_public_key_sha256:evidence.credentials.guest_ssh_public_key_sha256,image_datastore_id:evidence.storage.image_datastore_id,isolation_attestation_sha256:sha(raw),node_name:evidence.node_name,plan_principal:plan,snippet_datastore_id:evidence.storage.snippet_datastore_id,snippet_directory:evidence.storage.snippet_directory,ssh_address:evidence.host_key.ssh_address,ssh_agent_public_key_sha256:evidence.credentials.ssh_agent_public_key_sha256,ssh_username:sshPrincipal,target_id:evidence.target_id})+"\n");
}
if(require.main===module){try{main()}catch(error){console.error(error.message);process.exit(1)}}
module.exports={protectedRead,stable};
