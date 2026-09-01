#!/usr/bin/env python3
"""Focused hostile-input tests for protocol-v4 preparation and host bootstrap."""

from __future__ import annotations

import copy
import datetime as dt
import errno
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
sys.path.insert(0, str(NIX / "proxmox"))
import bundle
import planner
import prepare

sys.dont_write_bytecode = True


def load_installer():
    path = ROOT / "scripts/bootstrap-proxmox-nix-host"
    loader = importlib.machinery.SourceFileLoader("bootstrap_proxmox_nix_host_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec); loader.exec_module(module)
    return module


def load_access():
    path = ROOT / "scripts/bootstrap-proxmox-nix-access"
    loader = importlib.machinery.SourceFileLoader("bootstrap_proxmox_nix_access_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec); loader.exec_module(module)
    return module


class ProxmoxNixBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.projection = json.loads((NIX / "proxmox/projection.json").read_bytes())
        cls.projection["nixMutationFrozen"] = False
        next(item for item in cls.projection["planningPolicy"]["domains"] if item["domain"] == "managed-artifacts")["automatic"] = True
        cls.manifest = json.loads((NIX / "proxmox/package-manifest.json").read_bytes())
        cls.observation = json.loads((NIX / "proxmox/fixture-observation.json").read_bytes())
        cls.observation["domains"]["protectedAccess"] = {"expectedCount": 6, "matches": True, "observedCount": 6, "status": "complete"}
        cls.observation["domains"]["protectedHardware"] = {"expectedCount": 3, "matches": True, "observedCount": 3, "status": "complete"}
        projected_account_names = {account["name"] for kind in ("service", "human") for account in cls.projection["accounts"][kind]}
        cls.observation["domains"]["accounts"]["records"] = [
            record for record in cls.observation["domains"]["accounts"]["records"]
            if record["name"] in projected_account_names
        ]
        for record in cls.observation["domains"]["accounts"]["records"]:
            if record["name"] == "tofu-apply":
                record["shell"] = "/usr/local/libexec/home-lab/proxmox-apply-transport"
                record["expectedGroupsMatch"] = True
        observed_names = {record["name"] for record in cls.observation["domains"]["accounts"]["records"]}
        for account in cls.projection["accounts"]["service"]:
            if account["name"] not in observed_names:
                cls.observation["domains"]["accounts"]["records"].append({
                    "commentMatches": True, "exists": True, "expectedGroupsMatch": True,
                    "home": account["home"], "name": account["name"], "passwordLocked": True,
                    "primaryGroupMatches": True, "shell": account["shell"],
                })
        cls.observation["domains"]["accounts"]["records"].sort(key=lambda record: record["name"])
        cls.observation["domains"]["auditAbsence"]["records"] = [
            {"count": 0, "target": absence["path"], "type": absence["absence"]}
            for absence in cls.projection["auditAbsence"]
        ]
        managed_records = cls.observation["domains"]["managedFiles"]["records"]
        projected_managed_targets = {managed["path"] for managed in cls.projection["managedFiles"]}
        managed_records[:] = [record for record in managed_records if record["target"] in projected_managed_targets]
        managed_targets = {record["target"] for record in managed_records}
        for managed in cls.projection["managedFiles"]:
            if managed["path"] not in managed_targets:
                managed_records.append({"contentMatches": True, "groupMatches": True, "mode": managed["mode"],
                                        "ownerMatches": True, "target": managed["path"], "type": "file"})
        managed_records.sort(key=lambda record: record["target"])
        cls.bindings = {"activationEnvelopeSchemaSha256": "1"*64, "activatorSha256": "2"*64,
            "bundleContentSha256": "3"*64, "bundleFormat": planner.BUNDLE_FORMAT, "flakeLockSha256": "4"*64,
            "gitCommit": "5"*40, "gitTree": "6"*40, "observerProtocol": 4,
            "observerSha256": cls.observation["observerSha256"], "packageManifestSha256": "7"*64,
            "planSchemaSha256": "8"*64, "privatePreconditionsSchemaSha256": "9"*64,
            "privatePreparationRequestSchemaSha256": "a"*64, "privatePreparerSha256": "b"*64,
            "projectionSha256": "c"*64}
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.plan = planner.build_plan(cls.bindings, cls.projection, cls.manifest, cls.observation,
            planner.format_time(now), planner.format_time(now + dt.timedelta(seconds=1)), False)
        assert cls.plan["status"] == "ready" and len(cls.plan["actions"]) == 1
        rendered = bundle.expected_helper_content("proxmox-private-preparer", cls.projection)
        cls.preparer = {"__name__": "fixed_preparer_test", "__file__": "/tmp/fixed-proxmox-private-preparer"}
        exec(compile(rendered, "fixed-preparer", "exec"), cls.preparer)

    def test_private_preparer_validates_installed_firewall_asset_hashes(self):
        bindings = copy.deepcopy(self.plan["bindings"])
        install = {
            "bindings": bindings,
            "bundleContentSha256": bindings["bundleContentSha256"],
            "firewallAssets": {"/usr/local/libexec/home-lab/example": {"mode": 0o755, "sha256": "d" * 64}},
            "format": "home-lab-proxmox-install-v2",
            "gitCommit": bindings["gitCommit"],
            "gitTree": bindings["gitTree"],
            "helpers": {"proxmox-activator": bindings["activatorSha256"],
                        "proxmox-observer": bindings["observerSha256"],
                        "proxmox-private-preparer": bindings["privatePreparerSha256"]},
        }
        with patch.dict(self.preparer, {"secure_json": lambda path, maximum: install,
                                        "self_sha256": lambda: bindings["privatePreparerSha256"]}):
            self.assertEqual(self.preparer["install_manifest"](), install)

    def test_summary_is_fixed_shape_and_never_emits_protected_values(self):
        key1 = "ssh-ed25519 " + __import__('base64').b64encode(b'A' * 32).decode() + " plan"
        key2 = "ssh-ed25519 " + __import__('base64').b64encode(b'B' * 32).decode() + " apply"
        key3 = "ssh-ed25519 " + __import__('base64').b64encode(b'C' * 32).decode() + " firewall"
        members = [f"/dev/disk/by-id/opaque-member-{index:02d}" for index in range(12)]
        state = {"access": {"applyKeys": [key2], "applyToken": "root@pam!tofu-apply=opaque-apply-token",
                  "applyTokenIdentity": "root@pam!tofu-apply", "firewallKeys": [key3], "planKeys": [key1],
                  "planToken": "root@pam!tofu-plan=opaque-plan-token", "planTokenIdentity": "root@pam!tofu-plan"},
                 "format": "home-lab-proxmox-protected-inputs-v1",
                 "hardware": {"gamesDiskIdentity": "/dev/disk/by-id/opaque-disk", "poolGuid": "123456789",
                              "poolMembers": members,
                              "usbMappings": [{"mapping":"zigbee-cp210x","port":"1-2","serial":"opaque-usb-a"},
                                              {"mapping":"zwave-cp210x","port":"1-3","serial":"opaque-usb-b"}]}}
        forced = 'restrict,command="sudo -n -- /usr/local/libexec/home-lab/proxmox-observer observe" ' + key1 + '\n'
        def read_fixed(path, required_mode=0o600, owner_name="root"):
            text = str(path)
            if "proxmox-plan-token.env" in text: return "PROXMOX_VE_API_TOKEN=root@pam!tofu-plan=opaque-plan-token\n"
            if "proxmox-apply-token.env" in text: return "PROXMOX_VE_API_TOKEN=root@pam!tofu-apply=opaque-apply-token\n"
            if "tofu-plan" in text: return forced
            if "tofu-apply" in text: return 'restrict,command="/usr/local/libexec/home-lab/proxmox-apply-transport" ' + key2 + "\n"
            if "firewall-apply" in text: return 'restrict,command="/usr/local/libexec/home-lab/proxmox-firewall-transport" ' + key3 + "\n"
            return None
        def run(args, accepted=(0,)):
            command = " ".join(args)
            if "/access/users/" in command and "/token/" in command: return b'{"privsep":1}\n'
            if "/access/acl" in command:
                return json.dumps([
                    {"path":"/","propagate":1,"roleid":"HomeLabTofuApply","ugid":"root@pam!tofu-apply"},
                    {"path":"/","propagate":1,"roleid":"HomeLabTofuPlan","ugid":"root@pam!tofu-plan"},
                    {"path":"/vms/100","propagate":1,"roleid":"HomeLabTofuPlanDiskInspect","ugid":"root@pam!tofu-plan"}]).encode()
            if "/cluster/mapping/usb/zigbee-cp210x" in command: return b'{"map":[{"node":"proxmox","path":"1-2"}]}\n'
            if "/cluster/mapping/usb/zwave-cp210x" in command: return b'{"map":[{"node":"proxmox","path":"1-3"}]}\n'
            if "qm config" in command: return b"scsi1: /dev/disk/by-id/opaque-disk,backup=0\n"
            if "zpool get" in command: return b"123456789\n"
            if "zpool status" in command:
                return ("\n".join(line for index in range(6) for line in
                    (f"  mirror-{index} ONLINE", f"    {members[index*2]} ONLINE", f"    {members[index*2+1]} ONLINE")) + "\n").encode()
            if "udevadm" in command: return b"P: /devices/pci/usb1/1-2\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-usb-a\n\nP: /devices/pci/usb1/1-3\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-usb-b\n"
            return None
        with patch.dict(self.preparer, {"runtime_state": lambda: state, "read_fixed": read_fixed, "run": run,
                                        "absent_fixed": lambda path: True, "token_valid": lambda token: True}):
            value = self.preparer["summaries"]()
        self.assertEqual(value, {"protectedAccess": {"expectedCount": 6, "matches": True, "observedCount": 6, "status": "complete"},
                                 "protectedHardware": {"expectedCount": 3, "matches": True, "observedCount": 3, "status": "complete"}})
        encoded = json.dumps(value)
        for protected in ("opaque-plan", "opaque-token", "opaque-disk", "opaque-guid", "opaque-member", "opaque-usb"):
            self.assertNotIn(protected, encoded)

    def test_prepare_generates_opaque_authenticated_sidecar_and_closes_unsafe_actions(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        plan = copy.deepcopy(self.plan)
        key = b"K" * 48
        install = {"bindings": plan["bindings"]}
        request = {"format": "home-lab-proxmox-private-preparation-request-v1",
                   "operatorGates": {"backupsConfirmed": False, "consoleConfirmed": False,
                                     "lanRollbackConfirmed": False, "noConcurrentMutationConfirmed": True},
                   "plan": plan, "protocol": 4, "requestedAt": planner.format_time(now)}
        class Input:
            def read(self, size): return planner.canonical_json(request)
        outputs=[]
        fake_sys = SimpleNamespace(stdin=SimpleNamespace(buffer=Input()))
        with patch.dict(self.preparer, {"sys": fake_sys, "install_manifest": lambda: install,
                "summaries": lambda: {"protectedAccess": {"expectedCount":5,"matches":True,"observedCount":5,"status":"complete"},
                                      "protectedHardware": {"expectedCount":3,"matches":True,"observedCount":3,"status":"complete"}},
                "secure_key": lambda: key, "self_sha256": lambda: plan["bindings"]["privatePreparerSha256"]}), patch.object(os, "write", side_effect=lambda fd,data: (outputs.append(data), len(data))[1]):
            self.preparer["prepare"]()
        sidecar=json.loads(outputs[0]); self.assertEqual(sidecar["packageSession"], None)
        self.assertNotIn("bundleFormat", sidecar["bindings"]); self.assertNotIn("observerProtocol", sidecar["bindings"])
        signing=copy.deepcopy(sidecar); signing["hostSession"].pop("sidecarMac")
        self.assertEqual(sidecar["hostSession"]["sidecarMac"], hmac.new(key, planner.canonical_json(signing), hashlib.sha256).hexdigest())
        for field in ("challenge", "id"): self.assertNotIn("opaque", str(sidecar["hostSession"].get(field, sidecar.get(field))))
        unsafe=copy.deepcopy(plan["actions"][0]); unsafe["rebootRequired"]=True
        with self.assertRaises(ValueError): self.preparer["catalog_action"](unsafe)
        unsafe=copy.deepcopy(plan["actions"][0]); unsafe["domain"]="packages"
        with self.assertRaises(ValueError): self.preparer["catalog_action"](unsafe)

    def test_controller_prepare_uses_fixed_transport_and_exclusive_private_output(self):
        self.assertEqual(prepare.SSH_PREPARE_COMMAND[-2:], ("tofu-apply@192.168.0.123", "sudo -n -- /usr/local/libexec/home-lab/proxmox-private-preparer prepare"))
        self.assertEqual(prepare.SSH_PREPARE_COMMAND[1:3], ("-F", "/dev/null"))
        self.assertIn(str(Path.home() / ".ssh/home-lab-proxmox-apply"), prepare.SSH_PREPARE_COMMAND)
        frozen = copy.deepcopy(self.projection); frozen["nixMutationFrozen"] = True
        frozen_args = SimpleNamespace(repo_root=str(ROOT), plan_sha="a" * 64, approve_plan_sha="a" * 64)
        with patch.object(planner, "bundle_inputs", return_value=({}, frozen, self.manifest, {})), \
                patch.object(prepare, "send") as transport, self.assertRaisesRegex(ValueError, "frozen"):
            prepare.prepare(frozen_args, Path("bundle"), Path("hash"), Path("source"))
        transport.assert_not_called()
        with tempfile.TemporaryDirectory() as name:
            repo=Path(name); reconcile=repo/".reconcile"; reconcile.mkdir(mode=0o700); plans=reconcile/"plans"; plans.mkdir(mode=0o700)
            plan=copy.deepcopy(self.plan); now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            path=plans/f'{plan["planSha256"]}.json'; path.write_bytes(planner.canonical_json(plan)); path.chmod(0o600)
            args=SimpleNamespace(repo_root=str(repo),plan_sha=plan["planSha256"],approve_plan_sha=plan["planSha256"],confirm_no_concurrent_mutation=True,confirm_console=False,confirm_lan_rollback=False,confirm_backups=False)
            metadata={"helperSha256":{"proxmox-activator":plan["bindings"]["activatorSha256"],"proxmox-private-preparer":plan["bindings"]["privatePreparerSha256"]},"activationEnvelopeSchemaSha256":plan["bindings"]["activationEnvelopeSchemaSha256"],"privatePreconditionsSchemaSha256":plan["bindings"]["privatePreconditionsSchemaSha256"],"privatePreparationRequestSchemaSha256":plan["bindings"]["privatePreparationRequestSchemaSha256"]}
            sidecar={"actionManifestSha256":planner.digest(plan["actions"]),"attestations":{"protectedAccess":{"expectedCount":5,"keyedAttestation":"d"*64,"matches":True},"protectedHardware":{"expectedCount":3,"keyedAttestation":"e"*64,"matches":True}},"bindings":{k:v for k,v in plan["bindings"].items() if k not in {"bundleFormat","observerProtocol"}},"challenge":"challenge_0123456789","createdAt":planner.format_time(now),"format":"home-lab-proxmox-private-preconditions-v1","hostSession":{"id":"session_01234567890","sidecarMac":"f"*64},"operatorGates":{"backupsConfirmed":False,"consoleConfirmed":False,"lanRollbackConfirmed":False,"noConcurrentMutationConfirmed":True},"packageSession":None,"planSha256":plan["planSha256"],"validUntil":planner.format_time(now+dt.timedelta(seconds=60))}
            with patch.object(planner,"bundle_inputs",return_value=(plan["bindings"],self.projection,self.manifest,metadata)),patch.object(prepare,"send",return_value=sidecar):
                result=prepare.prepare(args,Path("bundle"),Path("hash"),Path("source"))
                self.assertIn("status=prepared",result)
                with self.assertRaises(FileExistsError): prepare.prepare(args,Path("bundle"),Path("hash"),Path("source"))
            private=plans/f'{plan["planSha256"]}.private.json'; self.assertEqual(stat.S_IMODE(private.stat().st_mode),0o600)

    def test_installer_surface_atomic_rollback_and_key_policy_are_closed(self):
        installer=load_installer()
        source=(ROOT/"scripts/bootstrap-proxmox-nix-host").read_text()
        self.assertIn("<check|install|verify|recover|diagnose-recovery>",source)
        self.assertNotIn("argparse",source); self.assertNotIn("--path",source); self.assertNotIn("--host",source)
        for control in ("O_NOFOLLOW", "fingerprint(before)", "MIN_FREE", "operation_fd = acquire_lock(OPERATION_LOCK)",
                        "recover_previous_active", "expected_manifest", "durable_unlink", '"rolling-back"'):
            self.assertIn(control, source)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); target=root/"target"; target.write_bytes(b"old"); target.chmod(0o600)
            link=root/"link"; link.symlink_to(target)
            real_fstat=os.fstat; real_stat=os.stat
            def root(info):
                values=list(info); values[4]=0; values[5]=0; return os.stat_result(values)
            with patch.object(installer,"open_dir",side_effect=lambda path,mode=None,create=False: os.open(path,os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(installer,"ensure_dir",return_value=None), \
                    patch.object(installer.os,"fstat",side_effect=lambda fd:root(real_fstat(fd))), \
                    patch.object(installer.os,"stat",side_effect=lambda *args,**kwargs:root(real_stat(*args,**kwargs))), \
                    patch.object(installer.os,"fchown",return_value=None):
                with self.assertRaises((ValueError, OSError)): installer.secure_file(link,0o600)
                installer.atomic(target,b"new",0o600)
                self.assertEqual(target.read_bytes(),b"new")
                with patch.object(installer.os,"rename",side_effect=OSError("injected rename boundary")), \
                        self.assertRaises(OSError):
                    installer.atomic(target,b"never",0o600)
                self.assertEqual(target.read_bytes(),b"new")
                self.assertFalse(any(item.name.startswith(".bootstrap-") for item in Path(name).iterdir()))
                with patch.object(installer.os,"fsync",side_effect=OSError("injected fsync boundary")), \
                        self.assertRaises(OSError):
                    installer.atomic(target,b"never-fsynced",0o600)
                self.assertEqual(target.read_bytes(),b"new")
                self.assertFalse(any(item.name.startswith(".bootstrap-") for item in Path(name).iterdir()))
                with patch.object(installer.os,"write",side_effect=OSError(errno.ENOSPC,"injected full filesystem")), \
                        self.assertRaisesRegex(OSError,"full filesystem"):
                    installer.atomic(target,b"cannot-fit",0o600)
                self.assertEqual(target.read_bytes(),b"new")
                self.assertFalse(installer.pending_path(target).exists())
                with patch.object(installer.os,"fsync",side_effect=OSError("injected unlink fsync boundary")), \
                        self.assertRaises(OSError):
                    installer.durable_unlink(target)
                self.assertFalse(target.exists())

    def test_pve_manager_version_accepts_real_output_shape_and_rejects_mismatch(self):
        installer=load_installer()
        self.assertEqual(installer.pve_manager_version(
            "pve-manager/9.2.3/d0fde103346cf89a (running kernel: 7.0.14-8-pve)\n"), "9.2.3")
        self.assertNotEqual(installer.pve_manager_version(
            "pve-manager/9.2.4/deadbeef (running kernel: 7.0.14-8-pve)"), "9.2.3")
        for value in ("pve-manager/9.2.3", "prefix pve-manager/9.2.3/deadbeef (running kernel: kernel)",
                      "pve-manager/9.2.3/deadbeef (running kernel: kernel\nforged)",
                      "pve-manager/9.2.3/deadbeef (running kernel: kernel\x00forged)",
                      "pve-manager/9.2.3/deadbeef (running kernel: kernel forged)"):
            with self.assertRaises(ValueError):
                installer.pve_manager_version(value)

    def test_preparation_schema_cli_and_unavailable_summary_fail_closed(self):
        schema=json.loads((NIX/"proxmox/private-preparation-request.schema.json").read_bytes())
        self.assertFalse(schema["additionalProperties"]); self.assertEqual(schema["properties"]["protocol"]["const"],4)
        self.assertEqual(set(schema["required"]),{"format","protocol","requestedAt","plan","operatorGates"})
        request={"format":"home-lab-proxmox-private-preparation-request-v1","operatorGates":{"backupsConfirmed":False,
                 "consoleConfirmed":False,"lanRollbackConfirmed":False,"noConcurrentMutationConfirmed":True},
                 "plan":self.plan,"protocol":4,"requestedAt":self.plan["freshness"]["completedAt"]}
        invalid=copy.deepcopy(request); invalid["plan"]["observedState"]["domainStatuses"]["extra"]="complete"
        with tempfile.TemporaryDirectory() as name:
            document=Path(name)/"request.json"; document.write_text(json.dumps({"valid":request,"invalid":invalid}))
            result=__import__('subprocess').run(("node","-e",r'''
const fs=require('fs'),Ajv=require('ajv/dist/2020'); const root=process.argv[1],doc=JSON.parse(fs.readFileSync(process.argv[2]));
const ajv=new Ajv({strict:true}); ajv.addSchema(JSON.parse(fs.readFileSync(root+'/plan.schema.json')));
const validate=ajv.compile(JSON.parse(fs.readFileSync(root+'/private-preparation-request.schema.json')));
if(!validate(doc.valid)||validate(doc.invalid)) process.exit(1);
''',str(NIX/"proxmox"),str(document)),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        with patch.object(planner.sys,"argv",["proxmox-host","prepare","--repo-root","/tmp/repo","--plan-sha","0"*64,"--approve-plan-sha","0"*64,"--confirm-no-concurrent-mutation","--unknown"]),self.assertRaises(SystemExit):
            planner.parse_args()
        with patch.dict(self.preparer,{"runtime_state":lambda: (_ for _ in ()).throw(ValueError("unavailable"))}):
            value=self.preparer["summaries"]()
        self.assertEqual(value["protectedAccess"]["status"],"unavailable")
        self.assertIsNone(value["protectedHardware"]["matches"])

    def test_installer_rejects_traversal_unknown_oversize_and_models_crash_recovery(self):
        installer=load_installer()
        absent=lambda name:{"contentBase64":None,"name":name,"present":False,"sha256":None}
        generation={"format":"home-lab-proxmox-previous-v2","helpers":[absent(name) for name, _, _ in installer.managed_targets()],
                    "manifest":{"contentBase64":None,"present":False,"sha256":None}}
        base={"bundleContentSha256":"0"*64,"createdFirewallKey":False,"createdKey":False,"createdProtected":False,"createdProtectedMac":False,"firewallServiceBefore":{"enabled":{"home-lab-proxmox-firewall-config-recovery.service":False,"home-lab-proxmox-firewall-post-recovery.service":False,"home-lab-proxmox-firewall-rollback.timer":False},"timerActive":False},
              "format":"home-lab-proxmox-bootstrap-journal-v3","installed":[],"previous":generation,
              "rollbackCompleted":[],"state":"installing"}
        self.assertEqual(installer.validate_journal(copy.deepcopy(base)),base)
        for mutate in (
            lambda value:value["previous"]["helpers"][0].update(name="../../escape"),
            lambda value:value.update(unknown=True),
            lambda value:value["previous"]["helpers"][0].update(present=True,sha256="0"*64,
                contentBase64=__import__('base64').b64encode(b'x'*(installer.MAX_FILE+1)).decode()),
            lambda value:value.update(state="unknown"),
        ):
            bad=copy.deepcopy(base); mutate(bad)
            with self.assertRaises(ValueError): installer.validate_journal(bad)
        serialized=copy.deepcopy(base); serialized["previous"]["helpers"][0].update(present=True,contentBase64="A"*installer.MAX_JOURNAL,sha256="0"*64)
        with self.assertRaises(ValueError): installer.validate_journal(serialized)

    def test_strict_protected_parsers_reject_substrings_duplicates_and_injections(self):
        key = "ssh-ed25519 " + __import__('base64').b64encode(b'A'*32).decode()
        state={"access":{"applyKeys":[key+"\nssh-ed25519 bad"],"applyToken":"a@pve!x=s","applyTokenIdentity":"a@pve!x","firewallKeys":[key],
               "planKeys":[key],"planToken":"p@pve!x=s","planTokenIdentity":"p@pve!x"},
               "format":"home-lab-proxmox-protected-inputs-v1","hardware":{"gamesDiskIdentity":"/dev/disk/by-id/games",
               "poolGuid":"123","poolMembers":[f"/dev/disk/by-id/d{i}" for i in range(12)],
               "usbMappings":[{"mapping":"one","port":"1-2","serial":"a"},{"mapping":"two","port":"1-3","serial":"b"}]}}
        key_bytes = b"K" * 48
        state_mac = hmac.new(key_bytes, planner.canonical_json(state), hashlib.sha256).hexdigest() + "\n"
        with patch.dict(self.preparer,{"secure_json":lambda *args:state, "secure_key":lambda:key_bytes,
                                      "read_fixed":lambda *args,**kwargs:state_mac}),self.assertRaises(ValueError):
            self.preparer["runtime_state"]()
        duplicate=copy.deepcopy(state); other="ssh-ed25519 "+__import__('base64').b64encode(b'B'*32).decode(); duplicate["access"].update(applyKeys=[key+" apply-comment"],firewallKeys=[key+" firewall-comment"],planKeys=[other+" plan-comment"])
        installer=load_installer()
        with self.assertRaises(ValueError): installer.validate_protected(installer.canonical(duplicate))
        duplicate_mac=hmac.new(key_bytes,planner.canonical_json(duplicate),hashlib.sha256).hexdigest()+"\n"
        with patch.dict(self.preparer,{"secure_json":lambda *args:duplicate,"secure_key":lambda:key_bytes,"read_fixed":lambda *args,**kwargs:duplicate_mac}),self.assertRaises(ValueError): self.preparer["runtime_state"]()
        self.assertNotEqual(self.preparer["parse_qm_disk"](b"description: /dev/disk/by-id/games\n"),"/dev/disk/by-id/games")
        topology="\n".join([f"mirror-{i} ONLINE\n /dev/disk/by-id/d{i*2} ONLINE\n /dev/disk/by-id/d{i*2+1} ONLINE" for i in range(6)])
        self.assertEqual(len(self.preparer["parse_zfs_mirrors"](topology.encode())),6)
        with self.assertRaises(ValueError): self.preparer["parse_zfs_mirrors"]((topology+"\n /dev/disk/by-id/extra ONLINE").encode())
        self.assertFalse(self.preparer["pve_mapping_matches"]('{"map":[{"node":"proxmox","path":"1-2"},{"node":"proxmox","path":"1-2"}]}',"1-2"))
        device_id="a"*4+":"+"b"*4
        self.assertTrue(self.preparer["pve_mapping_matches"](
            json.dumps({"map":[f"id={device_id},node=proxmox,path=1-2"]}),"1-2"))
        self.assertFalse(self.preparer["pve_mapping_matches"](
            json.dumps({"map":[f"id={device_id},node=proxmox,path=1-2,extra=value"]}),"1-2"))
        self.assertFalse(self.preparer["pve_mapping_matches"](
            json.dumps({"map":["node=proxmox,path=1-2"]}),"1-2"))

    def test_udev_parser_accepts_only_unique_physical_usb_device_records(self):
        realistic = b"\n\n".join((
            b"P: /devices/pci0000:00/usb1/1-2\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-a",
            b"P: /devices/pci0000:00/usb1/1-2/1-2:1.0\nE: DEVTYPE=usb_interface\nE: ID_SERIAL_SHORT=opaque-a",
            b"P: /devices/pci0000:00/usb1/1-2/1-2:1.0/ttyUSB0\nE: DEVTYPE=tty\nE: ID_SERIAL_SHORT=opaque-a",
            b"P: /devices/pci0000:00/usb1/1-3\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-b",
            b"P: /devices/pci0000:00/usb1/1-4\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-a\nE: ID_SERIAL_SHORT=duplicate",
            b"P: /devices/pci0000:00/usb1/not-a-port\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-c",
        ))
        self.assertEqual(self.preparer["parse_udev"](realistic), [("opaque-a", "1-2"), ("opaque-b", "1-3")])
        duplicated_parent = realistic + b"\n\nP: /devices/pci0000:00/usb1/1-5\nE: DEVTYPE=usb_device\nE: ID_SERIAL_SHORT=opaque-a"
        resolved = [item for item in self.preparer["parse_udev"](duplicated_parent) if item[0] == "opaque-a"]
        self.assertEqual(resolved, [("opaque-a", "1-2"), ("opaque-a", "1-5")])

    def test_unavailable_protected_domains_are_deterministic_plan_blockers(self):
        observation=copy.deepcopy(self.observation)
        observation["domains"]["protectedAccess"]={"expectedCount":5,"matches":None,"observedCount":None,"status":"unavailable"}
        observation["domains"]["protectedHardware"]={"expectedCount":3,"matches":None,"observedCount":None,"status":"unavailable"}
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        plan=planner.build_plan(self.bindings,self.projection,self.manifest,observation,planner.format_time(now),planner.format_time(now+dt.timedelta(seconds=1)),False)
        self.assertEqual(plan["status"],"blocked")
        self.assertEqual({item["domain"] for item in plan["blockers"] if item["code"]=="observation-unavailable"},
                         {"protected-access","protected-hardware"})

    def test_preparer_plan_parser_rejects_schema_semantic_mutations(self):
        install={"bindings":self.plan["bindings"]}
        for mutate in (
            lambda value:value["observedState"]["domainStatuses"].update(extra="complete"),
            lambda value:value["findings"][0].update(detail=3),
            lambda value:value["actions"][0]["before"].update(extra=True),
            lambda value:value["bindings"].update(observerProtocol=True),
        ):
            changed=copy.deepcopy(self.plan); mutate(changed)
            action=changed["actions"][0]
            target=action["target"].get("path",action["target"].get("name"))
            action["preconditionSha256"]=planner.digest({"before":action["before"],"domain":action["domain"],"target":target})
            action["id"]=planner.digest({"after":action["after"],"before":action["before"],"domain":action["domain"],"kind":action["kind"],"target":target})
            action["postconditions"]=[{"expected":action["after"],"type":"state-equals"}]
            changed["planSha256"]=planner.digest({k:v for k,v in changed.items() if k!="planSha256"})
            with patch.dict(self.preparer,{"self_sha256":lambda:changed["bindings"]["privatePreparerSha256"]}),self.assertRaises(ValueError):
                self.preparer["validate_plan"](changed,{"bindings":changed["bindings"]})

    def test_plan_semantic_validator_rejects_every_issue_action_observed_and_binding_field(self):
        install={"bindings":self.plan["bindings"]}
        cases=[]
        issue=self.plan["findings"][0]
        invalid_issue={"code":"Upper","detail":3,"domain":3,"id":"bad","kind":"wrong","target":3}
        for field,bad in invalid_issue.items():
            changed=copy.deepcopy(self.plan); changed["findings"][0][field]=bad
            if field=="code":
                item=changed["findings"][0]; item["id"]=planner.digest({"code":item["code"],"domain":item["domain"],"target":item["target"]})
            cases.append(changed)
        changed=copy.deepcopy(self.plan); changed["findings"][0]["extra"]=True; cases.append(changed)
        for field in self.plan["actions"][0]:
            changed=copy.deepcopy(self.plan); changed["actions"][0][field]=None; cases.append(changed)
        for field in self.plan["observedState"]:
            changed=copy.deepcopy(self.plan); changed["observedState"][field]=None; cases.append(changed)
        for field in self.plan["bindings"]:
            changed=copy.deepcopy(self.plan); changed["bindings"][field]=None; cases.append(changed)
        for changed in cases:
            changed["planSha256"]=planner.digest({k:v for k,v in changed.items() if k!="planSha256"})
            with self.subTest(changed=next((k for k in changed if changed[k] is None),"nested")):
                with self.assertRaises((ValueError,TypeError,KeyError,AttributeError)):
                    planner.validate_plan(changed,self.projection,self.manifest)
                with patch.dict(self.preparer,{"self_sha256":lambda:self.plan["bindings"]["privatePreparerSha256"]}), \
                        self.assertRaises((ValueError,TypeError,KeyError,AttributeError)):
                    self.preparer["validate_plan"](changed,install)
        with tempfile.TemporaryDirectory() as name:
            document=Path(name)/"plans.json"; document.write_text(json.dumps(cases))
            result=__import__('subprocess').run(("node","-e",r'''
const fs=require('fs'),Ajv=require('ajv/dist/2020'); const schema=JSON.parse(fs.readFileSync(process.argv[1]));
const validate=new Ajv({strict:true,allErrors:true}).compile(schema); const docs=JSON.parse(fs.readFileSync(process.argv[2]));
for(const doc of docs) if(validate(doc)) throw new Error('mutated plan passed schema');
''',str(NIX/"proxmox/plan.schema.json"),str(document)),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_installer_lock_space_fault_and_previous_generation_recovery(self):
        installer=load_installer()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); lock=root/"operation.lock"
            real_fstat=os.fstat
            def root_info(fd):
                values=list(real_fstat(fd)); values[4]=0; values[5]=0; return os.stat_result(values)
            with patch.object(installer,"ensure_dir",return_value=None), \
                    patch.object(installer,"open_dir",side_effect=lambda path,mode=None,create=False: os.open(root,os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(installer.os,"fstat",side_effect=root_info):
                first=installer.acquire_lock(lock)
                try:
                    with self.assertRaises(BlockingIOError): installer.acquire_lock(lock)
                finally: os.close(first)
        helpers={name:b"new" for name in installer.HELPERS}
        generation={"format":"home-lab-proxmox-previous-v2",
                    "helpers":[{"contentBase64":None,"name":name,"present":False,"sha256":None} for name, _, _ in installer.managed_targets()],
                    "manifest":{"contentBase64":None,"present":False,"sha256":None}}
        with patch.object(installer,"reject_locks"),patch.object(installer,"capture",return_value=generation["helpers"]), \
                patch.object(installer,"capture_manifest",return_value=generation["manifest"]), \
                patch.object(installer,"firewall_service_state",return_value={"enabled": {unit: False for unit in ("home-lab-proxmox-firewall-config-recovery.service", "home-lab-proxmox-firewall-post-recovery.service", "home-lab-proxmox-firewall-rollback.timer")}, "timerActive": False}), \
                patch.object(installer.os,"stat",return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o700)), \
                patch.object(installer.shutil,"disk_usage",return_value=SimpleNamespace(free=0)), \
                patch.object(installer,"write_journal") as write:
            with self.assertRaisesRegex(ValueError,"free-space"): installer.install("a"*40,"b"*40,{},"c"*64,b"{}\n",helpers)
            write.assert_not_called()
        rolled=[]
        def secure_existing(path,mode,maximum=installer.MAX_FILE):
            if path==installer.SESSION_KEY:return b'K'*48
            if path==installer.PROTECTED:return b'protected'
            raise FileNotFoundError
        with patch.object(installer,"reject_locks"),patch.object(installer,"capture",return_value=generation["helpers"]), \
                patch.object(installer,"capture_manifest",return_value=generation["manifest"]), \
                patch.object(installer,"firewall_service_state",return_value={"enabled": {unit: False for unit in ("home-lab-proxmox-firewall-config-recovery.service", "home-lab-proxmox-firewall-post-recovery.service", "home-lab-proxmox-firewall-rollback.timer")}, "timerActive": False}), \
                patch.object(installer.os,"stat",return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o700)), \
                patch.object(installer.shutil,"disk_usage",return_value=SimpleNamespace(free=installer.MIN_FREE*4)), \
                patch.object(installer,"write_journal"),patch.object(installer,"ensure_dir"), \
                patch.object(installer,"exists_nofollow",return_value=True),patch.object(installer,"secure_file",side_effect=secure_existing), \
                patch.object(installer,"atomic",side_effect=OSError("injected rename/fsync boundary")), \
                patch.object(installer,"rollback",side_effect=lambda journal:rolled.append(copy.deepcopy(journal))):
            with self.assertRaises(OSError): installer.install("a"*40,"b"*40,{},"c"*64,b'protected',helpers)
        self.assertEqual(len(rolled),1)
        old=b"old-activator"; old_hash=hashlib.sha256(old).hexdigest()
        generation["helpers"][0]={"contentBase64":__import__('base64').b64encode(old).decode(),"name":"helper:proxmox-activator","present":True,"sha256":old_hash}
        raw_generation=planner.canonical_json(generation)
        raw_lock=planner.canonical_json({"activatorSha256":old_hash,"bundleContentSha256":"1"*64,"gitCommit":"2"*40,
            "gitTree":"3"*40,"hostSessionId":"session_01234567890","operation":"proxmox-guarded-apply",
            "planSha256":"4"*64,"startedAt":"2026-01-01T00:00:00Z"})
        restored=[]
        def secure(path,mode,maximum=installer.MAX_FILE):
            if path==installer.PREVIOUS:return raw_generation
            if path==installer.APPLY_LOCK:return raw_lock
            if path==installer.HELPER_ROOT/"proxmox-activator":return b"different"
            raise FileNotFoundError
        with patch.object(installer,"secure_file",side_effect=secure),patch.object(installer,"restore_generation",side_effect=lambda value:restored.append(value)):
            installer.recover_previous_active()
        self.assertEqual(restored,[generation])

    def test_recovery_diagnostic_is_closed_and_read_only(self):
        installer=load_installer()
        with patch.object(installer,"exists_nofollow",return_value=False):
            self.assertEqual(installer.diagnose_recovery(),"clear")
        with patch.object(installer,"exists_nofollow",side_effect=lambda path:path==installer.ANSIBLE_LOCK):
            self.assertEqual(installer.diagnose_recovery(),"ansible-ownership-active")
        source=(ROOT/"scripts/bootstrap-proxmox-nix-host").read_text()
        diagnostic=source[source.index("def diagnose_recovery():"):source.index("\ndef main():")]
        for forbidden in ("durable_unlink", "restore_generation", "atomic(", "os.unlink", "os.rename"):
            self.assertNotIn(forbidden,diagnostic)
        main=source[source.index("def main():"):]
        diagnostic_branch=main.index('if operation == "diagnose-recovery":')
        self.assertLess(diagnostic_branch,main.index("ensure_dir(BOOT"))
        self.assertLess(diagnostic_branch,main.index("acquire_lock(LOCK)"))
        self.assertNotIn("physical_console()",main[diagnostic_branch:main.index("ensure_dir(BOOT")])

    def test_bootstrap_failure_phases_are_closed(self):
        source=(ROOT/"scripts/bootstrap-proxmox-nix-host").read_text()
        expected=("bootstrap-directories", "bootstrap-lock", "operation-lock", "pending-reconciliation",
                  "recovery", "ownership-preflight", "host-preflight", "bundle-snapshot", "install-transaction")
        for phase in expected:
            self.assertIn(f'FAILURE_PHASE = "{phase}"',source)
        self.assertIn('print("proxmox-nix-bootstrap-failure=" + FAILURE_PHASE',source)
        self.assertNotIn("fixed operation failed",source)

    def test_fixed_lifecycle_tools_are_no_argument_gated_and_do_not_retain_old_keys(self):
        for name,gate in (("prepare-proxmox-nix-protected-inputs","PROXMOX_NIX_PROTECTED_CREATE_CONFIRMED"),
                          ("refresh-proxmox-nix-protected-inputs","PROXMOX_NIX_PROTECTED_REFRESH_CONFIRMED"),
                          ("rotate-proxmox-nix-session-key","PROXMOX_NIX_SESSION_KEY_ROTATE_CONFIRMED")):
            path=ROOT/"scripts"/name; source=path.read_text()
            self.assertTrue(os.access(path,os.X_OK)); self.assertIn(gate,source); self.assertNotIn("argparse",source)
        rotation_path=ROOT/"scripts/rotate-proxmox-nix-session-key"; rotation=rotation_path.read_text()
        self.assertIn("validate_retained",rotation); self.assertIn("os.urandom(48)",rotation)
        self.assertNotIn("old_key",rotation); self.assertNotIn("contentBase64",rotation)
        loader=importlib.machinery.SourceFileLoader("rotation_validation_test",str(rotation_path))
        spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)
        for journal,manifest in (({},{}),({"state":"released-committed"},{}),
                                 ({"state":"released-recovered","pendingTransition":None},{"actions":[]})):
            with self.assertRaises(ValueError): module.validate_retained("a"*64,journal,manifest)

    def test_exact_token_acl_and_complete_zfs_topology_attacks_are_rejected(self):
        acl = [{"path":"/", "propagate":1, "roleid":"HomeLabTofuApply", "ugid":"root@pam!tofu-apply"}]
        with patch.dict(self.preparer, {"run": lambda *args, **kwargs: b'{"privsep":1}\n'}):
            self.assertTrue(self.preparer["token_policy_valid"](
                "root@pam!tofu-apply=secret", "apply", acl, "root@pam!tofu-apply"))
            self.assertFalse(self.preparer["token_policy_valid"](
                "evil@pam!other=secret", "apply", acl, "root@pam!tofu-apply"))
            bad = copy.deepcopy(acl); bad[0]["propagate"] = 0
            self.assertFalse(self.preparer["token_policy_valid"](
                "root@pam!tofu-apply=secret", "apply", bad, "root@pam!tofu-apply"))
            duplicate = acl + copy.deepcopy(acl)
            self.assertFalse(self.preparer["token_policy_valid"](
                "root@pam!tofu-apply=secret", "apply", duplicate, "root@pam!tofu-apply"))
        members = [f"/dev/disk/by-id/d{i}" for i in range(12)]
        topology = "\n".join([f"mirror-{i} ONLINE\n {members[i*2]} ONLINE\n {members[i*2+1]} ONLINE" for i in range(6)])
        for suffix in ("\nlogs\n /dev/sdz ONLINE", "\ncache\n /dev/disk/by-id/cache ONLINE",
                       "\nspecial\n mirror-9 ONLINE\n /dev/disk/by-id/x ONLINE\n /dev/disk/by-id/y ONLINE"):
            with self.assertRaises(ValueError):
                self.preparer["parse_zfs_mirrors"]((topology + suffix).encode())

    def test_cross_authority_lock_order_rejects_both_race_orders(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); operation = root / "operation.lock"; nix = root / "apply.lock"; ansible = root / "ansible.lock"
            operation.touch(mode=0o600)
            # Nix persistent ownership first: Ansible's guarded critical section refuses it.
            nix.write_text("owned")
            guard_script = ('import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDWR); '
                            'fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); '
                            'sys.exit(1) if os.path.lexists(sys.argv[2]) else os.mkdir(sys.argv[3])')
            command = (sys.executable, "-c", guard_script, str(operation), str(nix), str(ansible))
            result = __import__('subprocess').run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(ansible.exists())
            nix.unlink(); ansible.mkdir()
            # Ansible persistent ownership first: both generated Nix authorities see it under the same mutex.
            self.assertTrue(self.preparer["persistent_exists"](ansible))
            rendered = bundle.expected_helper_content("proxmox-activator", self.projection)
            namespace = {"__name__":"fixed_activator_lock_test", "__file__":"/tmp/fixed-activator"}
            exec(compile(rendered, "fixed-activator", "exec"), namespace)
            self.assertTrue(namespace["persistent_exists"](ansible))
            fd = os.open(operation, os.O_RDWR)
            __import__('fcntl').flock(fd, __import__('fcntl').LOCK_EX | __import__('fcntl').LOCK_NB)
            try:
                blocked = __import__('subprocess').run((sys.executable,"-c",
                    'import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDWR); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)',
                    str(operation)),capture_output=True)
                self.assertNotEqual(blocked.returncode, 0)
            finally:
                os.close(fd)

    def test_terminal_install_recovery_finalizes_without_rollback_or_secret_deletion(self):
        installer = load_installer()
        absent = lambda name:{"contentBase64":None,"name":name,"present":False,"sha256":None}
        previous = {"format":"home-lab-proxmox-previous-v2", "helpers":[absent(name) for name, _, _ in installer.managed_targets()],
                    "manifest":{"contentBase64":None,"present":False,"sha256":None}}
        journal = {"bundleContentSha256":"c"*64,"createdFirewallKey":True,"createdKey":True,"createdProtected":True,"createdProtectedMac":True,"firewallServiceBefore":{"enabled":{"home-lab-proxmox-firewall-config-recovery.service":False,"home-lab-proxmox-firewall-post-recovery.service":False,"home-lab-proxmox-firewall-rollback.timer":False},"timerActive":False},
                   "format":"home-lab-proxmox-bootstrap-journal-v3","installed":[name for name, _, _ in installer.managed_targets()],
                   "previous":previous,"rollbackCompleted":[],"state":"installed"}
        helper_bytes = {name:("helper-"+name).encode() for name in installer.HELPERS}
        manifest = {"bindings":{},"bundleContentSha256":"c"*64,"firewallAssets":{},"format":"home-lab-proxmox-install-v2",
                    "gitCommit":"a"*40,"gitTree":"b"*40,
                    "helpers":{name:hashlib.sha256(raw).hexdigest() for name,raw in helper_bytes.items()}}
        key=b"K"*48; protected=b'{"access":{},"format":"x","hardware":{}}\n'
        mac=hmac.new(key,protected,hashlib.sha256).hexdigest().encode()+b"\n"
        mapping={installer.INSTALL_MANIFEST:installer.canonical(manifest),installer.SESSION_KEY:key,
                 installer.PROTECTED:protected,installer.PROTECTED_MAC:mac,installer.PREVIOUS:installer.canonical(previous),
                 **{installer.HELPER_ROOT/name:raw for name,raw in helper_bytes.items()}}
        removed=[]
        with patch.object(installer,"secure_file",side_effect=lambda path,*args,**kwargs:mapping[path]), \
                patch.object(installer,"validate_protected",return_value=protected), \
                patch.object(installer,"firewall_assets",return_value={}), \
                patch.object(installer,"verify_firewall_assets",return_value=None), \
                patch.object(installer,"durable_unlink",side_effect=lambda path,*args:removed.append(path)):
            installer.finalize_installed(copy.deepcopy(journal))
        self.assertEqual(removed,[installer.JOURNAL])
        with self.assertRaises(ValueError): installer.rollback(copy.deepcopy(journal))

    def test_sigkill_pending_boundaries_are_reconciled_and_rolled_back(self):
        installer = load_installer()
        absent = lambda name: {"contentBase64": None, "name": name, "present": False, "sha256": None}
        previous = {"format": "home-lab-proxmox-previous-v2", "helpers": [absent("helper:" + name) for name in installer.HELPERS],
                    "manifest": {"contentBase64": None, "present": False, "sha256": None}}
        base_journal = {"bundleContentSha256": "0" * 64, "createdFirewallKey": False, "createdKey": False, "createdProtected": False,
                        "createdProtectedMac": False, "firewallServiceBefore": {"enabled": {"home-lab-proxmox-firewall-config-recovery.service": False, "home-lab-proxmox-firewall-post-recovery.service": False, "home-lab-proxmox-firewall-rollback.timer": False}, "timerActive": False}, "format": "home-lab-proxmox-bootstrap-journal-v3",
                        "installed": [], "previous": previous, "rollbackCompleted": [], "state": "installing"}
        child = r'''
import importlib.machinery,importlib.util,os,signal,sys
from pathlib import Path
loader=importlib.machinery.SourceFileLoader("killed_installer",sys.argv[1]); spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec); loader.exec_module(m)
root=Path(sys.argv[2]); m.BOOT=root/"boot"; m.INCOMING=m.BOOT/"incoming"; m.RUNTIME=root/"runtime"
m.HELPER_ROOT=root/"helpers"; m.JOURNAL=m.BOOT/"install-journal.json"; m.PREVIOUS=m.BOOT/"previous-generation.json"
m.PROTECTED=m.RUNTIME/"protected-inputs.json"; m.PROTECTED_MAC=m.RUNTIME/"protected-inputs.mac"; m.SESSION_KEY=m.RUNTIME/"session.key"
m.INSTALL_MANIFEST=m.RUNTIME/"install-manifest.json"; m.PROTECTED_INCOMING=m.INCOMING/"protected-inputs.json"
m.OPERATION_LOCK=m.RUNTIME/"operation.lock"; m.APPLY_LOCK=m.RUNTIME/"apply.lock"
for p,mode in ((m.BOOT,0o700),(m.INCOMING,0o700),(m.RUNTIME,0o700),(m.HELPER_ROOT,0o755)): p.mkdir(parents=True,exist_ok=True,mode=mode); p.chmod(mode)
m.open_dir=lambda p,mode=None,create=False: os.open(p,os.O_RDONLY|os.O_DIRECTORY)
m.ensure_dir=lambda p,mode: (p.mkdir(parents=True,exist_ok=True),p.chmod(mode))
m.os.fchown=lambda *args: None
targets={"journal":m.JOURNAL,"incoming":m.PROTECTED_INCOMING,"key":m.SESSION_KEY,"protected":m.PROTECTED,"protected-mac":m.PROTECTED_MAC,
 "helper":m.HELPER_ROOT/m.HELPERS[0],"manifest":m.INSTALL_MANIFEST,"previous":m.PREVIOUS}
target=targets[sys.argv[3]]; payload=Path(sys.argv[4]).read_bytes(); original=m.os.rename
def die(*args,**kwargs): os.kill(os.getpid(),signal.SIGKILL)
m.os.rename=die
m.atomic(target,payload,0o755 if sys.argv[3]=="helper" else 0o600)
'''
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for directory, mode in ((root / "boot", 0o700), (root / "boot/incoming", 0o700),
                                    (root / "runtime", 0o700), (root / "helpers", 0o755)):
                directory.mkdir(parents=True, exist_ok=True, mode=mode); directory.chmod(mode)
            def configure(module):
                module.BOOT=root/"boot"; module.INCOMING=module.BOOT/"incoming"; module.RUNTIME=root/"runtime"
                module.HELPER_ROOT=root/"helpers"; module.JOURNAL=module.BOOT/"install-journal.json"
                module.PREVIOUS=module.BOOT/"previous-generation.json"; module.PROTECTED=module.RUNTIME/"protected-inputs.json"
                module.PROTECTED_MAC=module.RUNTIME/"protected-inputs.mac"; module.SESSION_KEY=module.RUNTIME/"session.key"
                module.INSTALL_MANIFEST=module.RUNTIME/"install-manifest.json"; module.PROTECTED_INCOMING=module.INCOMING/"protected-inputs.json"
                module.OPERATION_LOCK=module.RUNTIME/"operation.lock"
                module.APPLY_LOCK=module.RUNTIME/"apply.lock"; module.SNAPSHOT=module.BOOT/".verified-snapshot.pending"
            configure(installer)
            real_fstat, real_stat = os.fstat, os.stat
            def root_result(info):
                values=list(info); values[4]=0; values[5]=0; return os.stat_result(values)
            def patched_stat(*args, **kwargs): return root_result(real_stat(*args, **kwargs))
            payload = root / "payload"
            payload.write_bytes(installer.canonical(base_journal))
            result=subprocess.run((sys.executable,"-c",child,str(ROOT/"scripts/bootstrap-proxmox-nix-host"),str(root),"journal",str(payload)))
            self.assertEqual(result.returncode, -signal.SIGKILL)
            initial_targets = [("helper:" + name, installer.HELPER_ROOT / name, 0o755) for name in installer.HELPERS]
            with patch.object(installer,"managed_targets",return_value=initial_targets), \
                    patch.object(installer,"open_dir",side_effect=lambda path,mode=None,create=False:os.open(path,os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(installer,"ensure_dir",side_effect=lambda path,mode:(path.mkdir(parents=True,exist_ok=True),path.chmod(mode))), \
                    patch.object(installer.os,"fstat",side_effect=lambda fd:root_result(real_fstat(fd))), \
                    patch.object(installer.os,"stat",side_effect=patched_stat), patch.object(installer.os,"fchown",return_value=None):
                installer.reconcile_pending()
            self.assertEqual((root/"boot/install-journal.json").read_bytes(), installer.canonical(base_journal))
            for boundary in ("incoming", "key", "protected", "protected-mac", "helper", "manifest", "previous"):
                journal=copy.deepcopy(base_journal)
                if boundary=="key": journal["createdKey"]=True
                if boundary=="protected": journal["createdProtected"]=True
                if boundary=="protected-mac": journal["createdProtectedMac"]=True
                (root/"boot/install-journal.json").write_bytes(installer.canonical(journal)); (root/"boot/install-journal.json").chmod(0o600)
                payload.write_bytes(("opaque-secret-"+boundary).encode())
                result=subprocess.run((sys.executable,"-c",child,str(ROOT/"scripts/bootstrap-proxmox-nix-host"),str(root),boundary,str(payload)))
                self.assertEqual(result.returncode,-signal.SIGKILL,boundary)
                with patch.object(installer,"open_dir",side_effect=lambda path,mode=None,create=False:os.open(path,os.O_RDONLY|os.O_DIRECTORY)), \
                        patch.object(installer,"ensure_dir",side_effect=lambda path,mode:(path.mkdir(parents=True,exist_ok=True),path.chmod(mode))), \
                        patch.object(installer.os,"fstat",side_effect=lambda fd:root_result(real_fstat(fd))), \
                        patch.object(installer.os,"stat",side_effect=patched_stat), patch.object(installer.os,"fchown",return_value=None):
                    installer.reconcile_pending()
                    names = {record["name"] for record in journal["previous"]["helpers"]}
                    filtered = [item for item in installer.managed_targets() if item[0] in names]
                    with patch.object(installer,"managed_targets",return_value=filtered), \
                            patch.object(installer,"rollback_firewall_services",return_value=None):
                        installer.rollback(copy.deepcopy(journal))
                self.assertFalse(any(path.name.endswith(".bootstrap-pending") for path in root.rglob("*")), boundary)
                self.assertFalse((root/"boot/install-journal.json").exists(), boundary)
                for secret_path in (root/"runtime/session.key",root/"runtime/protected-inputs.json",root/"runtime/protected-inputs.mac"):
                    self.assertFalse(secret_path.exists(), boundary)
            unknown=root/"runtime/.attacker.bootstrap-pending"; unknown.write_bytes(b"opaque"); unknown.chmod(0o600)
            with patch.object(installer,"open_dir",side_effect=lambda path,mode=None,create=False:os.open(path,os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(installer,"ensure_dir",side_effect=lambda path,mode:(path.mkdir(parents=True,exist_ok=True),path.chmod(mode))), \
                    patch.object(installer.os,"fstat",side_effect=lambda fd:root_result(real_fstat(fd))), \
                    patch.object(installer.os,"stat",side_effect=patched_stat), self.assertRaisesRegex(ValueError,"unknown pending"):
                installer.reconcile_pending()
            unknown.unlink()

    def test_destination_space_is_gated_per_distinct_filesystem(self):
        installer=load_installer()
        previous={"format":"home-lab-proxmox-previous-v2","helpers":[],"manifest":{"contentBase64":None,"present":False,"sha256":None}}
        journal={"previous":previous}
        devices={installer.BOOT:1,installer.RUNTIME:2,installer.HELPER_ROOT:3}
        for failing in devices:
            queried=[]
            def usage(path):
                queried.append(path)
                return SimpleNamespace(free=0 if path==failing else 10**9)
            with patch.object(installer.os,"stat",side_effect=lambda path,**kwargs:SimpleNamespace(st_dev=devices[path],st_mode=stat.S_IFDIR|0o700)), \
                    patch.object(installer.shutil,"disk_usage",side_effect=usage), self.assertRaisesRegex(ValueError,"destination free-space"):
                installer.gate_destination_space(journal,b"protected",{name:b"helper" for name in installer.HELPERS})
            self.assertIn(failing, queried)
        queried=[]
        with patch.object(installer.os,"stat",side_effect=lambda path,**kwargs:SimpleNamespace(st_dev=devices[path],st_mode=stat.S_IFDIR|0o700)), \
                patch.object(installer.shutil,"disk_usage",side_effect=lambda path:(queried.append(path),SimpleNamespace(free=10**9))[1]):
            installer.gate_destination_space(journal,b"protected",{name:b"helper" for name in installer.HELPERS})
        self.assertEqual(set(queried),set(devices))

    def test_fresh_access_bootstrap_is_console_bound_closed_and_secret_safe(self):
        path=ROOT/"scripts/bootstrap-proxmox-nix-access"; source=path.read_text()
        access=load_access()
        self.assertTrue(os.access(path,os.X_OK))
        for control in ('/dev/tty[1-9][0-9]*', 'install-reviewed-access-authority',
                        'recover-reviewed-access-bootstrap', 'PVE token creation response differs',
                        'root@pam!tofu-plan', 'root@pam!tofu-apply', 'runtime.atomic(ESCROWS[principal]',
                        'refresh-reviewed-apply-role', 'recover-reviewed-role-refresh',
                        'role refresh permits only one reviewed privilege addition', 'role refresh exact before state differs',
                        'refresh-reviewed-qualification-acl', 'recover-reviewed-qualification-acl',
                        'qualification ACL exact before state differs', 'qualification ACL verification differs',
                        'refresh-reviewed-import-storage', 'recover-reviewed-import-storage',
                        'import storage exact before state differs', 'import storage verification differs'):
            self.assertIn(control,source)
        for forbidden in ('argparse', '--path', '--host', 'print(result["value"]'):
            self.assertNotIn(forbidden,source.lower())
        self.assertIn('<install|converge|refresh-role|refresh-qualification-acl|refresh-import-storage|recover>',source)
        self.assertIn('converge-reviewed-legacy-access-authority',source)
        self.assertIn('legacy apply authority differs',source)
        self.assertIn('home-lab-proxmox-access-converge-v1',source)
        self.assertIn('home-lab-proxmox-access-role-refresh-v1',source)
        self.assertIn('home-lab-proxmox-access-qualification-acl-v1',source)
        self.assertIn('base64.b64decode(previous["keys"]',source)
        docs=(ROOT/"docs/proxmox-bootstrap.md").read_text()
        self.assertIn("deterministic manual assertion boundary",docs)
        self.assertIn("scripts/bootstrap-proxmox-nix-access install",docs)
        desired=["Datastore.Allocate", "SDN.Audit", "SDN.Use", "VM.Audit"]
        self.assertEqual(access.role_refresh_previous(desired), ["SDN.Audit", "SDN.Use", "VM.Audit"])
        with self.assertRaises(ValueError): access.role_refresh_previous(["SDN.Audit", "VM.Audit"])
        journal={"completed":False,"format":access.ROLE_REFRESH_FORMAT,
                 "previousPrivileges":["SDN.Audit","SDN.Use","VM.Audit"],"role":access.APPLY_ROLE}
        self.assertEqual(access.validate_role_refresh_journal(journal),journal)
        with self.assertRaises(ValueError): access.validate_role_refresh_journal({**journal,"role":"evil"})

    def test_user_owned_ssh_helpers_enforce_real_uid_gid_modes_links_and_no_follow(self):
        access=load_access()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); ssh=root/".ssh"; access.user_directory(ssh,os.getuid(),os.getgid(),0o700)
            target=ssh/"authorized_keys"; access.user_file_write(target,b"key\n",os.getuid(),os.getgid())
            self.assertEqual(access.user_file_read(target,os.getuid(),os.getgid(),0o600),b"key\n")
            with self.assertRaises(ValueError): access.user_file_read(target,os.getuid()+1,os.getgid(),0o600)
            target.chmod(0o644)
            with self.assertRaises(ValueError): access.user_file_read(target,os.getuid(),os.getgid(),0o600)
            target.unlink(); target.symlink_to("/dev/null")
            with self.assertRaises(OSError): access.user_file_read(target,os.getuid(),os.getgid(),0o600)
            target.unlink()
            pending=access.runtime.pending_path(target)
            real_rename=os.rename
            with patch.object(access.os,"rename",side_effect=OSError("injected crash boundary")), self.assertRaises(OSError):
                access.user_file_write(target,b"pending\n",os.getuid(),os.getgid())
            self.assertTrue(pending.exists())
            access.user_file_unlink(pending,os.getuid(),os.getgid(),False)
            self.assertFalse(pending.exists())
            access.user_file_write(target,b"retry\n",os.getuid(),os.getgid())
            self.assertEqual(access.user_file_read(target,os.getuid(),os.getgid(),0o600),b"retry\n")

    def test_access_pending_reconciliation_promotes_journal_and_removes_every_target_remnant(self):
        access=load_access()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); access.JOURNAL=root/"access-journal.json"; access.ESCROWS={"plan":root/"plan.env","apply":root/"apply.env"}
            access.runtime.HELPER_ROOT=root/"helpers"; access.runtime.BOOT=root; access.runtime.FIREWALL_TARGETS={}
            sudo=root/"sudo"; auth=root/"authorized_keys"
            projection={"accounts":{"service":[],"human":[]}}
            journal={"accounts":["tofu-plan","tofu-apply","firewall-apply","proxmox"],"completed":[],"format":access.FORMAT,
                     "roles":[],"state":"applying","tokens":[access.TOKEN_ID["plan"],access.TOKEN_ID["apply"]]}
            pending_journal=access.runtime.pending_path(access.JOURNAL); pending_journal.write_bytes(access.canonical(journal)); pending_journal.chmod(0o600)
            pending_sudo=access.runtime.pending_path(sudo); pending_sudo.write_bytes(b"partial"); pending_sudo.chmod(0o600)
            with patch.object(access,"access_targets",return_value={access.JOURNAL,sudo,auth}), \
                    patch.object(access,"account_spec",side_effect=StopIteration), \
                    patch.object(access.runtime,"secure_file",side_effect=lambda path,*args,**kwargs:path.read_bytes()),  \
                    patch.object(access.runtime,"open_dir",side_effect=lambda path,mode=None,create=False:os.open(path,os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(access.runtime,"exists_nofollow",side_effect=lambda path:path.exists()), \
                    patch.object(access.runtime,"durable_unlink",side_effect=lambda path,*args:path.unlink()):
                with patch.object(access,"KEY_INPUTS",{}): access.reconcile_pending(projection)
            self.assertTrue(access.JOURNAL.exists()); self.assertFalse(pending_journal.exists()); self.assertFalse(pending_sudo.exists())

    def test_access_atomic_sigkill_leaves_only_deterministic_reconcilable_pending_name(self):
        child=r'''
import importlib.machinery,importlib.util,os,signal,sys
from pathlib import Path
loader=importlib.machinery.SourceFileLoader("access_kill",sys.argv[1]); spec=importlib.util.spec_from_loader(loader.name,loader)
a=importlib.util.module_from_spec(spec); loader.exec_module(a); target=Path(sys.argv[2]); target.parent.mkdir(parents=True,exist_ok=True)
a.runtime.open_dir=lambda p,mode=None,create=False:os.open(p,os.O_RDONLY|os.O_DIRECTORY)
a.runtime.ensure_dir=lambda p,mode:None; a.runtime.os.fchown=lambda *args:None
a.runtime.os.rename=lambda *args,**kwargs:os.kill(os.getpid(),signal.SIGKILL)
a.runtime.atomic(target,b"journal",0o600)
'''
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            for relative in ("access-journal.json", "plan-token.env", "sudoers/tofu-apply", "home/.ssh/authorized_keys"):
                target=root/relative
                result=subprocess.run((sys.executable,"-c",child,str(ROOT/"scripts/bootstrap-proxmox-nix-access"),str(target)))
                self.assertEqual(result.returncode,-signal.SIGKILL,relative)
                self.assertFalse(target.exists(),relative)
                pending=target.parent/("."+target.name+".bootstrap-pending")
                self.assertTrue(pending.exists(),relative); pending.unlink()

    def test_apply_transport_rejects_arbitrary_commands_and_accepts_only_exact_fixed_operations(self):
        transport=ROOT/"infrastructure/proxmox-firewall/host/proxmox-apply-transport"
        env={**os.environ,"SSH_ORIGINAL_COMMAND":"uname -a"}
        rejected=subprocess.run((transport,"-c","/usr/local/libexec/home-lab/proxmox-apply-transport"),env=env,capture_output=True)
        self.assertEqual(rejected.returncode,64)
        source=transport.read_text()
        self.assertIn("proxmox-private-preparer prepare",source)
        self.assertIn("proxmox-activator session",source)
        self.assertNotIn("bash",source); self.assertNotIn("$@",source)

    def test_absent_firewall_units_allow_bounded_systemctl_stderr_and_key_pending_is_reconciled(self):
        installer=load_installer(); calls=[]
        class Result:
            returncode=1; stderr=b"unit absent"; stdout=b""
        with patch.object(installer.subprocess,"run",side_effect=lambda *args,**kwargs:(calls.append(args[0]),Result())[1]):
            result=installer.systemctl("is-enabled","missing.service",allowed=(0,1),permit_stderr=True)
        self.assertEqual(result.returncode,1); self.assertEqual(len(calls),1)
        self.assertIn(installer.pending_path(installer.FIREWALL_KEY),installer.pending_targets())

    def test_fixed_access_and_firewall_assets_are_in_transactional_bootstrap_surface(self):
        installer=load_installer()
        expected={"proxmox-firewall-transaction.py","proxmox-firewall-transport","proxmox-apply-transport","proxmox-ansible-plan-transport",
                  "proxmox-ansible-deploy-transport","proxmox-ansible-deploy-activator","proxmox-firewall-boot-recovery",
                  "proxmox-firewall-policy.json","50-home-lab-firewall-recovery.conf",
                  *installer.FIREWALL_UNITS}
        self.assertEqual({source.name for source, _ in installer.FIREWALL_TARGETS.values()},expected)
        source=(ROOT/"scripts/bootstrap-proxmox-nix-host").read_text()
        for control in ("createdFirewallKey", "firewallServiceBefore", "configure_firewall_services",
                        "rollback_firewall_services", "verify_firewall_assets"):
            self.assertIn(control,source)
        self.assertFalse((ROOT/"ansible/roles/proxmox_firewall").exists())

    def test_firewall_policy_is_recursively_canonical(self):
        path=ROOT/"infrastructure/proxmox-firewall/host/proxmox-firewall-policy.json"
        raw=path.read_bytes(); value=json.loads(raw)
        expected=(json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True)+"\n").encode()
        self.assertEqual(raw,expected)

    def test_contract_closes_apply_and_forces_both_service_identities(self):
        contract=(ROOT/"infrastructure/contract/home-lab.yml").read_text()
        self.assertIn('tofu-apply ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-private-preparer prepare, /usr/local/libexec/home-lab/proxmox-activator session',contract)
        self.assertIn('restrict,command="/usr/local/libexec/home-lab/proxmox-apply-transport"',contract)
        self.assertNotIn('tofu-apply ALL=(root) NOPASSWD: ALL',contract)
        self.assertIn('tofu-plan ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-observer observe',contract)
        self.assertIn('restrict,command="sudo -n -- /usr/local/libexec/home-lab/proxmox-observer observe"',contract)
        self.assertIn('      - /usr/local/libexec/home-lab',contract)
        transport=(ROOT/"infrastructure/proxmox-firewall/host/proxmox-apply-transport").read_text()
        self.assertIn("SSH_ORIGINAL_COMMAND",transport); self.assertIn("proxmox-activator session",transport)
        self.assertNotIn("$@",transport)
        self.assertFalse((ROOT/"ansible/roles/proxmox_host").exists())
        self.assertFalse((ROOT/"ansible/playbooks/proxmox-site.yml").exists())


if __name__ == "__main__": unittest.main()
