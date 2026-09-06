#!/usr/bin/env python3
"""Offline fixtures only: SSH is always mocked, with no host or credential reads."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("maintenance_launcher", ROOT / "scripts/maintenance-launcher.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
NOW = "2026-09-05T12:00:00Z"


class MaintenanceLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.key = b"synthetic public host key bytes"
        import base64
        self.fingerprint = "SHA256:"+base64.b64encode(__import__("hashlib").sha256(self.key).digest()).decode().rstrip("=")
        self.c = {"reviewed_commit":"a"*40,"contract_sha256":"b"*64,"repository":str(ROOT),"node":subprocess.check_output(["/usr/bin/which","node"],text=True).strip(),"known_hosts":"/protected/known","capability_evidence":"/protected/attestation","hosts":{h:{"inventory_sha256":"c"*64,"host_key_fingerprint":self.fingerprint} for h in ("debian","proxmox")},"challenge_capabilities":{h:{"known_hosts":"/protected/"+h,"attestation":"/protected/"+h+"-proof","package_artifact":"/protected/"+h+"-package"} for h in ("debian","proxmox")},"output":str(self.directory),"inputs":str(self.directory)}
        self.wire={"format":"home-lab-maintenance-observation-v1","host":"debian","nonce":"d"*64,"source_commit":"a"*40,"contract_sha256":"b"*64,"observed_at":NOW,"producer_sha256":"e"*64,"package_sha256":"1"*64,"transport_sha256":"2"*64,"package":{"proposal":{"host":"debian","observed_at":NOW}},"reboot":{"required":None,"backup_proven":False},"active_locks":[],**m.FLAGS}

        self.proof={field:self.wire[field] for field in ("producer_sha256","package_sha256","transport_sha256")}

    def test_wire_positive_and_unknown_reboot(self):
        m.validate_wire(self.wire,self.c,"debian","d"*64,self.proof,NOW,NOW)
        later=copy.deepcopy(self.wire);later["observed_at"]="2026-09-05T12:00:01Z"
        m.validate_wire(later,self.c,"debian","d"*64,self.proof,NOW,"2026-09-05T12:00:01Z")
        self.assertEqual(later["package"]["proposal"]["observed_at"],NOW)

    def test_wire_binding_authority_unknown_fields_and_locks(self):
        for field,value in [("nonce","f"*64),("source_commit","f"*40),("contract_sha256","f"*64),("host","proxmox"),("producer_sha256","f"*64),("package_sha256","f"*64),("transport_sha256","f"*64),("observed_at","2026-09-05T12:00:01Z"),("authorized",True),("automatic_apply",True),("automatic_reboot",True),("automatic_retry_allowed",True),("active_locks",["observation-unavailable"]),("active_locks",["backup"]),("extra","secret")]:
            wire=copy.deepcopy(self.wire);wire[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                m.validate_wire(wire,self.c,"debian","d"*64,self.proof,NOW,NOW)

    def test_wire_timeout_package_time_and_backup_claim(self):
        with self.assertRaises(ValueError):
            m.validate_wire(self.wire,self.c,"debian","d"*64,self.proof,NOW,"2026-09-05T12:02:01Z")
        for modify in (lambda w:w["package"]["proposal"].update(host="proxmox"),lambda w:w["package"]["proposal"].update(observed_at="2026-09-05T11:59:59Z"),lambda w:w["reboot"].update(backup_proven=True),lambda w:w["reboot"].update(required=1)):
            wire=copy.deepcopy(self.wire);modify(wire)
            with self.assertRaises(ValueError):m.validate_wire(wire,self.c,"debian","d"*64,self.proof,NOW,NOW)

    def test_fixed_transport_arguments(self):
        for host,target in (("debian","docker-host"),("proxmox","proxmox")):
            argv=m.ssh_argv(self.c,host,"d"*64)
            self.assertEqual(argv[-5:],["ansible-maintenance-plan@"+target,"observe","d"*64,"a"*40,"b"*64])
            for expected in ("StrictHostKeyChecking=yes","IdentityAgent=none","PasswordAuthentication=no","PubkeyAuthentication=no","ConnectionAttempts=1","GlobalKnownHostsFile=/dev/null","ProxyCommand=none"):
                self.assertIn(expected,argv)
            self.assertNotIn("sudo",argv);self.assertNotIn("ansible-deploy",str(argv))
        self.assertEqual(m.ssh_argv(self.c)[-2:],["ansible-plan@proxmox","observe-package"])

    def test_mocked_challenge_transport_both_hosts(self):
        import base64
        for host,target in (("debian","docker-host"),("proxmox","proxmox")):
            wire=copy.deepcopy(self.wire);wire["host"]=host;wire["package"]["proposal"]["host"]=host;wire["producer_sha256"]=m.sha(b"producer")
            proof={"format":"home-lab-maintenance-challenge-installation-v1","source_commit":"a"*40,"contract_sha256":"b"*64,"host":host,"host_key_fingerprint":self.fingerprint,"observed_at":NOW,"expires_at":m.expires(NOW),"producer_sha256":m.sha(b"producer"),"package_sha256":m.sha(b"package"),"transport_sha256":m.sha(b"transport"),"audit_sha256":"2"*64,"complete_audit":True,"active_locks":[]}
            wire["package_sha256"]=proof["package_sha256"];wire["transport_sha256"]=proof["transport_sha256"]
            files={"/protected/"+host+"-package":b"package","/protected/"+host+"-proof":m.canonical(proof),"/protected/"+host:(target+" ssh-ed25519 "+base64.b64encode(self.key).decode()+"\n").encode(),str(ROOT/"infrastructure/maintenance/host/maintenance-read-only-observer"):b"producer",str(ROOT/"infrastructure/maintenance/host/maintenance-plan-transport"):b"transport"}
            with patch.object(m,"regular",side_effect=lambda p,*args:files[str(p)]),patch.object(m,"stamp",return_value=NOW),patch.object(m.secrets,"token_hex",return_value="d"*64),patch.object(m,"bounded",return_value=m.canonical(wire)) as transport,patch.object(m,"node",return_value={"proposal":{},"candidate":None}):
                records=m.challenge_collect(self.c,host,NOW)
                self.assertEqual(transport.call_count,1)
                self.assertEqual(transport.call_args.args[0][-5:],m.ssh_argv(self.c,host,"d"*64)[-5:])
                self.assertEqual(records["package"]["provenance"],"challenge-verified")
                self.assertEqual(records["reboot"]["payload"]["required"],None)
                self.assertEqual(records["package"]["evidence_sha256"],m.sha(m.canonical(wire)))
            for component in ("package_sha256","transport_sha256"):
                swapped=copy.deepcopy(wire);swapped[component]="f"*64
                with patch.object(m,"regular",side_effect=lambda p,*args:files[str(p)]),patch.object(m,"stamp",return_value=NOW),patch.object(m.secrets,"token_hex",return_value="d"*64),patch.object(m,"bounded",return_value=m.canonical(swapped)),self.assertRaises(m.CollectionFailure):m.challenge_collect(self.c,host,NOW)
            files["/protected/"+host+"-package"]=b"swapped-package"
            with patch.object(m,"regular",side_effect=lambda p,*args:files[str(p)]),patch.object(m,"bounded") as transport,self.assertRaises(ValueError):m.challenge_collect(self.c,host,NOW)
            transport.assert_not_called();files["/protected/"+host+"-package"]=b"package"
            files["/protected/"+host+"-proof"]=m.canonical({**proof,"source_commit":"f"*40})
            with patch.object(m,"regular",side_effect=lambda p,*args:files[str(p)]),patch.object(m,"bounded") as transport,self.assertRaises(ValueError):m.challenge_collect(self.c,host,NOW)
            transport.assert_not_called()

    def test_read_identity_ignores_atime_but_preserves_nanosecond_race_checks(self):
        from types import SimpleNamespace
        p = self.directory / "identity"
        p.write_bytes(b"fixture\n"); p.chmod(0o600)
        before = p.stat()
        values = {name: getattr(before, name) for name in dir(before) if name.startswith("st_")}
        access = SimpleNamespace(**{**values, "st_atime": before.st_atime + 1, "st_atime_ns": before.st_atime_ns + 1000000000})
        with patch.object(m, "parents"), patch.object(m.os, "fstat", side_effect=[before, access]), \
                patch.object(Path, "lstat", return_value=access):
            self.assertEqual(m.regular(p), b"fixture\n")
        for field in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"):
            changed = SimpleNamespace(**{**values, field: values[field] + 1})
            for pathname_only in (False, True):
                with self.subTest(field=field, pathname_only=pathname_only), patch.object(m, "parents"), \
                        patch.object(m.os, "fstat", side_effect=[before, before if pathname_only else changed]), \
                        patch.object(Path, "lstat", return_value=changed), self.assertRaises(ValueError):
                    m.regular(p)

    def test_protected_input_regular_symlink_hardlink_fifo_mode(self):
        p=self.directory/"input";p.write_bytes(b'{}\n');p.chmod(0o600)
        self.assertEqual(m.parse(m.regular(p)),{})
        link=self.directory/"link";link.symlink_to(p)
        with self.assertRaises(OSError):m.regular(link)
        hard=self.directory/"hard";os.link(p,hard)
        with self.assertRaises(ValueError):m.regular(p)
        hard.unlink();p.chmod(0o644)
        with self.assertRaises(ValueError):m.regular(p)
        fifo=self.directory/"fifo";os.mkfifo(fifo,0o600)
        with self.assertRaises(ValueError):m.regular(fifo)

    def test_canonical_duplicate_oversize_and_secret_errors(self):
        for raw in (b'{"x":1,"x":2}\n',b'{ "x": 1 }\n'):
            with self.assertRaises(ValueError):m.parse(raw)
        p=self.directory/"large";p.write_bytes(b'x'*(m.MAX+1));p.chmod(0o600)
        with self.assertRaises(ValueError):m.regular(p)

    def test_bounded_process_failure_timeout_output(self):
        self.assertEqual(m.bounded([sys.executable,"-I","-c","print('fixture')"]),b'fixture\n')
        for code in ("import sys;sys.exit(1)","import sys;sys.stderr.write('not exposed')","print('x'*1048577)"):
            with self.assertRaises(ValueError):m.bounded([sys.executable,"-I","-c",code])
        with self.assertRaises(ValueError):m.bounded([sys.executable,"-I","-c","import time;time.sleep(5)"],timeout=0.05)

    def test_receipts_are_append_only_and_failed_collection_retained(self):
        receipt=m.receipt(self.c,"debian","package",NOW,{"failure":"transport-failed"},"failed-collection","0"*64)
        m.save(self.c,receipt,"input");before=list(self.directory.iterdir());m.save(self.c,receipt,"input")
        self.assertEqual(before,list(self.directory.iterdir()))
        self.assertEqual(m.parse(m.regular(before[0])),receipt)
        self.assertEqual(os.stat(before[0]).st_mode & 0o777,0o600)
        m.save(self.c,m.receipt(self.c,"debian","package","2026-09-05T12:01:00Z",{"failure":"capability-unavailable"},"failed-collection","0"*64),"input")
        self.assertEqual(len(list(self.directory.iterdir())),2)

    def test_partial_failed_challenge_never_falls_back(self):
        def render(c,script,value):
            if script=="maintenance-report.js":return {"report_sha256":"e"*64,"complete":False,"records":value["records"]}
            raise AssertionError("unexpected command")
        with patch.object(m,"challenge_collect",side_effect=ValueError),patch.object(m,"bounded") as transport,patch.object(m,"node",side_effect=render),patch.object(m,"stamp",return_value=NOW),patch("builtins.print"):
            m.collect(self.c)
        transport.assert_not_called()
        report=m.parse(m.regular(next(self.directory.glob("report-*.json"))))
        failures=report["records"]
        self.assertEqual(len(failures),4)
        self.assertTrue(all(r["payload"]["failure"]=="prerequisite-invalid" for r in failures))
        self.assertEqual(len(list(self.directory.glob("attempt-*.json"))),2)

    def test_malformed_local_slots_preserve_real_partial_report(self):
        pins = {name: {"covered": True, "sha256": "1" * 64} for name in
                ("cloud_image", "standalone_tools", "ansible_collections", "opentofu_providers")}
        valid = m.receipt(self.c, "debian", "pins", NOW, pins, "reviewed-local-input", "2" * 64)
        wrong_host = {**valid, "host": "proxmox", "topic": "release"}
        cases = [{}, None, wrong_host, valid, {**valid, "topic": "release", "source_commit": "f" * 40}]
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                directory = self.directory / str(index); directory.mkdir(mode=0o700)
                c = {**self.c, "inputs": str(directory), "output": str(directory)}
                raw = m.canonical(value)
                for filename, content in (("debian-release.json", raw), ("debian-pins.json", m.canonical(valid))):
                    path = directory / filename; path.write_bytes(content); path.chmod(0o600)

                def challenged(config, host, now):
                    return {
                        "package": m.receipt(config, host, "package", now, {"failure": "capability-unavailable"}, "failed-collection", "0" * 64),
                        "reboot": m.receipt(config, host, "reboot", now, {"required": False, "backup_proven": False}, "challenge-verified", "3" * 64),
                    }

                # Only host transport is replaced. Node aggregation, local file
                # reading, validation and append-only receipts execute for real.
                with patch.object(m, "challenge_collect", side_effect=challenged), patch.object(m, "stamp", return_value=NOW), patch("builtins.print"):
                    m.collect(c)
                report = m.parse(m.regular(next(directory.glob("report-*.json"))))
                entries = {(e["host"], e["topic"]): e for e in report["entries"]}
                failed = entries[("debian", "release")]
                self.assertEqual(failed["status"], "failed")
                self.assertEqual(failed["detail"], "invalid-output")
                self.assertEqual(failed["evidence_sha256"], m.sha(raw))
                self.assertEqual(entries[("debian", "pins")]["freshness"], "fresh")
                self.assertEqual(entries[("proxmox", "reboot")]["values"]["required"], False)
                retained = [m.parse(m.regular(p)) for p in directory.glob("input-*.json")]
                self.assertTrue(any(r["host"] == "debian" and r["topic"] == "release" and r["evidence_sha256"] == m.sha(raw) for r in retained))
                self.assertEqual(len(list(directory.glob("attempt-*.json"))), 2)

    def test_reviewed_config_source_and_dry_run(self):
        location=patch.object(m,"__file__","/protected/maintenance-launcher.py");location.start();self.addCleanup(location.stop)
        c=json.loads((ROOT/"infrastructure/maintenance/mac/controller.example.json").read_bytes())
        c.update(repository=str(ROOT),inputs=str(self.directory),output=str(self.directory),reviewed_commit="a"*40,launcher_sha256=m.sha(b"launcher"),node_sha256=m.sha(b"node"),python_sha256=m.sha(b"python"),contract_sha256=m.sha(b"contract"))
        for h in c["hosts"].values():h["inventory_sha256"]=m.sha(b"inventory")
        def read(path,*args):
            name=str(path)
            if name=="/config":return m.canonical(c)
            if name==str(Path(m.__file__).absolute()) or name.endswith("scripts/maintenance-launcher.py"):return b"launcher"
            if name==c["node"]:return b"node"
            if name==c["python"]:return b"python"
            if name.endswith("home-lab.yml"):return b"contract"
            if name.endswith("home-lab.maintenance.plist"):return (ROOT/"infrastructure/maintenance/mac/home-lab.maintenance.plist").read_bytes()
            return b"inventory"
        def git(argv):
            if "show" in argv:return read(ROOT/argv[-1].split(":",1)[1])
            if "rev-parse" in argv:return b"a"*40+b"\n"
            return b""
        with patch.object(m,"regular",side_effect=read),patch.object(m,"bounded",side_effect=git):
            self.assertEqual(m.validate_config(Path("/config")),c)
        with patch.object(m,"regular",side_effect=read),patch.object(m,"bounded",side_effect=lambda argv: b"altered" if "show" in argv else git(argv)),self.assertRaises(ValueError):m.validate_config(Path("/config"))
        for responses in ([b"f"*40+b"\n"],[b"a"*40+b"\n",b" M unreviewed.py\n"]):
            with patch.object(m,"regular",side_effect=read),patch.object(m,"bounded",side_effect=responses),self.assertRaises(ValueError):m.validate_config(Path("/config"))
        import io
        stdout=io.TextIOWrapper(io.BytesIO())
        with patch.object(m,"validate_config",return_value=c),patch.object(m,"regular",side_effect=read),patch.object(m,"bounded") as command,patch.object(m.sys,"argv",["launcher","--config","/config","--dry-run"]),patch.object(m.sys,"stdout",stdout):
            m.main();xml=stdout.buffer.getvalue()
        command.assert_not_called()
        plist=plistlib.loads(xml)
        self.assertEqual(plist["ProgramArguments"][-1],"--collect")
        self.assertEqual(plist["ProgramArguments"][0],c["python"])
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_existing_controller_descriptor_lock_integration(self):
        import shutil
        repo=self.directory/"repo";repo.mkdir(mode=0o700)
        for name in ("scripts/controller/controller-apply-lock.py","scripts/controller/controller_lock.py"):
            destination=repo/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,destination)
        c={**self.c,"repository":str(repo),"python":sys.executable}
        driver=self.directory/"driver.py"
        driver.write_text("import importlib.util,sys\n"+f"s=importlib.util.spec_from_file_location('launcher',{str(ROOT/'scripts/maintenance-launcher.py')!r});m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"+f"m.validate_config=lambda p:{c!r}\n"+"m.collect=lambda c:print('locked-fixture-only')\nm.main()\n")
        argv=[sys.executable,"-I",str(repo/"scripts/controller/controller-apply-lock.py"),"run","--repo-root",str(repo),"--commit","a"*40,"--phase","steady","--",sys.executable,"-I",str(driver),"--config","/unused","--locked"]
        result=subprocess.run(argv,capture_output=True,text=True,env=m.ENV,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,"locked-fixture-only\n")
        lock=repo/".reconcile/controller-apply.lock";inode=lock.stat().st_ino
        result=subprocess.run(argv,capture_output=True,text=True,env=m.ENV,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(lock.stat().st_ino,inode)
        spoof=subprocess.run([sys.executable,"-I",str(driver),"--config","/unused","--locked"],capture_output=True,text=True,env={**m.ENV,"RECONCILE_CONTROLLER_LOCK_FD":"999","RECONCILE_CONTROLLER_LOCK_TOKEN":"f"*64},timeout=10)
        self.assertNotEqual(spoof.returncode,0);self.assertNotIn("locked-fixture-only",spoof.stdout)

    def test_launchagent_no_install_no_retry(self):
        value=plistlib.loads((ROOT/"infrastructure/maintenance/mac/home-lab.maintenance.plist").read_bytes())
        self.assertNotIn("KeepAlive",value);self.assertNotIn("RunAtLoad",value)
        self.assertEqual(value["StartCalendarInterval"],{"Hour":6,"Minute":17})
        self.assertFalse(value["ProcessType"]=="Interactive")
        source=(ROOT/"scripts/maintenance-launcher.py").read_text()
        self.assertNotIn("launchctl",source)
        self.assertIn('"RECONCILE_CONTROLLER_LOCK_FD"',source)
        self.assertIn('"core.fsmonitor=false"',source)
        self.assertIn('"--porcelain=v1"',source)
        self.assertIn('"scripts/controller/controller-apply-lock.py"',source)


if __name__=="__main__":unittest.main()
