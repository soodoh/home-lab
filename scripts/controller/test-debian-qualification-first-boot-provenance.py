#!/usr/bin/env python3
"""Synthetic first-boot producer, receipt-chain and publication regressions."""
import copy
import importlib.util
import io
import json
import os
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("first_boot_fixtures", ROOT / "scripts/controller/test-debian-qualification-first-boot.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
controller = fixtures.controller_module
helper = fixtures.helper
OBSERVATION = fixtures.value
REVISION = "a" * 40


def envelope(request):
    return {"format": "home-lab-debian-qualification-first-boot-envelope-v1", "request": copy.deepcopy(request), "producer": copy.deepcopy(request["producer"]), "snippet": copy.deepcopy(request["snippet"]), "booted_snippet_sha256": request["snippet"]["sha256"], "observation": copy.deepcopy(OBSERVATION)}


class FirstBootProvenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".local")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "lifecycle"
        self.output.mkdir(mode=0o700)
        self.known = self.root / "known-hosts"
        self.known.write_bytes(b"synthetic non-credential host trust\n")
        self.known.chmod(0o600)
        self.public = self.root / "guest.pub"
        public = "ssh-ed25519 QUFBQQ== qualification-synthetic"
        self.public.write_text(public + "\n")
        self.public.chmod(0o600)
        admission = {"format": "home-lab-disposable-pve-target-admission-v1", "route": "production-pve-disposable-vm", "target_id": "production-pve-vm9900-qualification", "node_name": "proxmox", "endpoint": "https://proxmox:8006/api2/json", "network": {"production_cidrs_denied": ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"], "controller_ipv4": "192.168.0.12"}, "credentials": {"ssh_authentication": "tailscale-policy", "ssh_principal": "qualification-apply", "guest_ssh_public_key_sha256": controller.sha(public.encode())}, "storage": {"snippet_content_enabled": True}, "host_key": {"known_hosts_sha256": controller.sha(self.known.read_bytes()), "ssh_address": "proxmox", "out_of_band_verified": True}}
        self.admission = self.put(self.root / "admission.json", admission)
        content = controller.snippet.render(public)
        self.snippet = {"admission_sha256": controller.sha(self.admission.read_bytes()), "commit": "b" * 40, "file_id": "local:snippets/home-lab-debian-lifecycle-qualification.yaml", "format": "home-lab-debian-qualification-snippet-receipt-v1", "guest_ssh_public_key_sha256": controller.sha(public.encode()), "known_hosts_sha256": controller.sha(self.known.read_bytes()), "mode": "0600", "node_name": "proxmox", "sha256": controller.sha(content), "size": len(content), "target_id": admission["target_id"], "version": 1, "changed": True, "plan_sha256": "c" * 64}
        self.snippet_path = self.put(self.root / ("c" * 64 + ".receipt.json"), self.snippet)
        self.foundation = {"admission_sha256": controller.sha(self.admission.read_bytes()), "commit": "b" * 40, "format": "home-lab-debian-qualification-foundation-receipt-v1", "operation": "create-stopped-foundation", "plan_sha256": "d" * 64, "resources": controller.RESOURCES, "snippet_receipt_sha256": controller.sha(self.snippet_path.read_bytes()), "state_sha256": "e" * 64, "target_id": admission["target_id"], "version": 1, "vm_started": False, "vmid": 9900}
        self.foundation_path = self.put(self.output / ("d" * 64 + ".receipt.json"), self.foundation)
        self.start = {**self.foundation, "format": "home-lab-debian-qualification-start-receipt-v1", "operation": "start", "plan_sha256": "f" * 64, "vm_started": True, "prior_receipt_sha256": controller.sha(self.foundation_path.read_bytes()), "snippet_sha256": self.snippet["sha256"]}
        self.start_path = self.put(self.output / ("f" * 64 + ".receipt.json"), self.start)
        self.args = types.SimpleNamespace(admission=self.admission, known_hosts=self.known, foundation_receipt=self.foundation_path, start_receipt=self.start_path, snippet_receipt=self.snippet_path, guest_public_key=self.public)
        self.request = controller.observation_request({"isolation_attestation_sha256": self.foundation["admission_sha256"]}, self.foundation_path.read_bytes(), self.start_path.read_bytes(), self.snippet_path.read_bytes(), {key: self.snippet[key] for key in ("file_id", "sha256", "size")})

    def put(self, path, value):
        path.write_bytes(controller.canonical_bytes(value) + b"\n")
        path.chmod(0o600)
        return path

    def capture(self, remote):
        with patch.object(controller, "commit", return_value=REVISION), patch.object(controller, "remote_first_boot", side_effect=remote), redirect_stdout(io.StringIO()):
            controller.capture(self.args, REVISION, self.output)

    def published(self):
        return [p for p in self.output.glob("*.json") if not p.name.endswith(".receipt.json")]

    def test_exact_chain_publishes_v2(self):
        self.capture(lambda *args: envelope(args[-1]))
        paths = self.published()
        self.assertEqual(len(paths), 1)
        raw = paths[0].read_bytes()
        result = json.loads(raw)
        self.assertEqual(paths[0].name, controller.sha(raw) + ".json")
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["booted_template_commit"], REVISION)
        self.assertEqual(result["template_sha256"], controller.sha(controller.TEMPLATE.read_bytes()))
        self.assertEqual(result["provenance"]["booted_snippet_sha256"], self.start["snippet_sha256"])
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_old_false_ready_observation_is_refused(self):
        # This observation alone passed the old controller despite wrong installed
        # helper bytes or unrelated cloud-init user-data on the running guest.
        self.assertEqual(controller.validated_observation(OBSERVATION), "192.168.0.53")
        with self.assertRaisesRegex(SystemExit, "envelope binding"):
            self.capture(lambda *args: copy.deepcopy(OBSERVATION))
        self.assertEqual(self.published(), [])

    def test_replayed_or_mismatched_envelopes_never_publish(self):
        changes = [("producer", "helper_sha256"), ("producer", "transport_sha256"), ("producer", "sudoers_sha256"), ("request", "nonce"), ("request", "foundation_receipt_sha256"), ("request", "start_receipt_sha256"), ("request", "snippet_receipt_sha256"), ("snippet", "sha256")]
        for section, field in changes:
            with self.subTest(section=section, field=field):
                def remote(*args):
                    result = envelope(args[-1])
                    result[section][field] = "0" * 64
                    return result
                with self.assertRaises(SystemExit):
                    self.capture(remote)
                self.assertEqual(self.published(), [])
        with self.assertRaises(SystemExit):
            self.capture(lambda *args: {**envelope(args[-1]), "booted_snippet_sha256": "0" * 64})
        def float_size(*args):
            result = envelope(args[-1])
            result["snippet"]["size"] = float(result["snippet"]["size"])
            return result
        with self.assertRaises(SystemExit):
            self.capture(float_size)
        with self.assertRaises(SystemExit):
            self.capture(lambda *args: envelope(self.request))  # a prior invocation nonce
        self.assertEqual(self.published(), [])

    def test_snippet_receipt_and_rendered_source_must_match_start(self):
        for field, value in (("sha256", "0" * 64), ("size", True), ("changed", 1), ("format", "unknown"), ("commit", None)):
            with self.subTest(field=field):
                self.put(self.snippet_path, {**self.snippet, field: value})
                with self.assertRaises(SystemExit):
                    self.capture(lambda *args: self.fail("must refuse before transport"))
        self.put(self.snippet_path, self.snippet)
        changed_template = self.root / "changed.tftpl"
        changed_template.write_bytes(controller.TEMPLATE.read_bytes() + b"# different boot template\n")
        with patch.object(controller.snippet, "TEMPLATE", changed_template), self.assertRaises(SystemExit):
            self.capture(lambda *args: self.fail("wrong booted template accepted"))
        self.assertEqual(self.published(), [])

    def test_observation_receipt_variant(self):
        value = {k: v for k, v in self.snippet.items() if k not in ("changed", "plan_sha256")}
        value.update(format="home-lab-debian-qualification-snippet-observation-receipt-v1", observation_sha256="1" * 64)
        raw = controller.canonical_bytes(value) + b"\n"
        self.args.snippet_receipt = self.put(self.root / (controller.sha(raw) + ".observation-receipt.json"), value)
        self.foundation["snippet_receipt_sha256"] = controller.sha(raw)
        self.put(self.foundation_path, self.foundation)
        self.start.update(snippet_receipt_sha256=controller.sha(raw), prior_receipt_sha256=controller.sha(self.foundation_path.read_bytes()))
        self.put(self.start_path, self.start)
        self.capture(lambda *args: envelope(args[-1]))
        self.assertEqual(len(self.published()), 1)

    def test_source_change_and_intervening_receipt_refuse_publication(self):
        template = self.root / "template"
        template.write_bytes(controller.TEMPLATE.read_bytes())
        def changed(*args):
            template.write_bytes(template.read_bytes() + b"# changed during observation\n")
            return envelope(args[-1])
        with patch.object(controller, "TEMPLATE", template), self.assertRaisesRegex(SystemExit, "source changed"):
            self.capture(changed)
        executable = self.root / "helper"
        executable.write_bytes(controller.HELPER.read_bytes())
        def changed_executable(*args):
            executable.write_bytes(executable.read_bytes() + b"# different observer\n")
            return envelope(args[-1])
        with patch.object(controller, "HELPER", executable), self.assertRaisesRegex(SystemExit, "source changed"):
            self.capture(changed_executable)
        def intervening(*args):
            self.put(self.output / "intervening.receipt.json", {"restart": True})
            return envelope(args[-1])
        with self.assertRaisesRegex(SystemExit, "intervening"):
            self.capture(intervening)
        self.assertEqual(self.published(), [])

    def test_receipt_publication_failure_propagates_without_retry(self):
        with patch.object(controller, "write_json", side_effect=OSError("fsync failure")) as writer, self.assertRaises(OSError):
            self.capture(lambda *args: envelope(args[-1]))
        self.assertEqual(writer.call_count, 1)
        self.assertEqual(self.published(), [])

    def test_uptime_boundaries_on_producer_and_controller(self):
        for delta, valid in ((-2.01, False), (-2, True), (-1.99, True), (119.99, True), (120, True), (120.01, False)):
            with self.subTest(delta=delta):
                observation = {**OBSERVATION, "pve_uptime_seconds": 200, "guest_uptime_seconds": 200 - delta, "startup_delta_seconds": delta}
                def run(command):
                    if command[:3] == ["/usr/sbin/qm", "status", "9900"]:
                        return "status: running\nuptime: 200\n"
                    if command[5:] == ["/usr/bin/cat", "/proc/uptime"]:
                        return fixtures.qga(f"{200-delta:.2f} 0\n")
                    return fixtures.fake(command)
                with patch.object(helper, "run", side_effect=run):
                    if valid:
                        controller.validated_observation(observation)
                        self.assertEqual(helper._first_boot()["startup_delta_seconds"], delta)
                    else:
                        with self.assertRaises(SystemExit): controller.validated_observation(observation)
                        with self.assertRaises(RuntimeError): helper._first_boot()
        for invalid in (None, [], {}, {**OBSERVATION, "boot_count": True}, {**OBSERVATION, "pve_uptime_seconds": True}, {**OBSERVATION, "guest_uptime_seconds": float("nan")}, {**OBSERVATION, "startup_delta_seconds": float("inf")}, {**OBSERVATION, "network": []}, {**OBSERVATION, "boot_id": 123}):
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                controller.validated_observation(invalid)

    def test_locked_producer_checks_and_cleanup(self):
        for fault in (None, "helper", "transport", "sudoers", "snippet", "booted", "changed", "lock"):
            with self.subTest(fault=fault):
                closed = []
                producer = dict(self.request["producer"])
                if fault in ("helper", "transport", "sudoers"):
                    producer[fault + "_sha256"] = "0" * 64
                current_snippet = dict(self.request["snippet"])
                if fault == "snippet": current_snippet["sha256"] = "0" * 64
                versions = [producer, {**producer, "helper_sha256": "0" * 64}] if fault == "changed" else [producer, producer]
                with patch.object(helper, "first_boot_request", return_value=self.request), patch.object(helper, "acquire_shared_operation_lock", return_value=11), patch.object(helper, "acquire_lock", side_effect=RuntimeError("lock held") if fault == "lock" else lambda: 12), patch.object(helper.os.path, "lexists", return_value=False), patch.object(helper, "first_boot_producer", side_effect=versions), patch.object(helper, "first_boot_snippet", return_value=current_snippet), patch.object(helper, "_first_boot", return_value=OBSERVATION) as observe, patch.object(helper, "booted_snippet_hash", return_value="0" * 64 if fault == "booted" else current_snippet["sha256"]), patch.object(helper.os, "close", side_effect=closed.append):
                    if fault is None:
                        controller.validated_envelope(helper.first_boot(), self.request)
                    else:
                        with self.assertRaises(RuntimeError): helper.first_boot()
                    if fault in ("helper", "transport", "sudoers", "snippet", "lock"):
                        observe.assert_not_called()
                self.assertEqual(closed, [11] if fault == "lock" else [12, 11])

    def test_booted_cache_and_current_snippet_are_observed_not_echoed(self):
        with patch.object(helper, "run", return_value="cicustom: user=local:snippets/other.yaml\nide2: local-lvm:vm-9900-cloudinit,media=cdrom\n"), patch.object(helper, "inspect") as inspect:
            with self.assertRaisesRegex(RuntimeError, "boot snippet configuration"):
                helper.first_boot_snippet()
            inspect.assert_not_called()
        with patch.object(helper, "guest_exec", return_value="0" * 64 + "\n") as guest:
            self.assertEqual(helper.booted_snippet_hash("iid-nocloud"), "0" * 64)
            argv = guest.call_args.args[0]
            self.assertEqual(argv[:2], ["/usr/bin/python3", "-c"])
            self.assertEqual(argv[-1], "iid-nocloud")
            self.assertIn('os.open("user-data.txt",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)', argv[2])
            self.assertIn('hashlib.sha256(raw).hexdigest()', argv[2])
        for instance in ("../other", "..", "/root", True):
            with patch.object(helper, "guest_exec") as guest, self.assertRaises(RuntimeError):
                helper.booted_snippet_hash(instance)
            guest.assert_not_called()
        with patch.object(helper, "guest_exec", return_value="not-a-digest"), self.assertRaises(RuntimeError):
            helper.booted_snippet_hash("iid-nocloud")

    def test_request_schema_and_transport_are_exact(self):
        invalids = [[], {}, {**self.request, "vmid": True}, {**self.request, "nonce": ""}, {**self.request, "producer": {}}, {**self.request, "snippet": {**self.request["snippet"], "size": True}}, {**self.request, "extra": True}]
        for value in invalids:
            with self.subTest(value=value), patch.object(helper, "read_plan", return_value=(b"", value)), self.assertRaises(RuntimeError):
                helper.first_boot_request()
        with patch.object(helper, "read_plan", return_value=(b"", self.request)):
            self.assertEqual(helper.first_boot_request(), self.request)
        for raw in (b"[]\n", b"not json\n", json.dumps(envelope(self.request), indent=2).encode(), controller.canonical_bytes({**envelope(self.request), "extra": True}) + b"\n"):
            with self.subTest(raw=raw[:30]), patch.object(controller.subprocess, "run", return_value=types.SimpleNamespace(stdout=raw, stderr=b"", returncode=0)):
                with self.assertRaises(SystemExit):
                    value = controller.remote_first_boot({"ssh_address": "proxmox", "ssh_username": "qualification-apply"}, self.known, self.output, b"start", self.request)
                    controller.validated_envelope(value, self.request)


if __name__ == "__main__":
    unittest.main()
