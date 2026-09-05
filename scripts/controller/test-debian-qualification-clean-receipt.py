#!/usr/bin/env python3
"""A real synthetic v2 producer receipt must pass its downstream host-key consumer."""
import copy
import datetime as dt
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = load("clean_receipt_producer_fixtures", "scripts/controller/test-debian-qualification-first-boot-provenance.py")
consumer = load("clean_receipt_consumer", "scripts/controller/debian-qualification-host-key.py")


class CleanReceiptConsumer(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.FirstBootProvenance()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.capture(lambda *args: fixtures.envelope(args[-1]))
        self.original_path = self.fixture.published()[0]
        self.value = json.loads(self.original_path.read_bytes())
        self.target = {"target_id": self.value["target_id"]}
        self.stopped = {
            "prior_receipt_sha256": self.value["start_receipt_sha256"],
            "snippet_receipt_sha256": self.value["snippet_receipt_sha256"],
            "snippet_sha256": self.fixture.start["snippet_sha256"],
        }

    def consume(self, value, stopped=None, filename=None, admission_mode="fresh", ancestor=True):
        raw = consumer.canonical_bytes(value) + b"\n"
        path = self.fixture.root / (filename or consumer.sha(raw) + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)

        def command(argv, **kwargs):
            if argv[:2] == ["node", str(consumer.snippet.VALIDATOR)]:
                return subprocess.CompletedProcess(argv, 0, json.dumps({**self.target, "admission_mode": admission_mode}), "")
            if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(argv, 0 if ancestor else 1, "", "")
            raise AssertionError(f"unexpected command: {argv}")

        with patch.object(consumer, "revision", return_value=fixtures.REVISION), patch.object(consumer.subprocess, "run", side_effect=command):
            return consumer.clean_boot(path, self.fixture.admission, self.fixture.known, self.target, stopped or self.stopped)

    def test_genuine_v2_publication_is_consumable(self):
        address, digest = self.consume(self.value)
        self.assertEqual(address, fixtures.OBSERVATION["guest_ipv4"])
        self.assertEqual(digest, consumer.sha(consumer.canonical_bytes(self.value) + b"\n"))
        self.assertEqual(self.consume(self.value, admission_mode="expired-safe-stop")[0], address)

    def test_valid_observation_does_not_rescue_v1_receipt(self):
        value = copy.deepcopy(self.value)
        value.update(version=1, format="home-lab-debian-qualification-clean-first-boot-receipt-v1")
        for key in ("provenance", "booted_template_commit", "snippet_receipt_sha256"):
            del value[key]
        with self.assertRaises(SystemExit):
            self.consume(value)

    def test_individually_tampered_outer_bindings_fail(self):
        for key, replacement in (
            ("version", True), ("version", 2.0), ("vmid", 100),
            ("format", "unknown"), ("status", "candidate"), ("target_id", "production"),
            ("admission_sha256", "0" * 64), ("foundation_receipt_sha256", "0" * 64),
            ("start_receipt_sha256", "0" * 64), ("snippet_receipt_sha256", "0" * 64),
            ("observation_sha256", "0" * 64), ("helper_sha256", "0" * 64),
            ("helper_source_sha256", "0" * 64), ("transport_sha256", "0" * 64),
            ("transport_source_sha256", "0" * 64), ("template_sha256", "0" * 64),
            ("booted_template_commit", "0" * 40), ("commit", None), ("provenance", None),
        ):
            with self.subTest(key=key, replacement=replacement):
                value = copy.deepcopy(self.value)
                value[key] = replacement
                with self.assertRaises(SystemExit):
                    self.consume(value)

    def test_nested_schema_source_and_chain_bindings_fail(self):
        cases = [
            (("producer", "helper_sha256"), "0" * 64),
            (("producer", "transport_sha256"), "0" * 64),
            (("producer", "sudoers_sha256"), "0" * 64),
            (("booted_snippet_sha256",), "0" * 64),
            (("snippet", "file_id"), "local:snippets/production.yaml"),
            (("snippet", "sha256"), "0" * 64),
            (("snippet", "size"), True), (("snippet", "size"), 0),
            (("snippet", "size"), 65537), (("snippet", "extra"), "unexpected"),
            (("request", "nonce"), "replay"), (("request", "extra"), True),
            (("request", "format"), "legacy"), (("request", "vmid"), 100),
            (("request", "admission_sha256"), "0" * 64),
            (("request", "foundation_receipt_sha256"), "0" * 64),
            (("request", "start_receipt_sha256"), "0" * 64),
            (("request", "snippet_receipt_sha256"), "0" * 64),
            (("request", "producer", "sudoers_sha256"), "0" * 64),
            (("request", "snippet", "sha256"), "0" * 64),
            (("format",), "legacy"), (("extra",), True),
        ]
        for path, replacement in cases:
            with self.subTest(path=path, replacement=replacement):
                value = copy.deepcopy(self.value)
                node = value["provenance"]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                with self.assertRaises(SystemExit):
                    self.consume(value)

    def test_self_consistent_snippet_size_cannot_exceed_producer_bound(self):
        for size in (65537, 1048576):
            value = copy.deepcopy(self.value)
            value["provenance"]["snippet"]["size"] = size
            value["provenance"]["request"]["snippet"]["size"] = size
            with self.subTest(size=size), self.assertRaises(SystemExit):
                self.consume(value)

    def test_self_consistent_forged_producer_and_booted_snippet_fail(self):
        value = copy.deepcopy(self.value)
        for node in (value["provenance"]["producer"], value["provenance"]["request"]["producer"]):
            node["helper_sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            self.consume(value)
        value = copy.deepcopy(self.value)
        value["provenance"]["booted_snippet_sha256"] = "0" * 64
        for node in (value["provenance"]["snippet"], value["provenance"]["request"]["snippet"]):
            node["sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            self.consume(value)

    def test_distinct_valid_outer_and_inner_observations_fail(self):
        value = copy.deepcopy(self.value)
        value["provenance"]["observation"]["package"] = "install ok installed different-version"
        consumer.clean.validated_observation(value["provenance"]["observation"])
        with self.assertRaises(SystemExit):
            self.consume(value)

    def test_stopped_lineage_filename_time_and_ancestry_fail_closed(self):
        for key in self.stopped:
            with self.subTest(key=key):
                stopped = {**self.stopped, key: "0" * 64}
                with self.assertRaises(SystemExit):
                    self.consume(self.value, stopped=stopped)
        for delta in (dt.timedelta(hours=-5), dt.timedelta(minutes=1)):
            value = copy.deepcopy(self.value)
            value["observed_at"] = (dt.datetime.now(dt.timezone.utc) + delta).isoformat()
            with self.assertRaises(SystemExit):
                self.consume(value)
        for kwargs in ({"filename": "renamed.json"}, {"admission_mode": "invalid"}, {"ancestor": False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SystemExit):
                self.consume(self.value, **kwargs)


if __name__ == "__main__":
    unittest.main()
