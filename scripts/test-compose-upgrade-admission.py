#!/usr/bin/env python3
"""Exercise admission with real source archives, not workflow/source-text assertions."""

from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/compose-upgrade-admission.py"
SPEC = importlib.util.spec_from_file_location("compose_upgrade", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
POLICY = json.loads((ROOT / "controller/compose-updates.json").read_text())


def image(tag="1.2.3", digest="a", name="example/app"):
    return f"{name}:{tag}@sha256:{digest * 64}"


def source(tag="1.2.3", digest="a", name="example/app"):
    return f"services:\n  app:\n    image: {image(tag, digest, name)}\n    restart: unless-stopped\n".encode()


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="compose-admission-")
        cls.directory = Path(cls.work.name)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def archive(self, name, compose=None, extra=None):
        files = {
            "docker-compose.yml": b"include:\n  - services/apps.yml\n",
            "services/apps.yml": source() if compose is None else compose,
            "secrets/production.sops.yaml": b"encrypted authority\n",
        }
        files.update(extra or {})
        path = self.directory / name
        with tarfile.open(path, "w") as archive:
            for filename, content in files.items():
                entry = tarfile.TarInfo(filename)
                entry.size, entry.mode = len(content), 0o644
                archive.addfile(entry, io.BytesIO(content))
        return path

    def compare(self, new, old=None, extra=None):
        return MODULE.admit_archives(
            self.archive("active.tar", old), self.archive("candidate.tar", new, extra)
        )

    def test_unchanged_source_is_idempotent(self):
        self.assertEqual(self.compare(source()), 0)

    def test_patch_minor_and_digest_upgrades(self):
        for tag in ("1.2.4", "1.3.0", "1.2.3"):
            with self.subTest(tag=tag):
                self.assertEqual(self.compare(source(tag, "b")), 1)

    def test_database_variants_and_two_component_versions(self):
        for old, new in (("18.6-alpine", "18.7-alpine"), ("11.8.9-ubi9", "11.9.0-ubi9"),
                         ("8.10.1-alpine", "8.10.2-alpine"), ("12.1", "12.2")):
            with self.subTest(old=old):
                self.assertEqual(self.compare(source(new, "b"), source(old)), 1)

    def test_shared_nextcloud_anchor(self):
        def shared(tag, digest):
            return (f"x-nextcloud-image: &nextcloud-image {image(tag, digest, 'nextcloud')}\n"
                    "services:\n  web:\n    image: *nextcloud-image\n  cron:\n    image: *nextcloud-image\n").encode()
        self.assertEqual(self.compare(shared("34.0.5-apache", "b"), shared("34.0.4-apache", "a")), 1)

    def test_multiple_images_in_one_batch(self):
        old = source() + b"  other:\n    image: " + image("2.0.0").encode() + b"\n"
        new = source("1.3.0", "b") + b"  other:\n    image: " + image("2.0.1", "b").encode() + b"\n"
        self.assertEqual(self.compare(new, old), 2)

    def test_major_downgrade_variant_and_package_changes_refuse(self):
        for candidate in (source("2.0.0"), source("1.2.2"), source("1.2.4-alpine"),
                          source("1.2.4", name="other/app")):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    self.compare(candidate)

    def test_floating_and_prerelease_digest_changes_refuse(self):
        for tag in ("latest", "stable", "1.2.3-develop", "1.2.3-beta.1"):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    self.compare(source(tag, "b"), source(tag))

    def test_configuration_secret_scope_and_anchor_changes_refuse(self):
        changes = [
            (source("1.2.4").replace(b"unless-stopped", b"always"), None),
            (source("1.2.4"), {"secrets/production.sops.yaml": b"other ciphertext"}),
            (source("1.2.4"), {"services/new.yml": source()}),
            (source("1.2.4").replace(b"image:", b"image: &changed"), None),
        ]
        for candidate, extra in changes:
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    self.compare(candidate, extra=extra)

    def test_archive_member_traversal_refuses_without_extraction(self):
        path = self.archive("bad.tar", extra={"../escape": b"private"})
        with self.assertRaises(ValueError):
            MODULE.read_archive(path)
        self.assertFalse((self.directory.parent / "escape").exists())

    def test_window_boundaries_in_both_dst_offsets(self):
        for day, utc_start in (("2026-07-01", 13), ("2026-12-01", 14)):
            for offset, allowed in ((-1, False), (0, True), (149, True), (150, False), (180, False)):
                from datetime import timedelta
                moment = datetime.fromisoformat(f"{day}T{utc_start:02}:00:00+00:00") + timedelta(minutes=offset)
                with self.subTest(day=day, offset=offset):
                    self.assertEqual(MODULE.window_open(POLICY, moment), allowed)

    def test_invalid_window_fails_closed(self):
        for settings in ({**POLICY, "end_hour": 5}, {**POLICY, "minimum_remaining_minutes": 0},
                         {**POLICY, "start_hour": True}):
            with self.assertRaises(ValueError):
                MODULE.window_open(settings, datetime.now(timezone.utc))

    def test_cli_refusal_does_not_disclose_source(self):
        active = self.archive("active.tar")
        candidate = self.archive("candidate.tar", extra={"secrets/production.sops.yaml": b"DO-NOT-PRINT"})
        result = subprocess.run(
            ["python3", str(SCRIPT), "--active-archive", str(active), "--candidate-archive", str(candidate)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non_image_source_change", result.stderr)
        self.assertNotIn("DO-NOT-PRINT", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
