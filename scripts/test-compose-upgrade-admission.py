#!/usr/bin/env python3
"""Exercise admission with real source archives, not workflow/source-text assertions."""

import copy
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


def image(tag="1.2.3", digest="a", name="example/app"):
    return f"{name}:{tag}@sha256:{digest * 64}"


def source(tag="1.2.3", digest="a", name="example/app"):
    return f"services:\n  app:\n    image: {image(tag, digest, name)}\n    restart: unless-stopped\n".encode()


WOLF_POLICY_PATH = "services/data/wolf/security.json"
WOLF_POLICY = json.loads((ROOT / WOLF_POLICY_PATH).read_bytes())


def wolf_policy(policy=None):
    return (json.dumps(WOLF_POLICY if policy is None else policy, indent=2) + "\n").encode()


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

    def compare(self, new, old=None, extra=None, old_extra=None):
        return MODULE.admit_archives(
            self.archive("active.tar", old, old_extra), self.archive("candidate.tar", new, extra)
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

    def test_wolf_stable_digest_update_joins_routine_batch(self):
        wolf = "ghcr.io/games-on-whales/wolf"
        old = {"services/gaming.yml": source("stable", name=wolf)}
        new = {"services/gaming.yml": source("stable", "b", wolf)}
        self.assertEqual(self.compare(source("1.3.0", "b"), extra=new, old_extra=old), 2)
        self.assertEqual(self.compare(source(), extra=old, old_extra=old), 0)

    def test_wolf_exception_does_not_admit_other_tags_images_or_paths(self):
        wolf = "ghcr.io/games-on-whales/wolf"
        candidates = [
            ("stable", "latest", wolf, "services/gaming.yml"),
            ("latest", "stable", wolf, "services/gaming.yml"),
            ("latest", "latest", wolf, "services/gaming.yml"),
            ("stable", "stable", "other/wolf", "services/gaming.yml"),
            ("stable", "stable", "ghcr.io/games-on-whales/steam", "services/gaming.yml"),
            ("stable", "stable", wolf, "services/other.yml"),
        ]
        for old_tag, new_tag, name, path in candidates:
            with self.subTest(old_tag=old_tag, new_tag=new_tag, name=name, path=path):
                with self.assertRaises(ValueError):
                    self.compare(source(), extra={path: source(new_tag, "b", name)},
                                 old_extra={path: source(old_tag, name=name)})
        with self.assertRaises(ValueError):
            self.compare(source(),
                         old_extra={"services/gaming.yml": source("stable", name=wolf)},
                         extra={"services/gaming.yml": source("stable", "b", "other/wolf")})

    def test_wolf_digest_update_does_not_admit_configuration_or_invalid_pin_changes(self):
        wolf = "ghcr.io/games-on-whales/wolf"
        old = {"services/gaming.yml": source("stable", name=wolf)}
        new = {"services/gaming.yml": source("stable", "b", wolf)}
        for extra, old_extra in (
            ({**new, "services/gaming.yml": new["services/gaming.yml"].replace(
                b"unless-stopped", b"always")}, old),
            ({**new, "services/data/wolf/security.json": b"new spawned image"},
             {**old, "services/data/wolf/security.json": b"old spawned image"}),
            ({**new, "secrets/production.sops.yaml": b"other ciphertext"}, old),
        ):
            with self.subTest(paths=sorted(extra)):
                with self.assertRaises(ValueError):
                    self.compare(source(), extra=extra, old_extra=old_extra)

    def test_each_spawned_digest_and_combined_wolf_updates_join_routine_batch(self):
        for sources in ([pin["source"]] for pin in WOLF_POLICY["image_pins"]):
            updated = copy.deepcopy(WOLF_POLICY)
            for pin in updated["image_pins"]:
                if pin["source"] in sources:
                    pin["image"] = pin["source"] + "@sha256:" + "b" * 64
            with self.subTest(sources=sources):
                self.assertEqual(self.compare(source(),
                    old_extra={WOLF_POLICY_PATH: wolf_policy()},
                    extra={WOLF_POLICY_PATH: wolf_policy(updated)}), 1)
        updated = copy.deepcopy(WOLF_POLICY)
        for pin in updated["image_pins"]:
            pin["image"] = pin["source"] + "@sha256:" + "b" * 64
        self.assertEqual(self.compare(source("1.3.0", "b"),
            old_extra={WOLF_POLICY_PATH: wolf_policy(), "services/gaming.yml": source("stable", name="ghcr.io/games-on-whales/wolf")},
            extra={WOLF_POLICY_PATH: wolf_policy(updated), "services/gaming.yml": source("stable", "b", "ghcr.io/games-on-whales/wolf")}), 5)
        self.assertEqual(self.compare(source(), old_extra={WOLF_POLICY_PATH: wolf_policy()},
            extra={WOLF_POLICY_PATH: wolf_policy()}), 0)

    def test_spawned_digest_exception_refuses_security_configuration_and_identity_changes(self):
        updated = copy.deepcopy(WOLF_POLICY)
        updated["image_pins"][0]["image"] = updated["image_pins"][0]["source"] + "@sha256:" + "b" * 64
        candidates = []
        for key, value in (("tcp_ports", [22]), ("lan_interface", "eth0"), ("unexpected", True)):
            candidate = copy.deepcopy(updated)
            candidate[key] = value
            candidates.append(candidate)
        for replacement in ("ghcr.io/games-on-whales/wolf-ui:stable", "untrusted/wolf-ui:main"):
            candidate = copy.deepcopy(updated)
            candidate["image_pins"][0] = {"source": replacement, "image": replacement + "@sha256:" + "b" * 64}
            candidates.append(candidate)
        for pins in (updated["image_pins"][:-1], updated["image_pins"] + [updated["image_pins"][0]],
                     list(reversed(updated["image_pins"]))):
            candidates.append({**updated, "image_pins": pins})
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.compare(source(), old_extra={WOLF_POLICY_PATH: wolf_policy()},
                             extra={WOLF_POLICY_PATH: wolf_policy(candidate)})
        for content in (wolf_policy(updated).replace(b'"image_pins": [', b'"image_pins": [], "image_pins": ['),
                        wolf_policy(updated).replace(b'"source": ', b'"source": "unknown", "source": ', 1),
                        wolf_policy(updated).replace(b"b" * 64, b"B" * 64),
                        wolf_policy(updated).replace(b"@sha256:" + b"b" * 64, b"")):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.compare(source(), old_extra={WOLF_POLICY_PATH: wolf_policy()},
                             extra={WOLF_POLICY_PATH: content})

    def test_spawned_digest_exception_requires_exact_path_and_accepted_baseline(self):
        updated = copy.deepcopy(WOLF_POLICY)
        updated["image_pins"][0]["image"] = updated["image_pins"][0]["source"] + "@sha256:" + "b" * 64
        for path in ("services/data/wolf/other.json", "services/security.yml"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.compare(source(), old_extra={path: wolf_policy()}, extra={path: wolf_policy(updated)})
        invalid = copy.deepcopy(WOLF_POLICY)
        invalid["image_pins"][0]["source"] = "ghcr.io/games-on-whales/wolf-ui:stable"
        invalid["image_pins"][0]["image"] = invalid["image_pins"][0]["source"] + "@sha256:" + "a" * 64
        with self.assertRaises(ValueError):
            self.compare(source(), old_extra={WOLF_POLICY_PATH: wolf_policy(invalid)},
                         extra={WOLF_POLICY_PATH: wolf_policy(updated)})

    def test_floating_and_prerelease_tag_transitions_require_manual_deployment(self):
        for old_tag, new_tag in (("latest", "0.6.6"), ("2.6.5-develop", "2.6.5")):
            with self.subTest(old_tag=old_tag, new_tag=new_tag):
                with self.assertRaises(ValueError):
                    self.compare(source(new_tag, "b"), source(old_tag))

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
