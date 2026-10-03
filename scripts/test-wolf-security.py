#!/usr/bin/env python3
"""Behavior tests for the spawned-image policy boundary."""

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("image_policy", ROOT / "scripts/check-compose-image-pins.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
SOURCE = "ghcr.io/games-on-whales/es-de:edge"
PIN = {"source": SOURCE, "image": SOURCE + "@sha256:" + "a" * 64}


class WolfImagePolicyTests(unittest.TestCase):
    def test_accepts_exact_reference_without_changing_source(self):
        self.assertEqual(POLICY.validate_wolf_pins({"image_pins": [PIN]}), 1)

    def test_refuses_unpinned_or_retargeted_images(self):
        for image in [SOURCE, SOURCE + "@sha256:short", SOURCE + "@sha256:" + "A" * 64,
                      "ghcr.io/untrusted/es-de:edge@sha256:" + "a" * 64]:
            with self.subTest(image=image), self.assertRaisesRegex(ValueError, "wolf_image_not_tag_and_digest"):
                POLICY.validate_wolf_pins({"image_pins": [{"source": SOURCE, "image": image}]})

    def test_refuses_duplicate_or_ambiguous_sources(self):
        with self.assertRaisesRegex(ValueError, "wolf_image_source_duplicate"):
            POLICY.validate_wolf_pins({"image_pins": [PIN, copy.deepcopy(PIN)]})

    def test_refuses_missing_and_invalid_policy_shapes(self):
        for value in [{}, {"image_pins": []}, {"image_pins": "invalid"}, {"image_pins": [None]}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                POLICY.validate_wolf_pins(value)


if __name__ == "__main__":
    unittest.main()
