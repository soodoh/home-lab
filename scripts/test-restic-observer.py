#!/usr/bin/env python3
"""Tests for complete-chain selection in the live Restic observer."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("restic_observer", ROOT / "scripts/observe-restic-backups.py")
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OBSERVER
SPEC.loader.exec_module(OBSERVER)

POLICY = "a" * 64
ARTIFACT = "b" * 64
TAGS = ["cadence=daily", f"policy={POLICY}", f"artifact={ARTIFACT}"]


def snapshot(identity: str, timestamp: str, *, original: str | None = None, tags: list[str] | None = None):
    value = {"id": identity, "time": timestamp, "tags": list(TAGS if tags is None else tags)}
    if original is not None:
        value["original"] = original
    return value


class ResticObserverTests(unittest.TestCase):
    def test_selects_newest_complete_chain_not_newest_incomplete_source(self):
        complete = "1" * 64
        incomplete = "2" * 64
        games = [
            snapshot(incomplete, "2026-09-21T08:00:00Z"),
            snapshot(complete, "2026-09-21T07:00:00Z"),
        ]
        nfs = [snapshot("3" * 64, "2026-09-21T07:00:00Z", original=complete)]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=complete)]
        selected = OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)
        self.assertEqual(selected[0]["id"], complete)

    def test_requires_current_policy_artifact_cadence_and_matching_tags(self):
        source = "1" * 64
        games = [snapshot(source, "2026-09-21T07:00:00Z", tags=["cadence=daily"])]
        nfs = [snapshot("3" * 64, "2026-09-21T07:00:00Z", original=source)]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=source)]
        with self.assertRaisesRegex(OBSERVER.ObservationError, "complete_chain_missing"):
            OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)

    def test_refuses_ambiguous_destination_mapping(self):
        source = "1" * 64
        games = [snapshot(source, "2026-09-21T07:00:00Z")]
        nfs = [
            snapshot("3" * 64, "2026-09-21T07:00:00Z", original=source),
            snapshot("5" * 64, "2026-09-21T07:01:00Z", original=source),
        ]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=source)]
        with self.assertRaisesRegex(OBSERVER.ObservationError, "snapshot_mapping_ambiguous"):
            OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)


if __name__ == "__main__":
    unittest.main()
