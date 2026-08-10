#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts/controller/audit-root-local-paths.py"
SPEC = importlib.util.spec_from_file_location("audit_root_local_paths", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load root-local audit")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RootLocalAuditTests(unittest.TestCase):
    def test_preserves_and_removes_only_declared_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preserved = root / "config/home-lab"
            removable = root / "local/share/fish"
            unknown = root / "local/bin/custom-tool"
            preserved.mkdir(parents=True)
            removable.mkdir(parents=True)
            unknown.parent.mkdir(parents=True)
            (preserved / "token.env").write_text("protected")
            (removable / "state").write_text("legacy")
            unknown.write_text("unknown")
            policy = {
                "inspect_roots": [str(root / "config"), str(root / "local")],
                "preserve_paths": [str(preserved)],
                "remove_paths": [str(removable)],
            }
            self.assertEqual(MODULE.audit(policy), [str(root / "local/bin")])

    def test_reports_unknown_top_level_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "local/application"
            application.mkdir(parents=True)
            policy = {
                "inspect_roots": [str(root / "local")],
                "preserve_paths": [],
                "remove_paths": [],
            }
            self.assertEqual(MODULE.audit(policy), [str(application)])


if __name__ == "__main__":
    unittest.main()
