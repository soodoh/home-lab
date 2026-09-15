#!/usr/bin/env python3
"""Keep both Proton unit namespaces compatible with confined repository traversal.

These are local configuration regressions, not a substitute for Linux validation.
A systemd probe running the real check_mount as UID 60000 reproduced mount_identity
with InaccessiblePaths=/mnt/games and passed with a read-only temporary filesystem.
Neither that probe nor this test invokes Restic or writes a repository.
"""

import configparser
from pathlib import Path
import unittest


TEMPLATES = Path(__file__).resolve().parent.parent / "ansible/roles/restic_backup/templates"


class ProtonSandboxTests(unittest.TestCase):
    def test_repository_is_reachable_without_exposing_the_games_tree(self):
        for cadence in ("daily", "maintenance"):
            with self.subTest(cadence=cadence):
                unit = configparser.ConfigParser(interpolation=None)
                unit.read(TEMPLATES / f"home-lab-restic-{cadence}-proton.service.j2")
                service = unit["Service"]
                self.assertEqual(service["User"], "restic-proton")
                self.assertEqual(service["Group"], "restic-proton")
                inaccessible = service["InaccessiblePaths"].split()
                self.assertNotIn("/mnt/games", inaccessible)
                self.assertIn("/mnt/games:ro", service.get("TemporaryFileSystem", "").split())
                self.assertEqual(
                    service["BindReadOnlyPaths"], "{{ restic_systemd.games_repository_path }}"
                )
                self.assertEqual(
                    service["BindPaths"], "{{ restic_systemd.games_repository_path }}/locks"
                )
                for path in ("/srv/home-lab-state", "/mnt/storage", "/home/docker", "/etc/docker-compose"):
                    self.assertIn(path, inaccessible)
                self.assertEqual(service["ProtectSystem"], "strict")
                self.assertEqual(service["PrivateDevices"], "true")
                self.assertEqual(service["NoNewPrivileges"], "true")


if __name__ == "__main__":
    unittest.main()
