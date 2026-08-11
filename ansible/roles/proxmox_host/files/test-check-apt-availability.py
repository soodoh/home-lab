#!/usr/bin/env python3
"""Unit tests for the isolated exact APT transaction helper."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import sys

MODULE_PATH = Path(__file__).with_name("check-apt-availability.py")
SPEC = importlib.util.spec_from_file_location("check_apt_availability", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load exact APT transaction helper")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class AptTransactionHelperTest(unittest.TestCase):
    def test_environment_is_allowlisted(self) -> None:
        with patch.dict("os.environ", {"http_proxy": "http://proxy.invalid", "APT_CONFIG": "/tmp/unsafe"}):
            environment = HELPER.sanitized_environment()
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertNotIn("http_proxy", environment)
        self.assertNotIn("APT_CONFIG", environment)

    def test_apt_options_bound_network_operations(self) -> None:
        options = HELPER.apt_options(
            Path("/tmp/sources"),
            Path("/tmp/config"),
            Path("/tmp/lists"),
            Path("/tmp/cache"),
            Path("/tmp/log"),
            no_locking=True,
        )
        joined = " ".join(options)
        self.assertIn("Acquire::Retries=3", joined)
        self.assertIn("Acquire::http::Timeout=20", joined)
        self.assertIn("Acquire::https::Timeout=20", joined)
        self.assertIn("Acquire::MaxReleaseFileSize=16777216", joined)
        self.assertIn("Acquire::MaxFileSize=536870912", joined)
        self.assertIn("Dir::Etc::main=/dev/null", joined)
        self.assertIn("Debug::NoLocking=1", joined)
        apply_options = HELPER.apt_options(
            Path("/tmp/sources"), Path("/tmp/config"), Path("/tmp/lists"),
            Path("/tmp/cache"), Path("/tmp/log"), no_locking=False,
        )
        self.assertNotIn("Debug::NoLocking=1", " ".join(apply_options))
        for isolated_path in ["/tmp/sources", "/tmp/config", "/tmp/lists", "/tmp/cache", "/tmp/log"]:
            self.assertIn(isolated_path, " ".join(apply_options))

    def test_simulation_and_apply_use_the_same_exact_transaction(self) -> None:
        options = ["-o", "Dir::State::lists=/tmp/lists"]
        specs = ["apt=3.0.3", "curl=8.0-2"]
        simulation = HELPER.transaction_command(options, specs, apply=False)
        mutation = HELPER.transaction_command(options, specs, apply=True)
        self.assertIn("--simulate", simulation)
        self.assertNotIn("--yes", simulation)
        self.assertIn("--yes", mutation)
        self.assertNotIn("--simulate", mutation)
        for argument in [
            "Dir::State::lists=/tmp/lists", "--no-remove", "--no-install-recommends",
            "--no-allow-downgrades", "install", *specs,
        ]:
            self.assertIn(argument, simulation)
            self.assertIn(argument, mutation)

    def test_run_command_has_a_bounded_timeout(self) -> None:
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(["apt-get"], 1)):
            with self.assertRaisesRegex(SystemExit, "command_timeout"):
                HELPER.run_command(["/usr/bin/apt-get", "update"], timeout=1)

    def test_parse_simulation_builds_complete_final_map(self) -> None:
        installed = {
            "chrony": "4.6.1-3+deb13u1",
            "curl": "8.14.1-2+deb13u3",
            "libcurl4t64:amd64": "8.14.1-2+deb13u3",
        }
        expected = {
            "chrony": "4.6.1-3+deb13u2",
            "curl": "8.14.1-2+deb13u4",
            "libcurl4t64:amd64": "8.14.1-2+deb13u4",
        }
        output = "\n".join([
            "Inst chrony [4.6.1-3+deb13u1] (4.6.1-3+deb13u2 Debian:13/stable [all])",
            "Inst curl [8.14.1-2+deb13u3] (8.14.1-2+deb13u4 Debian:13/stable [amd64]) []",
            "Inst libcurl4t64 [8.14.1-2+deb13u3] (8.14.1-2+deb13u4 Debian:13/stable [amd64])",
        ])
        final, transitioned_names = HELPER.parse_simulation(output, installed, expected, "amd64")
        self.assertEqual(final, expected)
        self.assertEqual(transitioned_names, {"chrony", "curl", "libcurl4t64:amd64"})
        HELPER.compare_complete_package_map(final, expected)

    def test_parse_simulation_accepts_standard_removal_suffix(self) -> None:
        final, transitioned_names = HELPER.parse_simulation(
            "Remv apt [3.0.2] []", {"apt": "3.0.2"}, {}, "amd64",
        )
        self.assertEqual(final, {})
        self.assertEqual(transitioned_names, {"apt"})

    def test_simulation_rejects_foreign_and_malformed_transitions(self) -> None:
        installed = {"apt": "3.0.2"}
        expected = {"apt": "3.0.3"}
        for output, reason in [
            ("Inst apt [3.0.2] (3.0.3 Debian [arm64])", "simulation_foreign_architecture"),
            ("Inst malformed", "simulation_unrecognized_transition"),
            ("Remv apt trailing-junk", "simulation_unrecognized_transition"),
        ]:
            with self.subTest(output=output):
                with self.assertRaisesRegex(SystemExit, reason):
                    HELPER.parse_simulation(output, installed, expected, "amd64")

    def test_installed_inventory_uses_status_abbrev_installed_character(self) -> None:
        result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="held\thi \t1.0\nreinstall\tri \t2.0\nremoved\trc \t3.0\n",
        )
        with patch.object(HELPER, "run_command", return_value=result):
            installed = HELPER.installed_package_map("amd64", {"held", "reinstall"})
        self.assertEqual(installed, {"held": "1.0", "reinstall": "2.0"})

    def test_complete_map_rejects_every_drift_class(self) -> None:
        expected = {"apt": "3.0.3", "curl": "8.0-2"}
        for actual, reason in [
            ({**expected, "unexpected": "1.0"}, "unexpected_packages"),
            ({"apt": "3.0.3"}, "missing_packages"),
            ({"apt": "3.0.3", "curl": "8.0-1"}, "unexpected_versions"),
        ]:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(SystemExit, reason):
                    HELPER.compare_complete_package_map(actual, expected)

    def test_default_mode_rejects_existing_extras_before_transaction(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unexpected_packages packages=legacy"):
            HELPER.reject_existing_extras(
                {"apt": "3.0.3", "legacy": "1.0-1"}, {"apt": "3.0.3"},
            )

    def test_default_cli_rejects_extras_before_apt_or_mutation(self) -> None:
        policy = {"manifest_sha256": "0" * 64, "packages": []}
        argv = [
            str(MODULE_PATH), "--policy-base64", "ignored", "--manifest", "/manifest.json",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(HELPER, "load_policy", return_value=policy),
            patch.object(HELPER, "load_manifest", return_value={}),
            patch.object(
                HELPER, "validate_manifest", return_value=("amd64", {"apt": "3.0.3"}),
            ),
            patch.object(
                HELPER, "installed_package_map",
                return_value={"apt": "3.0.3", "legacy": "1.0-1"},
            ),
            patch.object(HELPER.tempfile, "TemporaryDirectory", side_effect=AssertionError("APT path used")),
        ):
            with self.assertRaisesRegex(SystemExit, "unexpected_packages packages=legacy"):
                HELPER.main()

    def test_allow_existing_extras_requires_them_to_remain_unchanged(self) -> None:
        installed = {"apt": "3.0.2", "legacy": "1.0-1"}
        expected = {"apt": "3.0.3"}
        final, transitioned_names = HELPER.parse_simulation(
            "Inst apt [3.0.2] (3.0.3 Debian:13/stable [amd64])",
            installed,
            expected,
            "amd64",
            allow_existing_extras=True,
        )
        HELPER.compare_map_preserving_extras(installed, final, expected, transitioned_names)

    def test_allow_existing_extras_rejects_all_extra_transition_classes(self) -> None:
        installed = {"apt": "3.0.2", "legacy": "1.0-1"}
        expected = {"apt": "3.0.3"}
        cases = [
            ({"apt": "3.0.3", "legacy": "1.0-2"}, {"apt", "legacy"}, "changed"),
            ({"apt": "3.0.3", "legacy": "1.0-1", "new": "1.0-1"}, {"apt", "new"}, "new"),
            ({"apt": "3.0.3"}, {"apt", "legacy"}, "removed"),
        ]
        for final, transitioned_names, label in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(SystemExit, "extra_package_transition"):
                    HELPER.compare_map_preserving_extras(
                        installed, final, expected, transitioned_names,
                    )

    def test_allow_existing_extras_rejects_post_apply_extra_map_drift(self) -> None:
        installed = {"apt": "3.0.2", "legacy": "1.0-1"}
        expected = {"apt": "3.0.3"}
        cases = [
            ({"apt": "3.0.3", "legacy": "1.0-2"}, "unexpected_versions"),
            ({"apt": "3.0.3", "legacy": "1.0-1", "new": "1.0-1"}, "unexpected_packages"),
            ({"apt": "3.0.3"}, "missing_packages"),
        ]
        for applied, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(SystemExit, reason):
                    HELPER.compare_map_preserving_extras(
                        installed, applied, expected, set(),
                    )

    def test_allow_existing_extras_still_requires_expected_versions(self) -> None:
        installed = {"apt": "3.0.2", "legacy": "1.0-1"}
        with self.assertRaisesRegex(SystemExit, "unexpected_versions"):
            HELPER.compare_map_preserving_extras(
                installed, installed, {"apt": "3.0.3"}, set(),
            )

    def test_verify_installed_only_skips_network_and_apt_transaction(self) -> None:
        policy = {"manifest_sha256": "0" * 64}
        expected = {"apt": "3.0.3"}
        argv = [
            str(MODULE_PATH), "--policy-base64", "ignored", "--manifest", "/manifest.json",
            "--verify-installed-only",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(HELPER, "load_policy", return_value=policy),
            patch.object(HELPER, "load_manifest", return_value={}),
            patch.object(HELPER, "validate_manifest", return_value=("amd64", expected)),
            patch.object(HELPER, "installed_package_map", return_value=expected) as inventory,
            patch.object(HELPER, "verified_keyring", side_effect=AssertionError("network path used")),
            patch.object(HELPER.tempfile, "TemporaryDirectory", side_effect=AssertionError("APT path used")),
        ):
            HELPER.main()
        inventory.assert_called_once_with("amd64", {"apt"})

    def test_foreign_and_ambiguous_multiarch_are_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "foreign_architecture"):
            HELPER.canonical_package_name("libc6:arm64", "amd64", {"libc6:amd64"})
        with self.assertRaisesRegex(SystemExit, "ambiguous_multiarch"):
            HELPER.canonical_package_name("libc6", "amd64", {"libc6:i386", "libc6:arm64"})

    def test_transferred_manifest_is_checksum_bound(self) -> None:
        content = b'{"version":1,"architecture":"amd64","packages":[{"name":"apt","version":"3.0.3"}]}'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_bytes(content)
            self.assertIsInstance(HELPER.load_manifest(path, hashlib.sha256(content).hexdigest()), dict)
            with self.assertRaisesRegex(SystemExit, "manifest_checksum"):
                HELPER.load_manifest(path, "0" * 64)

    def test_manifest_rejects_types_versions_and_foreign_qualifiers(self) -> None:
        base = {
            "version": 1,
            "architecture": "amd64",
            "provenance": {
                "installedInventory": {
                    "format": "dpkg-query-status-tsv-v1",
                    "installedRecords": 1,
                    "sha256": "1" * 64,
                },
                "solverResult": {
                    "format": "apt-get-simulate-v1",
                    "sha256": "2" * 64,
                    "changes": [{
                        "action": "upgrade",
                        "name": "apt",
                        "previousVersion": "3.0.2",
                        "version": "3.0.3",
                    }],
                },
            },
            "packages": [{"name": "apt", "version": "3.0.3"}],
        }
        for package, reason in [
            ({"name": 42, "version": "1.0"}, "manifest_package_name"),
            ({"name": "apt", "version": 42}, "manifest_package_version"),
            ({"name": "apt", "version": "latest"}, "manifest_package_version"),
            ({"name": "apt", "version": "unstable1"}, "manifest_package_version"),
            ({"name": "apt", "version": "1.0-"}, "manifest_package_version"),
            ({"name": "libc6:arm64", "version": "1:2:3-1"}, "manifest_foreign_architecture"),
        ]:
            manifest = {**base, "packages": [package]}
            with self.subTest(package=package):
                with self.assertRaisesRegex(SystemExit, reason):
                    HELPER.validate_manifest(manifest)
        valid_epoch = {
            **base,
            "packages": [{"name": "apt", "version": "1:2:3-1"}],
            "provenance": {
                **base["provenance"],
                "solverResult": {
                    **base["provenance"]["solverResult"],
                    "changes": [{
                        "action": "upgrade",
                        "name": "apt",
                        "previousVersion": "1:2:3-0",
                        "version": "1:2:3-1",
                    }],
                },
            },
        }
        architecture, packages = HELPER.validate_manifest(valid_epoch)
        self.assertEqual(architecture, "amd64")
        self.assertEqual(packages["apt"], "1:2:3-1")

    def test_manifest_provenance_mutations_fail_closed(self) -> None:
        manifest = {
            "version": 1,
            "architecture": "amd64",
            "packages": [{"name": "apt", "version": "3.0.3"}],
            "provenance": {
                "installedInventory": {
                    "format": "dpkg-query-status-tsv-v1",
                    "installedRecords": 1,
                    "sha256": "1" * 64,
                },
                "solverResult": {
                    "format": "apt-get-simulate-v1",
                    "sha256": "2" * 64,
                    "changes": [{
                        "action": "upgrade",
                        "name": "apt",
                        "previousVersion": "3.0.2",
                        "version": "3.0.3",
                    }],
                },
            },
        }
        mutations = [
            (lambda value: value["provenance"]["solverResult"]["changes"][0].update(previousVersion=None), "manifest_transition_fields"),
            (lambda value: value["provenance"]["solverResult"]["changes"][0].update(version="3.0.2"), "manifest_transition_fields"),
            (lambda value: value["provenance"]["solverResult"]["changes"].append(dict(value["provenance"]["solverResult"]["changes"][0])), "manifest_transition_duplicate"),
            (lambda value: value["provenance"]["solverResult"]["changes"][0].update(version="3.0.4"), "manifest_transition_final_version"),
            (lambda value: value["provenance"]["solverResult"]["changes"][0].update(action="remove", version=None), "manifest_transition_final_presence"),
        ]
        for mutate, reason in mutations:
            value = json.loads(json.dumps(manifest))
            mutate(value)
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(SystemExit, reason):
                    HELPER.validate_manifest(value)


class ProxmoxPackagePlayStructureTest(unittest.TestCase):
    def test_cleanup_precedes_final_exact_verification_and_lock_release(self) -> None:
        repository_root = MODULE_PATH.parents[4]
        playbook_path = repository_root / "ansible/playbooks/proxmox-site.yml"
        playbook = playbook_path.read_text()
        cleanup_index = playbook.index("    - role: proxmox_cleanup")
        post_tasks_index = playbook.index("  post_tasks:")
        verify_index = playbook.index("Verify the final complete installed package map after cleanup")
        release_index = playbook.index("Release the shared host-side mutation lock after success")
        self.assertLess(cleanup_index, post_tasks_index)
        self.assertLess(post_tasks_index, verify_index)
        self.assertLess(verify_index, release_index)
        verification_block = playbook[verify_index:release_index]
        self.assertIn("name: proxmox_host", verification_block)
        self.assertIn("tasks_from: verify-exact-packages", verification_block)
        self.assertIn("proxmox_host_verify_installed_only: true", verification_block)
        self.assertIn("when: not ansible_check_mode", verification_block)

    def test_transaction_mode_is_limited_to_check_or_approved_cleanup(self) -> None:
        task_path = MODULE_PATH.parents[1] / "tasks/verify-exact-packages.yml"
        task_source = task_path.read_text()
        self.assertIn("--allow-existing-extras", task_source)
        self.assertIn("ansible_check_mode or (proxmox_cleanup_migration_confirmed | bool)", task_source)
        self.assertIn("--verify-installed-only", task_source)
        self.assertIn("changed_when: false", task_source)


if __name__ == "__main__":
    unittest.main()
