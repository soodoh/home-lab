#!/usr/bin/env python3
"""Focused tests for the managed Omada controller hostname alias."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HELPER = Path(__file__).with_name("omada-host-alias.py")


def load_helper():
    spec = importlib.util.spec_from_file_location("omada_host_alias", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {HELPER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


alias = load_helper()


class OmadaHostAliasTests(unittest.TestCase):
    def test_configure_is_atomic_and_idempotently_refreshes_the_marked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n100.64.0.2\tOmada # home-lab-omada\n")
            alias.configure(hosts, "100.111.210.72")
            self.assertEqual(
                hosts.read_text(),
                "127.0.0.1 localhost\n100.111.210.72\tOmada # home-lab-omada\n",
            )

    def test_configure_rejects_unmanaged_or_duplicate_aliases(self) -> None:
        unmanaged = "127.0.0.1 localhost\n100.111.210.72 Omada\n"
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(unmanaged, "100.111.210.72")
        for equivalent in ("omada", "oMaDa"):
            with self.subTest(equivalent=equivalent), self.assertRaises(alias.AliasError):
                alias.render_hosts(
                    f"127.0.0.1 localhost\n100.111.210.72 {equivalent}\n",
                    "100.111.210.72",
                )
        duplicate = (
            "127.0.0.1 localhost\n"
            "100.111.210.72 Omada # home-lab-omada\n"
            "100.111.210.72 Omada # home-lab-omada\n"
        )
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(duplicate, "100.111.210.72")
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(
                "127.0.0.1 localhost # home-lab-omada\n",
                "100.111.210.72",
            )

    def test_configure_rejects_non_tailscale_addresses(self) -> None:
        with self.assertRaises(alias.AliasError):
            alias.render_hosts("127.0.0.1 localhost\n", "192.168.0.100")

    def test_resolution_rejects_non_tailscale_or_multiple_addresses(self) -> None:
        non_tailscale = [(None, None, None, None, ("192.168.0.100", 0))]
        with mock.patch.object(alias.socket, "getaddrinfo", return_value=non_tailscale):
            with self.assertRaises(alias.AliasError):
                alias.resolve_tailscale_ipv4("Omada")
        mixed = [
            (None, None, None, None, ("100.111.210.72", 0)),
            (None, None, None, None, ("192.168.0.100", 0)),
        ]
        with mock.patch.object(alias.socket, "getaddrinfo", return_value=mixed):
            with self.assertRaises(alias.AliasError):
                alias.resolve_tailscale_ipv4("Omada")

    def test_verify_requires_exact_matching_resolutions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("100.111.210.72\tOmada # home-lab-omada\n")
            with mock.patch.object(
                alias,
                "resolve_tailscale_ipv4",
                side_effect=("100.111.210.72", "100.111.210.72"),
            ):
                alias.verify(hosts)
            with mock.patch.object(
                alias,
                "resolve_tailscale_ipv4",
                side_effect=("100.111.210.72", "100.100.100.100"),
            ):
                with self.assertRaises(alias.AliasError):
                    alias.verify(hosts)

    def test_verify_rejects_an_additional_case_insensitive_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text(
                "100.111.210.72\tOmada # home-lab-omada\n"
                "100.111.210.72\tomada\n"
            )
            with self.assertRaises(alias.AliasError):
                alias.verify(hosts)

    def test_remove_deletes_only_the_marked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n100.111.210.72\tOmada # home-lab-omada\n")
            alias.remove(hosts)
            self.assertEqual(hosts.read_text(), "127.0.0.1 localhost\n")


if __name__ == "__main__":
    unittest.main()
