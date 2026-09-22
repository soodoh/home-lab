#!/usr/bin/env python3
"""Focused tests for the managed Omada controller LAN hostname alias."""

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
if alias.DOCKER_HOST_IPV4 != "192.168.0.100":
    raise RuntimeError("Omada alias must follow the fixed Docker LAN reservation")


class OmadaHostAliasTests(unittest.TestCase):
    def test_configure_is_atomic_and_idempotently_refreshes_the_marked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n100.64.0.2\tOmada # home-lab-omada\n")
            alias.configure(hosts, "192.168.0.100")
            self.assertEqual(
                hosts.read_text(),
                "127.0.0.1 localhost\n192.168.0.100\tOmada # home-lab-omada\n",
            )

    def test_configure_rejects_unmanaged_or_duplicate_aliases(self) -> None:
        unmanaged = "127.0.0.1 localhost\n192.168.0.100 Omada\n"
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(unmanaged, "192.168.0.100")
        for equivalent in ("omada", "oMaDa"):
            with self.subTest(equivalent=equivalent), self.assertRaises(alias.AliasError):
                alias.render_hosts(
                    f"127.0.0.1 localhost\n192.168.0.100 {equivalent}\n",
                    "192.168.0.100",
                )
        duplicate = (
            "127.0.0.1 localhost\n"
            "192.168.0.100 Omada # home-lab-omada\n"
            "192.168.0.100 Omada # home-lab-omada\n"
        )
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(duplicate, "192.168.0.100")
        with self.assertRaises(alias.AliasError):
            alias.render_hosts(
                "127.0.0.1 localhost # home-lab-omada\n",
                "192.168.0.100",
            )

    def test_configure_accepts_only_the_fixed_lan_reservation(self) -> None:
        for value in ("100.111.210.72", "192.168.0.101", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(alias.AliasError):
                alias.render_hosts("127.0.0.1 localhost\n", value)

    def test_resolution_rejects_non_lan_or_multiple_addresses(self) -> None:
        wrong = [(None, None, None, None, ("100.111.210.72", 0))]
        with mock.patch.object(alias.socket, "getaddrinfo", return_value=wrong):
            with self.assertRaises(alias.AliasError):
                alias.resolve_ipv4("Omada")
        mixed = [
            (None, None, None, None, ("192.168.0.100", 0)),
            (None, None, None, None, ("192.168.0.101", 0)),
        ]
        with mock.patch.object(alias.socket, "getaddrinfo", return_value=mixed):
            with self.assertRaises(alias.AliasError):
                alias.resolve_ipv4("Omada")

    def test_verify_requires_exact_matching_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("192.168.0.100\tOmada # home-lab-omada\n")
            with mock.patch.object(alias, "resolve_ipv4", return_value="192.168.0.100"):
                alias.verify(hosts)
            with mock.patch.object(alias, "resolve_ipv4", return_value="192.168.0.101"):
                with self.assertRaises(alias.AliasError):
                    alias.verify(hosts)

    def test_verify_rejects_an_additional_case_insensitive_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text(
                "192.168.0.100\tOmada # home-lab-omada\n"
                "192.168.0.100\tomada\n"
            )
            with self.assertRaises(alias.AliasError):
                alias.verify(hosts)

    def test_remove_deletes_only_the_marked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n192.168.0.100\tOmada # home-lab-omada\n")
            alias.remove(hosts)
            self.assertEqual(hosts.read_text(), "127.0.0.1 localhost\n")


if __name__ == "__main__":
    unittest.main()
