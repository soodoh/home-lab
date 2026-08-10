#!/usr/bin/env python3
"""Manage and verify the trusted controller's Omada hostname alias."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile

ALIAS = "Omada"
DOCKER_HOST = "docker-host"
MARKER = "# home-lab-omada"
TAILSCALE_IPV4 = ipaddress.IPv4Network("100.64.0.0/10")


class AliasError(ValueError):
    """Raised when the managed hostname alias is unsafe or inconsistent."""


def require_tailscale_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise AliasError("Docker host did not resolve to an IPv4 address") from error
    if address not in TAILSCALE_IPV4:
        raise AliasError("Docker host IPv4 address is outside the Tailscale CGNAT range")
    return str(address)


def resolve_tailscale_ipv4(hostname: str) -> str:
    addresses = {
        entry[4][0]
        for entry in socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    }
    if len(addresses) != 1:
        raise AliasError(f"{hostname} must resolve only to one Tailscale IPv4 address")
    return require_tailscale_ipv4(addresses.pop())


def line_has_alias(line: str) -> bool:
    content = line.split("#", 1)[0]
    fields = content.split()
    alias = ALIAS.casefold()
    return any(field.casefold() == alias for field in fields[1:])


def render_hosts(content: str, docker_ip: str | None = None) -> str:
    retained: list[str] = []
    marker_count = 0
    for line in content.splitlines():
        if MARKER in line:
            if not line.rstrip().endswith(MARKER) or not line_has_alias(line):
                raise AliasError("the managed Omada marker is attached to an invalid hosts entry")
            marker_count += 1
            continue
        if line_has_alias(line):
            raise AliasError("an unmanaged Omada entry already exists in the hosts file")
        retained.append(line)
    if marker_count > 1:
        raise AliasError("the hosts file contains duplicate managed Omada entries")
    if docker_ip is not None:
        retained.append(f"{require_tailscale_ipv4(docker_ip)}\t{ALIAS} {MARKER}")
    return "\n".join(retained) + "\n"


def atomic_write_hosts(path: Path, content: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AliasError("hosts path must be a regular, non-symlink file")
    metadata = path.stat()
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=".home-lab-hosts.",
        delete=False,
    ) as stream:
        stream.write(content)
        temporary = Path(stream.name)
    try:
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        if os.geteuid() == 0:
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def configure(path: Path, docker_ip: str) -> None:
    if path == Path("/etc/hosts") and os.geteuid() != 0:
        raise AliasError("configuring /etc/hosts requires explicit sudo")
    atomic_write_hosts(path, render_hosts(path.read_text(), docker_ip))


def remove(path: Path) -> None:
    if path == Path("/etc/hosts") and os.geteuid() != 0:
        raise AliasError("removing the /etc/hosts entry requires explicit sudo")
    content = path.read_text()
    if MARKER not in content:
        raise AliasError("the managed Omada hosts entry is absent")
    atomic_write_hosts(path, render_hosts(content))


def verify(path: Path) -> None:
    content = path.read_text()
    render_hosts(content)
    docker_ip = resolve_tailscale_ipv4(DOCKER_HOST)
    expected = f"{docker_ip}\t{ALIAS} {MARKER}"
    if content.splitlines().count(expected) != 1:
        raise AliasError("the exact managed Omada hosts entry is missing or stale")
    omada_ip = resolve_tailscale_ipv4(ALIAS)
    if omada_ip != docker_ip:
        raise AliasError("Omada and docker-host resolve to different Tailscale addresses")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("configure", "verify", "remove"))
    parser.add_argument("--hosts-file", type=Path, default=Path("/etc/hosts"))
    parser.add_argument("--docker-ip")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.action == "configure":
            docker_ip = require_tailscale_ipv4(args.docker_ip) if args.docker_ip else resolve_tailscale_ipv4(DOCKER_HOST)
            configure(args.hosts_file, docker_ip)
        elif args.action == "verify":
            if args.docker_ip is not None:
                raise AliasError("--docker-ip is valid only for configure")
            verify(args.hosts_file)
        else:
            if args.docker_ip is not None:
                raise AliasError("--docker-ip is valid only for configure")
            remove(args.hosts_file)
        return 0
    except (AliasError, OSError, socket.gaierror) as error:
        print(f"Omada host alias failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
