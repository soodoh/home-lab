#!/usr/bin/env python3
"""Manage and verify the trusted LAN alias for the Omada controller."""

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
DOCKER_HOST_IPV4 = "192.168.0.100"
LAN_IPV4 = ipaddress.IPv4Network("192.168.0.0/24")
MARKER = "# home-lab-omada"


class AliasError(ValueError):
    """Raised when the managed hostname alias is unsafe or inconsistent."""


def require_docker_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise AliasError("Docker host did not resolve to an IPv4 address") from error
    if address not in LAN_IPV4 or str(address) != DOCKER_HOST_IPV4:
        raise AliasError("Docker host IPv4 address differs from its fixed LAN reservation")
    return str(address)


def resolve_ipv4(hostname: str) -> str:
    addresses = {
        entry[4][0]
        for entry in socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    }
    if len(addresses) != 1:
        raise AliasError(f"{hostname} must resolve to exactly one IPv4 address")
    return require_docker_ipv4(addresses.pop())


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
        retained.append(f"{require_docker_ipv4(docker_ip)}\t{ALIAS} {MARKER}")
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
    expected = f"{DOCKER_HOST_IPV4}\t{ALIAS} {MARKER}"
    if content.splitlines().count(expected) != 1:
        raise AliasError("the exact managed Omada LAN hosts entry is missing or stale")
    if resolve_ipv4(ALIAS) != DOCKER_HOST_IPV4:
        raise AliasError("Omada does not resolve to the fixed Docker host LAN reservation")


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
            docker_ip = require_docker_ipv4(args.docker_ip or DOCKER_HOST_IPV4)
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
