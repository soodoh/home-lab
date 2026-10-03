#!/usr/bin/env python3
"""Exercise rendered native nftables rules in disposable process-owned namespaces.

No host interfaces, host rules or named namespace files are changed. A later hook
models Tailscale's independent denial; provider policy tests qualify its identity
selectors separately. Requires Linux root, iproute2, util-linux and nftables.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

TCP = [47984, 47989, 48010]
UDP = [47999, 48100, 48200]


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(f"native fixture command failed: {args}: {result.stderr.strip()}")
    return result.stdout


def client():
    print("ready", flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        family = socket.AF_INET6 if ":" in request["source"] else socket.AF_INET
        kind = socket.SOCK_DGRAM if request["protocol"] == "udp" else socket.SOCK_STREAM
        with socket.socket(family, kind) as sock:
            sock.settimeout(0.2)
            try:
                sock.bind((request["source"], 0))
                sock.connect((request["target"], request["port"]))
                sock.send(b"wolf-fixture")
                allowed = sock.recv(64) == b"wolf-fixture"
            except OSError:
                allowed = False
        print(json.dumps(allowed), flush=True)


def serve(sock, udp):
    while True:
        try:
            if udp:
                data, address = sock.recvfrom(64)
                sock.sendto(data, address)
            else:
                conn, _ = sock.accept()
                with conn:
                    conn.settimeout(1)
                    data = conn.recv(64)
                    conn.sendall(data)
        except OSError:
            return


def fixture(rules, nft):
    peers, servers = [], []
    try:
        run("ip", "link", "set", "lo", "up")
        # Each peer's namespace exists only for the lifetime of its process.
        definitions = [
            ("ens18", "lanpeer", "192.168.0.100/24", ["192.168.0.10/24", "198.51.100.10/32"], "fd00:1::100/64", ["fd00:1::10/64"]),
            ("tailscale0", "tspeer", "100.116.163.42/24", ["100.116.163.2/24", "100.116.163.3/24"], "fd7a:115c:a1e0::42/64", ["fd7a:115c:a1e0::2/64", "fd7a:115c:a1e0::3/64"]),
            ("outside0", "extpeer", "198.51.101.1/24", ["198.51.101.10/24", "192.168.0.20/32"], "fd00:2::1/64", ["fd00:2::10/64"]),
        ]
        for server_if, client_if, ipv4, client_ips, ipv6, client_v6 in definitions:
            peer = subprocess.Popen(["unshare", "--net", sys.executable, __file__, "--client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            peers.append(peer)
            assert peer.stdout.readline().strip() == "ready"
            run("ip", "link", "add", server_if, "type", "veth", "peer", "name", client_if)
            run("ip", "link", "set", client_if, "netns", str(peer.pid))
            run("ip", "addr", "add", ipv4, "dev", server_if)
            run("ip", "-6", "addr", "add", ipv6, "dev", server_if, "nodad")
            run("ip", "link", "set", server_if, "up")
            for address in client_ips:
                run("nsenter", "-t", str(peer.pid), "-n", "ip", "addr", "add", address, "dev", client_if)
            for address in client_v6:
                run("nsenter", "-t", str(peer.pid), "-n", "ip", "-6", "addr", "add", address, "dev", client_if, "nodad")
            run("nsenter", "-t", str(peer.pid), "-n", "ip", "link", "set", client_if, "up")
        # Routes for the deliberately non-LAN/spoofed sources make the pre-rule
        # feedback loop succeed, so a routing failure cannot masquerade as denial.
        run("ip", "route", "add", "198.51.100.10/32", "dev", "ens18")
        run("ip", "route", "add", "192.168.0.20/32", "dev", "outside0")
        for udp, ports in [(False, TCP + [22]), (True, UDP)]:
            for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
                for port in ports:
                    sock = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((address, port))
                    if not udp:
                        sock.listen()
                    servers.append(sock)
                    threading.Thread(target=serve, args=(sock, udp), daemon=True).start()

        cases = [
            (0, "192.168.0.10", "192.168.0.100", True),
            (0, "198.51.100.10", "192.168.0.100", False),
            (1, "100.116.163.2", "100.116.163.42", True),
            (1, "100.116.163.3", "100.116.163.42", False),
            (2, "198.51.101.10", "198.51.101.1", False),
            (2, "192.168.0.20", "198.51.101.1", False),
            (0, "fd00:1::10", "fd00:1::100", False),
            (1, "fd7a:115c:a1e0::2", "fd7a:115c:a1e0::42", True),
            (1, "fd7a:115c:a1e0::3", "fd7a:115c:a1e0::42", False),
            (2, "fd00:2::10", "fd00:2::1", False),
        ]

        def probe(case, protocol, port):
            index, source, target, _ = case
            peer = peers[index]
            peer.stdin.write(json.dumps({"source": source, "target": target, "protocol": protocol, "port": port}) + "\n")
            peer.stdin.flush()
            return json.loads(peer.stdout.readline())

        for case in cases:
            assert probe(case, "tcp", TCP[0]), ("baseline_tcp", case)
            assert probe(case, "udp", UDP[0]), ("baseline_udp", case)

        run(nft, "--check", "--file", rules)
        run(nft, "--file", rules)
        # Loading the same desired table again must neither fail nor disturb
        # unrelated tables. Denials in a later hook must remain authoritative.
        tailnet = """table inet test_tailnet {
chain input { type filter hook input priority 0; policy accept;
iifname "tailscale0" ip saddr 100.116.163.2 return
iifname "tailscale0" ip6 saddr fd7a:115c:a1e0::2 return
iifname "tailscale0" tcp dport {47984,47989,48010} drop
iifname "tailscale0" udp dport {47999,48100,48200} drop
}
}
"""
        run(nft, "--file", "-", input=tailnet)
        run(nft, "--file", rules)
        run(nft, "list", "table", "inet", "test_tailnet")
        for case in cases:
            for protocol, ports in [("tcp", TCP), ("udp", UDP)]:
                for port in ports:
                    assert probe(case, protocol, port) == case[3], ("protocol_admission", case, protocol, port)
            assert probe(case, "tcp", 22), ("unrelated_port_changed", case)
        # Loopback healthchecks remain possible without granting remote access.
        for address in ["127.0.0.1", "::1"]:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            for protocol, ports in [("tcp", TCP), ("udp", UDP)]:
                for port in ports:
                    with socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        sock.connect((address, port))
                        sock.send(b"wolf-fixture")
                        assert sock.recv(64) == b"wolf-fixture"
        print("wolf_firewall=verified ipv4_ipv6=checked later_denial=preserved unrelated_ports=preserved atomic_reload=checked")
    finally:
        for sock in servers:
            sock.close()
        for peer in peers:
            peer.terminate()
            peer.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--rules")
    parser.add_argument("--nft", default="/usr/sbin/nft")
    args = parser.parse_args()
    if args.client:
        client()
    elif args.child:
        fixture(args.rules, args.nft)
    else:
        assert os.geteuid() == 0, "Run namespace firewall behavior tests as Linux root."
        assert args.rules and Path(args.rules).is_file()
        subprocess.run(["unshare", "--net", sys.executable, __file__, "--child", "--rules", args.rules, "--nft", args.nft], check=True, timeout=90)
