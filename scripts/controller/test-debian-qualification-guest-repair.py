#!/usr/bin/env python3
"""Verify VM9900 guest DNS repair boundaries."""
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-qualification-guest-repair.py"; spec=importlib.util.spec_from_file_location("guest_repair",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); source=SOURCE.read_text()
assert module.CONTENT==b"[DHCPv4]\nUseDNS=no\n[Network]\nDNS=1.1.1.1\nDNS=9.9.9.9\n"
for required in ("REPAIR_VM9900_PUBLIC_DNS","home-lab-debian-qualification-restart-receipt-v1","home-lab-debian-qualification-host-key-receipt-v1","StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","UpdateHostKeys=no","IdentityAgent=none","IdentitiesOnly=yes","PasswordAuthentication=no","KbdInteractiveAuthentication=no","RequestTTY=no","guest-repair.lock","automatic_apply","before_sha256","machine_id_sha256","os.O_NOFOLLOW","fcntl.LOCK_EX|fcntl.LOCK_NB","resolvectl","1.1.1.1","9.9.9.9","curl","resolvectl\",\"revert"):
 assert required in source,required
for forbidden in ("192.168.0.100","/srv/home-lab-state","/mnt/storage","docker compose","tailscale up","apt-get","apt install"):
 assert forbidden not in source,forbidden
print("debian_qualification_guest_repair=verified exact_dns_only=true")
