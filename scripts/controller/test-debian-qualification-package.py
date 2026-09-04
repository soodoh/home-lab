#!/usr/bin/env python3
"""Verify exact VM9900 package transaction boundaries."""
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];SOURCE=ROOT/"scripts/controller/debian-qualification-package.py";spec=importlib.util.spec_from_file_location("qualification_package",SOURCE);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);source=SOURCE.read_text()
compile(module.observation_program(),"observation","exec");compile(module.refresh_program({"packages":[],"machine_id_sha256":"a","sources":{}},"b"*64),"refresh","exec");compile(module.install_program({"packages":[],"machine_id_sha256":"a","qga":[],"sources":{}},["qemu-guest-agent=1:10.0.2-1"],"b"*64),"install","exec")
for required in ("REFRESH_VM9900_DEBIAN_METADATA","INSTALL_VM9900_EXACT_QEMU_GUEST_AGENT","automatic_apply","before_sha256","restart_receipt_sha256","host_key_receipt_sha256","dns_receipt_sha256","apt-get","--simulate","--no-install-recommends","--no-upgrade","candidate drift","added!=approved or removed","qemu-guest-agent.service","is-active","package mutation during refresh","DEBIAN_FRONTEND","home-lab-debian-qualification-package.lock"):
 assert required in source,required
for forbidden in ("dist-upgrade","full-upgrade","autoremove","upgrade\"]","192.168.0.100","/mnt/storage","docker.io","tailscale"):
 assert forbidden not in source,forbidden
assert sorted(module.FILES)==["/etc/apt/mirrors/debian-security.list","/etc/apt/mirrors/debian.list","/etc/apt/sources.list","/etc/apt/sources.list.d/debian.sources"]
print("debian_qualification_package=verified exact_actions=true automatic_apply=false")
