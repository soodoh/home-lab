#!/usr/bin/env python3
"""Require every rendered Compose service image to retain a tag and exact digest."""

import json
import re
import subprocess
import sys

IMAGE = re.compile(r"^\S+:[^@\s]+@sha256:[0-9a-f]{64}$")


def main() -> None:
    rendered = subprocess.run(
        ["docker", "compose", "config", "--no-interpolate", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(rendered.stdout)
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise SystemExit("compose_image_pins=failed reason=services_missing")
    invalid = sorted(
        name
        for name, service in services.items()
        if not isinstance(service, dict)
        or not isinstance(service.get("image"), str)
        or IMAGE.fullmatch(service["image"]) is None
    )
    if invalid:
        print(
            "compose_image_pins=failed reason=image_not_tag_and_digest services="
            + ",".join(invalid),
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"compose_image_pins=verified services={len(services)}")


if __name__ == "__main__":
    main()
