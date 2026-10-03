#!/usr/bin/env python3
"""Require every rendered Compose service image to retain a tag and exact digest."""

import json
import re
from pathlib import Path
import subprocess
import sys

IMAGE = re.compile(r"^\S+:[^@\s]+@sha256:[0-9a-f]{64}$")


def validate_wolf_pins(document: dict) -> int:
    """Validate the app references consumed by native Wolf configuration convergence."""
    pins = document.get("image_pins")
    if not isinstance(pins, list) or not pins:
        raise ValueError("wolf_image_pins_missing")
    sources = set()
    for pin in pins:
        if not isinstance(pin, dict):
            raise ValueError("wolf_image_pin_shape")
        source, image = pin.get("source"), pin.get("image")
        if (not isinstance(source, str) or not isinstance(image, str)
                or re.fullmatch(r"ghcr.io/games-on-whales/[a-z0-9-]+:[a-zA-Z0-9._-]+", source) is None
                or IMAGE.fullmatch(image) is None or not image.startswith(source + "@sha256:")):
            raise ValueError("wolf_image_not_tag_and_digest")
        if source in sources:
            raise ValueError("wolf_image_source_duplicate")
        sources.add(source)
    return len(pins)


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
    try:
        policy = json.loads((Path(__file__).resolve().parents[1] / "services/data/wolf/security.json").read_text())
        wolf_count = validate_wolf_pins(policy)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        reason = str(error) if isinstance(error, ValueError) else "wolf_policy_shape"
        raise SystemExit(f"wolf_image_pins=failed reason={reason}") from error
    print(f"compose_image_pins=verified services={len(services)}")
    print(f"wolf_image_pins=verified applications={wolf_count}")


if __name__ == "__main__":
    main()
