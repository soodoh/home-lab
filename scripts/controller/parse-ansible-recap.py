#!/usr/bin/env python3
"""Parse one host's final Ansible recap into stable JSON."""

import json
from pathlib import Path
import re
import sys

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
RECAP = re.compile(
    r"^(?P<host>[^\s]+)\s*:\s*"
    r"ok=(?P<ok>\d+)\s+"
    r"changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+"
    r"skipped=(?P<skipped>\d+)\s+"
    r"rescued=(?P<rescued>\d+)\s+"
    r"ignored=(?P<ignored>\d+)\s*$"
)


def main() -> None:
    log_path = Path(sys.argv[1])
    expected_host = sys.argv[2]
    matches = []

    for raw_line in log_path.read_text(encoding="utf-8").splitlines():
        line = ANSI_ESCAPE.sub("", raw_line)
        match = RECAP.fullmatch(line)
        if match is not None and match.group("host") == expected_host:
            matches.append(match.groupdict())

    if len(matches) != 1:
        raise SystemExit(
            f"expected one recap for {expected_host}, found {len(matches)} in {log_path}"
        )

    recap = {
        key: int(value)
        for key, value in matches[0].items()
        if key != "host"
    }
    recap["host"] = expected_host
    print(json.dumps(recap, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
