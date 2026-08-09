#!/usr/bin/env python3
"""Remove nondeterministic controller metadata from an Ansible check log."""

from pathlib import Path
import re
import sys


if len(sys.argv) != 2:
    raise SystemExit("usage: normalize-ansible-plan.py <check-log>")

text = Path(sys.argv[1]).read_text(encoding="utf-8")
text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
text = re.sub(
    r'(?m)^\s*"(?:delta|end|start)":\s*"[^"]*",?\s*\n',
    "",
    text,
)
text = re.sub(
    r'(?m)^\s*"(?:atime|ctime|inode|mtime|version)":\s*(?:"[^"]*"|[^,\n]+),?\s*\n',
    "",
    text,
)
text = re.sub(
    r"(?m)(?:/[^\s\"']+)?/\.ansible/tmp/ansible-tmp-[^/\s\"']+",
    "/.ansible/tmp/<normalized>",
    text,
)
text = re.sub(
    r"(?m)(?:/[^\s\"']+)?/\.ansible/tmp/ansible-local-[^/\s\"']+",
    "/.ansible/tmp/<normalized>",
    text,
)
text = re.sub(
    r"(?m)(/\.ansible/tmp/<normalized>)/[^/\s\"']+/",
    r"\1/<normalized>/",
    text,
)
sys.stdout.write(text)
