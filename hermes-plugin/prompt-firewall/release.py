#!/usr/bin/env python3
"""Release quarantined content the owner reviewed and found benign.

Exactly that content (by its sha256) passes from now on. Anything else, including an edited
version of the same file or page, is scanned as usual. Owner-only: run it yourself, never ask the
agent to, and only after reading the quarantined original.

    python3 ~/.hermes/plugins/prompt-firewall/release.py fw-20260929-2b0e42 [more ids]
    python3 ~/.hermes/plugins/prompt-firewall/release.py --list

Uses HERMES_HOME (default ~/.hermes); --home picks another profile.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Release quarantined content by its hash.")
    ap.add_argument("ids", nargs="*", help="quarantine ids (fw-YYYYMMDD-xxxxxx)")
    ap.add_argument("--home", default=os.environ.get("HERMES_HOME") or "~/.hermes")
    ap.add_argument("--list", action="store_true", help="show what is released")
    a = ap.parse_args(argv)
    fw = Path(os.path.expanduser(a.home)) / "firewall"
    released = fw / "released.txt"
    if a.list:
        print(released.read_text() if released.exists() else "nothing released", end="")
        return 0
    if not a.ids:
        ap.error("give at least one quarantine id")
    lines = []
    for qid in a.ids:
        p = fw / "quarantine" / f"{qid}.json"
        if not re.fullmatch(r"fw-\d{8}-[0-9a-f]{6}", qid) or not p.is_file():
            print(f"{qid}: no such quarantine entry under {fw / 'quarantine'}", file=sys.stderr)
            return 1
        rec = json.loads(p.read_text())
        digest = rec.get("content_sha256")
        if not digest:
            print(f"{qid}: quarantined by a plugin older than 0.4.0, which kept no content hash", file=sys.stderr)
            return 1
        lines.append(f"{digest} {qid} {rec.get('tool', '?')} released {time.strftime('%Y-%m-%d')}\n")
    fw.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(released, "a") as f:
        f.writelines(lines)
    os.chmod(released, 0o600)
    for line in lines:
        print("released", line.split()[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
