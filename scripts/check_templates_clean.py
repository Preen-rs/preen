#!/usr/bin/env python3
"""Fail if templates contain VCS/runtime junk files."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
BLOCKED_NAMES = {".DS_Store", "__pycache__"}


def main() -> int:
    issues: list[Path] = []
    for path in TEMPLATES.rglob("*"):
        if not path.exists():
            continue
        if path.name in BLOCKED_NAMES:
            issues.append(path)
            continue
        if path.is_dir() and path.name == ".git":
            issues.append(path)
    if not issues:
        print("templates clean: OK")
        return 0
    print("templates clean check failed:", file=sys.stderr)
    for path in issues:
        print(f" - {path.relative_to(ROOT)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
