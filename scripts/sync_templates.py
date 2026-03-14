#!/usr/bin/env python3
"""Sync tracked files from local rulepack/registry repos into templates/ snapshots."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
WORKTREE_DIR = ROOT / ".template-worktrees"

SUPPORTED = {
    "preen-rulepack": TEMPLATES_DIR / "preen-rulepack",
    "preen-rulepack-homebrew": TEMPLATES_DIR / "preen-rulepack-homebrew",
    "preen-registry": TEMPLATES_DIR / "preen-registry",
}


def run_git(source: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(source), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


def tracked_files(source: Path) -> list[str]:
    out = run_git(source, "ls-files", "-z")
    return [item for item in out.split("\0") if item]


def clean_destination(dest: Path) -> None:
    if not dest.exists():
        dest.mkdir(parents=True, exist_ok=True)
        return
    for child in dest.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def sync_repo(source: Path, dest: Path) -> None:
    files = tracked_files(source)
    clean_destination(dest)
    copied = 0
    for rel in files:
        src_file = source / rel
        if not src_file.is_file():
            continue
        dst_file = dest / rel
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst_file)
        copied += 1
    print(f"synced {copied} files: {source} -> {dest}")


def parse_pair(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected NAME=/absolute/path")
    name, source = value.split("=", 1)
    if name not in SUPPORTED:
        allowed = ", ".join(sorted(SUPPORTED))
        raise argparse.ArgumentTypeError(f"unsupported template name '{name}' (allowed: {allowed})")
    source_path = Path(source).expanduser()
    if not source_path.is_absolute():
        raise argparse.ArgumentTypeError("source path must be absolute")
    return name, source_path


def default_source(name: str) -> Path:
    return WORKTREE_DIR / name


def ensure_git_repo(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"source path not found: {path}")
    try:
        run_git(path, "rev-parse", "--is-inside-work-tree")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"source is not a git repo: {path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync template snapshots from local repos. Default source root: .template-worktrees/",
    )
    parser.add_argument(
        "--sync",
        action="append",
        default=[],
        help="Explicit mapping NAME=/absolute/path (repeatable).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Sync all supported templates from default .template-worktrees/NAME paths.",
    )
    args = parser.parse_args()

    mappings: dict[str, Path] = {}
    if args.all:
        for name in SUPPORTED:
            mappings[name] = default_source(name)
    for item in args.sync:
        name, source = parse_pair(item)
        mappings[name] = source

    if not mappings:
        parser.error("no templates selected; use --all or --sync NAME=/absolute/path")

    for name, source in mappings.items():
        ensure_git_repo(source)
        sync_repo(source, SUPPORTED[name])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
