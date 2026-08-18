#!/usr/bin/env python3
#
# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0
#
"""
Copyright header checker for touched files.

For each given file, verifies that:
  * A "Copyright ... Morse Micro" line exists near the top of the file, and
  * The year (or the end of a year range/list) in that line covers the
    current year.

Files that consist only of Kconfig `rsource` redirects are exempt, since
they contain no original content of their own to copyright.

Files/directories that are known to carry a different copyright convention
(e.g. vendored third-party sources) can be excluded via a blocklist file -
see --blocklist and DEFAULT_BLOCKLIST below.
"""

import argparse
import fnmatch
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

CHECKED_SUFFIXES = {".c", ".h", ".dts", ".dtsi", ".overlay", ".conf", ".py", ".sh"}

# How many lines from the top of the file to search for a copyright header.
HEADER_SCAN_LINES = 40

# Blocklist file consulted by default, relative to this script's directory.
DEFAULT_BLOCKLIST = Path(__file__).resolve().parent / "copyright-blocklist.txt"

COPYRIGHT_RE = re.compile(r"copyright\b(?:\s*\(c\))?\s*(.*)", re.IGNORECASE)
YEAR_RE = re.compile(r"\d{4}")
RSOURCE_ONLY_RE = re.compile(r"^\s*rsource\b")


def load_blocklist(path):
    """Parse a blocklist file into a list of patterns.

    Blank lines and lines starting with '#' are ignored. A trailing '#
    comment' on a pattern line is stripped. Patterns ending in '/' match
    anything under that directory; other patterns are matched against the
    full relative path with both fnmatch globbing (where '*' also matches
    '/') and as a directory prefix, so 'samples/foo' blocks the whole tree
    under samples/foo as well as a same-named file.
    """
    if path is None or not path.is_file():
        return []

    patterns = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return patterns


def is_blocklisted(path, patterns):
    posix_path = PurePosixPath(path).as_posix()
    for pattern in patterns:
        stripped = pattern.rstrip("/")
        if (
            posix_path == stripped
            or posix_path.startswith(stripped + "/")
            or fnmatch.fnmatch(posix_path, pattern)
        ):
            return True
    return False


def is_checked_file(path):
    """Return True if this file is expected to carry a copyright header."""
    name = path.name
    if name == "CMakeLists.txt" or name.startswith("Kconfig"):
        return True
    return path.suffix in CHECKED_SUFFIXES


def is_rsource_only(lines):
    """True if every non-blank line is a Kconfig `rsource` directive."""
    non_blank = [line for line in lines if line.strip()]
    return bool(non_blank) and all(RSOURCE_ONLY_RE.match(line) for line in non_blank)


class CopyrightChecker:
    def __init__(self, current_year, blocklist_patterns=None):
        self.current_year = current_year
        self.blocklist_patterns = blocklist_patterns or []
        self.violations = []

    def check_file(self, path):
        p = Path(path)
        if not p.is_file():
            # Deleted / not present at this revision - nothing to check.
            return

        if not is_checked_file(p):
            return

        if is_blocklisted(path, self.blocklist_patterns):
            return

        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Binary or unreadable file - not something we can header-check.
            return

        lines = text.splitlines()

        if p.name.startswith("Kconfig") and is_rsource_only(lines):
            return

        header_lines = lines[:HEADER_SCAN_LINES]

        copyright_lines = [line for line in header_lines if COPYRIGHT_RE.search(line)]

        if not copyright_lines:
            self.violations.append((path, "missing a copyright header entirely"))
            return

        mm_lines = [line for line in copyright_lines if "morse micro" in line.lower()]

        if not mm_lines:
            self.violations.append(
                (path, "has a copyright header but no 'Morse Micro' copyright line")
            )
            return

        max_year = max(
            int(year) for line in mm_lines for year in YEAR_RE.findall(line)
        )

        if max_year < self.current_year:
            self.violations.append(
                (
                    path,
                    f"Morse Micro copyright year ({max_year}) does not cover "
                    f"the current year ({self.current_year})",
                )
            )

    def report(self):
        if not self.violations:
            print("✓ All touched files have an up-to-date copyright header!")
            return 0

        print(f"✗ Found {len(self.violations)} copyright issue(s):\n")
        for path, reason in self.violations:
            print(f"  File: {path}")
            print(f"  Issue: {reason}\n")

        print(
            "See DEVELOPERS.md: add and/or update the Morse Micro copyright "
            "header in each file you edit."
        )
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Check that touched files have an up-to-date Morse Micro copyright header"
    )
    parser.add_argument(
        "-f", "--file",
        help="Read the list of touched files from this file (default: stdin), one path per line",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to require coverage of (default: current year)",
    )
    parser.add_argument(
        "--blocklist",
        type=Path,
        default=DEFAULT_BLOCKLIST,
        help=(
            "Path to a blocklist file of paths/globs to skip entirely "
            f"(default: {DEFAULT_BLOCKLIST.name} next to this script). "
            "Pass a nonexistent path (or an empty file) to disable it."
        ),
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as f:
            file_list = f.read()
    else:
        file_list = sys.stdin.read()

    paths = [line.strip() for line in file_list.splitlines() if line.strip()]

    current_year = args.year if args.year is not None else datetime.now().year
    blocklist_patterns = load_blocklist(args.blocklist)

    checker = CopyrightChecker(current_year, blocklist_patterns)
    for path in paths:
        checker.check_file(path)

    return checker.report()


if __name__ == "__main__":
    sys.exit(main())
