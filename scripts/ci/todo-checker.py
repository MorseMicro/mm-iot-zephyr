#!/usr/bin/env python3
"""
TODO format checker for git diffs.
Validates that all TODO comments match: TODO: OSP-<TICKET> - Description
"""

import sys
import re
import argparse
from pathlib import Path


class TodoChecker:
    # Match TODO in any case/format (TODO, to-do, etc)
    TODO_PATTERN = re.compile(r'(todo|to-do|to_do)\s*:\s*(.+)', re.IGNORECASE)

    # Valid format: OSP-<number> - <description>
    VALID_FORMAT = re.compile(r'^OSP-\d+\s*-\s*.+')

    def __init__(self):
        self.violations = []

    def check_diff(self, diff_text):
        """Check a unified diff for TODO format violations."""
        lines = diff_text.split('\n')
        current_file = None
        line_num = 0

        for line in lines:
            # Track file name from diff header
            if line.startswith('+++'):
                # Extract filename from "++++ b/path/to/file"
                current_file = line.split(' b/', 1)[1] if ' b/' in line else line[4:]
                line_num = 0
                continue

            # Track line numbers from hunk headers
            if line.startswith('@@'):
                # Parse "@@ -old_start,old_count +new_start,new_count @@"
                match = re.search(r'\+(\d+)', line)
                if match:
                    line_num = int(match.group(1)) - 1
                continue

            # Check added/modified lines only (prefixed with +)
            if line.startswith('+') and not line.startswith('+++'):
                line_num += 1
                content = line[1:]  # Remove the + prefix

                # Look for TODO comments
                todo_match = self.TODO_PATTERN.search(content)
                if todo_match:
                    todo_content = todo_match.group(2).strip()

                    # Validate format
                    if not self.VALID_FORMAT.match(todo_content):
                        self.violations.append({
                            'file': current_file,
                            'line': line_num,
                            'content': content,
                            'reason': 'Invalid format. Expected: TODO: OSP-<TICKET> - Description'
                        })
            elif line.startswith(' ') and not line.startswith('  '):
                # Context line (no +/-)
                line_num += 1

    def report(self):
        """Print violation report and return exit code."""
        if not self.violations:
            print("✓ All TODOs are properly formatted!")
            return 0

        print(f"✗ Found {len(self.violations)} improperly formatted TODO(s):\n")
        for v in self.violations:
            print(f"  File: {v['file']}")
            print(f"  Line: {v['line']}")
            print(f"  Content: {v['content']}")
            print(f"  Issue: {v['reason']}\n")

        return 1


def main():
    parser = argparse.ArgumentParser(
        description='Check git diff for properly formatted TODOs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Expected TODO format:
  TODO: OSP-<JIRA_TICKET> - Description

Examples:
  git diff HEAD~1 HEAD | todo-checker.py
  todo-checker.py -f pull-request.diff
        '''
    )
    parser.add_argument('-f', '--file', help='Read git diff from file (default: stdin)')

    args = parser.parse_args()

    # Read diff
    if args.file:
        try:
            with open(args.file, 'r') as f:
                diff_text = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 2
    else:
        # Read from stdin
        diff_text = sys.stdin.read()

    # Check and report
    checker = TodoChecker()
    checker.check_diff(diff_text)
    return checker.report()


if __name__ == '__main__':
    sys.exit(main())
