#!/usr/bin/env python3
"""
Fix specific syntax errors in Python files
"""

import os
import re
from pathlib import Path


def fix_file(filepath):
    """Fix common syntax errors in a file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except BaseException:
        return False

    modified = False
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Fix incomplete string literals
        if (
            'detail="No GitHub repository connected. Use' in line
            and not line.rstrip().endswith('"')
        ):
            line = line.rstrip() + '"\n'
            modified = True

        # Fix incomplete f-strings
        if 'f"Device {' in line and not "}" in line:
            line = line.rstrip() + 'device_id}"\n'
            modified = True

        # Fix isolated route decorators
        if line.strip() == "/auth":
            line = "# /auth\n"
            modified = True

        # Fix incomplete docstrings
        if line.strip() == '"""' and i > 0 and not lines[i - 1].strip().endswith('"""'):
            # Look for the next non-empty line
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and not lines[j].strip().startswith('"""'):
                line = '    """\n    Documentation placeholder\n    """\n'
                modified = True

        # Fix broken dictionary definitions
        if "Any]] = {}  # In production" in line:
            line = line.replace(
                "Any]] = {}  # In production", "Any] = {}  # In production"
            )
            modified = True

        if "Any]] = {}  # request_id -> request_data" in line:
            line = line.replace(
                "Any]] = {}  # request_id -> request_data",
                "Any] = {}  # request_id -> request_data",
            )
            modified = True

        # Fix indentation issues - if a line starts with def/class but previous
        # non-empty line doesn't end properly
        if (
            line.strip().startswith("def ") or line.strip().startswith("class ")
        ) and i > 0:
            # Check if previous non-empty line needs fixing
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            if j >= 0:
                prev_line = lines[j]
                # If previous line is incomplete (no colon, no closing bracket, etc)
                if prev_line.strip() and not prev_line.rstrip().endswith(
                    (":", "}", ")", "]", ",", '"""', "'''", '"', "'")
                ):
                    # Add pass statement if needed
                    new_lines.append("    pass\n")
                    modified = True

        new_lines.append(line)
        i += 1

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True

    return False


def main():
    """Fix syntax errors in all Python files"""

    # Files with known issues from Black output
    problem_files = [
        "src/api/middleware.py",
        "src/api/auth_endpoints.py",
        "src/api/deployment_endpoints.py",
        "src/api/simple_deploy_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/auth/oauth.py",
        "src/auth/jwt_handler.py",
        "src/auth/saml.py",
        "src/auth/mfa.py",
        "src/auth/ssh_auth.py",
    ]

    fixed_count = 0
    for filepath in problem_files:
        full_path = Path(filepath)
        if full_path.exists():
            if fix_file(full_path):
                print(f"Fixed: {filepath}")
                fixed_count += 1

    print(f"\nFixed {fixed_count} files")


if __name__ == "__main__":
    main()
