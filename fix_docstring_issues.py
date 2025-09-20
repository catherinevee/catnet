#!/usr/bin/env python3
"""
Fix docstring issues that prevent Black from parsing files
"""

import os
import re
from pathlib import Path


def fix_class_docstrings(content):
    """Fix class definitions with docstrings on the same line."""
    # Fix pattern: class Name:"""docstring"""
    content = re.sub(
        r'^(\s*)(class\s+\w+.*:)("""[^"]*""")$',
        r"\1\2\n\1    \3",
        content,
        flags=re.MULTILINE,
    )

    # Fix pattern: class Name(Base):"""docstring"""
    content = re.sub(
        r'^(\s*)(class\s+\w+\([^)]*\):)("""[^"]*""")$',
        r"\1\2\n\1    \3",
        content,
        flags=re.MULTILINE,
    )

    # Fix pattern: def func():"""docstring"""
    content = re.sub(
        r'^(\s*)(def\s+\w+\([^)]*\):)("""[^"]*""")$',
        r"\1\2\n\1    \3",
        content,
        flags=re.MULTILINE,
    )

    return content


def fix_broken_strings(content):
    """Fix broken string literals."""
    lines = content.split("\n")
    fixed_lines = []

    for i, line in enumerate(lines):
        # Fix lines with unclosed quotes followed by backslash
        if line.rstrip().endswith('" \\'):
            line = line.rstrip()[:-2] + '"'

        # Fix f-strings with broken formatting
        if 'f"' in line and line.count('"') % 2 != 0:
            # Check if it's missing a closing quote
            if not line.rstrip().endswith('"'):
                line = line.rstrip() + '"'

        fixed_lines.append(line)

    return "\n".join(fixed_lines)


def fix_indentation_after_docstring(content):
    """Fix incorrect indentation after docstrings."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check if this is a method/function with incorrect docstring indentation
        if re.match(r"^(\s*)(def|async def)\s+\w+\(.*\):\s*$", line):
            indent_match = re.match(r"^(\s*)", line)
            base_indent = indent_match.group(1) if indent_match else ""
            expected_indent = base_indent + "    "

            fixed_lines.append(line)
            i += 1

            # Check next lines for docstring issues
            if i < len(lines):
                next_line = lines[i]
                # If next line is not properly indented docstring or code
                if next_line.strip() and not next_line.startswith(expected_indent):
                    # It's likely a misplaced docstring or code
                    if next_line.strip().startswith(
                        '"""'
                    ) or next_line.strip().startswith("'''"):
                        fixed_lines.append(expected_indent + next_line.strip())
                    else:
                        fixed_lines.append(next_line)
                else:
                    fixed_lines.append(next_line)

        else:
            fixed_lines.append(line)

        i += 1

    return "\n".join(fixed_lines)


def fix_file(filepath):
    """Fix all docstring and syntax issues in a file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except BaseException:
        return False

    original = content

    # Apply fixes
    content = fix_class_docstrings(content)
    content = fix_broken_strings(content)
    content = fix_indentation_after_docstring(content)

    # Remove any standalone "Documentation placeholder" lines
    content = re.sub(
        r"^\s*Documentation placeholder\s*$", "", content, flags=re.MULTILINE
    )

    # Fix broken multiline strings in specific patterns
    content = re.sub(r'(\w+)\s*"\s*\n\s*f"', r'\1" \\\n    f"', content)

    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def main():
    """Fix docstring issues in all Python files."""

    # Files that Black cannot parse
    problem_files = [
        "src/api/auth_endpoints.py",
        "src/api/deployment_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/middleware.py",
        "src/api/rollback_endpoints.py",
        "src/api/simple_deploy_endpoints.py",
        "src/auth/jwt_handler.py",
        "src/auth/mfa.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/ssh_auth.py",
    ]

    fixed = 0
    for filepath in problem_files:
        if Path(filepath).exists():
            if fix_file(filepath):
                print(f"Fixed: {filepath}")
                fixed += 1

    print(f"\nFixed {fixed} files")

    # Now run Black
    print("\nRunning Black formatter...")
    import subprocess

    result = subprocess.run(
        ["python", "-m", "black", "src/", "--line-length", "88"],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        print("Black formatting successful!")
        print(result.stdout)
    else:
        print("Black encountered issues:")
        print(result.stderr[:1000])


if __name__ == "__main__":
    main()
