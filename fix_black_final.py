#!/usr/bin/env python3
"""
Final comprehensive fix for Black parsing errors
"""

import os
import re
from pathlib import Path


def fix_file(filepath):
    """Fix all syntax issues in a Python file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except BaseException:
        return False

    fixed_lines = []
    i = 0
    modified = False

    while i < len(lines):
        line = lines[i]

        # Fix class with docstring on same line: class Name:"""docstring"""
        if re.match(r'^(\s*)class\s+\w+.*:(\s*""".*"""\s*)$', line):
            match = re.match(r'^(\s*)(class\s+\w+.*:)(\s*""".*"""\s*)$', line)
            if match:
                indent = match.group(1)
                class_def = match.group(2)
                docstring = match.group(3).strip()
                fixed_lines.append(f"{indent}{class_def}\n")
                fixed_lines.append(f"{indent}    {docstring}\n")
                modified = True
                i += 1
                continue

        # Fix function/method definitions with improper docstrings
        if re.match(r"^(\s*)(async\s+)?def\s+\w+\(.*\):\s*$", line):
            fixed_lines.append(line)
            i += 1

            # Check if next non-empty line is improperly indented docstring or code
            while i < len(lines) and not lines[i].strip():
                fixed_lines.append(lines[i])
                i += 1

            if i < len(lines):
                next_line = lines[i]
                # Check if it's a docstring that's not indented properly
                if next_line.strip().startswith('"""') or next_line.strip().startswith(
                    "'''"
                ):
                    indent_match = re.match(r"^(\s*)", line)
                    base_indent = indent_match.group(1) if indent_match else ""
                    proper_indent = base_indent + "    "

                    # If it's not properly indented, fix it
                    if not next_line.startswith(proper_indent):
                        fixed_lines.append(f"{proper_indent}{next_line.strip()}\n")
                        modified = True
                        i += 1
                        continue

                # Check if it's code without docstring that starts too far left
                elif next_line.strip() and not next_line.strip().startswith("#"):
                    indent_match = re.match(r"^(\s*)", line)
                    base_indent = indent_match.group(1) if indent_match else ""
                    proper_indent = base_indent + "    "

                    # If the indentation is wrong, fix it
                    if len(next_line) - len(next_line.lstrip()) < len(proper_indent):
                        fixed_lines.append(f"{proper_indent}{next_line.strip()}\n")
                        modified = True
                        i += 1
                        continue

                fixed_lines.append(next_line)
                i += 1
                continue

        # Fix standalone docstrings appearing randomly
        if line.strip() == '"""' and i > 0:
            # Check if previous line is a class or function definition
            prev_line = lines[i - 1] if i > 0 else ""
            if not (
                prev_line.strip().endswith(":") or prev_line.strip().endswith('"""')
            ):
                # Skip this orphaned docstring quote
                modified = True
                i += 1
                continue

        # Fix broken f-strings
        if 'f"' in line and line.count('"') % 2 != 0:
            # Try to close unclosed f-string
            if not line.rstrip().endswith('"'):
                line = line.rstrip() + '"\n'
                modified = True

        # Fix lines with broken quotes in headers
        if "response.headers[" in line and '] = "' in line:
            # Fix pattern like: f"response.headers["X-Frame-Options"] = "DENY"
            line = re.sub(
                r'f"response\.headers\["([^"]+)"\] = "([^"]+)"',
                r'response.headers["\1"] = "\2"',
                line,
            )
            modified = True

        fixed_lines.append(line)
        i += 1

    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(fixed_lines)
        return True

    return False


def fix_specific_issues(filepath):
    """Fix specific known patterns in files."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except BaseException:
        return False

    original = content

    # Remove all blank lines between class definition and its content
    content = re.sub(r"(class\s+\w+.*:)\n\n+(\s+)", r"\1\n\2", content)

    # Fix Calculate SSH key fingerprint appearing on wrong line
    content = re.sub(r"(\s+)Calculate SSH key fingerprint.*\n", "", content)

    # Fix standalone field definitions appearing without class context
    content = re.sub(
        r"^(\s*\w+:\s*\w+.*(?:=.*)?)\n", r"    \1\n", content, flags=re.MULTILINE
    )

    # Fix enum values appearing at wrong indentation
    content = re.sub(
        r'^(\s*[A-Z_]+\s*=\s*"[^"]+")$', r"    \1", content, flags=re.MULTILINE
    )

    # Remove "Documentation placeholder" strings
    content = re.sub(
        r"^\s*Documentation placeholder\s*\n", "", content, flags=re.MULTILINE
    )

    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def main():
    """Fix all Black parsing errors."""

    # List of files that Black cannot parse
    problem_files = [
        "src/api/auth_endpoints.py",
        "src/api/deployment_endpoints.py",
        "src/api/device_endpoints.py",
        "src/api/device_connection_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/middleware.py",
        "src/api/rollback_endpoints.py",
        "src/api/simple_deploy_endpoints.py",
        "src/auth/jwt_handler.py",
        "src/auth/mfa.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/session.py",
        "src/auth/ssh_auth.py",
        "src/automation/workflows.py",
        "src/cli/auth_utils.py",
        "src/cli/commands.py",
        "src/compliance/reporting.py",
        "src/core/api_config.py",
        "src/core/config.py",
        "src/core/logging.py",
        "src/core/metrics.py",
    ]

    fixed_count = 0
    for filepath in problem_files:
        if Path(filepath).exists():
            fixed = fix_file(filepath)
            fixed |= fix_specific_issues(filepath)
            if fixed:
                print(f"Fixed: {filepath}")
                fixed_count += 1

    print(f"\nFixed {fixed_count} files")

    # Test with Black
    print("\nTesting with Black...")
    import subprocess

    result = subprocess.run(
        ["python", "-m", "black", "--check", "src/"], capture_output=True, text=True
    )

    if result.returncode == 0:
        print("✓ All files can be parsed by Black!")
    else:
        errors = result.stderr.count("error: cannot format")
        print(f"✗ Black still has {errors} parsing errors")

        # Show first few errors
        error_lines = [
            line for line in result.stderr.split("\n") if "error: cannot format" in line
        ]
        for error in error_lines[:5]:
            print(f"  {error}")


if __name__ == "__main__":
    main()
