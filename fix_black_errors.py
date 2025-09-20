#!/usr/bin/env python3
"""
Fix Black parsing errors by removing incorrect "Documentation placeholder" strings
and fixing indentation issues in Python files.
"""

import os
import re
from pathlib import Path


def fix_documentation_placeholders(filepath):
    """Remove incorrect 'Documentation placeholder' strings and fix indentation."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except BaseException:
        return False

    original_content = content

    # Pattern 1: Remove standalone "Documentation placeholder" lines
    content = re.sub(
        r'^[ \t]*"""[ \t]*\n[ \t]*Documentation placeholder[ \t]*\n[ \t]*"""[ \t]*\n',
        "",
        content,
        flags=re.MULTILINE,
    )

    # Pattern 2: Remove incorrectly placed Documentation placeholder at wrong
    # indentation
    content = re.sub(r"\n[ \t]*Documentation placeholder[ \t]*\n", "\n", content)

    # Pattern 3: Fix docstrings that have Documentation placeholder breaking them
    # Match docstrings with Documentation placeholder interrupting them
    def fix_broken_docstring(match):
        indent = match.group(1)
        docstring_start = match.group(2)
        # Return properly formatted docstring
        return f'{indent}"""{docstring_start}"""'

    # Fix pattern where docstring is broken by Documentation placeholder
    content = re.sub(
        r'^([ \t]*)(""".*?)\n[ \t]*"""[ \t]*\n[ \t]*Documentation placeholder[ \t]*\n[ \t]*"""',
        fix_broken_docstring,
        content,
        flags=re.MULTILINE,
    )

    # Pattern 4: Remove duplicate pass statements
    content = re.sub(r"(\n[ \t]*pass[ \t]*\n)([ \t]*pass[ \t]*\n)+", r"\1", content)

    # Pattern 5: Remove pass statements right before function/class definitions
    content = re.sub(
        r"\n[ \t]*pass[ \t]*\n([ \t]*(?:def|class|async def))", r"\n\1", content
    )

    # Pattern 6: Fix methods that have pass followed by docstring
    content = re.sub(r'(def [^:]+:)\n([ \t]*)pass\n([ \t]*""")', r"\1\n\3", content)

    if content != original_content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def fix_file_specific_issues(filepath):
    """Fix specific known issues in certain files."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except BaseException:
        return False

    filename = os.path.basename(filepath)
    modified = False
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Skip documentation placeholder lines that are out of place
        if line.strip() == "Documentation placeholder":
            i += 1
            continue

        # Fix broken docstrings
        if i < len(lines) - 2:
            if (
                line.strip() == '"""'
                and lines[i + 1].strip() == "Documentation placeholder"
                and lines[i + 2].strip() == '"""'
            ):
                # Skip these three lines, they're a broken docstring
                i += 3
                modified = True
                continue

        new_lines.append(line)
        i += 1

    if modified or len(new_lines) != len(lines):
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True

    return False


def main():
    """Fix Black parsing errors in all Python files."""

    # Get all Python files that Black had issues with
    problem_files = [
        "src/api/auth_endpoints.py",
        "src/api/deployment_endpoints.py",
        "src/api/device_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/middleware.py",
        "src/api/simple_deploy_endpoints.py",
        "src/auth/jwt_handler.py",
        "src/auth/mfa.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/ssh_auth.py",
        "src/core/validation.py",
        "src/db/models.py",
        "src/devices/cisco_handler.py",
        "src/devices/juniper_handler.py",
        "src/gitops/git_integration.py",
        "src/ml/anomaly_detection.py",
        "src/monitoring/advanced_monitoring.py",
        "src/security/audit.py",
        "src/security/encryption.py",
        "src/security/vault_client.py",
        "src/workers/deployment_worker.py",
    ]

    # Also scan for all Python files in src/
    src_path = Path("src")
    if src_path.exists():
        all_py_files = list(src_path.rglob("*.py"))
        for py_file in all_py_files:
            if str(py_file) not in problem_files:
                problem_files.append(str(py_file))

    fixed_count = 0
    for filepath in problem_files:
        full_path = Path(filepath)
        if full_path.exists():
            # First fix documentation placeholders
            if fix_documentation_placeholders(full_path):
                print(f"Fixed documentation issues: {filepath}")
                fixed_count += 1

            # Then fix file-specific issues
            if fix_file_specific_issues(full_path):
                print(f"Fixed specific issues: {filepath}")
                fixed_count += 1

    print(f"\nProcessed {len(problem_files)} files, fixed {fixed_count} files")

    # Now try to run Black on the fixed files
    print("\nAttempting to run Black formatter...")
    os.system("black src/ --line-length 88")


if __name__ == "__main__":
    main()
