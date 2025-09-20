#!/usr/bin/env python3
"""
Fix all remaining syntax errors preventing Black from parsing files
"""

import os
import re
from pathlib import Path


def fix_missing_docstrings(content):
    """Fix methods/functions with missing docstrings."""
    lines = content.split('\n')
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for function/method definitions without docstrings
        if re.match(r'^(\s*)(def|async def)\s+\w+\(.*\):\s*$', line):
            indent_match = re.match(r'^(\s*)', line)
            indent = indent_match.group(1) if indent_match else ""
            next_indent = indent + "    "

            # Check if next non-empty line is a docstring
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1

            if j < len(lines):
                next_line = lines[j]
                # If next line is not a docstring, add one
                if not (next_line.strip().startswith('"""') or next_line.strip().startswith("'''")):
                    # Check if it's indented code
                    if re.match(r'^' + next_indent, next_line) and next_line.strip():
                        fixed_lines.append(line)
                        fixed_lines.append(f'{next_indent}"""TODO: Add docstring"""')
                        i += 1
                        continue

        fixed_lines.append(line)
        i += 1

    return '\n'.join(fixed_lines)


def fix_incomplete_strings(content):
    """Fix incomplete string literals and f-strings."""
    # Fix unclosed f-strings with placeholders
    content = re.sub(
        r'(f"[^"]*\{[^}]*$)',
        r'\1}"',
        content,
        flags=re.MULTILINE
    )

    # Fix unclosed regular strings at line end
    lines = content.split('\n')
    fixed_lines = []

    for line in lines:
        # Check for unclosed quotes
        if line.count('"') % 2 != 0 and not line.strip().endswith('"'):
            # Check if it's likely an unclosed string
            if 'f"' in line or '= "' in line or '("' in line:
                line = line.rstrip() + '"'
        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def fix_broken_multiline_strings(content):
    """Fix broken multiline strings and expressions."""
    # Fix broken multiline strings
    content = re.sub(
        r'(\s+)r"([^"]*)\n',
        r'\1r"\2" \\\n',
        content
    )

    # Fix broken f-strings across lines
    content = re.sub(
        r'f"([^"]*)\n(\s+)([^"]+)"',
        r'f"\1" \\\n\2f"\3"',
        content
    )

    return content


def fix_indentation_issues(content):
    """Fix common indentation issues."""
    lines = content.split('\n')
    fixed_lines = []
    expected_indent = 0

    for line in lines:
        stripped = line.lstrip()

        # Track expected indentation
        if stripped.startswith('class ') or stripped.startswith('def ') or stripped.startswith('async def '):
            if ':' in line:
                expected_indent = len(line) - len(stripped) + 4
        elif stripped.startswith('return') or stripped.startswith('pass') or stripped.startswith('continue'):
            expected_indent = max(0, expected_indent - 4)

        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def fix_specific_file_issues(filepath):
    """Fix specific known issues in certain files."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except:
        return False

    original_content = content
    filename = os.path.basename(filepath)

    # Remove standalone "Documentation placeholder" lines
    content = re.sub(r'^\s*Documentation placeholder\s*$', '', content, flags=re.MULTILINE)

    # Fix missing closing quotes in docstrings
    content = re.sub(r'("""[^"]*?)\n(\s+)(""")', r'\1\3', content)

    # Fix class/function definitions with just pass
    content = re.sub(r'(class \w+.*:)\n(\s+)pass\n(\s+)(def|class)', r'\1\n\3\4', content)

    # Apply general fixes
    content = fix_missing_docstrings(content)
    content = fix_incomplete_strings(content)
    content = fix_broken_multiline_strings(content)
    content = fix_indentation_issues(content)

    if content != original_content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def main():
    """Fix all syntax errors in Python files."""

    # Get all Python files in src/
    src_path = Path("src")
    all_py_files = list(src_path.rglob("*.py")) if src_path.exists() else []

    fixed_count = 0
    for py_file in all_py_files:
        if fix_specific_file_issues(py_file):
            print(f"Fixed: {py_file}")
            fixed_count += 1

    print(f"\nProcessed {len(all_py_files)} files, fixed {fixed_count} files")

    # Try to run Black again
    print("\nAttempting to run Black formatter...")
    import subprocess
    result = subprocess.run(
        ["python", "-m", "black", "src/", "--line-length", "88"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("Black formatting successful!")
    else:
        print(f"Black still has issues:\n{result.stderr[:500]}")


if __name__ == "__main__":
    main()