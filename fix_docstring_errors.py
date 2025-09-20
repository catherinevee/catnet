#!/usr/bin/env python3
"""
Fix all docstring-related errors in the CatNet codebase.
Specifically fixes missing opening triple quotes for function docstrings.
"""

import os
import re
from pathlib import Path


def fix_missing_function_docstrings(filepath):
    """Fix functions that have Args/Returns but missing opening triple quotes."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False

    fixed_lines = []
    i = 0
    fixed = False

    while i < len(lines):
        line = lines[i]

        # Check for function definition
        func_match = re.match(r"^(\s*)(async\s+)?def\s+\w+.*:\s*$", line)
        if func_match:
            indent = func_match.group(1)
            fixed_lines.append(line)
            i += 1

            # Check if next line is Args: or Returns: (missing docstring)
            if i < len(lines):
                next_line = lines[i]
                # Check if it looks like docstring content without opening
                # quotes
                if re.match(
                    r"^(\s*)(Args:|Returns:|Raises:|Note:|Example:)", next_line
                ):
                    # Insert opening triple quotes
                    fixed_lines.append(f'{indent}    """\n')
                    fixed_lines.append(f"{indent}    Function docstring.\n")
                    fixed_lines.append(f"{indent}    \n")
                    fixed = True
                    # Continue with the Args/Returns content
                    fixed_lines.append(next_line)
                    i += 1

                    # Find the end of the docstring content
                    while i < len(lines):
                        line = lines[i]
                        # If we hit code (not indented like docstring), close the
                        # docstring
                        if line.strip() and not line.startswith(
                                f"{indent}    "):
                            fixed_lines.append(f'{indent}    """\n')
                            break
                        fixed_lines.append(line)
                        i += 1
                else:
                    continue
            continue

        # Check for methods with just Args: without proper docstring
        if re.match(r"^(\s+)Args:\s*$", line):
            # Look back to see if there's a function def
            if i > 0:
                prev_line = lines[i - 1]
                if re.match(r"^(\s*)(async\s+)?def\s+\w+.*:\s*$", prev_line):
                    # We need to add docstring before Args
                    indent_match = re.match(r"^(\s*)", prev_line)
                    if indent_match:
                        indent = indent_match.group(1)
                        # Insert docstring opening before Args
                        fixed_lines.append(f'{indent}    """\n')
                        fixed_lines.append(f"{indent}    Method docstring.\n")
                        fixed_lines.append(f"{indent}    \n")
                        fixed = True

        fixed_lines.append(line)
        i += 1

    if fixed:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.writelines(fixed_lines)
            return True
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return False

    return False


def fix_class_docstrings_in_dataclasses(filepath):
    """Fix dataclass fields that appear right after docstrings."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False

    fixed_lines = []
    i = 0
    fixed = False

    while i < len(lines):
        line = lines[i]

        # Check for @dataclass decorator or class definition
        if "@dataclass" in line or re.match(r"^class\s+\w+.*:", line):
            fixed_lines.append(line)
            i += 1

            # Check next lines for docstring
            if i < len(lines) and '"""' in lines[i]:
                fixed_lines.append(lines[i])
                i += 1

                # Now check if next non-empty line is a field without proper
                # indentation
                while i < len(lines):
                    if lines[i].strip():
                        # This should be a class field
                        if not lines[i].startswith(
                                "    def ") and ":" in lines[i]:
                            # Ensure proper indentation
                            field_line = lines[i].lstrip()
                            fixed_lines.append(f"    {field_line}")
                            fixed = True
                        else:
                            fixed_lines.append(lines[i])
                        i += 1
                        break
                    else:
                        fixed_lines.append(lines[i])
                        i += 1
                continue

        fixed_lines.append(line)
        i += 1

    if fixed:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.writelines(fixed_lines)
            return True
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return False

    return False


def main():
    """Main function to fix all docstring errors."""
    src_dir = Path("C:/Users/cathe/OneDrive/Desktop/github/catnet/src")

    # Get all Python files
    python_files = list(src_dir.glob("**/*.py"))

    fixed_count = 0
    print(
        f"Processing {
            len(python_files)} Python files for docstring fixes...")

    # Focus on the files Black reported as problematic
    problematic_files = [
        "auth/ssh_auth.py",
        "auth/mfa.py",
        "auth/oauth.py",
        "auth/saml.py",
        "auth/session.py",
        "api/auth_endpoints.py",
        "api/simple_deploy_endpoints.py",
        "automation/workflows.py",
        "compliance/reporting.py",
        "core/config.py",
        "core/api_config.py",
        "core/logging.py",
        "core/metrics.py",
    ]

    for relative_path in problematic_files:
        filepath = src_dir / relative_path
        if filepath.exists():
            print(f"Checking: {relative_path}")
            if fix_missing_function_docstrings(str(filepath)):
                fixed_count += 1
                print(f"  Fixed function docstrings")
            if fix_class_docstrings_in_dataclasses(str(filepath)):
                fixed_count += 1
                print(f"  Fixed class field indentation")

    print(f"\nFixed docstring issues in {fixed_count} files")

    # Test with Black
    print("\nTesting with Black...")
    os.system("python -m black src/ --check 2>&1 | grep -c 'error: cannot format'")


if __name__ == "__main__":
    main()
