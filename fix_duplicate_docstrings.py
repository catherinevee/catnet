#!/usr/bin/env python3
"""
Fix duplicate docstrings and broken indentation in Python files.
"""
import re
from pathlib import Path


def fix_file(content):
    """Fix various syntax issues in the file."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for duplicate docstrings in class definitions
        if "class " in line and "(BaseModel)" in line:
            fixed_lines.append(line)
            i += 1

            # Check for docstring
            if i < len(lines) and '"""' in lines[i]:
                docstring = lines[i].strip()
                fixed_lines.append(f"    {docstring}")
                i += 1

                # Skip duplicate docstring if present
                if i < len(lines) and '"""' in lines[i]:
                    i += 1  # Skip duplicate

                # Skip empty line if present
                if i < len(lines) and lines[i].strip() == "":
                    fixed_lines.append("")
                    i += 1

                # Now process fields - ensure they are properly indented
                while i < len(lines):
                    field_line = lines[i].strip()
                    if field_line == "":
                        fixed_lines.append("")
                        i += 1
                    elif (
                        field_line.startswith("class ")
                        or field_line.startswith("def ")
                        or field_line.startswith("@")
                    ):
                        break  # End of this class
                    elif ":" in field_line and not field_line.startswith("#"):
                        # This is a field definition
                        fixed_lines.append(f"    {field_line}")
                        i += 1
                    else:
                        fixed_lines.append(lines[i])
                        i += 1

        # Fix missing docstring quotes in function definitions
        elif line.strip().startswith("def ") or line.strip().startswith("async def "):
            fixed_lines.append(line)
            i += 1

            # Check if next line should be a docstring but is missing quotes
            if i < len(lines):
                next_line = lines[i].strip()
                # Check for patterns that look like unquoted docstrings
                if (
                    next_line
                    and not next_line.startswith('"""')
                    and not next_line.startswith("#")
                    and ":" not in next_line
                    and not next_line.startswith("return")
                    and not next_line.startswith("if ")
                    and not next_line.startswith("try:")
                    and not next_line.startswith("logger")
                    and len(next_line) > 10
                    and next_line[0].isupper()
                ):
                    # This looks like an unquoted docstring
                    # Find indentation level
                    indent = len(line) - len(line.lstrip())
                    fixed_lines.append(f'{" " * (indent + 4)}"""')
                    fixed_lines.append(f'{" " * (indent + 4)}{next_line}')
                    i += 1

                    # Collect rest of docstring
                    while (
                        i < len(lines)
                        and lines[i].strip()
                        and not lines[i].strip().startswith('"""')
                    ):
                        fixed_lines.append(f'{" " * (indent + 4)}{lines[i].strip()}')
                        i += 1

                    fixed_lines.append(f'{" " * (indent + 4)}"""')
        else:
            fixed_lines.append(line)
            i += 1

    return "\n".join(fixed_lines)


def main():
    """Fix all files with syntax issues."""

    files_to_fix = [
        "src/api/deployment_endpoints.py",
        "src/api/auth_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/rollback_endpoints.py",
        "src/api/device_endpoints.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/session.py",
        "src/deployment/rollback.py",
    ]

    for file_path in files_to_fix:
        full_path = Path(file_path)
        if full_path.exists():
            print(f"Processing {file_path}...")
            content = full_path.read_text(encoding="utf-8")
            fixed_content = fix_file(content)

            if fixed_content != content:
                full_path.write_text(fixed_content, encoding="utf-8")
                print(f"  Fixed issues")
            else:
                print(f"  No changes needed")

    print("\nDone!")


if __name__ == "__main__":
    main()
