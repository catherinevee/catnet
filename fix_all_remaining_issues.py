#!/usr/bin/env python3
"""
Comprehensive fix for all remaining syntax issues in Python files.
"""
import re
import ast
from pathlib import Path


def remove_duplicate_docstrings(content):
    """Remove duplicate docstrings in class definitions."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        fixed_lines.append(line)

        # Check if this is a class definition
        if "class " in line and (
            "BaseModel" in line or "@dataclass" in lines[max(0, i - 1)]
        ):
            i += 1
            # Look for docstring
            if i < len(lines) and '"""' in lines[i]:
                docstring_line = lines[i]
                fixed_lines.append(docstring_line)
                i += 1

                # Skip empty line
                if i < len(lines) and lines[i].strip() == "":
                    fixed_lines.append(lines[i])
                    i += 1

                # Check for duplicate docstring
                if (
                    i < len(lines)
                    and '"""' in lines[i]
                    and lines[i].strip() == docstring_line.strip()
                ):
                    # Skip duplicate
                    i += 1
                    # Also skip empty line after duplicate if present
                    if i < len(lines) and lines[i].strip() == "":
                        i += 1
        else:
            i += 1

    return "\n".join(fixed_lines)


def fix_unclosed_docstrings(content):
    """Fix unclosed docstrings in functions."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for function definitions with missing docstring quotes
        if line.strip().startswith("def ") or line.strip().startswith("async def "):
            fixed_lines.append(line)
            i += 1

            # Check next line
            if i < len(lines):
                next_line = lines[i]
                # Check if it looks like an unquoted docstring
                if (
                    next_line.strip()
                    and not next_line.strip().startswith('"""')
                    and not next_line.strip().startswith("#")
                    and ":" not in next_line
                    and not next_line.strip().startswith("return")
                    and not next_line.strip().startswith("if ")
                    and not next_line.strip().startswith("try:")
                    and not next_line.strip().startswith("logger")
                    and not next_line.strip().startswith("await ")
                    and not next_line.strip().startswith("raise ")
                    and len(next_line.strip()) > 5
                ):
                    # Check if this looks like descriptive text
                    first_word = (
                        next_line.strip().split()[0] if next_line.strip() else ""
                    )
                    if first_word and (
                        first_word[0].isupper()
                        or first_word in ["TODO:", "FIXME:", "NOTE:"]
                    ):
                        # Add proper docstring quotes
                        indent = len(line) - len(line.lstrip())
                        fixed_lines.append(f'{" " * (indent + 4)}"""')
                        fixed_lines.append(f'{" " * (indent + 4)}{next_line.strip()}')
                        i += 1

                        # Collect rest of docstring content
                        while i < len(lines):
                            content_line = lines[i]
                            if content_line.strip() == "":
                                break
                            if (
                                content_line.strip().startswith("return")
                                or content_line.strip().startswith("if ")
                                or content_line.strip().startswith("try:")
                                or content_line.strip().startswith("logger")
                                or content_line.strip().startswith("await ")
                                or content_line.strip().startswith("raise ")
                            ):
                                i -= 1
                                break
                            fixed_lines.append(
                                f'{" " * (indent + 4)}{content_line.strip()}'
                            )
                            i += 1

                        fixed_lines.append(f'{" " * (indent + 4)}"""')
                    else:
                        fixed_lines.append(next_line)
                else:
                    fixed_lines.append(next_line)
        else:
            fixed_lines.append(line)

        i += 1

    return "\n".join(fixed_lines)


def fix_broken_strings(content):
    """Fix broken multi-line strings and f-strings."""
    # Fix unclosed quotes in logging statements
    content = re.sub(
        r'(logger\.\w+\([^)]*)"([^"]*)\n\s*([^"]*)"',
        r'\1"\2" \\\n        "\3"',
        content,
    )

    # Fix broken f-strings
    content = re.sub(r'f"([^"]*)\n\s*([^"]*)"', r'f"\1" \\\n        f"\2"', content)

    return content


def fix_indentation_issues(content):
    """Fix indentation issues in dataclasses."""
    lines = content.split("\n")
    fixed_lines = []

    for i, line in enumerate(lines):
        # Fix incorrectly indented dataclass fields
        if i > 0 and ":" in line and not line.strip().startswith("#"):
            prev_line = lines[i - 1] if i > 0 else ""
            # Check if previous line was a docstring and this looks like a field
            if '"""' in prev_line or prev_line.strip() == "":
                # Check if line starts without proper indentation
                if line.strip() and not line.startswith("    ") and "=" in line:
                    fixed_lines.append("    " + line.strip())
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)

    return "\n".join(fixed_lines)


def fix_file(file_path):
    """Apply all fixes to a file."""
    try:
        content = file_path.read_text(encoding="utf-8")

        # Apply fixes in sequence
        content = remove_duplicate_docstrings(content)
        content = fix_unclosed_docstrings(content)
        content = fix_broken_strings(content)
        content = fix_indentation_issues(content)

        # Write back
        file_path.write_text(content, encoding="utf-8")

        # Verify it's valid Python
        try:
            ast.parse(content)
            return True, "Fixed"
        except SyntaxError as e:
            return False, f"Still has syntax error: {e}"
    except Exception as e:
        return False, f"Error processing: {e}"


def main():
    """Fix all Python files with remaining issues."""

    # Files identified with Black parsing errors
    files_to_fix = [
        "src/api/deployment_endpoints.py",
        "src/api/auth_endpoints.py",
        "src/api/device_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/rollback_endpoints.py",
        "src/api/device_connection_endpoints.py",
        "catnet_cli/client.py",
        "catnet_cli/config.py",
        "catnet_cli/commands/auth.py",
        "catnet_cli/commands/deploy.py",
        "catnet_cli/commands/device.py",
        "catnet_cli/commands/vault.py",
        "catnet_cli/utils.py",
        "scripts/quickstart.py",
        "scripts/generate_ca.py",
        "setup.py",
        "run_catnet.py",
        "migrations/versions/002_add_certificate_fields.py",
    ]

    success_count = 0
    fail_count = 0

    for file_path_str in files_to_fix:
        file_path = Path(file_path_str)
        if file_path.exists():
            print(f"Processing {file_path_str}...")
            success, message = fix_file(file_path)
            if success:
                print(f"  ✓ {message}")
                success_count += 1
            else:
                print(f"  ✗ {message}")
                fail_count += 1
        else:
            print(f"  File not found: {file_path_str}")

    print(
        f"\nSummary: {success_count} files fixed, {fail_count} files with remaining issues"
    )


if __name__ == "__main__":
    main()
