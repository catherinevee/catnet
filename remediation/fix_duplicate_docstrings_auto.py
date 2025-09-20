#!/usr/bin/env python3
"""
Automatically fix duplicate docstrings in class definitions.
Handles dataclasses, Pydantic models, and regular classes.
"""

import re
import json
from pathlib import Path
from typing import List, Tuple


def load_error_files():
    """Load list of files with errors from Black analysis."""
    with open("black_errors_v2.json", "r") as f:
        data = json.load(f)
    return data["error_files"]


def fix_duplicate_class_docstrings(content: str) -> Tuple[str, int]:
    """Fix duplicate docstrings in class definitions."""
    lines = content.split("\n")
    fixed_lines = []
    fixes_made = 0
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for class definition or @dataclass decorator
        is_dataclass = "@dataclass" in line
        class_match = re.match(r"^(\s*)class\s+(\w+)", line)

        if is_dataclass and i + 1 < len(lines):
            # Found @dataclass, check next line for class
            fixed_lines.append(line)
            i += 1
            line = lines[i]
            class_match = re.match(r"^(\s*)class\s+(\w+)", line)

        if class_match:
            indent = class_match.group(1)
            class_name = class_match.group(2)
            fixed_lines.append(line)
            i += 1

            # Check next few lines for duplicate docstrings
            docstring_count = 0
            temp_lines = []
            docstring_text = None

            while i < len(lines) and docstring_count < 3:
                next_line = lines[i]

                # Check for docstring
                docstring_match = re.match(r'^(\s*)(""".*?""")\s*$', next_line)
                if not docstring_match and '"""' in next_line:
                    # Multiline docstring start
                    docstring_match = re.match(r'^(\s*)(""".*)', next_line)

                if docstring_match:
                    docstring_count += 1
                    if docstring_count == 1:
                        # Keep first docstring with proper indentation
                        docstring_text = docstring_match.group(2)
                        fixed_lines.append(f"{indent}    {docstring_text}")
                        fixes_made += 1
                    # Skip duplicate docstrings
                    i += 1
                elif next_line.strip() == "":
                    # Empty line
                    temp_lines.append(next_line)
                    i += 1
                else:
                    # Non-docstring line, we're done
                    break

            # Add any temp lines collected
            fixed_lines.extend(temp_lines)
        else:
            fixed_lines.append(line)
            i += 1

    return "\n".join(fixed_lines), fixes_made


def fix_inline_docstrings(content: str) -> Tuple[str, int]:
    """Fix docstrings that appear on the same line as class/function definitions."""
    fixes_made = 0

    # Fix pattern: class Name:"""docstring"""
    pattern1 = re.compile(r'^(\s*)(class\s+\w+.*?):\s*(""".*?""")\s*$', re.MULTILINE)
    content, count1 = pattern1.subn(r"\1\2:\n\1    \3", content)
    fixes_made += count1

    # Fix pattern: def func():"""docstring"""
    pattern2 = re.compile(
        r'^(\s*)(def\s+\w+\([^)]*\)):\s*(""".*?""")\s*$', re.MULTILINE
    )
    content, count2 = pattern2.subn(r"\1\2:\n\1    \3", content)
    fixes_made += count2

    # Fix pattern: async def func():"""docstring"""
    pattern3 = re.compile(
        r'^(\s*)(async\s+def\s+\w+\([^)]*\)):\s*(""".*?""")\s*$', re.MULTILINE
    )
    content, count3 = pattern3.subn(r"\1\2:\n\1    \3", content)
    fixes_made += count3

    return content, fixes_made


def fix_misplaced_docstrings(content: str) -> Tuple[str, int]:
    """Fix docstrings with wrong indentation in dataclasses."""
    lines = content.split("\n")
    fixed_lines = []
    fixes_made = 0
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for BaseModel or dataclass with misplaced docstring
        if "BaseModel" in line or "@dataclass" in line:
            # Look ahead for class definition
            j = i + 1
            while j < len(lines) and j < i + 3:
                if re.match(r"^(\s*)class\s+\w+", lines[j]):
                    indent_match = re.match(r"^(\s*)", lines[j])
                    base_indent = indent_match.group(1) if indent_match else ""

                    # Check for docstring in next lines
                    k = j + 1
                    if k < len(lines) and '"""' in lines[k]:
                        # Check indentation
                        expected_indent = base_indent + "    "
                        if not lines[k].startswith(expected_indent):
                            # Fix indentation
                            docstring = lines[k].strip()
                            lines[k] = expected_indent + docstring
                            fixes_made += 1
                    break
                j += 1

        fixed_lines.append(lines[i])
        i += 1

    if fixes_made > 0:
        return "\n".join(lines), fixes_made
    return content, 0


def process_file(filepath: Path) -> bool:
    """Process a single file to fix duplicate docstrings."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        original = content
        total_fixes = 0

        # Apply fixes in order
        content, fixes1 = fix_inline_docstrings(content)
        total_fixes += fixes1

        content, fixes2 = fix_duplicate_class_docstrings(content)
        total_fixes += fixes2

        content, fixes3 = fix_misplaced_docstrings(content)
        total_fixes += fixes3

        if content != original:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True

    except Exception as e:
        print(f"    Error processing {filepath}: {e}")

    return False


def main():
    """Main function to fix duplicate docstrings in error files."""
    print("=" * 70)
    print("DUPLICATE DOCSTRING FIXER")
    print("=" * 70)

    # Load files with errors
    error_files = load_error_files()
    print(f"\nProcessing {len(error_files)} files with Black errors...\n")

    fixed_count = 0
    for file_path in error_files:
        filepath = Path(file_path)
        if filepath.exists() and filepath.suffix == ".py":
            print(f"  Checking: {filepath.name}...", end=" ")
            if process_file(filepath):
                print("✓ FIXED")
                fixed_count += 1
            else:
                print("- no changes")

    print(f"\n{'=' * 70}")
    print(f"Fixed {fixed_count} files")
    print("=" * 70)

    return fixed_count


if __name__ == "__main__":
    main()
