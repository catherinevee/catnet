#!/usr/bin/env python3
"""
Automatically fix indentation issues including unindent errors.
"""

import re
import json
from pathlib import Path
from typing import List, Tuple


def load_error_data():
    """Load Black error data."""
    with open("black_errors_v2.json", "r") as f:
        return json.load(f)


def detect_indent_style(lines: List[str]) -> str:
    """Detect whether file uses tabs or spaces."""
    space_count = 0
    tab_count = 0

    for line in lines:
        if line.startswith(" "):
            space_count += 1
        elif line.startswith("\t"):
            tab_count += 1

    return "\t" if tab_count > space_count else "    "


def fix_mixed_indentation(content: str) -> Tuple[str, int]:
    """Fix mixed tabs and spaces."""
    lines = content.split("\n")
    indent_style = detect_indent_style(lines)
    fixed_lines = []
    fixes_made = 0

    for line in lines:
        if "\t" in line and indent_style == "    ":
            # Replace tabs with 4 spaces
            fixed_line = line.replace("\t", "    ")
            fixed_lines.append(fixed_line)
            fixes_made += 1
        elif line.startswith(" ") and indent_style == "\t":
            # Replace leading spaces with tabs
            stripped = line.lstrip(" ")
            spaces = len(line) - len(stripped)
            tabs = spaces // 4
            remaining_spaces = spaces % 4
            fixed_line = "\t" * tabs + " " * remaining_spaces + stripped
            fixed_lines.append(fixed_line)
            fixes_made += 1
        else:
            fixed_lines.append(line)

    return "\n".join(fixed_lines), fixes_made


def calculate_expected_indent(lines: List[str], line_num: int) -> int:
    """Calculate expected indentation level for a line."""
    if line_num == 0:
        return 0

    # Look at previous non-empty lines
    indent_level = 0
    for i in range(line_num - 1, -1, -1):
        prev_line = lines[i].rstrip()
        if not prev_line:
            continue

        # Calculate indent of previous line
        prev_indent = len(prev_line) - len(prev_line.lstrip())

        # Check if previous line opens a block
        if prev_line.endswith(":"):
            indent_level = prev_indent + 4
            break
        elif any(
            keyword in prev_line
            for keyword in [
                "def ",
                "class ",
                "if ",
                "for ",
                "while ",
                "with ",
                "try:",
                "except:",
                "finally:",
                "elif ",
                "else:",
            ]
        ):
            if prev_line.endswith(":"):
                indent_level = prev_indent + 4
            else:
                indent_level = prev_indent
            break
        else:
            indent_level = prev_indent
            break

    return indent_level


def fix_unindent_errors(content: str, error_lines: List[int]) -> Tuple[str, int]:
    """Fix unindent errors by correcting indentation."""
    lines = content.split("\n")
    fixes_made = 0

    for line_num in error_lines:
        if 0 <= line_num - 1 < len(lines):  # Convert to 0-based index
            idx = line_num - 1
            line = lines[idx]

            if not line.strip():
                continue

            # Calculate expected indentation
            expected_indent = calculate_expected_indent(lines, idx)

            # Get actual indentation
            actual_indent = len(line) - len(line.lstrip())

            if actual_indent != expected_indent:
                # Fix the indentation
                stripped = line.lstrip()
                lines[idx] = " " * expected_indent + stripped
                fixes_made += 1

    return "\n".join(lines), fixes_made


def fix_inconsistent_indentation(content: str) -> Tuple[str, int]:
    """Fix inconsistent indentation in code blocks."""
    lines = content.split("\n")
    fixed_lines = []
    fixes_made = 0
    indent_stack = [0]

    for i, line in enumerate(lines):
        stripped = line.lstrip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            fixed_lines.append(line)
            continue

        # Calculate current indentation
        current_indent = len(line) - len(stripped)

        # Check if line starts a new block
        opens_block = line.rstrip().endswith(":") and any(
            keyword in line
            for keyword in [
                "def ",
                "class ",
                "if ",
                "for ",
                "while ",
                "with ",
                "try:",
                "except",
                "finally:",
                "elif ",
                "else:",
            ]
        )

        # Determine expected indentation
        if opens_block:
            # This line should be at current stack level
            if current_indent not in indent_stack and current_indent % 4 == 0:
                # Find closest valid indent
                valid_indents = [ind for ind in indent_stack if ind <= current_indent]
                if valid_indents:
                    expected_indent = max(valid_indents)
                else:
                    expected_indent = 0

                if current_indent != expected_indent:
                    line = " " * expected_indent + stripped
                    fixes_made += 1

            # Add new indent level for next line
            if current_indent not in indent_stack:
                indent_stack.append(current_indent)

        elif any(
            keyword in stripped
            for keyword in ["return ", "pass", "continue", "break", "raise "]
        ):
            # These statements don't change indentation
            pass

        else:
            # Regular line - should match stack
            if current_indent not in indent_stack:
                # Round to nearest multiple of 4
                expected_indent = (current_indent // 4) * 4
                if expected_indent != current_indent:
                    line = " " * expected_indent + stripped
                    fixes_made += 1

        fixed_lines.append(line)

        # Update indent stack
        if current_indent < indent_stack[-1] and current_indent in indent_stack:
            # Dedent - pop levels
            while indent_stack and indent_stack[-1] > current_indent:
                indent_stack.pop()

    return "\n".join(fixed_lines), fixes_made


def process_file_for_indentation(filepath: Path, error_info: dict) -> bool:
    """Process a file to fix indentation errors."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        original = content
        total_fixes = 0

        # Get indentation errors for this file
        file_errors = [
            e
            for e in error_info["errors"]
            if Path(e["file"]) == filepath and e["type"] == "indentation_error"
        ]

        # Get line numbers with unindent errors
        error_lines = [e["line"] for e in file_errors]

        # Apply fixes
        content, fixes1 = fix_mixed_indentation(content)
        total_fixes += fixes1

        if error_lines:
            content, fixes2 = fix_unindent_errors(content, error_lines)
            total_fixes += fixes2

        content, fixes3 = fix_inconsistent_indentation(content)
        total_fixes += fixes3

        if content != original:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True

    except Exception as e:
        print(f"    Error processing {filepath}: {e}")

    return False


def main():
    """Main function to fix indentation errors."""
    print("=" * 70)
    print("INDENTATION FIXER")
    print("=" * 70)

    # Load error data
    error_data = load_error_data()
    error_files = error_data["error_files"]

    print(f"\nProcessing {len(error_files)} files for indentation issues...\n")

    fixed_count = 0
    for file_path in error_files:
        filepath = Path(file_path)
        if filepath.exists() and filepath.suffix == ".py":
            # Check if this file has indentation errors
            file_errors = [e for e in error_data["errors"] if e["file"] == file_path]
            has_indent_errors = any(
                e["type"] == "indentation_error" for e in file_errors
            )

            if has_indent_errors:
                print(f"  Checking: {filepath.name}...", end=" ")
                if process_file_for_indentation(filepath, error_data):
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
