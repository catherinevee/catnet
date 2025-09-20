#!/usr/bin/env python3
"""
Automatically fix unclosed strings and broken f-strings.
"""

import re
import json
from pathlib import Path
from typing import List, Tuple


def load_error_data():
    """Load Black error data."""
    with open("black_errors_v2.json", "r") as f:
        return json.load(f)


def fix_unclosed_quotes(content: str) -> Tuple[str, int]:
    """Fix lines with unclosed quotes."""
    lines = content.split("\n")
    fixed_lines = []
    fixes_made = 0

    for i, line in enumerate(lines):
        fixed_line = line

        # Skip comment lines
        if line.strip().startswith("#"):
            fixed_lines.append(line)
            continue

        # Count quotes (excluding escaped quotes)
        single_quotes = len(re.findall(r"(?<!\\)'", line))
        double_quotes = len(re.findall(r'(?<!\\)"', line))

        # Check for unclosed single quotes
        if single_quotes % 2 != 0:
            # Check if line appears to be incomplete
            if not line.rstrip().endswith(("'", ")", "]", "}", ",")):
                fixed_line = line.rstrip() + "'"
                fixes_made += 1

        # Check for unclosed double quotes
        elif double_quotes % 2 != 0:
            # Check if it's an f-string
            if 'f"' in line or 'f"""' in line:
                # Handle f-string specifically
                if not line.rstrip().endswith('"'):
                    if '"""' in line and line.count('"""') % 2 != 0:
                        fixed_line = line.rstrip() + '"""'
                    else:
                        fixed_line = line.rstrip() + '"'
                    fixes_made += 1
            elif not line.rstrip().endswith('"'):
                fixed_line = line.rstrip() + '"'
                fixes_made += 1

        fixed_lines.append(fixed_line)

    return "\n".join(fixed_lines), fixes_made


def fix_broken_fstrings(content: str) -> Tuple[str, int]:
    """Fix broken f-string formatting."""
    fixes_made = 0

    # Fix pattern: f" text" f"more text" should be f" text more text"
    pattern1 = re.compile(r'f"([^"]*?)"\s*f"([^"]*?)"')
    content, count1 = pattern1.subn(r'f"\1 \2"', content)
    fixes_made += count1

    # Fix pattern: broken multi-line f-strings
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for f-string with unclosed bracket
        if 'f"' in line or "f'" in line:
            open_brackets = line.count("{") - line.count("}")
            if open_brackets > 0 and i + 1 < len(lines):
                # Look at next line
                next_line = lines[i + 1]
                if "}" in next_line:
                    # Merge lines
                    merged = line.rstrip() + " " + next_line.lstrip()
                    fixed_lines.append(merged)
                    i += 2
                    fixes_made += 1
                    continue

        fixed_lines.append(line)
        i += 1

    if fixes_made > 0:
        content = "\n".join(fixed_lines)

    return content, fixes_made


def fix_string_concatenation(content: str) -> Tuple[str, int]:
    """Fix broken string concatenation."""
    fixes_made = 0

    # Fix pattern: "string" \ on one line, "continuation" on next
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for line ending with backslash after quote
        if re.search(r'["\']\\s*\\$', line):
            if i + 1 < len(lines):
                next_line = lines[i + 1].lstrip()
                if next_line.startswith(('"', "'")):
                    # Fix by using proper concatenation
                    fixed_line = line.rstrip()[:-1]  # Remove backslash
                    fixed_lines.append(fixed_line)
                    fixed_lines.append(lines[i + 1])
                    i += 2
                    fixes_made += 1
                    continue

        fixed_lines.append(line)
        i += 1

    return "\n".join(fixed_lines), fixes_made


def fix_unclosed_brackets(content: str) -> Tuple[str, int]:
    """Fix unclosed brackets in function calls and data structures."""
    lines = content.split("\n")
    fixed_lines = []
    fixes_made = 0
    bracket_stack = []

    for i, line in enumerate(lines):
        # Track brackets
        for char in line:
            if char in "([{":
                bracket_stack.append(char)
            elif char in ")]}":
                if bracket_stack:
                    opening = bracket_stack[-1]
                    if (
                        (char == ")" and opening == "(")
                        or (char == "]" and opening == "[")
                        or (char == "}" and opening == "{")
                    ):
                        bracket_stack.pop()

        # Check if we have unclosed brackets at end of line
        if bracket_stack and i < len(lines) - 1:
            next_line = lines[i + 1] if i + 1 < len(lines) else ""

            # If next line doesn't continue the structure, close brackets
            if next_line and not next_line.lstrip().startswith((",", ")", "]", "}")):
                closing = ""
                for bracket in reversed(bracket_stack):
                    if bracket == "(":
                        closing += ")"
                    elif bracket == "[":
                        closing += "]"
                    elif bracket == "{":
                        closing += "}"

                if closing:
                    line = line.rstrip() + closing
                    bracket_stack = []
                    fixes_made += 1

        fixed_lines.append(line)

    return "\n".join(fixed_lines), fixes_made


def process_file_for_strings(filepath: Path, error_info: dict) -> bool:
    """Process a file to fix string-related errors."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        original = content
        total_fixes = 0

        # Get errors for this file
        file_errors = [e for e in error_info["errors"] if Path(e["file"]) == filepath]

        # Apply fixes based on error types
        for error in file_errors:
            if (
                "unclosed" in error.get("error", "").lower()
                or "unterminated" in error.get("error", "").lower()
            ):
                content, fixes = fix_unclosed_quotes(content)
                total_fixes += fixes
                break

        # Apply general string fixes
        content, fixes1 = fix_broken_fstrings(content)
        total_fixes += fixes1

        content, fixes2 = fix_string_concatenation(content)
        total_fixes += fixes2

        content, fixes3 = fix_unclosed_brackets(content)
        total_fixes += fixes3

        if content != original:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True

    except Exception as e:
        print(f"    Error processing {filepath}: {e}")

    return False


def main():
    """Main function to fix unclosed strings."""
    print("=" * 70)
    print("UNCLOSED STRING FIXER")
    print("=" * 70)

    # Load error data
    error_data = load_error_data()
    error_files = error_data["error_files"]

    print(f"\nProcessing {len(error_files)} files with string errors...\n")

    fixed_count = 0
    for file_path in error_files:
        filepath = Path(file_path)
        if filepath.exists() and filepath.suffix == ".py":
            # Check if this file has string-related errors
            file_errors = [e for e in error_data["errors"] if e["file"] == file_path]
            has_string_errors = any(
                "parse_error" in e.get("type", "")
                and any(
                    keyword in str(e.get("error", "")).lower()
                    for keyword in [
                        "unclosed",
                        "unterminated",
                        "quote",
                        "string",
                        "bracket",
                    ]
                )
                for e in file_errors
            )

            if has_string_errors:
                print(f"  Checking: {filepath.name}...", end=" ")
                if process_file_for_strings(filepath, error_data):
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
