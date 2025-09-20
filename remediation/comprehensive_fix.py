#!/usr/bin/env python3
"""
Comprehensive fix for all Black parsing errors.
Focuses on the most common patterns found in the codebase.
"""

import re
import json
from pathlib import Path
from typing import List, Tuple


def fix_unclosed_docstrings(content: str) -> str:
    """Fix unclosed docstrings."""
    lines = content.split("\n")
    fixed_lines = []
    in_docstring = False
    docstring_start_line = -1
    quote_style = None

    for i, line in enumerate(lines):
        # Check for docstring start
        if not in_docstring:
            if '"""' in line and line.count('"""') == 1:
                in_docstring = True
                docstring_start_line = i
                quote_style = '"""'
            elif "'''" in line and line.count("'''") == 1:
                in_docstring = True
                docstring_start_line = i
                quote_style = "'''"

        # Check for docstring end
        elif in_docstring:
            if quote_style in line:
                in_docstring = False
                docstring_start_line = -1
                quote_style = None

        fixed_lines.append(line)

    # If we ended in a docstring, close it
    if in_docstring and docstring_start_line >= 0:
        # Add closing quotes after the docstring content
        fixed_lines.insert(docstring_start_line + 1, quote_style)

    return "\n".join(fixed_lines)


def fix_class_docstring_patterns(content: str) -> str:
    """Fix docstring patterns in classes."""
    # Fix pattern: class followed by docstring on the same or wrong line
    content = re.sub(
        r'^(\s*)class\s+(\w+.*?):\s*\n\s*"""([^"]*?)"""',
        r'\1class \2:\n\1    """\3"""',
        content,
        flags=re.MULTILINE,
    )

    # Fix imports in docstrings
    content = re.sub(
        r'^"""([^"]*?)\nfrom\s+', r'"""\1\n"""\nfrom ', content, flags=re.MULTILINE
    )

    # Fix unclosed docstring with imports
    content = re.sub(
        r'^"""([^"]*?)\n(from\s+[^\n]+)', r'"""\1\n"""\n\2', content, flags=re.MULTILINE
    )

    return content


def fix_indentation_issues(content: str) -> str:
    """Fix common indentation issues."""
    lines = content.split("\n")
    fixed_lines = []

    for i, line in enumerate(lines):
        # Replace tabs with 4 spaces
        if "\t" in line:
            line = line.replace("\t", "    ")

        # Fix mixed indentation
        if line and line[0] in " \t":
            # Count leading whitespace
            stripped = line.lstrip()
            indent_count = len(line) - len(stripped)

            # Round to nearest multiple of 4
            proper_indent = (indent_count // 4) * 4
            if indent_count % 4 >= 2:
                proper_indent += 4

            line = " " * proper_indent + stripped

        fixed_lines.append(line)

    return "\n".join(fixed_lines)


def fix_broken_strings(content: str) -> str:
    """Fix broken string literals."""
    # Fix unclosed f-strings
    content = re.sub(r'(f"[^"\n]*?)\n', r'\1"\n', content)

    # Fix unclosed regular strings
    content = re.sub(r'^([^#]*?"[^"\n]*?)$', r'\1"', content, flags=re.MULTILINE)

    # Fix broken multiline strings
    content = re.sub(r'("[^"]*?)\s*\\\s*\n\s*f"', r'\1" \\\n    f"', content)

    return content


def fix_function_definitions(content: str) -> str:
    """Fix function definition issues."""
    # Fix functions with docstrings on wrong line
    content = re.sub(
        r'^(\s*)def\s+(\w+\([^)]*\)):\s*"""',
        r'\1def \2:\n\1    """',
        content,
        flags=re.MULTILINE,
    )

    # Fix async functions
    content = re.sub(
        r'^(\s*)async\s+def\s+(\w+\([^)]*\)):\s*"""',
        r'\1async def \2:\n\1    """',
        content,
        flags=re.MULTILINE,
    )

    return content


def fix_dataclass_issues(content: str) -> str:
    """Fix dataclass and Pydantic model issues."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for class definition with BaseModel or dataclass
        if "class " in line and (
            "BaseModel" in line or "@dataclass" in lines[i - 1] if i > 0 else False
        ):
            fixed_lines.append(line)
            i += 1

            # Check next line for docstring
            if i < len(lines) and '"""' in lines[i]:
                # Ensure proper indentation
                docstring_line = lines[i].strip()
                indent = "    "  # Standard class docstring indent

                # Check if it's a complete docstring
                if docstring_line.count('"""') == 2:
                    fixed_lines.append(indent + docstring_line)
                else:
                    # Multi-line docstring
                    fixed_lines.append(indent + docstring_line)

                i += 1
        else:
            fixed_lines.append(line)
            i += 1

    return "\n".join(fixed_lines)


def process_file(filepath: Path) -> bool:
    """Process a single file to fix all issues."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        original = content

        # Apply fixes in order
        content = fix_unclosed_docstrings(content)
        content = fix_class_docstring_patterns(content)
        content = fix_function_definitions(content)
        content = fix_dataclass_issues(content)
        content = fix_broken_strings(content)
        content = fix_indentation_issues(content)

        if content != original:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True

    except Exception as e:
        print(f"Error processing {filepath}: {e}")

    return False


def main():
    """Main function to fix all Python files."""
    print("=" * 70)
    print("COMPREHENSIVE BLACK ERROR FIXER")
    print("=" * 70)

    # Get all Python files
    python_files = list(Path("..").rglob("*.py"))

    # Exclude remediation directory
    python_files = [f for f in python_files if "remediation" not in str(f)]

    print(f"\nProcessing {len(python_files)} Python files...")

    fixed_count = 0
    for filepath in python_files:
        if process_file(filepath):
            fixed_count += 1
            print(f"  Fixed: {filepath.name}")

    print(f"\n{'=' * 70}")
    print(f"Fixed {fixed_count} files")

    # Check Black status
    import subprocess

    result = subprocess.run(
        ["python", "-m", "black", "..", "--check"], capture_output=True, text=True
    )
    error_count = result.stderr.count("error: cannot format")
    print(f"Remaining Black errors: {error_count}")
    print("=" * 70)

    return fixed_count


if __name__ == "__main__":
    main()
