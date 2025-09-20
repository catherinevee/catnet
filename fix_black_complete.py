#!/usr/bin/env python3
"""
Comprehensive fix for all Black parsing errors in the CatNet codebase.
This script fixes indentation issues after docstrings that were previously on the same line as class definitions.
"""

import os
import re
from pathlib import Path


def fix_file(filepath):
    """Fix Black parsing errors in a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False

    fixed_lines = []
    i = 0
    fixed = False
    in_class = False
    class_indent = ""
    after_class_docstring = False

    while i < len(lines):
        line = lines[i]

        # Detect class definition
        class_match = re.match(r'^(\s*)(class\s+\w+.*:)\s*$', line)
        if class_match:
            in_class = True
            class_indent = class_match.group(1)
            fixed_lines.append(line)
            i += 1

            # Check if next line is a docstring
            if i < len(lines):
                next_line = lines[i]
                # Check if docstring has wrong indentation (should be indented 4 spaces
                # from class)
                docstring_match = re.match(r'^(\s*)(""".*""")\s*$', next_line)
                if docstring_match:
                    current_indent = docstring_match.group(1)
                    expected_indent = class_indent + "    "
                    if current_indent != expected_indent:
                        # Fix docstring indentation
                        fixed_lines.append(
                            f'{expected_indent}{
                                docstring_match.group(2).strip()}\n')
                        fixed = True
                        after_class_docstring = True
                        i += 1
                    else:
                        fixed_lines.append(next_line)
                        after_class_docstring = True
                        i += 1
                elif next_line.strip() and not next_line.strip().startswith('#'):
                    # Next line is not a docstring, might be a class attribute
                    after_class_docstring = False
                    in_class = True
                else:
                    after_class_docstring = False
            continue

        # Fix class attributes that should be at class level (not indented like methods)
        if after_class_docstring and line.strip() and not line.strip().startswith('#'):
            # Check if this looks like a class attribute (not a method)
            if not re.match(r'^\s*(def|class|@)', line):
                # This should be a class attribute, check indentation
                current_indent = len(line) - len(line.lstrip())
                expected_indent = len(class_indent) + 4

                if current_indent != expected_indent:
                    # Fix indentation
                    fixed_lines.append(f'{class_indent}    {line.lstrip()}')
                    fixed = True
                else:
                    fixed_lines.append(line)

                # Check if we're still in the class attributes section
                if not line.strip().endswith(':'):
                    after_class_docstring = True
                else:
                    after_class_docstring = False
            else:
                fixed_lines.append(line)
                after_class_docstring = False
        else:
            fixed_lines.append(line)

            # Reset flags if we hit an empty line or a new class/function
            if not line.strip() or re.match(r'^\s*(def|class)', line):
                after_class_docstring = False
                if re.match(
                        r'^\S', line):  # No indentation means we're out of the class
                    in_class = False
                    class_indent = ""

        i += 1

    # Write fixed content
    if fixed:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)
            return True
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return False

    return False


def fix_function_docstrings(filepath):
    """Fix standalone function docstrings that have wrong indentation."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
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
        func_match = re.match(r'^(\s*)(def\s+\w+.*:)\s*$', line)
        if func_match:
            func_indent = func_match.group(1)
            fixed_lines.append(line)
            i += 1

            # Check if next line is a docstring
            if i < len(lines):
                next_line = lines[i]
                docstring_match = re.match(r'^(\s*)(""".*)', next_line)
                if docstring_match:
                    current_indent = docstring_match.group(1)
                    expected_indent = func_indent + "    "
                    if current_indent != expected_indent:
                        # Fix docstring indentation
                        fixed_lines.append(
                            f'{expected_indent}{
                                docstring_match.group(2).strip()}\n')
                        fixed = True
                        i += 1
                    else:
                        fixed_lines.append(next_line)
                        i += 1
                else:
                    continue
            continue

        fixed_lines.append(line)
        i += 1

    if fixed:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)
            return True
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return False

    return False


def fix_misplaced_code(filepath):
    """Fix code that's at wrong indentation level."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False

    # Fix specific patterns we've seen
    patterns = [
        # Fix standalone docstrings at wrong indentation
        (r'^(\s{0,3})("""[^"]*""")\s*\n(\s*)(\w)', r'\1\2\n\n\4'),
        # Fix code immediately after module docstring
        (r'^("""[^"]*""")\s*\n([a-z])', r'\1\n\n\2'),
        # Fix Args: sections with wrong indentation
        (r'\n(\s{8,})Args:\n', r'\n    Args:\n'),
        # Fix Returns: sections with wrong indentation
        (r'\n(\s{8,})Returns:\n', r'\n    Returns:\n'),
    ]

    fixed = False
    for pattern, replacement in patterns:
        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        if new_content != content:
            content = new_content
            fixed = True

    if fixed:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return False

    return False


def main():
    """Main function to fix all Black parsing errors."""
    src_dir = Path("C:/Users/cathe/OneDrive/Desktop/github/catnet/src")

    # Get all Python files
    python_files = list(src_dir.glob("**/*.py"))

    fixed_count = 0
    print(f"Processing {len(python_files)} Python files...")

    for filepath in python_files:
        filepath_str = str(filepath)

        # Apply all fixes
        fixed = False
        if fix_file(filepath_str):
            fixed = True
        if fix_function_docstrings(filepath_str):
            fixed = True
        if fix_misplaced_code(filepath_str):
            fixed = True

        if fixed:
            fixed_count += 1
            print(f"Fixed: {filepath.relative_to(src_dir.parent)}")

    print(f"\nFixed {fixed_count} files")

    # Test with Black
    print("\nTesting with Black...")
    os.system("python -m black src/ --check 2>&1 | grep -c 'error: cannot format'")


if __name__ == "__main__":
    main()
