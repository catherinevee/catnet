#!/usr/bin/env python3
"""
Complete Flake8 fixer for CatNet
Fixes all remaining issues comprehensively
"""

import os
import re
import sys
from pathlib import Path
import subprocess


def fix_line_lengths(file_path):
    """Fix E501 line too long issues"""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified = False
    new_lines = []

    for i, line in enumerate(lines):
        # Skip if already has continuation or is a comment
        if line.rstrip().endswith('\\') or line.strip().startswith('#'):
            new_lines.append(line)
            continue

        # Check if line is too long
        if len(line.rstrip()) > 79:
            modified = True
            stripped = line.rstrip()

            # Handle string literals specially
            if '"""' in stripped or "'''" in stripped:
                new_lines.append(line)
                continue

            # Handle imports
            if stripped.startswith('from ') or stripped.startswith('import '):
                if ',' in stripped:
                    # Multi-import, split at commas
                    parts = stripped.split('import ')
                    if len(parts) == 2:
                        imports = parts[1].split(',')
                        new_lines.append(f"{parts[0]}import (\n")
                        for imp in imports:
                            new_lines.append(f"    {imp.strip()},\n")
                        new_lines.append(")\n")
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
                continue

            # Handle function calls and definitions
            if '(' in stripped and ')' in stripped:
                # Find good split points
                if ',' in stripped:
                    # Split at commas within parentheses
                    indent = len(line) - len(line.lstrip())
                    before_paren = stripped.split('(')[0]

                    # Extract content between parentheses
                    match = re.search(r'\((.*)\)', stripped)
                    if match:
                        args = match.group(1)
                        args_list = args.split(',')

                        # Reconstruct with proper formatting
                        new_lines.append(f"{' ' * indent}{before_paren}(\n")
                        for arg in args_list[:-1]:
                                                        new_lines.append(
                                f"{' ' * (indent + 4)}{arg.strip()},
                                \n"
                            )
                        new_lines.append(f"{' ' * (indent + \
                            4)}{args_list[-1].strip()}\n")
                        new_lines.append(f"{' ' * \
                            indent}){stripped.split(')')[-1]}\n")
                        continue

            # Handle dictionary/list literals
            if '{' in stripped or '[' in stripped:
                if ',' in stripped:
                    indent = len(line) - len(line.lstrip())
                    # Simple split at commas
                    parts = stripped.split(',')
                    if len(parts) > 1:
                        new_lines.append(f"{parts[0]},\n")
                        for part in parts[1:]:
                            new_lines.append(f"{' ' * (indent + \
                                4)}{part.strip()}\n")
                        continue

            # Default: add backslash continuation
            if len(stripped) > 79:
                # Find a good split point
                split_point = 79
                for char in [' ', ',', '(', '[', '{']:
                    pos = stripped.rfind(char, 0, 79)
                    if pos > 40:  # Don't split too early
                        split_point = pos + 1
                        break

                part1 = stripped[:split_point].rstrip()
                part2 = stripped[split_point:].lstrip()

                if part1 and part2:
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(f"{part1} \\\n")
                    new_lines.append(f"{' ' * (indent + 4)}{part2}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if modified:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    return modified


def fix_other_issues(file_path):
    """Fix other Flake8 issues"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content

    # Fix E722: bare except
    content = re.sub(r'\bexcept\s*:\s*\n', 'except Exception:\n', content)

    # Fix W291: trailing whitespace
    lines = content.split('\n')
    lines = [line.rstrip() for line in lines]
    content = '\n'.join(lines)

    # Fix W292: no newline at end of file
    if content and not content.endswith('\n'):
        content += '\n'

    # Fix W293: blank line contains whitespace
    content = re.sub(r'^[ \t]+$', '', content, flags=re.MULTILINE)

    # Fix W391: blank line at end of file
    while content.endswith('\n\n'):
        content = content[:-1]
    if not content.endswith('\n'):
        content += '\n'

    # Fix E303: too many blank lines
    content = re.sub(r'\n{4,}', '\n\n\n', content)

    # Fix E302: expected 2 blank lines, found 1 (before class/function)
    content = re.sub(r'\n(class\s+\w+)', r'\n\n\1', content)
    content = re.sub(r'\n(def\s+\w+.*:)\n', r'\n\n\1\n', content)

    # Fix E741: ambiguous variable name 'l'
    content = re.sub(r'\bl\s*=', 'list_var =', content)
    content = re.sub(r'for\s+l\s+in', 'for item in', content)

    # Fix E203: whitespace before ':'
    content = re.sub(r'\s+:', ':', content)

    # Fix redundant backslashes between brackets (E502)
    content = re.sub(r'(\([^)]*)\\\n([^)]*\))', r'\1\n\2', content)
    content = re.sub(r'(\[[^\]]*)\\\n([^\]]*\])', r'\1\n\2', content)

    if content != original:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True

    return False


def remove_unused_imports(file_path):
    """Remove unused imports using autoflake"""
    try:
        result = subprocess.run(
            ['autoflake', '--in-place', '--remove-unused-variables',
             '--remove-all-unused-imports', str(file_path)],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def main():
    """Main function to fix all Python files"""
    project_root = Path.cwd()
    python_files = list(project_root.glob('**/*.py'))

    # Exclude virtual environments and cache
    python_files = [
        f for f in python_files
        if 'venv' not in str(f)
        and '__pycache__' not in str(f)
        and '.git' not in str(f)
    ]

    print(f"Found {len(python_files)} Python files to check")

    fixed_count = 0
    for file_path in python_files:
        fixed = False

        # First pass: fix other issues
        if fix_other_issues(file_path):
            fixed = True

        # Second pass: fix line lengths
        if fix_line_lengths(file_path):
            fixed = True

        # Third pass: remove unused imports
        if remove_unused_imports(file_path):
            fixed = True

        if fixed:
            fixed_count += 1
            print(f"Fixed: {file_path.relative_to(project_root)}")

    print(f"\nFixed {fixed_count} files")

    # Run flake8 to verify
    print("\nRunning Flake8 to verify fixes...")
    result = subprocess.run(
        ['python', '-m', 'flake8', '.', '--count'],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✓ All Flake8 issues fixed!")
    else:
        # Count remaining issues
        output_lines = result.stdout.strip().split('\n')
        if output_lines and output_lines[-1].isdigit():
            issue_count = output_lines[-1]
            print(f"Still {issue_count} issues remaining")
        else:
            print("Some issues remain")

    return result.returncode

if __name__ == "__main__":
    sys.exit(main())
