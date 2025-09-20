#!/usr/bin/env python
"""
Fix Flake8 issues automatically
"""
import os
import re
import subprocess
from pathlib import Path


def fix_file(filepath):
    """Fix common Flake8 issues in a file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified = False
    new_lines = []

    for i, line in enumerate(lines):
        # Fix E501: Line too long
        if len(line.rstrip()) > 88 and not line.strip().startswith('#'):
            # For import statements
            if 'from ' in line and 'import' in line:
                # Split long imports
                if ',' in line:
                    parts = line.split('import ')
                    if len(parts) == 2:
                        imports = parts[1].strip().rstrip('\n').split(', ')
                        new_line = parts[0] + 'import (\n'
                        for imp in imports:
                            new_line += f'    {imp.strip()},\n'
                        new_line = new_line.rstrip(',\n') + '\n)\n'
                        new_lines.append(new_line)
                        modified = True
                        continue
            # For strings, add line continuation
            elif '"' in line or "'" in line:
                # Find string boundaries and split
                if len(line) > 88:
                    # Simple approach: add backslash continuation
                    parts = []
                    current = line
                    while len(current.rstrip()) > 88:
                        # Find a good break point around 80 chars
                        break_point = 80
                                                while break_point > 0 and current[break_point] not in ' ,(
                            
                        )[]{}:;':
                            break_point -= 1
                        if break_point == 0:
                            break_point = 80
                        parts.append(current[:break_point + 1].rstrip() + ' \
                            \\\n')
                        current = '    ' + current[break_point + 1:].lstrip()
                    parts.append(current)
                    new_lines.extend(parts)
                    modified = True
                    continue

        # Fix W293: Remove whitespace from blank lines
        if line.strip() == '' and len(line) > 1:
            new_lines.append('\n')
            modified = True
            continue

        # Fix W292: Add newline at end of file
        if i == len(lines) - 1 and not line.endswith('\n'):
            line = line + '\n'
            modified = True

        new_lines.append(line)

    # Write back if modified
    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        return True
    return False


def fix_bare_except(filepath):
    """Fix E722: bare except"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace bare except with Exception
    modified_content = re.sub(r'\bexcept\s*:', 'except Exception:', content)

    if content != modified_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        return True
    return False


def remove_unused_imports(filepath):
    """Remove unused imports (F401)"""
    try:
        # Use autoflake to remove unused imports
        subprocess.run([
            'python', '-m', 'autoflake',
            '--in-place',
            '--remove-unused-variables',
            '--remove-all-unused-imports',
            str(filepath)
        ], capture_output=True, text=True)
        return True
    except Exception:
        return False


def main():
    """Fix all Flake8 issues"""
    print("Fixing Flake8 issues...\n")

    # Get all Python files
    src_dir = Path('src')
    test_dir = Path('tests')

    files_to_fix = list(src_dir.rglob('*.py')) + list(test_dir.rglob('*.py'))

    fixed_count = 0

    for filepath in files_to_fix:
        fixed = False

        # Fix common issues
        if fix_file(filepath):
            fixed = True

        # Fix bare except
        if fix_bare_except(filepath):
            fixed = True

        # Remove unused imports (if autoflake is available)
        if remove_unused_imports(filepath):
            fixed = True

        if fixed:
            print(f"Fixed: {filepath}")
            fixed_count += 1

    print(f"\nFixed {fixed_count} files")

    # Run flake8 again to check
    print("\nRunning Flake8 to verify...")
    result = subprocess.run([
        'python', '-m', 'flake8',
        'src/', 'tests/',
        '--max-line-length=88',
        '--extend-ignore=E203,W503'
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print("✓ All Flake8 issues fixed!")
    else:
        remaining = len(result.stdout.strip().split('\n')) if result.stdout \
            else 0
        print(f"Still {remaining} issues remaining")
        if remaining < 20:
            print(result.stdout)

    return result.returncode

if __name__ == '__main__':
    exit(main())
