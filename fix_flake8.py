#!/usr/bin/env python3
"""Fix all remaining Flake8 issues"""

import os
import re

def fix_line_lengths(filepath, max_length=88):
    """Fix lines that are too long"""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    modified = False
    for i, line in enumerate(lines):
        if len(line.rstrip()) > max_length and not line.strip().startswith('#'):
            # Try to break at logical points
            if ',' in line and line.count('"') % 2 == 0:
                # Break at comma for function arguments
                parts = line.split(',')
                if len(parts) > 1:
                    indent = len(line) - len(line.lstrip())
                    new_lines = []
                    current = parts[0]
                    for part in parts[1:]:
                        if len(current + ',' + part) > max_length:
                            new_lines.append(current + ',\n')
                            current = ' ' * (indent + 4) + part.lstrip()
                        else:
                            current += ',' + part
                    new_lines.append(current)
                    lines[i] = ''.join(new_lines)
                    modified = True
    
    if modified:
        with open(filepath, 'w') as f:
            f.writelines(lines)
    return modified

# Fix specific files
files_to_fix = [
    'src/auth/oauth.py',
    'src/auth/saml.py', 
    'src/gitops/config_validator.py',
    'src/gitops/git_manager.py',
    'src/gitops/secret_scanner.py',
]

for filepath in files_to_fix:
    if os.path.exists(filepath):
        fix_line_lengths(filepath)
        print(f"Processed {filepath}")
