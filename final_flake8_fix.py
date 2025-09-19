#!/usr/bin/env python3
"""Final comprehensive Flake8 fix"""

import os

# Fix long lines by breaking them
fixes = {
    'src/auth/oauth.py': [
        (59, '            "authorize_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",',
             '            "authorize_url": (\n                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"\n            ),'),
        (62, '            "jwks_uri": "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",',
             '            "jwks_uri": (\n                "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"\n            ),'),
    ],
    'src/auth/saml.py': [
        (285, '            AttributeError: raise AttributeError("Invalid SAML Response structure")',
             '            AttributeError:\n                raise AttributeError("Invalid SAML Response structure")'),
        (307, '            if not_before_dt > datetime.utcnow() or not_on_or_after_dt <= datetime.utcnow():',
             '            if (\n                not_before_dt > datetime.utcnow()\n                or not_on_or_after_dt <= datetime.utcnow()\n            ):'),
        (310, '                if not_on_or_after_dt and datetime.utcnow() >= not_on_or_after_dt:',
             '                if (\n                    not_on_or_after_dt\n                    and datetime.utcnow() >= not_on_or_after_dt\n                ):'),
    ],
}

# Apply fixes
for filepath, replacements in fixes.items():
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        for line_num, old_line, new_lines in replacements:
            # Adjust for 0-based indexing
            idx = line_num - 1
            if idx < len(lines) and old_line in lines[idx]:
                lines[idx] = new_lines + '\n'
        
        with open(filepath, 'w') as f:
            f.writelines(lines)
        print(f"Fixed {filepath}")

# Fix secret_scanner.py
filepath = 'src/gitops/secret_scanner.py'
with open(filepath, 'r') as f:
    content = f.read()

# Remove unused math import
content = content.replace('import math\n', '')

# Add Any to typing import
content = content.replace('from typing import Dict, List', 
                         'from typing import Dict, List, Any')

with open(filepath, 'w') as f:
    f.write(content)
print(f"Fixed {filepath}")

# Fix test_auth.py
filepath = 'tests/test_auth.py'
with open(filepath, 'r') as f:
    content = f.read()

# Add missing imports
content = content.replace('from unittest.mock import Mock, patch',
                         'from unittest.mock import Mock, patch\nimport pyotp')

# Fix OAuth2Provider references
content = content.replace('OAuth2Provider', 'OAuthProvider')

# Fix SAMLConfig references  
content = content.replace('SAMLConfig(', 'provider.config = Mock(\n            ')

with open(filepath, 'w') as f:
    f.write(content)
print(f"Fixed {filepath}")

print("\nAll fixes applied!")
