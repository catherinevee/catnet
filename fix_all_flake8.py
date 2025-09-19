#!/usr/bin/env python3
"""Fix all remaining Flake8 issues comprehensively"""

import os
import re

# Fix imports in config_validator.py
file_path = 'src/gitops/config_validator.py'
with open(file_path, 'r') as f:
    content = f.read()
    
# Remove unused imports
content = content.replace('import yaml\nimport json\n', '')
content = content.replace('from pathlib import Path\n', '')
content = content.replace('from typing import Dict, Any, Optional, List, Tuple', 
                         'from typing import Dict, Any, Optional, List')

# Fix unused hierarchy_stack
content = content.replace('hierarchy_stack = []\n        brace_count = 0', 'brace_count = 0')

with open(file_path, 'w') as f:
    f.write(content)
print(f"Fixed {file_path}")

# Fix imports in git_manager.py
file_path = 'src/gitops/git_manager.py'
with open(file_path, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if line.strip() == 'import git':
        lines[i] = ''
        break

with open(file_path, 'w') as f:
    f.writelines(lines)
print(f"Fixed {file_path}")

# Fix imports in gitops_workflow.py
file_path = 'src/gitops/gitops_workflow.py'
with open(file_path, 'r') as f:
    content = f.read()

content = content.replace('from .git_manager import GitManager, GitRepository', 
                         'from .git_manager import GitManager')

# Fix unused notification variable
content = re.sub(r'            notification = \{[^}]+\}\n', '', content, flags=re.DOTALL)

with open(file_path, 'w') as f:
    f.write(content)
print(f"Fixed {file_path}")

# Fix imports in secret_scanner.py
file_path = 'src/gitops/secret_scanner.py'
with open(file_path, 'r') as f:
    content = f.read()

content = content.replace('import hashlib\n', '')
content = content.replace('import base64\n', '')
content = content.replace('from typing import Optional, Dict, List, Tuple', 
                         'from typing import Dict, List')

# Add missing os import
if 'import os' not in content:
    content = content.replace('import re\nimport math', 'import os\nimport re\nimport math')

with open(file_path, 'w') as f:
    f.write(content)
print(f"Fixed {file_path}")

# Fix test imports
file_path = 'tests/test_auth.py'
with open(file_path, 'r') as f:
    lines = f.readlines()

# Remove unused imports
lines_to_remove = [
    'import asyncio',
    'from datetime import datetime, timedelta',
    'from unittest.mock import Mock, AsyncMock, patch',
    'import jwt',
    'import base64',
    'from src.auth.jwt_handler import JWTHandler, create_access_token, verify_token',
    'from src.auth.mfa import MFAProvider, generate_totp_secret, verify_totp_token',
    'from src.auth.oauth import OAuthProvider, OAuthConfig',
    'from src.auth.session import SessionManager, Session',
]

new_lines = []
for line in lines:
    should_keep = True
    for remove_line in lines_to_remove:
        if remove_line in line:
            should_keep = False
            break
    if should_keep:
        new_lines.append(line)

# Add back only what we need
import_section = '''"""
Comprehensive tests for CatNet Authentication
"""

import pytest
from unittest.mock import Mock, patch

from src.auth.jwt_handler import JWTHandler
from src.auth.mfa import MFAProvider
from src.auth.oauth import OAuthProvider
from src.auth.saml import SAMLProvider
from src.auth.session import SessionManager


'''

new_lines = [import_section] + new_lines[14:]

with open(file_path, 'w') as f:
    f.writelines(new_lines)
print(f"Fixed {file_path}")

# Fix test_gitops.py
file_path = 'tests/test_gitops.py'
with open(file_path, 'r') as f:
    content = f.read()

# Remove unused imports
content = content.replace('import asyncio\n', '')
content = content.replace('from unittest.mock import Mock, AsyncMock, patch, MagicMock',
                         'from unittest.mock import Mock, patch, MagicMock')
content = content.replace('''from src.gitops.webhook_processor import (
    WebhookProcessor,
    WebhookEvent,
    EventType,
    WebhookProvider,
)''', '''from src.gitops.webhook_processor import (
    WebhookProcessor,
    WebhookProvider,
)''')
content = content.replace('''from src.gitops.config_validator import (
    ConfigValidator,
    ValidationResult,
    ValidationType,
    Severity,
)''', '''from src.gitops.config_validator import (
    ConfigValidator,
    ValidationResult,
    ValidationType,
)''')
content = content.replace('''from src.gitops.gitops_workflow import (
    GitOpsWorkflow,
    DeploymentStrategy,
    WorkflowConfig,
    WorkflowState,
)''', '''from src.gitops.gitops_workflow import (
    GitOpsWorkflow,
    WorkflowConfig,
    WorkflowState,
)''')

# Fix unused variable
content = content.replace('            files = self.git_manager.list_files(repo.id, pattern="*.yml")',
                         '            self.git_manager.list_files(repo.id, pattern="*.yml")')

with open(file_path, 'w') as f:
    f.write(content)
print(f"Fixed {file_path}")

print("\nAll Flake8 issues fixed!")
