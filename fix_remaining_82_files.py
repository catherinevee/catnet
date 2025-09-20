#!/usr/bin/env python3
"""
Fix all remaining 82 files with Black parsing errors.
This script applies targeted fixes for each specific issue.
"""

import re
from pathlib import Path
from typing import List, Tuple

def fix_file(filepath: Path) -> bool:
    """Apply comprehensive fixes to a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original = content

        # Fix unclosed docstrings
        content = fix_unclosed_docstrings(content)

        # Fix broken f-strings
        content = fix_broken_fstrings(content)

        # Fix broken string concatenations
        content = fix_broken_strings(content)

        # Fix indentation issues
        content = fix_indentation(content)

        # Fix missing colons
        content = fix_missing_colons(content)

        # Fix unclosed brackets
        content = fix_unclosed_brackets(content)

        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
    return False


def fix_unclosed_docstrings(content: str) -> str:
    """Fix unclosed docstrings."""
    lines = content.split('\n')
    fixed_lines = []
    in_docstring = False
    docstring_quote = None
    docstring_start_line = -1

    for i, line in enumerate(lines):
        # Check for docstring start
        if not in_docstring:
            # Check for triple quotes
            if '"""' in line:
                count = line.count('"""')
                if count == 1:
                    in_docstring = True
                    docstring_quote = '"""'
                    docstring_start_line = i
                # If 2 on same line, docstring is complete
            elif "'''" in line:
                count = line.count("'''")
                if count == 1:
                    in_docstring = True
                    docstring_quote = "'''"
                    docstring_start_line = i
        else:
            # In docstring, check for closing
            if docstring_quote in line:
                in_docstring = False
                docstring_quote = None
                docstring_start_line = -1

        fixed_lines.append(line)

    # If we ended with an unclosed docstring, close it
    if in_docstring and docstring_quote:
        # Find the indentation of the docstring start
        indent = len(lines[docstring_start_line]) - len(lines[docstring_start_line].lstrip())
        fixed_lines.append(' ' * indent + docstring_quote)

    return '\n'.join(fixed_lines)


def fix_broken_fstrings(content: str) -> str:
    """Fix broken f-strings."""
    # Fix f-strings with unclosed brackets
    content = re.sub(r'(f"[^"]*)\{([^}]*?)$', r'\1{\2}"', content, flags=re.MULTILINE)
    content = re.sub(r'(f\'[^\']*)\{([^}]*?)$', r"\1{\2}'", content, flags=re.MULTILINE)

    # Fix f-strings split across lines
    lines = content.split('\n')
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for f-string with open bracket
        if ('f"' in line or "f'" in line) and '{' in line:
            open_brackets = line.count('{')
            close_brackets = line.count('}')

            if open_brackets > close_brackets:
                # Look for closing on next lines
                j = i + 1
                while j < len(lines) and open_brackets > close_brackets:
                    close_brackets += lines[j].count('}')
                    j += 1

                # If still unclosed, add closing brackets
                if open_brackets > close_brackets:
                    if line.rstrip().endswith('"'):
                        line = line[:-1] + '}' * (open_brackets - close_brackets) + '"'
                    elif line.rstrip().endswith("'"):
                        line = line[:-1] + '}' * (open_brackets - close_brackets) + "'"

        fixed_lines.append(line)
        i += 1

    return '\n'.join(fixed_lines)


def fix_broken_strings(content: str) -> str:
    """Fix broken string concatenations."""
    # Fix strings broken across lines
    lines = content.split('\n')
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for unclosed string
        if ('"' in line and line.count('"') % 2 != 0) or \
           ("'" in line and line.count("'") % 2 != 0):
            # Check if it's a multiline string
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                # If next line continues the string
                if next_line.strip() and not next_line.strip().startswith('#'):
                    # Try to merge
                    if line.rstrip().endswith('"') and next_line.lstrip().startswith('"'):
                        # Remove the quotes and join
                        line = line.rstrip()[:-1] + ' ' + next_line.lstrip()[1:]
                        i += 1  # Skip next line
                    elif line.rstrip().endswith("'") and next_line.lstrip().startswith("'"):
                        line = line.rstrip()[:-1] + ' ' + next_line.lstrip()[1:]
                        i += 1

        fixed_lines.append(line)
        i += 1

    return '\n'.join(fixed_lines)


def fix_indentation(content: str) -> str:
    """Fix indentation issues."""
    lines = content.split('\n')
    fixed_lines = []
    expected_indent = 0

    for line in lines:
        stripped = line.lstrip()

        if not stripped or stripped.startswith('#'):
            fixed_lines.append(line)
            continue

        # Decrease indent for certain keywords
        if stripped.startswith(('else:', 'elif ', 'except', 'finally:', 'except:')):
            expected_indent = max(0, expected_indent - 4)

        # Apply indentation
        if stripped:
            line = ' ' * expected_indent + stripped

        # Increase indent after certain patterns
        if line.rstrip().endswith(':') and not stripped.startswith('#'):
            expected_indent += 4

        # Decrease after return/break/continue/pass
        if any(stripped.startswith(kw) for kw in ['return ', 'break', 'continue', 'pass', 'raise ']):
            expected_indent = max(0, expected_indent - 4)

        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def fix_missing_colons(content: str) -> str:
    """Add missing colons after function/class definitions."""
    lines = content.split('\n')
    fixed_lines = []

    for line in lines:
        # Check for function/class definition without colon
        if re.match(r'^\s*(def |class |if |elif |else|for |while |try|except|finally|with )\s*.*[^:]$', line):
            if not line.rstrip().endswith(':'):
                line = line.rstrip() + ':'

        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def fix_unclosed_brackets(content: str) -> str:
    """Fix unclosed brackets."""
    lines = content.split('\n')
    fixed_lines = []
    bracket_stack = []

    for i, line in enumerate(lines):
        # Track brackets
        for char in line:
            if char in '([{':
                bracket_stack.append(char)
            elif char in ')]}':
                if bracket_stack:
                    opening = bracket_stack[-1]
                    if (char == ')' and opening == '(') or \
                       (char == ']' and opening == '[') or \
                       (char == '}' and opening == '{'):
                        bracket_stack.pop()

        # Check if we should close brackets at end of line
        if bracket_stack and i < len(lines) - 1:
            next_line = lines[i + 1] if i + 1 < len(lines) else ''
            # If next line doesn't continue, close brackets
            if next_line and not next_line.lstrip().startswith((',', ')', ']', '}')):
                closing = ''
                for bracket in reversed(bracket_stack):
                    if bracket == '(':
                        closing += ')'
                    elif bracket == '[':
                        closing += ']'
                    elif bracket == '{':
                        closing += '}'

                if closing and not line.rstrip().endswith(closing):
                    line = line.rstrip() + closing
                    bracket_stack = []

        fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def main():
    """Main function to fix all files."""
    print("=" * 80)
    print("FIXING REMAINING 82 FILES WITH BLACK PARSING ERRORS")
    print("=" * 80)

    # Get all Python files with errors
    error_files = []

    # API files
    api_files = [
        "src/api/gitops_endpoints.py",
        "src/api/simple_deploy_endpoints.py",
        "src/api/device_connection_endpoints.py",
        "src/api/middleware.py",
        "src/api/deployment_endpoints.py",
        "src/api/main.py",
        "src/api/device_endpoints.py",
        "src/api/rollback_endpoints.py",
        "src/api/auth_endpoints.py",
    ]

    # Auth files
    auth_files = [
        "src/auth/jwt_handler.py",
        "src/auth/mfa.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/session.py",
        "src/auth/ssh_auth.py",
    ]

    # Core files
    core_files = [
        "src/core/config.py",
        "src/core/logging.py",
        "src/core/metrics.py",
        "src/core/api_config.py",
        "src/core/mtls.py",
        "src/core/rate_limiter.py",
        "src/core/security_headers.py",
        "src/core/performance.py",
        "src/core/validators.py",
    ]

    # Deployment files
    deployment_files = [
        "src/deployment/deployment_manager.py",
        "src/deployment/executor.py",
        "src/deployment/health_check.py",
        "src/deployment/history.py",
        "src/deployment/rollback.py",
        "src/deployment/rollback_manager.py",
        "src/deployment/service.py",
        "src/deployment/validation.py",
        "src/deployment/simple_deploy.py",
        "src/deployment/strategies.py",
        "src/deployment/validator.py",
    ]

    # Device files
    device_files = [
        "src/devices/adapters/cisco_adapter.py",
        "src/devices/adapters/juniper_adapter.py",
        "src/devices/async_device_connector.py",
        "src/devices/cisco_handler.py",
        "src/devices/connector.py",
        "src/devices/device_connector.py",
        "src/devices/cert_manager.py",
        "src/devices/device_manager.py",
        "src/devices/device_store.py",
        "src/devices/juniper_handler.py",
        "src/devices/service.py",
        "src/devices/ssh_manager.py",
    ]

    # GitOps files
    gitops_files = [
        "src/gitops/config_validator.py",
        "src/gitops/git_manager.py",
        "src/gitops/gitops_workflow.py",
        "src/gitops/secret_scanner.py",
        "src/gitops/processor.py",
        "src/gitops/simple_github_client.py",
        "src/gitops/git_handler.py",
        "src/gitops/webhook_processor.py",
        "src/gitops/service.py",
    ]

    # Other source files
    other_files = [
        "src/automation/workflows.py",
        "src/cli/auth_utils.py",
        "src/cli/commands.py",
        "src/compliance/reporting.py",
        "src/ml/anomaly_detection.py",
        "src/main.py",
        "src/monitoring/alerting.py",
        "src/monitoring/metrics.py",
        "src/monitoring/observability.py",
        "src/monitoring/simple_metrics.py",
        "src/security/secrets_manager.py",
        "src/security/signing.py",
        "src/security/simple_security.py",
        "src/security/vault.py",
        "src/security/vault_service.py",
        "src/security/auth.py",
        "src/security/encryption.py",
    ]

    # Test files
    test_files = [
        "tests/test_auth.py",
        "tests/test_automation.py",
        "tests/test_compliance.py",
        "tests/test_cli.py",
        "tests/test_ml_anomaly.py",
        "tests/test_gitops.py",
        "tests/unit/test_enhanced_security.py",
        "tests/test_security.py",
        "tests/unit/test_monitoring.py",
    ]

    # Combine all files
    all_files = (api_files + auth_files + core_files + deployment_files +
                 device_files + gitops_files + other_files + test_files)

    fixed_count = 0
    failed_files = []

    for file_path in all_files:
        filepath = Path(file_path)
        if filepath.exists():
            print(f"Processing {file_path}...")
            if fix_file(filepath):
                print(f"  [OK] Fixed")
                fixed_count += 1
            else:
                print(f"  - No changes needed")
        else:
            print(f"  [ERROR] File not found: {file_path}")
            failed_files.append(file_path)

    print("\n" + "=" * 80)
    print(f"Successfully processed {fixed_count}/{len(all_files)} files")
    if failed_files:
        print(f"Failed to find {len(failed_files)} files")
    print("=" * 80)


if __name__ == "__main__":
    main()