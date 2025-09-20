#!/usr/bin/env python3
"""
Targeted fixes for the 82 remaining Black parsing errors.
Based on CI/CD failure analysis from 2025-09-20.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

# Exact error locations from CI/CD output
ERROR_LOCATIONS = {
    "src/api/deployment_endpoints.py": (26, 7, "Unclosed docstring"),
    "src/api/device_connection_endpoints.py": (16, 7, "Unclosed docstring"),
    "src/api/gitops_endpoints.py": (26, 7, "Unclosed docstring"),
    "src/api/device_endpoints.py": (15, 7, "Unclosed docstring"),
    "src/api/main.py": (60, 6, "Malformed f-string"),
    "src/api/rollback_endpoints.py": (16, 7, "Unclosed docstring"),
    "src/api/simple_deploy_endpoints.py": (17, 7, "Unclosed docstring"),
    "src/api/middleware.py": (82, 8, "Indentation error"),
    "src/api/auth_endpoints.py": (201, 7, "Unclosed docstring"),
    "src/auth/jwt_handler.py": (258, 7, "Unclosed docstring"),
    "src/auth/mfa.py": (225, 7, "Unclosed docstring"),
    "src/auth/oauth.py": (22, 7, "Unclosed docstring"),
    "src/auth/saml.py": (24, 7, "Unclosed docstring"),
    "src/auth/session.py": (22, 7, "Unclosed docstring"),
    "src/automation/workflows.py": (22, 7, "Unclosed docstring"),
    "src/auth/ssh_auth.py": (38, 15, "Incomplete statement"),
    "src/cli/auth_utils.py": (15, 0, "Indentation error"),
    "src/compliance/reporting.py": (22, 7, "Unclosed docstring"),
    "src/core/api_config.py": (22, 230, "Malformed __init__"),
    "src/core/config.py": (15, 7, "Unclosed docstring"),
    "src/cli/commands.py": (36, 8, "Else without if"),
    "src/core/logging.py": (13, 7, "Unclosed docstring"),
    "src/core/metrics.py": (17, 7, "Unclosed docstring"),
    "src/core/mtls.py": (24, 0, "Missing class definition"),
    "src/core/rate_limiter.py": (26, 0, "Malformed __init__"),
    "src/core/security_headers.py": (25, 0, "Malformed __init__"),
    "src/core/performance.py": (32, 0, "Malformed __init__"),
    "src/core/validators.py": (51, 0, "Missing method body"),
    "src/deployment/deployment_manager.py": (21, 0, "Missing enum body"),
    "src/deployment/executor.py": (31, 8, "Indentation error"),
    "src/deployment/health_check.py": (20, 0, "Missing enum body"),
    "src/deployment/history.py": (22, 0, "Unindent error"),
    "src/deployment/rollback.py": (19, 0, "Missing enum body"),
    "src/deployment/rollback_manager.py": (21, 0, "Missing dataclass body"),
    "src/deployment/service.py": (21, 0, "Missing __init__ body"),
    "src/deployment/validation.py": (19, 0, "Missing enum body"),
    "src/deployment/simple_deploy.py": (32, 0, "Missing dataclass field"),
    "src/deployment/strategies.py": (23, 0, "Missing enum body"),
    "src/deployment/validator.py": (16, 0, "Missing __init__ body"),
    "src/devices/adapters/cisco_adapter.py": (35, 0, "Unindent error"),
    "src/devices/async_device_connector.py": (24, 0, "Missing __init__ body"),
    "src/devices/cisco_handler.py": (28, 0, "Unindent error"),
    "src/devices/adapters/juniper_adapter.py": (34, 0, "Missing dict body"),
    "src/devices/connector.py": (22, 0, "Missing class definition"),
    "src/devices/device_connector.py": (21, 0, "Malformed __init__"),
    "src/devices/cert_manager.py": (38, 0, "Missing __init__ body"),
    "src/devices/device_manager.py": (21, 0, "Missing enum body"),
    "src/devices/device_store.py": (14, 0, "Missing dataclass field"),
    "src/devices/juniper_handler.py": (21, 0, "Missing dict body"),
    "src/devices/service.py": (19, 0, "Missing __init__ body"),
    "src/devices/ssh_manager.py": (27, 0, "Missing __init__ body"),
    "src/gitops/config_validator.py": (19, 0, "Missing enum body"),
    "src/gitops/git_manager.py": (35, 0, "Missing dataclass field"),
    "src/gitops/gitops_workflow.py": (26, 0, "Missing enum body"),
    "src/gitops/secret_scanner.py": (21, 0, "Missing enum body"),
    "src/gitops/processor.py": (27, 0, "Missing __init__ body"),
    "src/gitops/simple_github_client.py": (16, 0, "Missing dataclass field"),
    "src/gitops/git_handler.py": (46, 31, "Unclosed string"),
    "src/gitops/webhook_processor.py": (23, 0, "Missing enum body"),
    "src/gitops/service.py": (101, 0, "Unclosed parenthesis"),
    "src/ml/anomaly_detection.py": (80, 0, "Missing dataclass field"),
    "src/main.py": (174, 0, "Unclosed parenthesis"),
    "src/monitoring/alerting.py": (22, 0, "Missing enum body"),
    "src/monitoring/metrics.py": (21, 0, "Missing enum body"),
    "src/monitoring/observability.py": (23, 0, "Unindent error"),
    "src/monitoring/simple_metrics.py": (16, 0, "Missing dataclass field"),
    "src/security/secrets_manager.py": (25, 0, "Missing enum body"),
    "src/security/signing.py": (33, 0, "Missing __init__ body"),
    "src/security/simple_security.py": (20, 0, "Missing __init__ body"),
    "src/security/vault.py": (21, 0, "Unindent error"),
    "src/security/vault_service.py": (27, 0, "Missing enum body"),
    "src/security/auth.py": (39, 8, "Indentation error"),
    "src/security/encryption.py": (47, 0, "Unclosed parenthesis"),
    "tests/test_auth.py": (72, 12, "Missing argument"),
    "tests/test_automation.py": (356, 0, "Unindent error"),
    "tests/test_compliance.py": (137, 26, "Missing closing bracket"),
    "tests/test_cli.py": (402, 12, "Missing argument"),
    "tests/test_ml_anomaly.py": (26, 34, "Missing closing bracket"),
    "tests/test_gitops.py": (360, 16, "Missing closing bracket"),
    "tests/unit/test_enhanced_security.py": (76, 15, "Unclosed f-string"),
    "tests/test_security.py": (119, 16, "Missing closing bracket"),
    "tests/unit/test_monitoring.py": (93, 23, "Unclosed f-string"),
}


class TargetedFixer:
    """Apply targeted fixes based on exact error locations."""

    def __init__(self):
        self.fixes_applied = 0
        self.files_fixed = []

    def fix_unclosed_docstring(self, filepath: Path, line_num: int) -> bool:
        """Fix unclosed docstring at specific line."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if 0 <= line_num - 1 < len(lines):
                line = lines[line_num - 1]

                # Check if line has unclosed triple quotes
                if '"""' in line and line.count('"""') == 1:
                    # Add closing quotes on next line if not present
                    if line_num < len(lines) and '"""' not in lines[line_num]:
                        indent = len(line) - len(line.lstrip())
                        lines.insert(line_num, " " * indent + '"""\n')

                        with open(filepath, "w", encoding="utf-8") as f:
                            f.writelines(lines)
                        return True

        except Exception as e:
            print(f"Error fixing docstring in {filepath}: {e}")

        return False

    def fix_malformed_fstring(self, filepath: Path, line_num: int) -> bool:
        """Fix malformed f-string at specific line."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if 0 <= line_num - 1 < len(lines):
                line = lines[line_num - 1]

                # Fix common f-string issues
                if 'f"' in line or "f'" in line:
                    # Count brackets
                    open_brackets = line.count("{")
                    close_brackets = line.count("}")

                    if open_brackets > close_brackets:
                        # Add missing closing brackets
                        line = line.rstrip()
                        if not line.endswith('"') and not line.endswith("'"):
                            line += "}" * (open_brackets - close_brackets) + '"\n'
                        else:
                            # Insert before closing quote
                            quote_pos = (
                                line.rfind('"') if '"' in line else line.rfind("'")
                            )
                            line = (
                                line[:quote_pos]
                                + "}" * (open_brackets - close_brackets)
                                + line[quote_pos:]
                            )

                        lines[line_num - 1] = line

                        with open(filepath, "w", encoding="utf-8") as f:
                            f.writelines(lines)
                        return True

        except Exception as e:
            print(f"Error fixing f-string in {filepath}: {e}")

        return False

    def fix_missing_body(self, filepath: Path, line_num: int, context: str) -> bool:
        """Fix missing method/class body."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if 0 <= line_num - 1 < len(lines):
                line = lines[line_num - 1]

                # Check if line ends with colon but has no body
                if line.rstrip().endswith(":"):
                    # Check next line
                    if line_num < len(lines):
                        next_line = lines[line_num]
                        # If next line is not indented, add pass
                        if next_line.strip() and not next_line.startswith((" ", "\t")):
                            indent = len(line) - len(line.lstrip()) + 4
                            lines.insert(line_num, " " * indent + "pass\n")

                            with open(filepath, "w", encoding="utf-8") as f:
                                f.writelines(lines)
                            return True

        except Exception as e:
            print(f"Error fixing missing body in {filepath}: {e}")

        return False

    def fix_unindent_error(self, filepath: Path, line_num: int) -> bool:
        """Fix unindent error at specific line."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if 1 <= line_num - 1 < len(lines):
                current_line = lines[line_num - 1]
                prev_line = lines[line_num - 2]

                # Calculate expected indentation
                prev_indent = len(prev_line) - len(prev_line.lstrip())
                current_indent = len(current_line) - len(current_line.lstrip())

                # If previous line ends with colon, current should be indented more
                if prev_line.rstrip().endswith(":"):
                    expected_indent = prev_indent + 4
                else:
                    expected_indent = prev_indent

                if current_indent != expected_indent:
                    # Fix the indentation
                    lines[line_num - 1] = " " * expected_indent + current_line.lstrip()

                    with open(filepath, "w", encoding="utf-8") as f:
                        f.writelines(lines)
                    return True

        except Exception as e:
            print(f"Error fixing unindent in {filepath}: {e}")

        return False

    def apply_targeted_fixes(self):
        """Apply all targeted fixes based on error locations."""
        print("=" * 70)
        print("TARGETED FIXES FOR 82 BLACK PARSING ERRORS")
        print("=" * 70)

        for file_path, (line, col, issue_type) in ERROR_LOCATIONS.items():
            filepath = (
                Path("..") / file_path
            )  # Adjust path relative to remediation folder

            if not filepath.exists():
                print(f"  Skipping {file_path}: File not found")
                continue

            print(f"\n  Fixing {file_path}:{line}:{col} - {issue_type}")

            fixed = False

            if "docstring" in issue_type.lower():
                fixed = self.fix_unclosed_docstring(filepath, line)
            elif "f-string" in issue_type.lower():
                fixed = self.fix_malformed_fstring(filepath, line)
            elif "unindent" in issue_type.lower():
                fixed = self.fix_unindent_error(filepath, line)
            elif "missing" in issue_type.lower() and "body" in issue_type.lower():
                fixed = self.fix_missing_body(filepath, line, issue_type)
            elif "enum body" in issue_type.lower():
                fixed = self.fix_missing_body(filepath, line, "enum")
            elif "init" in issue_type.lower():
                fixed = self.fix_missing_body(filepath, line, "__init__")

            if fixed:
                self.fixes_applied += 1
                self.files_fixed.append(file_path)
                print(f"    ✓ Fixed")
            else:
                print(f"    - Manual fix needed")

        print("\n" + "=" * 70)
        print(
            f"Summary: Fixed {self.fixes_applied} issues in {len(set(self.files_fixed))} files"
        )
        print("=" * 70)


if __name__ == "__main__":
    fixer = TargetedFixer()
    fixer.apply_targeted_fixes()
