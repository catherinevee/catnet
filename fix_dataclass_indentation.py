#!/usr/bin/env python3
"""
Fix dataclass field indentation issues in Python files.
"""
import re
from pathlib import Path


def fix_dataclass_indentation(content):
    """Fix incorrectly indented dataclass fields."""
    lines = content.split("\n")
    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        fixed_lines.append(line)

        # Check if this is a class definition with BaseModel or dataclass
        if "class " in line and (
            "(BaseModel)" in line or "@dataclass" in lines[max(0, i - 1)]
        ):
            # Look for docstring on next line
            if i + 1 < len(lines) and '"""' in lines[i + 1]:
                fixed_lines.append(lines[i + 1])  # Add docstring line

                # Now check for incorrectly indented fields
                j = i + 2
                while j < len(lines):
                    field_line = lines[j]

                    # If we hit an empty line followed by indented content, it might be
                    # fields
                    if field_line.strip() == "":
                        fixed_lines.append(field_line)
                        j += 1
                        if j < len(lines):
                            next_line = lines[j]
                            # Check if the next line has incorrect indentation (starts
                            # with field name)
                            if (
                                next_line.strip()
                                and not next_line.startswith("    ")
                                and ":" in next_line
                            ):
                                # This is likely a misindented field
                                # Read all the fields until we hit a properly formatted
                                # line
                                while j < len(lines):
                                    field_content = lines[j]
                                    if field_content.strip():
                                        # Check if this looks like a field definition
                                        if not field_content.startswith("    ") and (
                                            ":" in field_content
                                            or field_content.strip().startswith('"""')
                                        ):
                                            # Add proper indentation
                                            fixed_lines.append(
                                                "    " + field_content.strip()
                                            )
                                        elif (
                                            field_content.startswith("        ")
                                            and ":" in field_content
                                        ):
                                            # This is an incorrectly indented field (too
                                            # much indentation)
                                            fixed_lines.append(
                                                "    " + field_content.strip()
                                            )
                                        else:
                                            # Check if we've reached the end of the
                                            # class
                                            if (
                                                field_content.startswith("class ")
                                                or field_content.startswith("def ")
                                                or field_content.startswith("@")
                                            ):
                                                j -= 1  # Back up to reprocess this line
                                                break
                                            fixed_lines.append(field_content)
                                    else:
                                        fixed_lines.append(field_content)
                                        # Check if next line is a new class or function
                                        if j + 1 < len(lines):
                                            peek = lines[j + 1]
                                            if (
                                                peek.startswith("class ")
                                                or peek.startswith("def ")
                                                or peek.startswith("@")
                                            ):
                                                break
                                    j += 1
                                i = j - 1
                                break
                            else:
                                # Normal processing
                                break
                    else:
                        break
                i += 1
            else:
                i += 1
        else:
            i += 1

    return "\n".join(fixed_lines)


def main():
    """Fix all Python files with dataclass indentation issues."""

    files_to_fix = [
        "src/api/deployment_endpoints.py",
        "src/api/device_endpoints.py",
        "src/api/auth_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/rollback_endpoints.py",
        "src/auth/jwt_handler.py",
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/session.py",
        "src/compliance/compliance.py",
        "src/compliance/reports.py",
        "src/core/circuit_breaker.py",
        "src/core/config_parser.py",
        "src/core/database.py",
        "src/core/service_registry.py",
        "src/core/scheduler.py",
        "src/dashboard/metrics.py",
        "src/db/models.py",
        "src/deployment/canary.py",
        "src/deployment/executor.py",
        "src/deployment/rollback.py",
        "src/deployment/validator.py",
        "src/devices/cisco_handler.py",
        "src/devices/connection_pool.py",
        "src/devices/juniper_handler.py",
        "src/integrations/jira.py",
        "src/integrations/teams.py",
        "src/integrations/servicenow.py",
        "src/integrations/splunk.py",
        "src/ml/predictor.py",
        "src/monitoring/alerts.py",
        "src/monitoring/elastic.py",
        "src/monitoring/grafana.py",
        "src/monitoring/health.py",
        "src/monitoring/prometheus.py",
        "src/security/certificates.py",
        "src/security/vault.py",
        "src/workers/deployment_worker.py",
        "catnet_cli/client.py",
        "catnet_cli/config.py",
    ]

    for file_path in files_to_fix:
        full_path = Path(file_path)
        if full_path.exists():
            print(f"Processing {file_path}...")
            content = full_path.read_text(encoding="utf-8")
            fixed_content = fix_dataclass_indentation(content)

            if fixed_content != content:
                full_path.write_text(fixed_content, encoding="utf-8")
                print(f"  Fixed indentation issues")
            else:
                print(f"  No changes needed")
        else:
            print(f"  File not found: {file_path}")

    print("\nDone!")


if __name__ == "__main__":
    main()
