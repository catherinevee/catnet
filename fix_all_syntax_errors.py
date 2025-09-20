#!/usr/bin/env python3
"""
Comprehensive fix for all syntax errors in Python files preventing Black from formatting.
"""

import os
import re
from pathlib import Path


def fix_ssh_auth_file():
    """Specifically fix the ssh_auth.py file's broken docstrings."""
    filepath = Path("src/auth/ssh_auth.py")
    if not filepath.exists():
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Fix the broken docstring pattern in calculate_fingerprint
    content = re.sub(
        r'def calculate_fingerprint\(self, public_key: str\) -> str:\s*"""[^"]*?"""\s*Args:',
        'def calculate_fingerprint(self, public_key: str) -> str:\n        """\n        Calculate SSH key fingerprint.\n        \n        Args:',
        content,
        flags=re.DOTALL,
    )

    # Fix the standalone Returns: that's not in a docstring
    content = re.sub(
        r"\n(\s*)Returns:\s*\n(\s+)Fingerprint string",
        r"\n\1        Returns:\n\1            Fingerprint string",
        content,
    )

    # Fix the add_ssh_key method's broken docstring
    content = re.sub(
        r"async def add_ssh_key\([^)]+\) -> UserSSHKey:\s*Add SSH public key",
        'async def add_ssh_key(\n        self,\n        user_id: str,\n        public_key: str,\n        key_name: str,\n        comment: Optional[str] = None,\n    ) -> UserSSHKey:\n        """\n        Add SSH public key',
        content,
        flags=re.DOTALL,
    )

    # Ensure all method docstrings are properly closed
    lines = content.split("\n")
    fixed_lines = []
    in_function = False
    in_docstring = False
    docstring_indent = ""

    for i, line in enumerate(lines):
        # Detect function/method definition
        if re.match(r"^(\s*)(async\s+)?def\s+\w+.*:\s*$", line):
            in_function = True
            func_indent = re.match(r"^(\s*)", line).group(1)
            docstring_indent = func_indent + "    "
            fixed_lines.append(line)
            continue

        # If we're in a function and see Args: or Returns: without proper docstring
        if in_function and not in_docstring:
            if re.match(r"^\s*(Args?|Returns?|Raises?):", line):
                # Start a docstring
                fixed_lines.append(docstring_indent + '"""')
                fixed_lines.append(docstring_indent + "Method implementation.")
                fixed_lines.append(docstring_indent + "")
                in_docstring = True

        # If we're in a docstring, check if we need to close it
        if in_docstring:
            # Check if next line is actual code (not docstring content)
            if line.strip() and not line.startswith(docstring_indent):
                if not re.match(r"^\s*(Args?|Returns?|Raises?|\w+:)", line):
                    # Close the docstring first
                    fixed_lines.append(docstring_indent + '"""')
                    in_docstring = False
                    in_function = False

        fixed_lines.append(line)

    # Write back
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(fixed_lines))

    return True


def fix_dataclass_files():
    """Fix files with dataclass formatting issues."""
    files = [
        "src/auth/oauth.py",
        "src/auth/saml.py",
        "src/auth/session.py",
        "src/automation/workflows.py",
        "src/compliance/reporting.py",
    ]

    for filepath_str in files:
        filepath = Path(filepath_str)
        if not filepath.exists():
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Fix dataclass docstrings and field indentation
        lines = content.split("\n")
        fixed_lines = []
        in_dataclass = False
        class_indent = ""

        for i, line in enumerate(lines):
            # Detect dataclass
            if "@dataclass" in line or (i > 0 and "@dataclass" in lines[i - 1]):
                in_dataclass = True
                if "class " in line:
                    class_indent = re.match(r"^(\s*)", line).group(1)
            elif re.match(r"^class\s+\w+", line):
                if i > 0 and "@dataclass" in lines[i - 1]:
                    in_dataclass = True
                    class_indent = re.match(r"^(\s*)", line).group(1)
                else:
                    in_dataclass = False

            # Fix field indentation in dataclasses
            if in_dataclass and ":" in line and not line.strip().startswith("def"):
                # This looks like a field definition
                if not line.startswith(class_indent + "    "):
                    # Fix indentation
                    content = line.strip()
                    fixed_lines.append(class_indent + "    " + content)
                    continue

            # Reset when we exit the class
            if in_dataclass and line and not line[0].isspace():
                in_dataclass = False

            fixed_lines.append(line)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(fixed_lines))


def fix_api_endpoints():
    """Fix API endpoint files with broken docstrings."""
    files = [
        "src/api/auth_endpoints.py",
        "src/api/simple_deploy_endpoints.py",
        "src/api/device_endpoints.py",
        "src/api/device_connection_endpoints.py",
        "src/api/deployment_endpoints.py",
        "src/api/rollback_endpoints.py",
        "src/api/gitops_endpoints.py",
        "src/api/middleware.py",
        "src/api/main.py",
    ]

    for filepath_str in files:
        filepath = Path(filepath_str)
        if not filepath.exists():
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Fix broken f-strings
        content = re.sub(
            r'f"([^"]*)\[([^]]*)\]"\s*=\s*"([^"]*)"',
            r'response.headers["\2"] = "\3"',
            content,
        )

        # Fix class definitions with broken docstrings
        content = re.sub(
            r'class (\w+).*:\s*"""([^"]*)"""',
            r'class \1(BaseModel):\n    """\2"""',
            content,
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)


def fix_core_modules():
    """Fix core module files."""
    files = [
        "src/core/api_config.py",
        "src/core/config.py",
        "src/core/logging.py",
        "src/core/metrics.py",
        "src/core/mtls.py",
        "src/core/performance.py",
        "src/core/rate_limiter.py",
        "src/core/security_headers.py",
        "src/core/validators.py",
    ]

    for filepath_str in files:
        filepath = Path(filepath_str)
        if not filepath.exists():
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        fixed_lines = []
        for i, line in enumerate(lines):
            # Fix __init__ methods with broken signatures
            if "__init__(" in line and line.strip().endswith("("):
                # Look ahead for the rest of the signature
                j = i + 1
                while j < len(lines) and ")" not in lines[j]:
                    j += 1
                if j < len(lines):
                    # Combine the signature on one line
                    full_sig = line.rstrip() + " ".join(
                        l.strip() for l in lines[i + 1 : j + 1]
                    )
                    fixed_lines.append(full_sig)
                    # Skip the lines we just combined
                    for _ in range(j - i):
                        if i + 1 < len(lines):
                            lines.pop(i + 1)
                    continue

            # Fix standalone docstrings
            if line.strip() and not line[0].isspace() and i > 0:
                prev = lines[i - 1].strip()
                if prev.endswith(":") and '"""' not in line:
                    # Add proper indentation
                    fixed_lines.append("    " + line)
                    continue

            fixed_lines.append(line)

        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(fixed_lines)


def main():
    """Main function to fix all syntax errors."""
    os.chdir(r"C:\Users\cathe\OneDrive\Desktop\github\catnet")

    print("Fixing SSH auth file...")
    fix_ssh_auth_file()

    print("Fixing dataclass files...")
    fix_dataclass_files()

    print("Fixing API endpoint files...")
    fix_api_endpoints()

    print("Fixing core module files...")
    fix_core_modules()

    print("\nRunning Black formatter check...")
    import subprocess

    result = subprocess.run(
        ["python", "-m", "black", "src/", "--check"], capture_output=True, text=True
    )

    # Count remaining errors
    error_count = result.stderr.count("error: cannot format")
    print(f"\nRemaining Black errors: {error_count}")

    if error_count == 0:
        print("✓ All files can now be formatted by Black!")
        # Run Black to actually format them
        subprocess.run(["python", "-m", "black", "src/"])
        print("✓ Black formatting applied successfully!")
    else:
        print("Some errors remain. Showing first few:")
        errors = [
            line for line in result.stderr.split("\n") if "error: cannot format" in line
        ]
        for error in errors[:5]:
            print(f"  {error}")


if __name__ == "__main__":
    main()
