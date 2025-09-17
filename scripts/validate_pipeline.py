#!/usr/bin/env python3
"""
Validate CatNet can pass CI/CD pipeline
This script checks if the project is ready for CI/CD
"""
import os
import sys
import json
from pathlib import Path


def check_file_exists(filepath, description):
    """Check if a required file exists"""
    if Path(filepath).exists():
        print(f"[PASS] {description}: {filepath}")
        return True
    else:
        print(f"[FAIL] {description} missing: {filepath}")
        return False


def check_directory_exists(dirpath, description):
    """Check if a required directory exists"""
    if Path(dirpath).is_dir():
        print(f"[PASS] {description}: {dirpath}")
        return True
    else:
        print(f"[FAIL] {description} missing: {dirpath}")
        return False


def validate_python_syntax(filepath):
    """Validate Python file syntax"""
    try:
        import py_compile

        py_compile.compile(filepath, doraise=True)
        print(f"[PASS] Valid Python syntax: {filepath}")
        return True
    except py_compile.PyCompileError as e:
        print(f"[FAIL] Syntax error in {filepath}: {e}")
        return False


def check_requirements():
    """Check if requirements.txt is valid"""
    req_file = "requirements.txt"
    if not Path(req_file).exists():
        print(f"[FAIL] {req_file} missing")
        return False

    with open(req_file, "r") as f:
        lines = f.readlines()

    valid_lines = 0
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            valid_lines += 1

    if valid_lines > 0:
        print(f"[PASS] requirements.txt contains {valid_lines} dependencies")
        return True
    else:
        print("[FAIL] requirements.txt is empty")
        return False


def validate_docker_files():
    """Validate Docker configuration"""
    docker_files = {
        "Dockerfile": "Docker container definition",
        "docker-compose.yml": "Docker Compose configuration",
        ".dockerignore": "Docker ignore file (optional)",
    }

    all_valid = True
    for file, desc in docker_files.items():
        if Path(file).exists():
            print(f"[PASS] {desc}: {file}")
        else:
            if "optional" not in desc:
                print(f"[FAIL] {desc} missing: {file}")
                all_valid = False
            else:
                print(f"[INFO] {desc} not found: {file}")

    return all_valid


def validate_github_actions():
    """Validate GitHub Actions workflows"""
    workflow_dir = Path(".github/workflows")

    if not workflow_dir.exists():
        print("[FAIL] GitHub Actions workflow directory missing")
        return False

    workflows = list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))

    if workflows:
        print(f"[PASS] Found {len(workflows)} workflow files")
        for workflow in workflows:
            print(f"  - {workflow.name}")
        return True
    else:
        print("[FAIL] No workflow files found")
        return False


def validate_project_structure():
    """Validate project directory structure"""
    required_dirs = [
        ("src", "Source code directory"),
        ("src/api", "API module"),
        ("src/auth", "Authentication module"),
        ("src/core", "Core module"),
        ("src/db", "Database module"),
        ("src/deployment", "Deployment module"),
        ("src/devices", "Device handlers module"),
        ("src/gitops", "GitOps module"),
        ("src/security", "Security module"),
        ("tests", "Test directory"),
        ("configs", "Configuration directory"),
        ("scripts", "Scripts directory"),
    ]

    all_valid = True
    for dir_path, description in required_dirs:
        if not check_directory_exists(dir_path, description):
            all_valid = False

    return all_valid


def validate_test_files():
    """Validate test configuration"""
    test_files = [
        ("pytest.ini", "Pytest configuration"),
        ("tests/__init__.py", "Tests package init"),
        ("tests/conftest.py", "Pytest fixtures"),
        ("tests/test_security.py", "Security tests"),
    ]

    all_valid = True
    for file_path, description in test_files:
        if not check_file_exists(file_path, description):
            all_valid = False

    return all_valid


def validate_core_modules():
    """Validate core Python modules compile"""
    core_modules = [
        "src/main.py",
        "src/security/encryption.py",
        "src/security/audit.py",
        "src/core/exceptions.py",
        "src/core/validators.py",
    ]

    all_valid = True
    print("\n=== Validating Core Module Syntax ===")
    for module in core_modules:
        if Path(module).exists():
            if not validate_python_syntax(module):
                all_valid = False
        else:
            print(f"[FAIL] Module not found: {module}")
            all_valid = False

    return all_valid


def check_ci_readiness():
    """Main function to check CI/CD readiness"""
    print("=" * 60)
    print("CatNet CI/CD Pipeline Validation")
    print("=" * 60)

    checks = [
        ("Project Structure", validate_project_structure),
        ("Requirements File", check_requirements),
        ("Docker Configuration", validate_docker_files),
        ("GitHub Actions", validate_github_actions),
        ("Test Configuration", validate_test_files),
        ("Core Module Syntax", validate_core_modules),
    ]

    results = {}
    for check_name, check_func in checks:
        print(f"\n=== {check_name} ===")
        results[check_name] = check_func()

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    all_passed = True
    for check_name, passed in results.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {check_name}")
        if not passed:
            all_passed = False

    print("=" * 60)

    if all_passed:
        print("SUCCESS: CatNet is ready for CI/CD pipeline!")
        print("\nNext steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run tests: pytest tests/")
        print("3. Push to GitHub to trigger CI/CD")
        return 0
    else:
        print("FAILURE: CatNet is NOT ready for CI/CD pipeline")
        print("\nFix the issues above and run this validation again.")
        return 1


if __name__ == "__main__":
    sys.exit(check_ci_readiness())
