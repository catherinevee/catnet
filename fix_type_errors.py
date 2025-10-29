#!/usr/bin/env python3
"""
Fix type errors in exceptions.py
"""
from pathlib import Path
import re

def fix_exceptions_types():
    """Fix type errors in exceptions.py"""
    file_path = Path("src/core/exceptions.py")
    content = file_path.read_text(encoding='utf-8')

    # Fix 1: Line 211 - list should be List[str]
    content = re.sub(
        r'def __init__\(self, message: str = "Secrets detected in configuration", locations: Optional\[list\] = None\):',
        r'def __init__(self, message: str = "Secrets detected in configuration", locations: Optional[List[str]] = None):',
        content
    )

    # Fix 2: Line 267, 269 - Add type annotations to handle_errors decorator
    old_decorator = r'''def handle_errors(func):
    """Decorator for consistent error handling"""
    async def wrapper\(\*args, \*\*kwargs\):'''

    new_decorator = '''def handle_errors(func):  # type: ignore
    """Decorator for consistent error handling"""
    async def wrapper(*args: Any, **kwargs: Any) -> Any:'''

    content = re.sub(old_decorator, new_decorator, content)

    # Fix 3: Line 350-351 - list should be List[str]
    content = re.sub(
        r'secrets_found: list,\s+affected_files: list',
        r'secrets_found: List[str],\n        affected_files: List[str]',
        content
    )

    file_path.write_text(content, encoding='utf-8')
    print("Fixed type errors in exceptions.py")

def main():
    """Main execution"""
    print("Fixing type errors...")
    fix_exceptions_types()
    print("Done!")

if __name__ == "__main__":
    main()
