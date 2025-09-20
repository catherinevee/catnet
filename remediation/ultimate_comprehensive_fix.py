#!/usr/bin/env python3
"""
Ultimate comprehensive fix for all Black parsing errors.
Uses AST parsing, tokenization, and intelligent pattern matching.
"""

import ast
import re
import json
import tokenize
import io
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import subprocess


class ComprehensiveFixer:
    """Comprehensive Python code fixer for Black compatibility."""

    def __init__(self):
        self.error_patterns = self.load_error_patterns()
        self.fixes_applied = {}
        self.error_stats = {}

    def load_error_patterns(self) -> Dict:
        """Load error patterns from Black errors analysis."""
        patterns = {
            "unclosed_docstring": {
                "patterns": [
                    (r'^"""([^"]*?)$', r'"""\1\n"""'),
                    (r"^'''([^']*?)$", r"'''\1\n'''"),
                    (r'^"""([^"]*?)\n(from|import)', r'"""\1\n"""\n\2'),
                ],
                "multiline": True,
            },
            "duplicate_docstring": {
                "patterns": [
                    (r'(class\s+\w+.*?:\n\s+""".*?""")\s*\n\s*""".*?"""', r"\1"),
                    (r'(def\s+\w+.*?:\n\s+""".*?""")\s*\n\s*""".*?"""', r"\1"),
                ],
                "multiline": True,
            },
            "broken_fstring": {
                "patterns": [
                    (r'f"([^"]*?)\{([^}]*?)$', r'f"\1{\2}"'),
                    (r'f"([^"]*?)$', r'f"\1"'),
                    (r"f'([^']*?)$", r"f'\1'"),
                ],
                "multiline": False,
            },
            "unclosed_bracket": {
                "patterns": [
                    (r"(\([^)]*?)$", r"\1)"),
                    (r"(\[[^\]]*?)$", r"\1]"),
                    (r"(\{[^}]*?)$", r"\1}"),
                ],
                "multiline": False,
            },
            "broken_string_concat": {
                "patterns": [
                    (r'"([^"]*?)"\s*\\\s*\n\s*f"', r'"\1" \\\n    f"'),
                    (r'"([^"]*?)"\s+f"', r'"\1" f"'),
                ],
                "multiline": True,
            },
        }
        return patterns

    def analyze_syntax_error(self, filepath: Path) -> Optional[Dict]:
        """Analyze syntax errors in a file using AST."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            # Try to parse with AST
            try:
                ast.parse(content)
                return None  # No syntax errors
            except SyntaxError as e:
                return {
                    "line": e.lineno,
                    "offset": e.offset,
                    "msg": e.msg,
                    "text": e.text,
                }
        except Exception:
            return None

    def tokenize_safely(self, content: str) -> List:
        """Safely tokenize Python code."""
        tokens = []
        try:
            readline = io.StringIO(content).readline
            tokens = list(tokenize.generate_tokens(readline))
        except tokenize.TokenError:
            # Return partial tokens if tokenization fails
            pass
        return tokens

    def fix_by_line_analysis(self, content: str) -> str:
        """Fix issues by analyzing each line."""
        lines = content.split("\n")
        fixed_lines = []

        # State tracking
        in_class = False
        in_function = False
        in_docstring = False
        in_multiline_string = False
        docstring_quote = None
        bracket_stack = []
        current_indent = 0

        for i, line in enumerate(lines):
            original_line = line

            # Track indentation
            if line.strip():
                current_indent = len(line) - len(line.lstrip())

            # Fix tabs
            if "\t" in line:
                line = line.replace("\t", "    ")

            # Check for class definition
            class_match = re.match(r"^(\s*)class\s+(\w+)", line)
            if class_match:
                in_class = True
                in_function = False
                current_indent = len(class_match.group(1))

            # Check for function definition
            func_match = re.match(r"^(\s*)(async\s+)?def\s+(\w+)", line)
            if func_match:
                in_function = True
                current_indent = len(func_match.group(1))

            # Handle docstrings
            if not in_docstring:
                # Check for docstring start
                if '"""' in line:
                    count = line.count('"""')
                    if count == 1:
                        in_docstring = True
                        docstring_quote = '"""'
                    elif (
                        count == 2
                        and not line.strip().startswith('"""')
                        and not line.strip().endswith('"""')
                    ):
                        # Malformed docstring on same line
                        line = re.sub(
                            r':\s*"""(.*?)"""',
                            r":\n" + " " * (current_indent + 4) + r'"""\1"""',
                            line,
                        )
                elif "'''" in line:
                    count = line.count("'''")
                    if count == 1:
                        in_docstring = True
                        docstring_quote = "'''"
            else:
                # In docstring, check for end
                if docstring_quote in line:
                    in_docstring = False
                    docstring_quote = None

            # Fix unclosed strings (not in docstrings)
            if not in_docstring and not line.strip().startswith("#"):
                # Count quotes
                single_quotes = len([c for c in re.finditer(r"(?<!\\)'", line)])
                double_quotes = len([c for c in re.finditer(r'(?<!\\)"', line)])

                # Fix unclosed quotes
                if single_quotes % 2 != 0 and not line.rstrip().endswith("'"):
                    line = line.rstrip() + "'"
                elif double_quotes % 2 != 0 and not line.rstrip().endswith('"'):
                    line = line.rstrip() + '"'

            # Track brackets
            for char in line:
                if char in "([{":
                    bracket_stack.append(char)
                elif char in ")]}":
                    if bracket_stack:
                        opening = bracket_stack[-1]
                        if (
                            (char == ")" and opening == "(")
                            or (char == "]" and opening == "[")
                            or (char == "}" and opening == "{")
                        ):
                            bracket_stack.pop()

            # Fix unclosed brackets at end of line
            if bracket_stack and i < len(lines) - 1:
                next_line = lines[i + 1] if i + 1 < len(lines) else ""
                if next_line and not next_line.lstrip().startswith(
                    (",", ")", "]", "}")
                ):
                    # Add closing brackets
                    closing = ""
                    temp_stack = bracket_stack.copy()
                    while temp_stack:
                        bracket = temp_stack.pop()
                        if bracket == "(":
                            closing += ")"
                        elif bracket == "[":
                            closing += "]"
                        elif bracket == "{":
                            closing += "}"

                    if closing and not line.rstrip().endswith(closing):
                        line = line.rstrip() + closing
                        bracket_stack = []

            fixed_lines.append(line)

        # Close any unclosed docstring at end of file
        if in_docstring and docstring_quote:
            fixed_lines.append(docstring_quote)

        return "\n".join(fixed_lines)

    def fix_with_regex_patterns(self, content: str) -> str:
        """Apply regex pattern fixes."""
        for category, info in self.error_patterns.items():
            for pattern, replacement in info["patterns"]:
                if info["multiline"]:
                    content = re.sub(
                        pattern, replacement, content, flags=re.MULTILINE | re.DOTALL
                    )
                else:
                    content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

        return content

    def fix_indentation_comprehensively(self, content: str) -> str:
        """Fix all indentation issues comprehensively."""
        lines = content.split("\n")
        fixed_lines = []
        indent_stack = [0]

        for i, line in enumerate(lines):
            if not line.strip():
                fixed_lines.append(line)
                continue

            # Get current indentation
            current_indent = len(line) - len(line.lstrip())
            stripped = line.lstrip()

            # Determine expected indentation
            expected_indent = indent_stack[-1]

            # Check if line opens a new block
            opens_block = any(
                stripped.startswith(keyword) and line.rstrip().endswith(":")
                for keyword in [
                    "def ",
                    "async def ",
                    "class ",
                    "if ",
                    "elif ",
                    "else:",
                    "for ",
                    "while ",
                    "try:",
                    "except",
                    "finally:",
                    "with ",
                ]
            )

            # Check if line closes a block
            closes_block = any(
                stripped.startswith(keyword)
                for keyword in ["return", "break", "continue", "pass", "raise"]
            )

            # Adjust indentation
            if stripped.startswith(("elif ", "else:", "except", "finally:")):
                # These should be at the same level as their opening statement
                if indent_stack:
                    indent_stack.pop()
                    expected_indent = indent_stack[-1] if indent_stack else 0
            elif current_indent < expected_indent:
                # Dedenting
                while indent_stack and indent_stack[-1] > current_indent:
                    indent_stack.pop()
                expected_indent = indent_stack[-1] if indent_stack else 0

            # Apply the expected indentation
            fixed_line = " " * expected_indent + stripped
            fixed_lines.append(fixed_line)

            # Update indent stack for next line
            if opens_block:
                indent_stack.append(expected_indent + 4)
            elif closes_block and len(indent_stack) > 1:
                indent_stack.pop()

        return "\n".join(fixed_lines)

    def process_file(self, filepath: Path) -> bool:
        """Process a single file with comprehensive fixes."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            original = content

            # Phase 1: Line-by-line analysis and fixing
            content = self.fix_by_line_analysis(content)

            # Phase 2: Regex pattern fixes
            content = self.fix_with_regex_patterns(content)

            # Phase 3: Comprehensive indentation fix
            content = self.fix_indentation_comprehensively(content)

            # Phase 4: Final cleanup
            # Remove trailing whitespace
            lines = content.split("\n")
            lines = [line.rstrip() for line in lines]
            content = "\n".join(lines)

            # Remove excessive blank lines
            content = re.sub(r"\n{4,}", "\n\n\n", content)

            if content != original:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                return True

        except Exception as e:
            print(f"  Error processing {filepath.name}: {e}")

        return False

    def verify_file(self, filepath: Path) -> bool:
        """Verify a file can be parsed by Black."""
        try:
            result = subprocess.run(
                ["python", "-m", "black", str(filepath), "--check"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "error: cannot format" not in result.stderr
        except Exception:
            return False

    def run(self):
        """Run comprehensive fixing on all Python files."""
        print("=" * 80)
        print("ULTIMATE COMPREHENSIVE PYTHON FIXER")
        print("=" * 80)

        # Load error file list if available
        error_files = []
        if Path("remediation/black_errors_v2.json").exists():
            with open("remediation/black_errors_v2.json", "r") as f:
                data = json.load(f)
                error_files = [Path(f) for f in data.get("error_files", [])]

        if not error_files:
            # Get all Python files if no error list
            error_files = list(Path(".").rglob("*.py"))
            error_files = [
                f
                for f in error_files
                if "remediation" not in str(f) and "backup" not in str(f)
            ]

        print(f"\nProcessing {len(error_files)} files with errors...")
        print("-" * 80)

        fixed_count = 0
        verified_count = 0

        for i, filepath in enumerate(error_files, 1):
            if not filepath.exists():
                continue

            print(f"[{i}/{len(error_files)}] Processing: {filepath.name}...", end=" ")

            if self.process_file(filepath):
                fixed_count += 1
                # Verify the fix worked
                if self.verify_file(filepath):
                    verified_count += 1
                    print("✓ FIXED & VERIFIED")
                else:
                    print("✓ FIXED (needs more work)")
            else:
                print("- no changes needed")

        print("-" * 80)
        print(f"\nResults:")
        print(f"  Files processed: {len(error_files)}")
        print(f"  Files fixed: {fixed_count}")
        print(f"  Files verified: {verified_count}")

        # Final Black check
        print("\nRunning final Black check...")
        result = subprocess.run(
            ["python", "-m", "black", ".", "--check"], capture_output=True, text=True
        )

        final_errors = result.stderr.count("error: cannot format")
        print(f"  Remaining Black errors: {final_errors}")

        if final_errors == 0:
            print("\n✅ SUCCESS! All Black errors resolved!")
        else:
            print(f"\n⚠️  {final_errors} errors remain. Manual intervention needed.")

        print("=" * 80)


if __name__ == "__main__":
    fixer = ComprehensiveFixer()
    fixer.run()
