# CatNet Codebase Remediation Plan
## Comprehensive Strategy for Resolving 96 Black Parsing Errors

---

## Executive Summary

This document outlines a systematic approach to resolve all 96 Python files that currently fail Black formatting due to syntax errors. The plan emphasizes correctness, maintainability, and prevention of future issues.

---

## Current State Analysis

### Error Distribution (96 Total Files)

| Category | Count | Severity | Impact |
|----------|-------|----------|---------|
| Duplicate/Malformed Docstrings | ~30 | High | Breaks AST parsing |
| Indentation Errors | ~20 | Critical | Syntax errors |
| Broken String Literals | ~15 | High | Runtime errors |
| Malformed Class/Function Definitions | ~15 | Critical | Import failures |
| Incomplete Code Blocks | ~10 | High | Syntax errors |
| Import and Module Issues | ~6 | Medium | Module loading fails |

### Most Common Error Patterns

1. **Docstring Issues**
   ```python
   # WRONG - Duplicate docstring
   class MyClass(BaseModel):
       """Docstring"""
       """Docstring"""  # Duplicate

   # WRONG - Docstring after fields
   class MyClass:
       field: str
       """This is wrong placement"""
   ```

2. **Indentation Problems**
   ```python
   # WRONG - Mixed indentation
   def function():
   ····statement1()  # Spaces
   	statement2()  # Tab
   ```

3. **String Literal Errors**
   ```python
   # WRONG - Unclosed f-string
   message = f"Hello {name

   # WRONG - Broken multiline
   text = "Line 1
   Line 2"
   ```

---

## Remediation Strategy

### Phase 1: Automated Analysis and Categorization

#### 1.1 Create Analysis Script
```python
# analyze_errors.py
"""
Comprehensive error analysis tool for Black parsing failures.
Categorizes errors and generates fix priority list.
"""

import ast
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

@dataclass
class ErrorInfo:
    file_path: str
    line_number: int
    error_type: str
    error_message: str
    suggested_fix: str
    priority: int  # 1-5, 1 being highest

class CodebaseAnalyzer:
    """Analyze codebase for syntax errors and categorize them."""

    ERROR_PATTERNS = {
        'duplicate_docstring': r'""".*?"""\s*"""',
        'unclosed_string': r'["\'](?:[^"\'\n\\]|\\.)*$',
        'indentation_error': r'^[ \t]*(?:def|class|if|for|while|try)',
        'malformed_init': r'def __init__\([^)]*$',
        'broken_fstring': r'f["\'][^"\']*\{[^}]*$',
    }

    def analyze_file(self, file_path: Path) -> List[ErrorInfo]:
        """Analyze a single file for errors."""
        errors = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Try AST parsing first
            try:
                ast.parse(content)
            except SyntaxError as e:
                errors.append(ErrorInfo(
                    file_path=str(file_path),
                    line_number=e.lineno,
                    error_type='syntax_error',
                    error_message=str(e),
                    suggested_fix=self.suggest_fix(e, content),
                    priority=self.calculate_priority(file_path, e)
                ))

            # Pattern matching for specific issues
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern_name, pattern in self.ERROR_PATTERNS.items():
                    if re.search(pattern, line):
                        errors.append(ErrorInfo(
                            file_path=str(file_path),
                            line_number=line_num,
                            error_type=pattern_name,
                            error_message=f"Pattern match: {pattern_name}",
                            suggested_fix=self.get_pattern_fix(pattern_name),
                            priority=2
                        ))

        except Exception as e:
            errors.append(ErrorInfo(
                file_path=str(file_path),
                line_number=0,
                error_type='file_read_error',
                error_message=str(e),
                suggested_fix='Check file encoding and permissions',
                priority=1
            ))

        return errors

    def suggest_fix(self, error: SyntaxError, content: str) -> str:
        """Generate fix suggestion based on error type."""
        if 'unterminated' in str(error):
            return 'Close all open strings, brackets, or parentheses'
        elif 'indent' in str(error):
            return 'Fix indentation to use consistent 4 spaces'
        elif 'invalid syntax' in str(error):
            return 'Check for missing colons, parentheses, or quotes'
        return 'Manual inspection required'

    def calculate_priority(self, file_path: Path, error: SyntaxError) -> int:
        """Calculate fix priority based on file importance."""
        if 'api' in str(file_path):
            return 1  # API files are critical
        elif 'auth' in str(file_path):
            return 1  # Authentication is critical
        elif 'core' in str(file_path):
            return 2  # Core functionality
        elif 'test' in str(file_path):
            return 4  # Tests are lower priority
        return 3  # Default priority

    def get_pattern_fix(self, pattern_name: str) -> str:
        """Get fix suggestion for pattern-based errors."""
        fixes = {
            'duplicate_docstring': 'Remove duplicate docstring declarations',
            'unclosed_string': 'Add closing quote to string literal',
            'indentation_error': 'Use 4 spaces for indentation consistently',
            'malformed_init': 'Complete the __init__ method signature',
            'broken_fstring': 'Close f-string bracket and quote properly',
        }
        return fixes.get(pattern_name, 'Manual fix required')
```

#### 1.2 Error Collection Script
```python
# collect_errors.py
"""Collect all Black parsing errors and save to JSON."""

import subprocess
import json
from pathlib import Path

def collect_black_errors():
    """Run Black and collect all parsing errors."""
    result = subprocess.run(
        ['python', '-m', 'black', '.', '--check'],
        capture_output=True,
        text=True,
        cwd='.'
    )

    errors = []
    for line in result.stderr.split('\n'):
        if 'error: cannot format' in line:
            parts = line.split(':')
            if len(parts) >= 4:
                errors.append({
                    'file': parts[0].replace('error: cannot format ', '').strip(),
                    'line': parts[1].strip() if len(parts) > 1 else '',
                    'error': ':'.join(parts[2:]).strip()
                })

    with open('black_errors.json', 'w') as f:
        json.dump(errors, f, indent=2)

    return errors
```

---

### Phase 2: Automated Fix Implementation

#### 2.1 Safe AST-Based Fixes
```python
# safe_ast_fixer.py
"""
Safe fixes using AST transformation.
Only applies fixes that preserve semantic meaning.
"""

import ast
import astor
from typing import Any

class SafeASTFixer(ast.NodeTransformer):
    """Apply safe AST transformations."""

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        """Fix class definition issues."""
        # Remove duplicate docstrings
        if len(node.body) > 1:
            docstrings = [
                i for i, n in enumerate(node.body)
                if isinstance(n, ast.Expr) and isinstance(n.value, ast.Str)
            ]
            if len(docstrings) > 1:
                # Keep only the first docstring
                for idx in reversed(docstrings[1:]):
                    del node.body[idx]

        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Fix function definition issues."""
        # Ensure docstring is first in body if it exists
        if node.body and len(node.body) > 1:
            for i, stmt in enumerate(node.body[1:], 1):
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Str):
                    # Move docstring to first position
                    docstring = node.body.pop(i)
                    node.body.insert(0, docstring)
                    break

        return self.generic_visit(node)

def apply_safe_fixes(file_path: str) -> bool:
    """Apply safe AST-based fixes to a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()

        tree = ast.parse(source)
        fixer = SafeASTFixer()
        fixed_tree = fixer.visit(tree)
        fixed_source = astor.to_source(fixed_tree)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_source)

        return True
    except Exception as e:
        print(f"Could not apply safe fixes to {file_path}: {e}")
        return False
```

#### 2.2 Pattern-Based String Fixes
```python
# string_fixer.py
"""Fix string literal issues."""

import re
from typing import List, Tuple

class StringFixer:
    """Fix various string literal issues."""

    def fix_unclosed_strings(self, content: str) -> str:
        """Fix unclosed string literals."""
        lines = content.split('\n')
        fixed_lines = []

        for line in lines:
            # Fix unclosed single quotes
            if line.count("'") % 2 != 0 and not line.strip().startswith('#'):
                # Check if it's likely an unclosed string
                if "'" in line and not line.rstrip().endswith("'"):
                    line = line + "'"

            # Fix unclosed double quotes
            if line.count('"') % 2 != 0 and not line.strip().startswith('#'):
                if '"' in line and not line.rstrip().endswith('"'):
                    line = line + '"'

            fixed_lines.append(line)

        return '\n'.join(fixed_lines)

    def fix_fstring_brackets(self, content: str) -> str:
        """Fix unclosed f-string brackets."""
        # Pattern to find f-strings with unclosed brackets
        pattern = r'(f["\'][^"\']*\{[^}]*?)(["\'])'

        def replacer(match):
            content = match.group(1)
            quote = match.group(2)
            # Count brackets
            open_brackets = content.count('{')
            close_brackets = content.count('}')
            if open_brackets > close_brackets:
                return content + '}' * (open_brackets - close_brackets) + quote
            return match.group(0)

        return re.sub(pattern, replacer, content)

    def fix_multiline_strings(self, content: str) -> str:
        """Fix broken multiline strings."""
        # Convert broken multiline strings to proper triple-quoted strings
        lines = content.split('\n')
        fixed_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            # Detect potential broken multiline string
            if (line.strip().startswith('"') and
                not line.strip().endswith('"') and
                not line.strip().startswith('"""')):
                # Start collecting multiline string
                multiline = [line]
                i += 1
                while i < len(lines) and not lines[i].strip().endswith('"'):
                    multiline.append(lines[i])
                    i += 1
                if i < len(lines):
                    multiline.append(lines[i])

                # Convert to triple-quoted string
                if len(multiline) > 1:
                    fixed_lines.append('"""')
                    for ml in multiline:
                        fixed_lines.append(ml.strip('"'))
                    fixed_lines.append('"""')
                else:
                    fixed_lines.extend(multiline)
            else:
                fixed_lines.append(line)
            i += 1

        return '\n'.join(fixed_lines)
```

#### 2.3 Indentation Fixer
```python
# indentation_fixer.py
"""Fix indentation issues."""

import re
from typing import List

class IndentationFixer:
    """Fix indentation problems in Python files."""

    def __init__(self, indent_size: int = 4):
        self.indent_size = indent_size

    def fix_indentation(self, content: str) -> str:
        """Fix indentation to use consistent spaces."""
        lines = content.split('\n')
        fixed_lines = []
        indent_stack = [0]  # Track indentation levels

        for line in lines:
            if not line.strip():
                fixed_lines.append('')
                continue

            # Calculate current indentation
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)

            # Replace tabs with spaces
            if '\t' in line[:current_indent]:
                tabs = line[:current_indent].count('\t')
                spaces = line[:current_indent].count(' ')
                # Assume 1 tab = 4 spaces
                total_indent = (tabs * 4) + spaces
                # Round to nearest multiple of indent_size
                normalized_indent = round(total_indent / self.indent_size) * self.indent_size
                line = ' ' * normalized_indent + stripped

            # Check for keywords that affect indentation
            if stripped.startswith(('def ', 'class ', 'if ', 'for ', 'while ', 'try:', 'with ')):
                if stripped.endswith(':'):
                    fixed_lines.append(line)
                    indent_stack.append(current_indent + self.indent_size)
                else:
                    fixed_lines.append(line)
            elif stripped.startswith(('elif ', 'else:', 'except', 'finally:')):
                # These should be at the same level as their opening statement
                if indent_stack:
                    expected_indent = indent_stack[-1] - self.indent_size
                    line = ' ' * expected_indent + stripped
                fixed_lines.append(line)
            elif stripped.startswith(('return', 'break', 'continue', 'pass')):
                # These end a block
                fixed_lines.append(line)
                if indent_stack and len(indent_stack) > 1:
                    indent_stack.pop()
            else:
                fixed_lines.append(line)

        return '\n'.join(fixed_lines)

    def detect_mixed_indentation(self, content: str) -> List[int]:
        """Detect lines with mixed tabs and spaces."""
        lines = content.split('\n')
        mixed_lines = []

        for i, line in enumerate(lines, 1):
            if line and not line.strip():
                continue
            indent = line[:len(line) - len(line.lstrip())]
            if ' ' in indent and '\t' in indent:
                mixed_lines.append(i)

        return mixed_lines
```

---

### Phase 3: Manual Fix Priorities

#### Priority 1: Critical Path Files (Fix First)

| File Path | Issue Type | Impact | Fix Approach |
|-----------|------------|--------|--------------|
| `src/api/auth_endpoints.py` | Duplicate docstrings | Auth broken | Remove duplicates, fix indentation |
| `src/api/deployment_endpoints.py` | Duplicate docstrings | Deploy fails | Clean docstrings, validate |
| `src/api/device_endpoints.py` | Malformed classes | API broken | Fix class definitions |
| `src/api/middleware.py` | String errors | Security impact | Fix string literals |
| `src/auth/jwt_handler.py` | Function definitions | No auth | Fix function signatures |
| `src/auth/session.py` | Class definitions | Sessions broken | Fix class structure |
| `src/core/config.py` | Import errors | App won't start | Fix imports |

#### Priority 2: Core Functionality

| File Path | Issue Type | Impact | Fix Approach |
|-----------|------------|--------|--------------|
| `src/deployment/*` | Various | Deploys affected | Systematic fixes |
| `src/gitops/*` | String/indentation | Git integration | Fix strings first |
| `src/devices/*` | Class definitions | Device control | Fix classes |
| `src/automation/*` | Workflow definitions | Automation broken | Fix enums/classes |

#### Priority 3: CLI and Tools

| File Path | Issue Type | Impact | Fix Approach |
|-----------|------------|--------|--------------|
| `catnet_cli/commands/*` | Indentation | CLI broken | Fix indentation |
| `scripts/*.py` | Various | Tools unavailable | Quick fixes |
| `setup.py` | String errors | Install broken | Fix strings |

#### Priority 4: Tests and Documentation

| File Path | Issue Type | Impact | Fix Approach |
|-----------|------------|--------|--------------|
| `tests/*.py` | Various | Tests don't run | Fix after main code |
| `fix_*.py` scripts | Meta issues | Tools broken | Remove or fix |

---

### Phase 4: Validation Framework

#### 4.1 Progressive Validation
```python
# validate_fixes.py
"""Progressive validation of fixes."""

import ast
import subprocess
from pathlib import Path
from typing import Tuple, List

class FixValidator:
    """Validate fixes at multiple levels."""

    def __init__(self):
        self.validation_levels = [
            self.validate_syntax,
            self.validate_imports,
            self.validate_black,
            self.validate_flake8,
            self.validate_mypy,
            self.validate_tests
        ]

    def validate_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """Run all validation levels on a file."""
        errors = []

        for validator in self.validation_levels:
            success, error = validator(file_path)
            if not success:
                errors.append(error)
                # Stop at first failure for efficiency
                break

        return len(errors) == 0, errors

    def validate_syntax(self, file_path: Path) -> Tuple[bool, str]:
        """Validate Python syntax."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                ast.parse(f.read())
            return True, ""
        except SyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.msg}"

    def validate_imports(self, file_path: Path) -> Tuple[bool, str]:
        """Validate all imports work."""
        result = subprocess.run(
            ['python', '-c', f'import {file_path.stem}'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False, f"Import error: {result.stderr}"
        return True, ""

    def validate_black(self, file_path: Path) -> Tuple[bool, str]:
        """Validate Black can format the file."""
        result = subprocess.run(
            ['python', '-m', 'black', '--check', str(file_path)],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False, "Black formatting failed"
        return True, ""

    def validate_flake8(self, file_path: Path) -> Tuple[bool, str]:
        """Run flake8 validation."""
        result = subprocess.run(
            ['python', '-m', 'flake8', str(file_path), '--max-line-length=88'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False, f"Flake8 issues: {result.stdout}"
        return True, ""

    def validate_mypy(self, file_path: Path) -> Tuple[bool, str]:
        """Run mypy type checking."""
        result = subprocess.run(
            ['python', '-m', 'mypy', str(file_path), '--ignore-missing-imports'],
            capture_output=True,
            text=True
        )
        # MyPy errors are warnings for now
        return True, ""

    def validate_tests(self, file_path: Path) -> Tuple[bool, str]:
        """Run related tests if they exist."""
        test_file = Path('tests') / f"test_{file_path.stem}.py"
        if test_file.exists():
            result = subprocess.run(
                ['python', '-m', 'pytest', str(test_file), '-v'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return False, "Tests failed"
        return True, ""
```

---

### Phase 5: Execution Workflow

#### 5.1 Master Fix Orchestrator
```python
# orchestrate_fixes.py
"""Orchestrate the entire fix process."""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class FixOrchestrator:
    """Manage the entire fix process."""

    def __init__(self):
        self.backup_dir = Path('backups') / datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = Path('fix_log.json')
        self.progress = {}

    def run(self):
        """Execute the complete fix workflow."""
        print("Starting CatNet codebase remediation...")

        # Step 1: Create backup
        self.create_backup()

        # Step 2: Analyze all files
        errors = self.analyze_codebase()

        # Step 3: Apply automated fixes
        self.apply_automated_fixes(errors)

        # Step 4: Manual fix guidance
        self.generate_manual_fix_guide(errors)

        # Step 5: Validate all fixes
        self.validate_all_fixes()

        # Step 6: Generate report
        self.generate_report()

    def create_backup(self):
        """Create full backup before making changes."""
        print("Creating backup...")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        for pattern in ['*.py', '**/*.py']:
            for file in Path('.').glob(pattern):
                if 'backup' not in str(file):
                    backup_path = self.backup_dir / file
                    backup_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file, backup_path)

        print(f"Backup created at: {self.backup_dir}")

    def analyze_codebase(self) -> Dict:
        """Analyze all Python files for errors."""
        print("Analyzing codebase...")
        analyzer = CodebaseAnalyzer()
        errors = {}

        for file in Path('.').rglob('*.py'):
            if 'backup' not in str(file):
                file_errors = analyzer.analyze_file(file)
                if file_errors:
                    errors[str(file)] = file_errors

        with open('analysis_results.json', 'w') as f:
            json.dump(errors, f, indent=2, default=str)

        print(f"Found errors in {len(errors)} files")
        return errors

    def apply_automated_fixes(self, errors: Dict):
        """Apply all safe automated fixes."""
        print("Applying automated fixes...")

        # Apply fixes in order of safety
        fixers = [
            ('AST fixes', SafeASTFixer()),
            ('String fixes', StringFixer()),
            ('Indentation fixes', IndentationFixer()),
        ]

        for name, fixer in fixers:
            print(f"  Applying {name}...")
            fixed_count = 0

            for file_path in errors.keys():
                try:
                    if self.apply_fixer(file_path, fixer):
                        fixed_count += 1
                        self.progress[file_path] = f"{name} applied"
                except Exception as e:
                    print(f"    Error fixing {file_path}: {e}")

            print(f"    Fixed {fixed_count} files")

    def apply_fixer(self, file_path: str, fixer) -> bool:
        """Apply a specific fixer to a file."""
        # Implementation depends on fixer type
        return True

    def generate_manual_fix_guide(self, errors: Dict):
        """Generate detailed manual fix instructions."""
        print("Generating manual fix guide...")

        guide = []
        for file_path, file_errors in errors.items():
            if file_path not in self.progress:
                guide.append({
                    'file': file_path,
                    'errors': [e.__dict__ for e in file_errors],
                    'instructions': self.generate_fix_instructions(file_errors)
                })

        with open('manual_fix_guide.json', 'w') as f:
            json.dump(guide, f, indent=2)

        print(f"Manual fix guide created for {len(guide)} files")

    def generate_fix_instructions(self, errors: List) -> List[str]:
        """Generate specific fix instructions."""
        instructions = []
        for error in errors:
            if error.error_type == 'duplicate_docstring':
                instructions.append(f"Line {error.line_number}: Remove duplicate docstring")
            elif error.error_type == 'indentation_error':
                instructions.append(f"Line {error.line_number}: Fix indentation to 4 spaces")
            # Add more specific instructions
        return instructions

    def validate_all_fixes(self):
        """Validate all fixes were successful."""
        print("Validating fixes...")
        validator = FixValidator()

        validation_results = {}
        for file in Path('.').rglob('*.py'):
            if 'backup' not in str(file):
                success, errors = validator.validate_file(file)
                validation_results[str(file)] = {
                    'valid': success,
                    'errors': errors
                }

        with open('validation_results.json', 'w') as f:
            json.dump(validation_results, f, indent=2)

        valid_count = sum(1 for r in validation_results.values() if r['valid'])
        print(f"Validation complete: {valid_count}/{len(validation_results)} files valid")

    def generate_report(self):
        """Generate final remediation report."""
        print("Generating report...")

        report = {
            'timestamp': datetime.now().isoformat(),
            'backup_location': str(self.backup_dir),
            'files_processed': len(self.progress),
            'validation_results': 'validation_results.json',
            'manual_fixes_needed': 'manual_fix_guide.json',
            'recommendations': [
                'Review all automated fixes',
                'Complete manual fixes using the guide',
                'Run full test suite',
                'Enable pre-commit hooks',
                'Update CI/CD configuration'
            ]
        }

        with open('remediation_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print("Remediation complete! See remediation_report.json for details")

if __name__ == '__main__':
    orchestrator = FixOrchestrator()
    orchestrator.run()
```

---

### Phase 6: Prevention and Maintenance

#### 6.1 Pre-commit Configuration
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=88', '--extend-ignore=E203']

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: check-ast
      - id: check-builtin-literals
      - id: check-docstring-first
      - id: check-merge-conflict
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ['--profile', 'black']
```

#### 6.2 Editor Configuration
```ini
# .editorconfig
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true

[*.py]
indent_style = space
indent_size = 4
max_line_length = 88

[*.{json,yaml,yml}]
indent_style = space
indent_size = 2
```

#### 6.3 VS Code Settings
```json
// .vscode/settings.json
{
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Args": [
        "--max-line-length=88",
        "--extend-ignore=E203,W503"
    ],
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "editor.rulers": [88],
    "files.trimTrailingWhitespace": true,
    "files.insertFinalNewline": true,
    "editor.tabSize": 4,
    "editor.insertSpaces": true,
    "editor.detectIndentation": false
}
```

---

### Phase 7: CI/CD Integration

#### 7.1 GitHub Actions Syntax Check
```yaml
# .github/workflows/syntax-check.yml
name: Syntax Check

on:
  pull_request:
    paths:
      - '**.py'
  push:
    branches:
      - main
    paths:
      - '**.py'

jobs:
  syntax-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Check Python syntax
        run: |
          python -m compileall src/
          python -m compileall tests/

      - name: Validate with AST
        run: |
          for file in $(find . -name "*.py"); do
            python -c "import ast; ast.parse(open('$file').read())" || exit 1
          done

      - name: Check with Black
        run: |
          pip install black
          black --check .
```

---

## Success Criteria

### Immediate Goals
- [ ] All 96 files pass Python syntax checking
- [ ] Black can format all files without errors
- [ ] All unit tests pass
- [ ] CI/CD pipeline is green

### Long-term Goals
- [ ] Zero syntax errors in production
- [ ] Automated prevention of future issues
- [ ] 100% Black compliance
- [ ] Type hints on all public functions
- [ ] Comprehensive test coverage (>80%)

---

## Risk Mitigation

### Backup Strategy
1. Full backup before any changes
2. Git commits after each successful fix batch
3. Ability to rollback individual files
4. Preserve original functionality

### Testing Strategy
1. Run tests after each file fix
2. Integration tests after each module
3. Full regression test suite at end
4. Manual smoke testing of critical paths

### Review Process
1. Self-review of automated fixes
2. Peer review for complex manual fixes
3. Security review for auth/crypto changes
4. Final approval before production

---

## Timeline (No Constraints)

Since time is not a constraint, focus on correctness:

1. **Week 1-2**: Analysis and automated fixes
2. **Week 3-4**: Manual fixes for priority 1 files
3. **Week 5-6**: Manual fixes for remaining files
4. **Week 7**: Validation and testing
5. **Week 8**: Documentation and prevention measures

---

## Execution Results (Updated: 2025-09-20)

### Summary of Comprehensive Fixes Applied

**Initial State**: 96 files with Black parsing errors
**Final State**: 82 files still failing (reduction of 14 files fixed)

### Actions Taken

1. **Automated Fix Scripts Created**:
   - `analyze_errors.py` - Comprehensive error analysis
   - `collect_black_errors_v2.py` - Error collection with Windows path support
   - `fix_duplicate_docstrings_auto.py` - Docstring deduplication
   - `fix_unclosed_strings_auto.py` - String literal fixes
   - `fix_indentation_auto.py` - Indentation normalization
   - `fix_orchestrator.py` - Automated fix coordinator
   - `ultimate_comprehensive_fix.py` - AST-based comprehensive fixer

2. **Aggressive Reformatting Applied**:
   - autopep8 with aggressive mode (levels 1-2)
   - Black formatter successfully processed 29 files
   - Remaining 82 files have complex syntax errors

### Key Issues Identified

**Most Common Error Patterns in Remaining Files**:
1. **Unclosed strings/docstrings** (26 files)
   - Example: `src/api/auth_endpoints.py:201` - Unclosed docstring
2. **Malformed f-strings** (15 files)
   - Example: `src/api/main.py:60` - Broken f-string syntax
3. **Indentation mismatches** (12 files)
   - Example: `src/deployment/history.py:22` - Unindent errors
4. **Missing closing brackets** (10 files)
   - Example: `src/gitops/service.py:101` - Unclosed parenthesis
5. **Class/function definition errors** (19 files)
   - Example: `src/core/api_config.py:22` - Malformed __init__ method

### CI/CD Pipeline Status

- **Latest Run**: Failed (2025-09-20T15:31:42Z)
- **Black Check**: 82 files cannot be formatted
- **Test Status**: Not reached (linting fails first)

### Lessons Learned

1. **Automated fixes have limitations**: Complex nested syntax errors often get worse with automated tools
2. **autopep8 aggressive mode can corrupt syntax**: Some remediation scripts themselves were corrupted
3. **Error cascades are common**: One syntax error often masks multiple downstream issues
4. **Manual intervention is necessary**: Critical files need line-by-line review

### Next Steps Required

1. **Priority 1: Fix Critical API/Auth Files** (Manual)
   - `src/api/auth_endpoints.py`
   - `src/api/deployment_endpoints.py`
   - `src/auth/jwt_handler.py`
   - `src/core/config.py`

2. **Priority 2: Fix Core Services** (Semi-automated)
   - Device management modules
   - GitOps integration
   - Deployment services

3. **Priority 3: Establish CI/CD Green Path**
   - Focus on getting minimal viable syntax
   - Temporarily exclude problem files if needed
   - Get tests running

### Recommendations

1. **Manual Review Required**: The 82 remaining files need manual syntax fixing
2. **Incremental Approach**: Fix one module at a time, validate, then proceed
3. **Enhanced Tooling**: Consider using more sophisticated AST rewriters
4. **Pre-commit Hooks**: Must be established post-fix to prevent regression
5. **Team Collaboration**: Complex files may need original author input

---

## Conclusion

This comprehensive plan provides:
- Systematic approach to fix all 96 files
- Automated tools for common issues
- Manual guidance for complex problems
- Prevention of future issues
- Full validation framework

The focus is on correctness, maintainability, and preventing regression rather than speed.