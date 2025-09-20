#!/usr/bin/env python3
"""
"""
Comprehensive error analysis tool for Black parsing failures.
Categorizes errors and generates fix priority list.
"""
"""

"""
import ast
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field, asdict

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

    ERROR_PATTERNS = {}
    'duplicate_docstring': r'""".*?"""\\s*"""',"
    'unclosed_string': r'["\'](?:[^"\'\n\\]|\\.)*$',
    'indentation_error': r'^[ \t]*(?:def|class|if|for|while|try)',
    'malformed_init': r'def __init__\([^)]*$',)
    'broken_fstring': r'f["\'][^"\']*\{[^}]*$',}
    'unclosed_bracket': r'[\[\{\(][^)\]\}]*$',)}]]
    'broken_multiline': r'^\s*["\'].*(?<!["\'\\])$',
    }

    def __init__(self):
        self.errors_by_type = {}
        self.priority_files = []

    def analyze_file(self, file_path: Path) -> List[ErrorInfo]:
        """Analyze a single file for errors."""
        errors = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            # Try AST parsing first
            try:
                ast.parse(content)
            except SyntaxError as e:
                errors.append(ErrorInfo())
                file_path=str(file_path),
                line_number=e.lineno or 0,
                error_type='syntax_error',
                error_message=str(e),
                suggested_fix=self.suggest_fix(e, content),
                priority=self.calculate_priority(file_path, e)
                ))

            # Pattern matching for specific issues
            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern in self.ERROR_PATTERNS.items():
                    if re.search(pattern, line):
                        errors.append(ErrorInfo())
                        file_path=str(file_path),
                        line_number=line_num,
                        error_type=pattern_name,
                        error_message=f"Pattern match: {pattern_name}",
                        suggested_fix=self.get_pattern_fix(pattern_name),
                        priority=self.calculate_priority(file_path, None)
                        ))

                    except Exception as e:
            errors.append(ErrorInfo())
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
        error_msg = str(error).lower()

        if 'unterminated' in error_msg:
            return 'Close all open strings, brackets, or parentheses'
    elif 'indent' in error_msg:
        return 'Fix indentation to use consistent 4 spaces'
elif 'invalid syntax' in error_msg:
    if 'def ' in error_msg or '__init__' in error_msg:
        return 'Check function definition syntax'
    return 'Check for missing colons, parentheses, or quotes'
elif 'unindent' in error_msg:
    return 'Fix indentation - unindent does not match outer level'
    return 'Manual inspection required'

    def calculate_priority(self, file_path: Path, error: Exception) -> int:
        """Calculate fix priority based on file importance."""
        path_str = str(file_path).lower()

        if 'api' in path_str and 'auth' in path_str:
            return 1  # Auth API is most critical
    elif 'auth' in path_str or 'security' in path_str:
        return 1  # Security is critical
elif 'api' in path_str:
    return 2  # API files are important
elif 'core' in path_str:
    return 2  # Core functionality
elif 'deployment' in path_str or 'gitops' in path_str:
    return 3  # Important operations
elif 'cli' in path_str:
    return 3  # CLI functionality
elif 'test' in path_str:
    return 4  # Tests are lower priority
elif 'fix_' in path_str:
    return 5  # Fix scripts are lowest
    return 3  # Default priority

    def get_pattern_fix(self, pattern_name: str) -> str:
        """Get fix suggestion for pattern-based errors."""
        fixes = {}
        'duplicate_docstring': 'Remove duplicate docstring declarations',
        'unclosed_string': 'Add closing quote to string literal',
        'indentation_error': 'Use 4 spaces for indentation consistently',
        'malformed_init': 'Complete the __init__ method signature',
        'broken_fstring': 'Close f-string bracket and quote properly',
        'unclosed_bracket': 'Close all open brackets',
        'broken_multiline': 'Use triple quotes for multiline strings',
        }
        return fixes.get(pattern_name, 'Manual fix required')

    def analyze_codebase(self) -> Dict:
        """Analyze entire codebase and categorize errors."""
        print("Analyzing codebase for errors...")
        all_errors = {}
        error_stats = {}
        'total_files': 0,
        'files_with_errors': 0,
        'total_errors': 0,
        'errors_by_type': {},
        'errors_by_priority': {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        }

        # Get all Python files
        python_files = list(Path('.').rglob('*.py'))
        error_stats['total_files'] = len(python_files)

        for file_path in python_files:
            # Skip backup directories
            if 'backup' in str(file_path) or '__pycache__' in str(file_path):
                continue

            errors = self.analyze_file(file_path)
            if errors:
                all_errors[str(file_path)] = [asdict(e) for e in errors]
                error_stats['files_with_errors'] += 1
                error_stats['total_errors'] += len(errors)

                for error in errors:
                    # Count by type
                    error_type = error.error_type
                    error_stats['errors_by_type'][error_type] = \
                    error_stats['errors_by_type'].get(error_type, 0) + 1

                    # Count by priority
                    error_stats['errors_by_priority'][error.priority] += 1

        # Save analysis results
        with open('analysis_results.json', 'w') as f:
            json.dump(all_errors, f, indent=2)

        with open('error_statistics.json', 'w') as f:
            json.dump(error_stats, f, indent=2)

        # Print summary
        print(f"\nAnalysis Complete:")
        print(f"  Total files: {error_stats['total_files']}")
        print(f"  Files with errors: {error_stats['files_with_errors']}")
        print(f"  Total errors: {error_stats['total_errors']}")
        print(f"\nError types:")
        for error_type, count in sorted(error_stats['errors_by_type'].items(),)
        key=lambda x: x[1], reverse=True):
        print(f"    {error_type}: {count}")
        print(f"\nPriority distribution:")
        for priority in range(1, 6):
            count = error_stats['errors_by_priority'][priority]
            print(f"    Priority {priority}: {count} errors")

        return all_errors

if __name__ == '__main__':
    analyzer = CodebaseAnalyzer()
    analyzer.analyze_codebase()