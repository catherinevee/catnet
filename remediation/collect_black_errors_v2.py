#!/usr/bin/env python3
"""Collect all Black parsing errors and save to JSON - Fixed version."""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List


def collect_black_errors() -> Dict:
    """Run Black and collect all parsing errors."""
    print("Collecting Black formatting errors...")

    # Run Black check from project root
    result = subprocess.run(
        ['python', '-m', 'black', '.', '--check'],
        capture_output=True,
        text=True,
        cwd='..'
    )

    errors = []
    error_files = set()

    # Parse stderr for errors - handle Windows paths
    for line in result.stderr.split('\n'):
        if 'error: cannot format' in line:
            # Extract file path and error details (Windows path friendly)
            # Pattern: "error: cannot format C:\path\to\file.py: error details"
            parts = line.split('error: cannot format', 1)
            if len(parts) == 2:
                # Split by the first colon after the drive letter (if Windows)
                remaining = parts[1].strip()

                # Find the file path and error detail separator
                # Look for ": Cannot parse" or ": unindent"
                file_path = None
                error_detail = None

                if ': Cannot parse:' in remaining:
                    file_path, error_detail = remaining.split(
                        ': Cannot parse:', 1)
                    error_detail = 'Cannot parse:' + error_detail
                elif ': unindent' in remaining:
                    file_path, error_detail = remaining.split(': unindent', 1)
                    error_detail = 'unindent' + error_detail
                else:
                    # Try generic split on last colon
                    parts = remaining.rsplit(':', 1)
                    if len(parts) == 2:
                        file_path = parts[0].strip()
                        error_detail = parts[1].strip()

                if file_path and error_detail:
                    # Clean file path - remove quotes if present
                    file_path = file_path.strip().strip('"').strip("'")

                    # Try to extract line number and position
                    line_match = re.search(
                        r'Cannot parse:\s*(\d+):(\d+):\s*(.+)', error_detail)
                    unindent_match = re.search(
                        r'unindent .* line (\d+)', error_detail)

                    if line_match:
                        errors.append({
                            'file': file_path,
                            'line': int(line_match.group(1)),
                            'column': int(line_match.group(2)),
                            'error': line_match.group(3).strip(),
                            'type': 'parse_error'
                        })
                    elif unindent_match:
                        errors.append({
                            'file': file_path,
                            'line': int(unindent_match.group(1)),
                            'column': 0,
                            'error': 'unindent does not match any outer indentation level',
                            'type': 'indentation_error'
                        })
                    else:
                        errors.append({
                            'file': file_path,
                            'line': 0,
                            'column': 0,
                            'error': error_detail,
                            'type': 'unknown_error'
                        })

                    error_files.add(file_path)

    # Create summary
    summary = {
        'total_errors': len(errors),
        'unique_files': len(error_files),
        'errors': errors,
        'error_files': sorted(list(error_files))
    }

    # Save to JSON
    with open('black_errors_v2.json', 'w') as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print(f"\nBlack Error Summary:")
    print(f"  Total errors: {summary['total_errors']}")
    print(f"  Files with errors: {summary['unique_files']}")

    # Group errors by type
    error_types = {}
    for error in errors:
        error_type = error['type']
        error_types[error_type] = error_types.get(error_type, 0) + 1

    print(f"\nError types:")
    for error_type, count in sorted(
            error_types.items(), key=lambda x: x[1], reverse=True):
        print(f"    {error_type}: {count}")

    return summary


def create_priority_fix_list(black_errors: Dict) -> List[Dict]:
    """Create a prioritized list of files to fix."""
    priority_list = []

    # Priority scoring based on file path
    for file_path in black_errors['error_files']:
        priority_score = 5  # Default lowest priority

        # Normalize path for checking
        path_lower = file_path.lower().replace('\\', '/')

        # Adjust priority based on path
        if 'api' in path_lower and 'auth' in path_lower:
            priority_score = 1
        elif 'auth' in path_lower or 'security' in path_lower:
            priority_score = 1
        elif 'api' in path_lower:
            priority_score = 2
        elif 'core' in path_lower:
            priority_score = 2
        elif 'deployment' in path_lower or 'gitops' in path_lower:
            priority_score = 3
        elif 'cli' in path_lower:
            priority_score = 3
        elif 'test' in path_lower:
            priority_score = 4
        elif 'fix_' in path_lower or 'remediation' in path_lower:
            priority_score = 5

        # Get error count for this file
        error_count = len([e for e in black_errors['errors']
                          if e['file'] == file_path])

        # Get error types for this file
        error_types = set(
            [e['type'] for e in black_errors['errors'] if e['file'] == file_path])

        priority_list.append({
            'file': file_path,
            'priority': priority_score,
            'error_count': error_count,
            'error_types': list(error_types),
            'fix_order': priority_score * 100 + error_count  # Combined score
        })

    # Sort by fix_order
    priority_list.sort(key=lambda x: x['fix_order'])

    # Save priority list
    with open('priority_fix_list_v2.json', 'w') as f:
        json.dump(priority_list, f, indent=2)

    print(f"\nPriority Fix List created:")
    print(f"  Total files to fix: {len(priority_list)}")

    # Show top 10 priority files
    print(f"\nTop 10 priority files:")
    for i, item in enumerate(priority_list[:10], 1):
        print(
            f"  {i}. {
                Path(
                    item['file']).name} (Priority: {
                item['priority']}, Errors: {
                    item['error_count']})")

    return priority_list


if __name__ == '__main__':
    # Collect Black errors
    black_errors = collect_black_errors()

    # Create priority fix list
    if black_errors['error_files']:
        priority_list = create_priority_fix_list(black_errors)

        print("\nAnalysis complete! Check the following files:")
        print("  - black_errors_v2.json: All Black parsing errors")
        print("  - priority_fix_list_v2.json: Prioritized list of files to fix")
    else:
        print("\nNo Black errors found! The codebase is properly formatted.")
