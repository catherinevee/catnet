#!/usr/bin/env python3
"""
Orchestrator to run all fix scripts in proper order.
Includes validation and rollback capabilities.
"""

import subprocess
import shutil
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class FixOrchestrator:
    """Orchestrate the fixing of Black parsing errors."""

    def __init__(self):
        self.backup_dir = Path('backups')
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.fixes_applied = []
        self.error_count_history = []

    def create_backup(self, files: List[str]) -> Path:
        """Create backup of files before fixing."""
        backup_path = self.backup_dir / self.timestamp
        backup_path.mkdir(exist_ok=True)

        for file_path in files:
            src = Path(file_path)
            if src.exists():
                # Preserve directory structure in backup
                try:
                    rel_path = src.relative_to(Path.cwd())
                except ValueError:
                    # If file is absolute path, use just the filename
                    rel_path = Path(src.name)
                dst = backup_path / rel_path
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        print(f"  [OK] Backup created: {backup_path}")
        return backup_path

    def rollback(self, backup_path: Path, files: List[str]):
        """Rollback files from backup."""
        print("\n[WARNING]  Rolling back changes...")
        for file_path in files:
            src_file = Path(file_path)
            try:
                rel_path = src_file.relative_to(Path.cwd())
            except ValueError:
                # If file is absolute path, use just the filename
                rel_path = Path(src_file.name)
            backup_file = backup_path / rel_path

            if backup_file.exists():
                shutil.copy2(backup_file, src_file)
                print(f"  [OK] Restored: {src_file.name}")

    def count_black_errors(self) -> int:
        """Count current Black errors."""
        result = subprocess.run(
            ['python', '-m', 'black', '.', '--check'],
            capture_output=True,
            text=True,
            cwd='..'
        )
        # Count "error: cannot format" lines
        error_count = result.stderr.count('error: cannot format')
        return error_count

    def run_fix_script(self, script_name: str) -> bool:
        """Run a fix script and return success status."""
        print(f"\n  Running: {script_name}")
        result = subprocess.run(
            ['python', script_name],
            capture_output=True,
            text=True,
            cwd='.'
        )

        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"  [ERROR] Error running {script_name}")
            if result.stderr:
                print(f"    {result.stderr[:200]}")
            return False

    def validate_fixes(self) -> bool:
        """Validate that fixes improved the situation."""
        new_error_count = self.count_black_errors()

        if len(self.error_count_history) > 0:
            prev_count = self.error_count_history[-1]
            if new_error_count <= prev_count:
                print(
                    f"  [OK] Errors reduced: {prev_count} -> {new_error_count}")
                self.error_count_history.append(new_error_count)
                return True
            else:
                print(
                    f"  [ERROR] Errors increased: {prev_count} -> {new_error_count}")
                return False

        self.error_count_history.append(new_error_count)
        return True

    def run_autopep8(self, aggressive_level: int = 1) -> bool:
        """Run autopep8 with specified aggressiveness."""
        print(f"\n  Running autopep8 (aggressive={aggressive_level})")

        cmd = ['autopep8', '--recursive', '--in-place']
        for _ in range(aggressive_level):
            cmd.append('--aggressive')
        cmd.append('..')

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0

    def execute_phase(self, phase: str, scripts: List[str]) -> bool:
        """Execute a phase of fixes."""
        print(f"\n{'=' * 70}")
        print(f"PHASE: {phase}")
        print('=' * 70)

        success = True
        for script in scripts:
            if Path(script).exists():
                if not self.run_fix_script(script):
                    success = False
                    break

                # Validate after each script
                if not self.validate_fixes():
                    print("  [WARNING]  Validation failed, stopping phase")
                    success = False
                    break

                self.fixes_applied.append(script)

        return success

    def run(self):
        """Main orchestration logic."""
        print("\n" + "=" * 70)
        print("BLACK ERROR FIX ORCHESTRATOR")
        print("=" * 70)

        # Initial error count
        initial_errors = self.count_black_errors()
        self.error_count_history.append(initial_errors)
        print(f"\nInitial Black errors: {initial_errors}")

        if initial_errors == 0:
            print("[SUCCESS] No Black errors found!")
            return

        # Load error files for backup
        with open('black_errors_v2.json', 'r') as f:
            error_data = json.load(f)
        error_files = error_data['error_files']

        # Create backup
        print(f"\nCreating backup of {len(error_files)} files...")
        backup_path = self.create_backup(error_files)

        try:
            # Phase 1: Automated fixes
            phase1_scripts = [
                'fix_duplicate_docstrings_auto.py',
                'fix_unclosed_strings_auto.py',
                'fix_indentation_auto.py'
            ]

            if not self.execute_phase("Automated Fixes", phase1_scripts):
                print("\n[WARNING]  Phase 1 failed")

            # Phase 2: Aggressive autopep8
            current_errors = self.count_black_errors()
            if current_errors > 0:
                print(
                    f"\n{current_errors} errors remaining. Applying autopep8...")

                # Try different levels of aggressiveness
                for level in [1, 2]:
                    if self.run_autopep8(level):
                        new_count = self.count_black_errors()
                        if new_count < current_errors:
                            print(
                                f"  [OK] autopep8 level {level} reduced errors: {current_errors} -> {new_count}")
                            current_errors = new_count
                            self.error_count_history.append(new_count)

                            if new_count == 0:
                                break

            # Phase 3: Re-run Black to format what we can
            if current_errors > 0:
                print(
                    f"\n{current_errors} errors remaining. Running Black formatter...")
                subprocess.run(
                    ['python', '-m', 'black', '..', '--extend-exclude', 'remediation'],
                    capture_output=True,
                    text=True
                )

                final_errors = self.count_black_errors()
                self.error_count_history.append(final_errors)

            # Final report
            self.generate_report()

        except Exception as e:
            print(f"\n[ERROR] Orchestration failed: {e}")
            if input("\nRollback changes? (y/n): ").lower() == 'y':
                self.rollback(backup_path, error_files)

    def generate_report(self):
        """Generate final report."""
        print("\n" + "=" * 70)
        print("ORCHESTRATION REPORT")
        print("=" * 70)

        initial = self.error_count_history[0] if self.error_count_history else 0
        final = self.error_count_history[-1] if self.error_count_history else 0

        print(f"\n  Initial errors: {initial}")
        print(f"  Final errors:   {final}")
        print(f"  Improvement:    {initial -
                                   final} errors fixed ({((initial -
                                                           final) /
                                                          initial *
                                                          100):.1f}%)" if initial > 0 else "")

        print(f"\n  Fixes applied:")
        for fix in self.fixes_applied:
            print(f"    - {fix}")

        print(
            f"\n  Error history: {' -> '.join(map(str, self.error_count_history))}")

        # Save report
        report = {
            'timestamp': self.timestamp,
            'initial_errors': initial,
            'final_errors': final,
            'fixes_applied': self.fixes_applied,
            'error_history': self.error_count_history
        }

        with open(f'remediation_report_{self.timestamp}.json', 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n  Report saved: remediation_report_{self.timestamp}.json")

        if final == 0:
            print("\n[SUCCESS] SUCCESS! All Black errors resolved!")
        elif final < initial:
            print(
                f"\n[SUCCESS] Partial success: {
                    initial -
                    final} errors fixed")
        else:
            print("\n[WARNING]  No improvement achieved")


if __name__ == '__main__':
    orchestrator = FixOrchestrator()
    orchestrator.run()
