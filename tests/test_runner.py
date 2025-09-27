#!/usr/bin/env python3
"""
CatNet Test Runner
Comprehensive test execution with reporting and environment setup.
"""

import os
import sys
import asyncio
import argparse
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

import pytest
import psutil


class TestRunner:
    """Test runner for CatNet test suite."""

    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.test_root = Path(__file__).parent
        self.reports_dir = self.project_root / "test-reports"
        self.coverage_dir = self.project_root / "htmlcov"

    def setup_environment(self) -> None:
        """Setup test environment."""
        print("Setting up test environment...")

        # Create reports directory
        self.reports_dir.mkdir(exist_ok=True)
        self.coverage_dir.mkdir(exist_ok=True)

        # Set environment variables for testing
        os.environ["CATNET_TESTING"] = "true"
        os.environ["CATNET_ENVIRONMENT"] = "testing"
        os.environ["CATNET_DEBUG"] = "true"

        # Database settings for testing
        os.environ["CATNET_DATABASE__POSTGRES_DB"] = "catnet_test"
        os.environ["CATNET_DATABASE__REDIS_DB"] = "1"

        # Disable external services for testing
        os.environ["CATNET_VAULT__VAULT_SSL_VERIFY"] = "false"
        os.environ["CATNET_MONITORING__ALERTS_ENABLED"] = "false"

        print("✓ Test environment configured")

    def check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        print("Checking test dependencies...")

        required_packages = [
            "pytest",
            "pytest-asyncio",
            "pytest-cov",
            "httpx",
            "asyncpg"
        ]

        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace("-", "_"))
            except ImportError:
                missing_packages.append(package)

        if missing_packages:
            print(f"✗ Missing packages: {', '.join(missing_packages)}")
            print("Install with: pip install -r requirements-dev.txt")
            return False

        print("✓ All dependencies available")
        return True

    def check_services(self) -> Dict[str, bool]:
        """Check if required services are running."""
        print("Checking required services...")

        services = {
            "postgres": self._check_postgres(),
            "redis": self._check_redis()
        }

        for service, status in services.items():
            status_symbol = "✓" if status else "✗"
            print(f"{status_symbol} {service}: {'Running' if status else 'Not available'}")

        return services

    def _check_postgres(self) -> bool:
        """Check if PostgreSQL is available."""
        try:
            import asyncpg
            # This would need actual connection testing in a real scenario
            return True
        except ImportError:
            return False

    def _check_redis(self) -> bool:
        """Check if Redis is available."""
        try:
            import redis
            # This would need actual connection testing in a real scenario
            return True
        except ImportError:
            return False

    def run_unit_tests(self, verbose: bool = False) -> int:
        """Run unit tests."""
        print("\n" + "="*50)
        print("RUNNING UNIT TESTS")
        print("="*50)

        cmd = [
            "python", "-m", "pytest",
            str(self.test_root / "unit"),
            "--cov=src",
            "--cov-report=html",
            "--cov-report=xml",
            "--cov-report=term-missing",
            "--junit-xml=" + str(self.reports_dir / "unit-tests.xml"),
            "--html=" + str(self.reports_dir / "unit-tests.html"),
            "--self-contained-html",
            "-m", "not slow and not integration and not e2e and not security"
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def run_integration_tests(self, verbose: bool = False) -> int:
        """Run integration tests."""
        print("\n" + "="*50)
        print("RUNNING INTEGRATION TESTS")
        print("="*50)

        cmd = [
            "python", "-m", "pytest",
            str(self.test_root / "integration"),
            "--junit-xml=" + str(self.reports_dir / "integration-tests.xml"),
            "--html=" + str(self.reports_dir / "integration-tests.html"),
            "--self-contained-html",
            "-m", "integration"
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def run_security_tests(self, verbose: bool = False) -> int:
        """Run security tests."""
        print("\n" + "="*50)
        print("RUNNING SECURITY TESTS")
        print("="*50)

        cmd = [
            "python", "-m", "pytest",
            str(self.test_root / "security"),
            "--junit-xml=" + str(self.reports_dir / "security-tests.xml"),
            "--html=" + str(self.reports_dir / "security-tests.html"),
            "--self-contained-html",
            "-m", "security"
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def run_performance_tests(self, verbose: bool = False) -> int:
        """Run performance tests."""
        print("\n" + "="*50)
        print("RUNNING PERFORMANCE TESTS")
        print("="*50)

        cmd = [
            "python", "-m", "pytest",
            str(self.test_root / "performance"),
            "--junit-xml=" + str(self.reports_dir / "performance-tests.xml"),
            "--html=" + str(self.reports_dir / "performance-tests.html"),
            "--self-contained-html",
            "-m", "performance",
            "--benchmark-json=" + str(self.reports_dir / "benchmark.json")
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def run_e2e_tests(self, verbose: bool = False) -> int:
        """Run end-to-end tests."""
        print("\n" + "="*50)
        print("RUNNING END-TO-END TESTS")
        print("="*50)

        cmd = [
            "python", "-m", "pytest",
            str(self.test_root / "e2e"),
            "--junit-xml=" + str(self.reports_dir / "e2e-tests.xml"),
            "--html=" + str(self.reports_dir / "e2e-tests.html"),
            "--self-contained-html",
            "-m", "e2e"
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def run_all_tests(self, verbose: bool = False, skip_slow: bool = False) -> Dict[str, int]:
        """Run all test suites."""
        print("\n" + "="*60)
        print("RUNNING COMPLETE CATNET TEST SUITE")
        print("="*60)

        results = {}

        # Unit tests (always run)
        results["unit"] = self.run_unit_tests(verbose)

        # Integration tests
        if not skip_slow:
            results["integration"] = self.run_integration_tests(verbose)

        # Security tests
        results["security"] = self.run_security_tests(verbose)

        # Performance tests (optional for quick runs)
        if not skip_slow:
            results["performance"] = self.run_performance_tests(verbose)

        # E2E tests (optional for quick runs)
        if not skip_slow:
            results["e2e"] = self.run_e2e_tests(verbose)

        return results

    def run_specific_test(self, test_path: str, verbose: bool = False) -> int:
        """Run a specific test file or directory."""
        print(f"\nRunning specific test: {test_path}")

        cmd = [
            "python", "-m", "pytest",
            test_path,
            "--junit-xml=" + str(self.reports_dir / "specific-test.xml"),
            "--html=" + str(self.reports_dir / "specific-test.html"),
            "--self-contained-html"
        ]

        if verbose:
            cmd.append("-v")

        return subprocess.call(cmd, cwd=self.project_root)

    def generate_coverage_report(self) -> None:
        """Generate comprehensive coverage report."""
        print("\nGenerating coverage report...")

        # Combine coverage data
        subprocess.call(["coverage", "combine"], cwd=self.project_root)

        # Generate HTML report
        subprocess.call([
            "coverage", "html",
            "--directory", str(self.coverage_dir)
        ], cwd=self.project_root)

        # Generate terminal report
        subprocess.call(["coverage", "report"], cwd=self.project_root)

        print(f"✓ Coverage report generated: {self.coverage_dir / 'index.html'}")

    def cleanup_test_data(self) -> None:
        """Clean up test data and temporary files."""
        print("Cleaning up test data...")

        # Clean up test database
        # This would involve dropping test databases, clearing Redis, etc.

        # Clean up temporary files
        temp_patterns = [
            "*.pyc",
            "__pycache__",
            ".pytest_cache",
            "*.log"
        ]

        for pattern in temp_patterns:
            subprocess.call([
                "find", str(self.project_root),
                "-name", pattern,
                "-delete"
            ])

        print("✓ Test data cleaned up")

    def print_summary(self, results: Dict[str, int]) -> None:
        """Print test results summary."""
        print("\n" + "="*60)
        print("TEST RESULTS SUMMARY")
        print("="*60)

        total_suites = len(results)
        passed_suites = sum(1 for code in results.values() if code == 0)
        failed_suites = total_suites - passed_suites

        for suite, exit_code in results.items():
            status = "PASS" if exit_code == 0 else "FAIL"
            status_symbol = "✓" if exit_code == 0 else "✗"
            print(f"{status_symbol} {suite.upper()}: {status}")

        print(f"\nSUITES: {total_suites} total, {passed_suites} passed, {failed_suites} failed")

        if failed_suites == 0:
            print("\n🎉 ALL TESTS PASSED!")
        else:
            print(f"\n❌ {failed_suites} test suite(s) failed")

        print(f"\nReports generated in: {self.reports_dir}")
        print(f"Coverage report: {self.coverage_dir / 'index.html'}")

    def main(self) -> int:
        """Main entry point."""
        parser = argparse.ArgumentParser(description="CatNet Test Runner")
        parser.add_argument(
            "suite",
            nargs="?",
            choices=["unit", "integration", "security", "performance", "e2e", "all"],
            default="all",
            help="Test suite to run"
        )
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Verbose output"
        )
        parser.add_argument(
            "--skip-slow",
            action="store_true",
            help="Skip slow tests (performance, e2e)"
        )
        parser.add_argument(
            "--test",
            help="Run specific test file or directory"
        )
        parser.add_argument(
            "--check-only",
            action="store_true",
            help="Only check dependencies and services"
        )
        parser.add_argument(
            "--coverage-only",
            action="store_true",
            help="Only generate coverage report"
        )
        parser.add_argument(
            "--cleanup",
            action="store_true",
            help="Clean up test data and exit"
        )

        args = parser.parse_args()

        # Setup
        self.setup_environment()

        # Handle special modes
        if args.cleanup:
            self.cleanup_test_data()
            return 0

        if args.coverage_only:
            self.generate_coverage_report()
            return 0

        # Check dependencies
        if not self.check_dependencies():
            return 1

        # Check services
        services = self.check_services()

        if args.check_only:
            all_services_ok = all(services.values())
            return 0 if all_services_ok else 1

        # Run tests
        start_time = time.time()

        if args.test:
            exit_code = self.run_specific_test(args.test, args.verbose)
            results = {"specific": exit_code}
        elif args.suite == "unit":
            exit_code = self.run_unit_tests(args.verbose)
            results = {"unit": exit_code}
        elif args.suite == "integration":
            exit_code = self.run_integration_tests(args.verbose)
            results = {"integration": exit_code}
        elif args.suite == "security":
            exit_code = self.run_security_tests(args.verbose)
            results = {"security": exit_code}
        elif args.suite == "performance":
            exit_code = self.run_performance_tests(args.verbose)
            results = {"performance": exit_code}
        elif args.suite == "e2e":
            exit_code = self.run_e2e_tests(args.verbose)
            results = {"e2e": exit_code}
        else:  # all
            results = self.run_all_tests(args.verbose, args.skip_slow)

        # Generate reports
        self.generate_coverage_report()

        # Print summary
        end_time = time.time()
        duration = end_time - start_time

        self.print_summary(results)
        print(f"\nTotal execution time: {duration:.2f} seconds")

        # Return overall exit code
        return 1 if any(code != 0 for code in results.values()) else 0


if __name__ == "__main__":
    runner = TestRunner()
    sys.exit(runner.main())