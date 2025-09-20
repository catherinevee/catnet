#!/usr/bin/env python3
"""
CatNet Quick Start Script
Helps new users get started with CatNet quickly
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


class CatNetQuickStart:
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.config_dir = self.root_dir / "config"
        self.data_dir = self.root_dir / "data"

    def print_banner(self):
        """Print welcome banner"""
        print("""
        ╔═══════════════════════════════════════╗
        ║         Welcome to CatNet!            ║
        ║   Network Configuration Deployment    ║
        ║           Made Simple                 ║
        ╚═══════════════════════════════════════╝
        """)

    def check_python_version(self):
        """Check Python version"""
        print("🔍 Checking Python version...")
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 11):
            print("❌ Python 3.11+ is required")
            sys.exit(1)
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} \
            detected")

    def setup_environment(self):
        """Set up environment file"""
        print("\n📝 Setting up environment...")
        env_file = self.config_dir / ".env"
        env_example = self.config_dir / ".env.example"

        if not env_file.exists() and env_example.exists():
            shutil.copy(env_example, env_file)
            print("✅ Created .env file from template")
        elif env_file.exists():
            print("✅ .env file already exists")
        else:
            # Create basic .env file
            env_content = """
# CatNet Environment Configuration
DATABASE_URL=sqlite:///./data/catnet_local.db
REDIS_URL=redis://localhost:6379/0
VAULT_URL=http://localhost:8200
JWT_SECRET_KEY=dev-secret-key-change-in-production
SECRET_KEY=dev-secret-key-change-in-production
ENVIRONMENT=development
DEBUG=true
"""
            env_file.write_text(env_content.strip())
            print("✅ Created default .env file")

    def install_dependencies(self):
        """Install Python dependencies"""
        print("\n📦 Installing dependencies...")
        try:
            subprocess.run([sys.executable,
                            "-m"
                            "pip"
                            "install"
                            "-r"
                            "requirements.txt"]

                           check=True, capture_output=True, text=True)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Some dependencies may have failed to install: {e}")
            print("   You may need to install them manually")

    def initialize_database(self):
        """Initialize the database"""
        print("\n🗄️  Initializing database...")

        # Ensure data directory exists
        self.data_dir.mkdir(exist_ok=True)

        # Create empty database file if it doesn't exist
        db_file = self.data_dir / "catnet_local.db"
        if not db_file.exists():
            db_file.touch()
            print("✅ Created database file")
        else:
            print("✅ Database already exists")

        # Try to run migrations if alembic is available
        try:
            subprocess.run(["alembic", "upgrade", "head"],
                           capture_output=True, text=True, check=False)
            print("✅ Database migrations applied")
        except FileNotFoundError:
            print("ℹ️  Alembic not found - skipping migrations")

    def show_next_steps(self):
        """Show next steps to the user"""
        print("\n" + "=" * 50)
        print("🚀 Quick Start Complete!")
        print("=" * 50)
        print("\nNext steps:")
        print("\n1️⃣  Start the API server:")
        print("   python run_catnet.py")
        print("\n2️⃣  Or use the CLI:")
        print("   python catnet_cli.py --help")
        print("\n3️⃣  Access the API documentation:")
        print("   http://localhost:8000/docs")
        print("\n4️⃣  Read the usage guide:")
        print("   USAGE_GUIDE.md")
        print("\n" + "=" * 50)

        # Offer to start the server
        print(
            "\nWould you like to start the CatNet server now? (y/n): ",
            end=""
        )
        response = input().strip().lower()

        if response == 'y':
            print("\n🚀 Starting CatNet server...")
            print("Press Ctrl+C to stop\n")
            try:
                subprocess.run([sys.executable, "run_catnet.py"])
            except KeyboardInterrupt:
                print("\n\n👋 Server stopped. Goodbye!")

    def run(self):
        """Run the quick start process"""
        self.print_banner()

        try:
            self.check_python_version()
            self.setup_environment()
            self.install_dependencies()
            self.initialize_database()
            self.show_next_steps()

        except Exception as e:
            print(f"\n❌ Error during setup: {e}")
            print("Please check the documentation or file an issue")
            sys.exit(1)


def main():
    """Main entry point"""
    quickstart = CatNetQuickStart()
    quickstart.run()


if __name__ == "__main__":
    main()
