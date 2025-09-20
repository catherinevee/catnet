#!/usr/bin/env python3
"""CatNet CLI main entry point."""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.cli.commands import cli


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        if os.getenv("CATNET_DEBUG"):
            raise
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
