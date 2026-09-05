#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

# Add src and strict_engineering to sys.path
root = Path(__file__).parent
sys.path.insert(0, str(root / "src" / "strict_engineering"))
sys.path.insert(0, str(root / "strict_engineering"))
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root))

def main():
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(root / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

if __name__ == "__main__":
    main()
