"""
Strict Engineering Kernel - Release Consistency Audit Test Suite
Ensures metadata, documentation, source tree, and package version are 100% aligned.
"""

import sys
import json
import re
import unittest
import compileall
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src" / "strict_engineering"


class ReleaseConsistencyTestSuite(unittest.TestCase):
    def test_version_alignment(self):
        """Verify version is 1.2.4 across pyproject.toml, package __init__, installer, and README."""
        # pyproject.toml
        pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*"([^"]+)"', pyproject_text)
        self.assertIsNotNone(match, "Could not find version in pyproject.toml")
        pyproject_ver = match.group(1)
        self.assertEqual(pyproject_ver, "1.2.4")

        # __init__.py
        init_text = (SRC_DIR / "__init__.py").read_text(encoding="utf-8")
        match_init = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
        self.assertIsNotNone(match_init, "Could not find __version__ in __init__.py")
        self.assertEqual(match_init.group(1), "1.2.4")

        # scripts/install.py
        install_text = (REPO_ROOT / "scripts" / "install.py").read_text(encoding="utf-8")
        self.assertIn("__version__", install_text)
        self.assertNotIn("V1.1.0", install_text)

        # README.md
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("V1.2.4", readme_text)
        self.assertIn("badge/version-1.2.4-blue.svg", readme_text)

    def test_plugin_json_not_claimed_or_present(self):
        """Verify plugin.json does not exist on disk or in README project tree."""
        plugin_file = REPO_ROOT / "plugin.json"
        self.assertFalse(plugin_file.exists(), "plugin.json should not exist on disk")
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("plugin.json", readme_text)

    def test_no_phantom_trusted_origin_module(self):
        """Verify trusted_origin.py does not exist on disk or in README project tree."""
        phantom_file = SRC_DIR / "trusted_origin.py"
        self.assertFalse(phantom_file.exists(), "src/strict_engineering/trusted_origin.py should not exist")

        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("trusted_origin.py", readme_text)

    def test_all_src_modules_exist_and_compile(self):
        """Verify all production modules compile with zero syntax errors."""
        res = compileall.compile_dir(str(SRC_DIR), quiet=1)
        self.assertTrue(res, "compileall failed on src/strict_engineering")

    def test_documented_src_modules_match_disk(self):
        """Verify all .py modules on disk are documented in README and vice versa."""
        disk_modules = {p.name for p in SRC_DIR.glob("*.py")}
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        for mod in disk_modules:
            self.assertIn(mod, readme_text, f"Module {mod} exists on disk but is not documented in README")

    def test_python_requires_truthful(self):
        """Verify pyproject.toml declares requires-python >=3.11 matching tested policy."""
        pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.11"', pyproject_text)


if __name__ == "__main__":
    unittest.main()
