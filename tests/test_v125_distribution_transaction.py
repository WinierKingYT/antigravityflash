"""
Strict Engineering Kernel V1.2.5 - Full Distribution Transaction Closure Test Suite
Covers:
- VER-125-01 .. 05: Three-way release archive version parity and fail-closed validation
- TX-125-01 .. 02: Pre-mutation package rollback artifact creation and pre-mutation abort
- TX-125-03 .. 10: Real isolated venv package update, post-update parity, post-package failure injection,
                   automatic package rollback, 5-surface parity verification, and split-brain detection.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from strict_engineering import (
    __version__,
    distribution,
    installer,
    cli,
)


class ArchiveThreeWayParityTestSuite(unittest.TestCase):
    """
    VER-125-01 .. 05: Validates three-way parity enforcement (target == __version__ == pyproject.toml)
    and fail-closed behavior for missing or unparsable version files.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="strict_v125_archive_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_archive_content(self, mod_ver: str, pyproj_ver: str, omit_init: bool = False, omit_pyproject: bool = False, malformed_pyproject: bool = False):
        root = self.temp_dir / "extracted"
        root.mkdir(parents=True, exist_ok=True)
        mod_dir = root / "src" / "strict_engineering"
        mod_dir.mkdir(parents=True, exist_ok=True)

        # Copy required core modules
        for rm in ["kernel.py", "gate.py", "distribution.py", "installer.py", "cli.py"]:
            src_file = root_dir / "src" / "strict_engineering" / rm
            if src_file.exists():
                shutil.copy2(src_file, mod_dir / rm)
            else:
                (mod_dir / rm).write_text("# stub", encoding="utf-8")

        # Copy required agents
        shutil.copytree(root_dir / "agents", root / "agents", dirs_exist_ok=True)

        if not omit_init:
            (mod_dir / "__init__.py").write_text(f'__version__ = "{mod_ver}"\n', encoding="utf-8")

        if malformed_pyproject:
            (root / "pyproject.toml").write_text('this is not [valid toml\nversion = ', encoding="utf-8")
        elif not omit_pyproject:
            (root / "pyproject.toml").write_text(
                f'[project]\nname = "antigravity-strict-engineering"\nversion = "{pyproj_ver}"\n',
                encoding="utf-8"
            )
        return root

    def test_ver_125_01_three_way_parity_success(self):
        """VER-125-01: All three versions match -> valid=True."""
        root = self._create_archive_content(mod_ver="1.2.5", pyproj_ver="1.2.5")
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertTrue(ok, f"Validation failed unexpectedly: {err}")
        self.assertIsNotNone(resolved)

    def test_ver_125_02_target_mismatch(self):
        """VER-125-02: Target version does not match module version -> fail closed."""
        root = self._create_archive_content(mod_ver="1.2.4", pyproj_ver="1.2.4")
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertFalse(ok)
        self.assertIn("version mismatch", err.lower())

    def test_ver_125_03_pyproject_mismatch(self):
        """VER-125-03: Module version does not match pyproject version -> fail closed."""
        root = self._create_archive_content(mod_ver="1.2.5", pyproj_ver="1.2.4")
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertFalse(ok)
        self.assertIn("mismatch", err.lower())

    def test_ver_125_04_missing_pyproject(self):
        """VER-125-04: Missing pyproject.toml -> fail closed."""
        root = self._create_archive_content(mod_ver="1.2.5", pyproj_ver="1.2.5", omit_pyproject=True)
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertFalse(ok)
        self.assertIn("pyproject.toml", err.lower())

    def test_ver_125_05_missing_init_version(self):
        """VER-125-05: Missing __init__.py or missing __version__ -> fail closed."""
        root = self._create_archive_content(mod_ver="1.2.5", pyproj_ver="1.2.5", omit_init=True)
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertFalse(ok)
        self.assertIn("__init__.py", err.lower())

    def test_ver_125_06_malformed_pyproject(self):
        """VER-125-06: Malformed or unparsable pyproject.toml -> fail closed."""
        root = self._create_archive_content(mod_ver="1.2.5", pyproj_ver="1.2.5", malformed_pyproject=True)
        ok, err, resolved = distribution.validate_release_archive_content(root, target_version="1.2.5")
        self.assertFalse(ok)
        self.assertTrue("pyproject.toml" in err.lower())


class PreMutationArtifactTestSuite(unittest.TestCase):
    """
    TX-125-01 .. 02: Pre-mutation rollback artifact creation and abort before mutation.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="strict_v125_premut_"))
        self.fake_gemini = self.temp_dir / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        self.cfg_dir = self.fake_gemini / "config" / "strict-engineering"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tx_125_01_build_package_rollback_artifact_success(self):
        """TX-125-01: Generates valid package rollback artifact with sha256 and metadata."""
        snapshot_dir = self.cfg_dir / ".backups" / "test-snapshot"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        ok, msg, whl_path = distribution.build_package_rollback_artifact(
            gemini_dir=self.fake_gemini,
            backup_snapshot_dir=snapshot_dir,
            current_version="1.2.4",
            tx_id="tx-unit-01",
        )
        self.assertTrue(ok, f"Failed building artifact: {msg}")
        meta_file = snapshot_dir / "package" / "package-rollback.json"
        self.assertTrue(meta_file.exists())

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta.get("packageName"), "antigravity-strict-engineering")
        self.assertIn("pythonExecutable", meta)
        self.assertIn("txId", meta)

    def test_tx_125_02_pre_mutation_failure_aborts_without_mutation(self):
        """TX-125-02: Failure in pre-mutation artifact creation aborts update before any mutation."""
        # Setup initial runtime module in cfg_dir
        (self.cfg_dir / "__init__.py").write_text('__version__ = "1.2.4"\n# original code', encoding="utf-8")
        orig_content = (self.cfg_dir / "__init__.py").read_text(encoding="utf-8")

        # Create candidate source directory with new code
        new_source = self.temp_dir / "new_src"
        (new_source / "src" / "strict_engineering").mkdir(parents=True, exist_ok=True)
        (new_source / "src" / "strict_engineering" / "__init__.py").write_text('__version__ = "1.2.5"\n# mutated', encoding="utf-8")
        (new_source / "pyproject.toml").write_text('[project]\nname = "antigravity-strict-engineering"\nversion = "1.2.5"\n', encoding="utf-8")

        # Mock build_package_rollback_artifact to fail
        with patch.object(distribution, "build_package_rollback_artifact", return_value=(False, "Simulated disk failure", None)):
            ok, msg, _ = distribution.update_installation(
                source_dir=new_source,
                target_version="1.2.5",
                gemini_dir=self.fake_gemini,
                force=True,
            )
            self.assertFalse(ok)
            self.assertIn("Pre-mutation package rollback artifact creation failed", msg)

        # Invariant: cfg_dir files were never mutated or overwritten
        current_content = (self.cfg_dir / "__init__.py").read_text(encoding="utf-8")
        self.assertEqual(current_content, orig_content)


class IsolatedTransactionRealExecutionTestSuite(unittest.TestCase):
    """
    TX-125-03 .. 10: Real isolated venv end-to-end tests:
    - Real package upgrade from 1.2.4 to 1.2.5 via un-mocked pip
    - 5-surface version parity check
    - Failure injection after package upgrade
    - Automatic rollback restoring 1.2.4 across package, runtime, manifest, and CLI
    - Split-brain negative oracle
    """

    @classmethod
    def setUpClass(cls):
        cls.test_root = Path(tempfile.mkdtemp(prefix="strict_v125_e2e_"))

        # Build 1.2.4 package source
        cls.pkg124 = cls.test_root / "pkg124"
        (cls.pkg124 / "src" / "strict_engineering").mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, cls.pkg124 / "src" / "strict_engineering" / f.name)
        (cls.pkg124 / "src" / "strict_engineering" / "__init__.py").write_text('__version__ = "1.2.4"\n', encoding="utf-8")
        pyproj = (root_dir / "pyproject.toml").read_text(encoding="utf-8")
        import re
        (cls.pkg124 / "pyproject.toml").write_text(re.sub(r'version\s*=\s*"[^"]+"', 'version = "1.2.4"', pyproj), encoding="utf-8")
        shutil.copytree(root_dir / "agents", cls.pkg124 / "agents")

        # Build 1.2.5 package source
        cls.pkg125 = cls.test_root / "pkg125"
        (cls.pkg125 / "src" / "strict_engineering").mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, cls.pkg125 / "src" / "strict_engineering" / f.name)
        (cls.pkg125 / "src" / "strict_engineering" / "__init__.py").write_text('__version__ = "1.2.5"\n', encoding="utf-8")
        (cls.pkg125 / "pyproject.toml").write_text(re.sub(r'version\s*=\s*"[^"]+"', 'version = "1.2.5"', pyproj), encoding="utf-8")
        shutil.copytree(root_dir / "agents", cls.pkg125 / "agents")

        # Build wheels
        wheels_dir = cls.test_root / "wheels"
        wheels_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(wheels_dir), str(cls.pkg124)], check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(wheels_dir), str(cls.pkg125)], check=True, capture_output=True)
        cls.whl124 = list(wheels_dir.glob("*1.2.4*.whl"))[0]
        cls.whl125 = list(wheels_dir.glob("*1.2.5*.whl"))[0]

        # Create shared isolated test venv
        cls.venv_dir = cls.test_root / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(cls.venv_dir)], check=True)
        cls.venv_py = str(cls.venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))

        # Install 1.2.4 as base package
        subprocess.run([cls.venv_py, "-m", "pip", "install", "--no-deps", str(cls.whl124)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_root, ignore_errors=True)

    def setUp(self):
        # Reset package in venv to 1.2.4 before each test
        subprocess.run([self.venv_py, "-m", "pip", "install", "--no-deps", "--force-reinstall", str(self.whl124)], check=True, capture_output=True)
        self.test_gemini = Path(tempfile.mkdtemp(prefix="gemini_e2e_"))
        self.cfg_dir = self.test_gemini / "config" / "strict-engineering"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)

        # Setup 1.2.4 runtime in fake gemini
        for f in (self.pkg124 / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, self.cfg_dir / f.name)

        # Setup core agents in fake gemini
        agents_target = self.test_gemini / "config" / "agents"
        shutil.copytree(root_dir / "agents", agents_target, dirs_exist_ok=True)

        manifest = {
            "version": "1.2.4",
            "updatedAt": "2026-09-08T00:00:00Z",
            "installSource": "test",
            "managedFiles": {
                "modules": {f.name: {"sha256": "fake"} for f in self.cfg_dir.glob("*.py")},
                "agents": {d.name: {"sha256": "fake"} for d in agents_target.iterdir() if d.is_dir()},
            }
        }
        (self.cfg_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_gemini, ignore_errors=True)

    def test_tx_125_03_baseline_parity(self):
        """TX-125-03: Fresh isolated venv and runtime exhibit complete 1.2.4 parity."""
        ok, msg, details = distribution.verify_all_surfaces_parity(
            gemini_dir=self.test_gemini,
            expected_version="1.2.4",
            python_exe=self.venv_py,
        )
        self.assertTrue(ok, f"Baseline parity check failed: {msg}")
        self.assertEqual(details.get("manifest"), "1.2.4")
        self.assertEqual(details.get("runtime"), "1.2.4")
        self.assertEqual(details.get("package_metadata"), "1.2.4")
        self.assertEqual(details.get("package_import"), "1.2.4")

    def test_tx_125_04_to_05_real_package_upgrade_and_post_update_parity(self):
        """
        TX-125-04: Real un-mocked package upgrade to 1.2.5.
        TX-125-05: Post-update fresh subprocess verifies all surfaces report 1.2.5.
        """
        ok, msg, manifest = distribution.update_installation(
            source_dir=self.pkg125,
            target_version="1.2.5",
            gemini_dir=self.test_gemini,
            force=True,
            python_exe=self.venv_py,
        )
        self.assertTrue(ok, f"Update failed: {msg}")

        # Fresh subprocess checks
        ok_parity, msg_parity, details = distribution.verify_all_surfaces_parity(
            gemini_dir=self.test_gemini,
            expected_version="1.2.5",
            python_exe=self.venv_py,
        )
        self.assertTrue(ok_parity, f"Post-update parity failed: {msg_parity}")
        self.assertEqual(details.get("manifest"), "1.2.5")
        self.assertEqual(details.get("runtime"), "1.2.5")
        self.assertEqual(details.get("package_metadata"), "1.2.5")
        self.assertEqual(details.get("package_import"), "1.2.5")

    def test_tx_125_06_to_08_failure_after_package_upgrade_triggers_clean_rollback(self):
        """
        TX-125-06: Failure injected after successful package upgrade.
        TX-125-07: Automatic rollback cleanly restores 1.2.4 across package, runtime, and manifest.
        TX-125-08: Classification outcome is UPDATE_FAILED_ROLLBACK_COMPLETE.
        """
        # Inject failure in verify_manifest_integrity (which runs right after package upgrade)
        with patch.object(distribution, "verify_manifest_integrity", return_value=(False, ["Simulated post-package manifest failure"])):
            ok, msg, _ = distribution.update_installation(
                source_dir=self.pkg125,
                target_version="1.2.5",
                gemini_dir=self.test_gemini,
                force=True,
                python_exe=self.venv_py,
            )
            self.assertFalse(ok)
            self.assertIn("UPDATE_FAILED_ROLLBACK_COMPLETE", msg)

        # Verify that package, runtime, and manifest were completely restored to 1.2.4
        ok_rb, msg_rb, details = distribution.verify_all_surfaces_parity(
            gemini_dir=self.test_gemini,
            expected_version="1.2.4",
            python_exe=self.venv_py,
        )
        self.assertTrue(ok_rb, f"Rollback parity failed: {msg_rb}")
        self.assertEqual(details.get("manifest"), "1.2.4")
        self.assertEqual(details.get("runtime"), "1.2.4")
        self.assertEqual(details.get("package_metadata"), "1.2.4")
        self.assertEqual(details.get("package_import"), "1.2.4")

    def test_tx_125_09_split_brain_negative_oracle(self):
        """
        TX-125-09: If package rollback fails after upgrade, outcome is NOT UPDATE_FAILED_ROLLBACK_COMPLETE,
        and split-brain or package rollback failure is explicitly captured.
        """
        # Inject failure in post-update step AND simulate package rollback failure
        with patch.object(distribution, "verify_manifest_integrity", return_value=(False, ["Simulated post-package failure"])):
            with patch.object(distribution, "rollback_python_package", return_value=(False, "Simulated pip rollback failure")):
                ok, msg, _ = distribution.update_installation(
                    source_dir=self.pkg125,
                    target_version="1.2.5",
                    gemini_dir=self.test_gemini,
                    force=True,
                    python_exe=self.venv_py,
                )
                self.assertFalse(ok)
                self.assertNotIn("UPDATE_FAILED_ROLLBACK_COMPLETE", msg)
                self.assertTrue("UPDATE_FAILED_PACKAGE_ROLLBACK_FAILED" in msg or "UPDATE_FAILED_SPLIT_BRAIN_DETECTED" in msg, f"Expected failure status in msg, got: {msg}")

    def test_tx_125_10_standalone_rollback_restores_package(self):
        """
        TX-125-10: CLI / standalone rollback_installation restores the Python package
        if a package-rollback.json artifact is present in the chosen backup snapshot.
        """
        # 1. Update successfully to 1.2.5
        ok_up, msg_up, manifest_up = distribution.update_installation(
            source_dir=self.pkg125,
            target_version="1.2.5",
            gemini_dir=self.test_gemini,
            force=True,
            python_exe=self.venv_py,
        )
        self.assertTrue(ok_up, f"Initial update to 1.2.5 failed: {msg_up}")

        # Check package is indeed 1.2.5
        chk = subprocess.run([self.venv_py, "-c", "import importlib.metadata as m; print(m.version('antigravity-strict-engineering'))"], capture_output=True, text=True)
        self.assertEqual(chk.stdout.strip(), "1.2.5")

        # 2. Invoke standalone rollback_installation
        ok_rb, msg_rb, notes = distribution.rollback_installation(
            gemini_dir=self.test_gemini,
            python_exe=self.venv_py,
        )
        self.assertTrue(ok_rb, f"Standalone rollback failed: {msg_rb}")

        # 3. Verify that package in venv was restored to 1.2.4
        ok_parity, msg_parity, details = distribution.verify_all_surfaces_parity(
            gemini_dir=self.test_gemini,
            expected_version="1.2.4",
            python_exe=self.venv_py,
        )
        self.assertTrue(ok_parity, f"Parity check failed after standalone rollback: {msg_parity}")
        self.assertEqual(details.get("package_metadata"), "1.2.4")
        self.assertEqual(details.get("runtime"), "1.2.4")


if __name__ == "__main__":
    unittest.main()
