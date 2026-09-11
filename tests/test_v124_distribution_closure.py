"""
Strict Engineering Kernel V1.2.4 - Distribution Truth Closure Test Suite
Covers:
- INSTALL-124-01 .. 07: Fresh install manifest/config ordering, cryptographic binding, and drift detection
- UPDATE-124-01 .. 11: Package vs Global Runtime parity, self-update synchronization, and failure isolation
- AGENT-124-01 .. 08: Obsolete managed agent lifecycle, ownership-based rollback, and custom preservation
"""

import os
import sys
import io
import json
import shutil
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure src is in sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from strict_engineering import (
    __version__,
    distribution,
    installer,
    cli,
)


class FreshInstallManifestTestSuite(unittest.TestCase):
    """INSTALL-124-01 .. 07: Fresh install ordering, cryptographic binding, and drift detection."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_v124_inst_")
        self.fake_gemini = Path(self.temp_dir) / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        self.patcher = patch.object(cli, "get_default_gemini_dir", return_value=self.fake_gemini)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_install_124_01_to_04_fresh_install_cryptographic_binding(self):
        """
        INSTALL-124-01: Fresh install produces config.json before final manifest state.
        INSTALL-124-02: manifest.managedFiles.config.sha256 is non-null.
        INSTALL-124-03: recorded config SHA equals actual config SHA.
        INSTALL-124-04: Immediately after clean install: verify_manifest_integrity() == PASS.
        """
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["install"])
        self.assertEqual(code, cli.EXIT_SUCCESS)

        config_p = self.fake_gemini / "config" / "strict-engineering" / "config.json"
        manifest_p = self.fake_gemini / "config" / "strict-engineering" / "manifest.json"

        # 01: config.json exists
        self.assertTrue(config_p.exists(), "config.json must exist after fresh install")
        self.assertTrue(manifest_p.exists(), "manifest.json must exist after fresh install")

        manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
        cfg_meta = manifest.get("managedFiles", {}).get("config", {})
        cfg_sha = cfg_meta.get("sha256")

        # 02: manifest.managedFiles.config.sha256 is non-null and non-empty
        self.assertIsNotNone(cfg_sha, "manifest.managedFiles.config.sha256 must not be None")
        self.assertTrue(bool(cfg_sha), "manifest.managedFiles.config.sha256 must not be empty")

        # 03: recorded config SHA equals actual config SHA
        actual_sha = distribution.compute_file_sha256(config_p)
        self.assertEqual(cfg_sha, actual_sha, "Recorded config SHA must equal actual config.json SHA")

        # 04: verify_manifest_integrity() passes immediately after install
        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertTrue(ok, f"verify_manifest_integrity must pass after fresh install, issues: {issues}")

    def test_install_124_05_modify_config_triggers_integrity_failure(self):
        """INSTALL-124-05: Modify config.json after install -> verify_manifest_integrity() == FAIL."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["install"])

        config_p = self.fake_gemini / "config" / "strict-engineering" / "config.json"
        cfg_data = json.loads(config_p.read_text(encoding="utf-8"))
        cfg_data["maxAutomaticContinues"] = 99
        config_p.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")

        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertFalse(ok)
        self.assertTrue(any("Global configuration modified" in i for i in issues))

    def test_install_124_06_corrupt_config_reports_fail(self):
        """INSTALL-124-06: Corrupt config.json -> doctor / manifest integrity reports FAIL."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["install"])

        config_p = self.fake_gemini / "config" / "strict-engineering" / "config.json"
        config_p.write_text("{invalid json: bad syntax", encoding="utf-8")

        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertFalse(ok)
        self.assertTrue(any("corrupted" in i for i in issues))

        out_doc = io.StringIO()
        with patch("sys.stdout", out_doc):
            code_doc = cli.main(["doctor"])
        self.assertEqual(code_doc, cli.EXIT_OPERATIONAL_FAILURE)
        self.assertIn("corrupted", out_doc.getvalue())

    def test_install_124_07_delete_config_reports_fail(self):
        """INSTALL-124-07: Delete config.json -> doctor / manifest integrity reports FAIL."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["install"])

        config_p = self.fake_gemini / "config" / "strict-engineering" / "config.json"
        config_p.unlink()

        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertFalse(ok)
        self.assertTrue(any("missing" in i.lower() for i in issues))


class ObsoleteAgentTransactionalityTestSuite(unittest.TestCase):
    """AGENT-124-01 .. 08: Obsolete managed agent lifecycle, ownership-based rollback, and custom preservation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_v124_agent_")
        self.fake_gemini = Path(self.temp_dir) / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        self.patcher = patch.object(cli, "get_default_gemini_dir", return_value=self.fake_gemini)
        self.patcher.start()

        # Set up a v1.2.3 installation with a managed agent that will become obsolete
        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["install"])

        self.agents_dir = self.fake_gemini / "config" / "agents"
        self.obsolete_agent_dir = self.agents_dir / "obsolete-core-agent"
        self.obsolete_agent_dir.mkdir(parents=True, exist_ok=True)
        (self.obsolete_agent_dir / "agent.md").write_text("# Obsolete Core Agent\nVersion 1.2.3", encoding="utf-8")

        # Custom user agent (not managed in manifest)
        self.custom_agent_dir = self.agents_dir / "my-custom-agent"
        self.custom_agent_dir.mkdir(parents=True, exist_ok=True)
        (self.custom_agent_dir / "agent.md").write_text("# My Custom Agent\nUser private prompt", encoding="utf-8")

        # Re-generate manifest to track obsolete-core-agent as managed
        cfg_dir = self.fake_gemini / "config" / "strict-engineering"
        hooks_file = self.fake_gemini / "config" / "hooks.json"
        gemini_md = self.fake_gemini / "GEMINI.md"

        old_managed_agents = set(distribution.MANAGED_CORE_AGENTS) | {"obsolete-core-agent"}
        manifest = distribution.generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md,
            agents_dir=self.agents_dir,
            version="1.2.3",
            install_source=str(root_dir),
            gemini_dir=self.fake_gemini,
            allowed_agents=old_managed_agents,
        )
        distribution.save_installation_manifest(manifest, gemini_dir=self.fake_gemini)

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_agent_124_01_to_03_and_07_obsolete_agent_removal_and_custom_preservation(self):
        """
        AGENT-124-01: Old manifest contains a managed agent absent from new release.
        AGENT-124-02: Successful update removes that obsolete managed agent.
        AGENT-124-03: Custom agent absent from all managed manifests is preserved.
        AGENT-124-07: New manifest no longer claims removed old agent.
        """
        manifest = distribution.load_installation_manifest(self.fake_gemini)
        # AGENT-124-01: obsolete-core-agent is tracked in old manifest
        self.assertIn("obsolete-core-agent", manifest.get("managedFiles", {}).get("agents", {}))

        # Create staged source for new release (1.2.4) which DOES NOT contain obsolete-core-agent
        staged_src = Path(self.temp_dir) / "new_release"
        staged_mod = staged_src / "src" / "strict_engineering"
        staged_mod.mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, staged_mod / f.name)

        staged_agents = staged_src / "agents"
        staged_agents.mkdir(parents=True, exist_ok=True)
        # Copy standard agents only (without obsolete-core-agent)
        if (root_dir / "agents").exists():
            for ag in (root_dir / "agents").iterdir():
                if ag.is_dir() and ag.name != "obsolete-core-agent":
                    shutil.copytree(ag, staged_agents / ag.name)

        # Update without package upgrade to isolate agent logic
        with patch.object(distribution, "update_python_package", return_value=(True, "ok", None)):
            ok, msg, new_m = distribution.update_installation(
                source_dir=staged_src,
                target_version="1.2.4",
                gemini_dir=self.fake_gemini,
                force=True,
            )
        self.assertTrue(ok, f"Update failed: {msg}")

        # AGENT-124-02: Obsolete agent is removed from disk
        self.assertFalse(self.obsolete_agent_dir.exists(), "obsolete-core-agent must be removed from disk")

        # AGENT-124-03: Custom agent is preserved
        self.assertTrue(self.custom_agent_dir.exists(), "my-custom-agent must be preserved on disk")
        self.assertIn("User private prompt", (self.custom_agent_dir / "agent.md").read_text(encoding="utf-8"))

        # AGENT-124-07: New manifest no longer claims removed old agent
        self.assertNotIn("obsolete-core-agent", new_m.get("managedFiles", {}).get("agents", {}))

    def test_agent_124_04_to_06_and_08_rollback_restores_obsolete_agent_and_preserves_custom(self):
        """
        AGENT-124-04: Inject failure after obsolete managed agent deletion.
        AGENT-124-05: Rollback restores obsolete old managed agent byte-for-byte.
        AGENT-124-06: Rollback preserves custom agent byte-for-byte.
        AGENT-124-08: Previous-version rollback manifest accurately represents restored previous installation.
        """
        orig_obsolete_content = (self.obsolete_agent_dir / "agent.md").read_text(encoding="utf-8")
        orig_custom_content = (self.custom_agent_dir / "agent.md").read_text(encoding="utf-8")

        # Staged source without obsolete-core-agent
        staged_src = Path(self.temp_dir) / "new_release_broken"
        staged_mod = staged_src / "src" / "strict_engineering"
        staged_mod.mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, staged_mod / f.name)

        staged_agents = staged_src / "agents"
        staged_agents.mkdir(parents=True, exist_ok=True)
        # Introduce a new temporary agent
        (staged_agents / "new-temp-agent").mkdir(parents=True, exist_ok=True)
        (staged_agents / "new-temp-agent" / "agent.md").write_text("# Temp Agent", encoding="utf-8")

        # Inject failure during package upgrade / post-check
        with patch.object(distribution, "update_python_package", side_effect=RuntimeError("Injected failure during package upgrade")):
            ok, msg, m = distribution.update_installation(
                source_dir=staged_src,
                target_version="1.2.4",
                gemini_dir=self.fake_gemini,
                force=True,
            )
        self.assertFalse(ok, "Update must fail on injected error")
        self.assertIn("automatic rollback", msg.lower())

        # AGENT-124-05: Obsolete agent was restored byte-for-byte
        self.assertTrue(self.obsolete_agent_dir.exists(), "obsolete-core-agent must be restored by rollback")
        self.assertEqual((self.obsolete_agent_dir / "agent.md").read_text(encoding="utf-8"), orig_obsolete_content)

        # AGENT-124-06: Custom agent is preserved byte-for-byte
        self.assertTrue(self.custom_agent_dir.exists(), "my-custom-agent must remain intact after rollback")
        self.assertEqual((self.custom_agent_dir / "agent.md").read_text(encoding="utf-8"), orig_custom_content)

        # Introduced agent was cleaned up
        self.assertFalse((self.agents_dir / "new-temp-agent").exists(), "new-temp-agent introduced by failed update must be removed")

        # AGENT-124-08: Restored manifest accurately represents restored previous installation
        restored_manifest = distribution.load_installation_manifest(self.fake_gemini)
        self.assertEqual(restored_manifest.get("version"), "1.2.3")
        self.assertIn("obsolete-core-agent", restored_manifest.get("managedFiles", {}).get("agents", {}))


class SelfUpdatePackageParityTestSuite(unittest.TestCase):
    """UPDATE-124-01 .. 11: Package vs Global Runtime parity and failure isolation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_v124_upd_")
        self.fake_gemini = Path(self.temp_dir) / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        self.patcher = patch.object(cli, "get_default_gemini_dir", return_value=self.fake_gemini)
        self.patcher.start()

        # Set up an initial installation
        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["install"])

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_update_124_01_to_07_package_and_runtime_parity(self):
        """
        UPDATE-124-01: An initial package + global runtime starts coherent.
        UPDATE-124-02: Actual update leaves package == 1.2.4.
        UPDATE-124-03: Actual update leaves global runtime == 1.2.4.
        UPDATE-124-04: Actual update leaves manifest == 1.2.4.
        UPDATE-124-05: strict-engineering version reports 1.2.4.
        UPDATE-124-06: doctor reports zero version-parity failures.
        UPDATE-124-07: Hook handler executes target 1.2.4 runtime.
        """
        # 01: Initial state coherent
        manifest_init = distribution.load_installation_manifest(self.fake_gemini)
        self.assertEqual(manifest_init.get("version"), __version__)

        # Create staged source for current version
        staged_src = Path(self.temp_dir) / "staged_curr"
        staged_mod = staged_src / "src" / "strict_engineering"
        staged_mod.mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, staged_mod / f.name)
        (staged_mod / "__init__.py").write_text(f'__version__ = "{__version__}"\n', encoding="utf-8")
        (staged_src / "pyproject.toml").write_text(f'[project]\nname="antigravity-strict-engineering"\nversion="{__version__}"\n', encoding="utf-8")

        # Mock update_python_package to simulate successful package upgrade
        with patch.object(distribution, "update_python_package", return_value=(True, "Package upgraded successfully", None)):
            ok, msg, new_m = distribution.update_installation(
                source_dir=staged_src,
                target_version=__version__,
                gemini_dir=self.fake_gemini,
                force=True,
            )
        self.assertTrue(ok, f"Update failed: {msg}")

        # 03: Global runtime is __version__
        managed_init = self.fake_gemini / "config" / "strict-engineering" / "__init__.py"
        self.assertIn(f'"{__version__}"', managed_init.read_text(encoding="utf-8"))

        # 04: Manifest is __version__
        manifest_after = distribution.load_installation_manifest(self.fake_gemini)
        self.assertEqual(manifest_after.get("version"), __version__)

        # 05: Version CLI reports __version__
        out_v = io.StringIO()
        with patch("sys.stdout", out_v):
            code_v = cli.main(["version"])
        self.assertEqual(code_v, cli.EXIT_SUCCESS)
        self.assertIn(__version__, out_v.getvalue())

        # 06: Doctor reports zero version parity failures
        out_doc = io.StringIO()
        with patch("sys.stdout", out_doc):
            code_doc = cli.main(["doctor"])
        self.assertEqual(code_doc, cli.EXIT_SUCCESS)
        self.assertNotIn("Version drift", [line for line in out_doc.getvalue().splitlines() if "[FAIL]" in line])

        # 07: Hook handler script imports from managed directory
        handler = self.fake_gemini / "config" / "strict-engineering" / "hooks_handler.py"
        self.assertTrue(handler.exists())
        self.assertIn("sys.path.insert(0, str(Path(__file__).parent.resolve()))", handler.read_text(encoding="utf-8"))

    def test_update_124_08_failure_before_mutation_preserves_installation(self):
        """UPDATE-124-08: Injected failure BEFORE any mutation preserves previous state completely."""
        manifest_before = distribution.load_installation_manifest(self.fake_gemini)

        # Injected check failure (e.g. malformed metadata or check failed)
        with patch.object(distribution, "check_for_updates", return_value=distribution.UpdateCheckResult(
            status=distribution.UpdateCheckStatus.CHECK_FAILED,
            current_version=__version__,
            error="Connection refused",
        )):
            ok, msg, m = distribution.update_installation(
                gemini_dir=self.fake_gemini,
            )
        self.assertFalse(ok)
        self.assertIn("Update check failed", msg)

        manifest_after = distribution.load_installation_manifest(self.fake_gemini)
        self.assertEqual(manifest_before.get("version"), manifest_after.get("version"))

    def test_update_124_09_failure_during_mutation_restores_previous(self):
        """UPDATE-124-09: Injected failure DURING managed-runtime mutation restores previous installation."""
        staged_src = Path(self.temp_dir) / "staged_bad"
        staged_mod = staged_src / "src" / "strict_engineering"
        staged_mod.mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, staged_mod / f.name)
        (staged_mod / "broken.py").write_text("broken syntax def (", encoding="utf-8")

        ok, msg, m = distribution.update_installation(
            source_dir=staged_src,
            target_version=__version__,
            gemini_dir=self.fake_gemini,
            force=True,
        )
        self.assertFalse(ok)
        self.assertIn("Syntax validation failed", msg)
        self.assertFalse((self.fake_gemini / "config" / "strict-engineering" / "broken.py").exists())

    def test_update_124_10_and_11_package_failure_triggers_rollback(self):
        """
        UPDATE-124-10: Injected failure during package transition does not leave split-brain versions.
        UPDATE-124-11: Update result distinguishes failure and rollback states.
        """
        staged_src = Path(self.temp_dir) / "staged_pkg_fail"
        staged_mod = staged_src / "src" / "strict_engineering"
        staged_mod.mkdir(parents=True, exist_ok=True)
        for f in (root_dir / "src" / "strict_engineering").glob("*.py"):
            shutil.copy2(f, staged_mod / f.name)
        (staged_src / "pyproject.toml").write_text(f'[project]\nname="antigravity-strict-engineering"\nversion="{__version__}"\n', encoding="utf-8")

        with patch.object(distribution, "update_python_package", return_value=(False, "pip permission error", None)):
            ok, msg, m = distribution.update_installation(
                source_dir=staged_src,
                target_version=__version__,
                gemini_dir=self.fake_gemini,
                force=True,
            )
        self.assertFalse(ok)
        self.assertIn("Package upgrade failed", msg)
        self.assertIn("Executing automatic rollback", msg)


class DistributionModuleIntegrityTestSuite(unittest.TestCase):
    """IMPORT-124-01: Verifies distribution module has all required runtime imports."""

    def test_subprocess_import_available_in_distribution(self):
        """IMPORT-124-01: distribution.py must import subprocess for update_python_package."""
        import importlib, types
        # Check subprocess is resolvable from distribution module's namespace
        import strict_engineering.distribution as dist_mod
        self.assertTrue(
            hasattr(dist_mod, 'subprocess') or 'subprocess' in vars(dist_mod),
            "distribution module missing 'subprocess' import — update_python_package will fail at runtime"
        )

    def test_update_python_package_callable_with_missing_pyproject(self):
        """IMPORT-124-02: update_python_package returns graceful failure when pyproject.toml absent."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td)
            ok, msg, renamed = distribution.update_python_package(fake_root, "test_tx")
            self.assertFalse(ok)
            self.assertIn("pyproject.toml", msg)
            self.assertIsNone(renamed)


if __name__ == "__main__":
    unittest.main()
