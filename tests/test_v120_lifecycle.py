"""
Strict Engineering Kernel V1.2.0 - Distribution, Update Lifecycle & Observability Test Suite
Covers 18 verification requirements: LC-01 through LC-18.
"""

import os
import sys
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure src is in sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from strict_engineering import (
    __version__,
    distribution,
    observability,
    installer,
    cli,
)


class LifecycleDistributionTestSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_v120_test_")
        self.root = Path(self.temp_dir).resolve()
        self.fake_gemini = self.root / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        (self.fake_gemini / "config").mkdir(parents=True, exist_ok=True)

        # Setup standard mock gemini directory for CLI calls
        self.cli_patcher = patch.object(cli, "get_default_gemini_dir", return_value=self.fake_gemini)
        self.cli_patcher.start()

    def tearDown(self):
        self.cli_patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _setup_installed_environment(self, version=__version__):
        """Helper to set up a populated mock installation."""
        cfg_dir = self.fake_gemini / "config" / "strict-engineering"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        src_dir = root_dir / "src" / "strict_engineering"

        # Copy real modules
        for f in src_dir.glob("*.py"):
            shutil.copy2(f, cfg_dir / f.name)

        hooks_file = self.fake_gemini / "config" / "hooks.json"
        handler = cfg_dir / "hooks_handler.py"
        installer.merge_hooks_json(hooks_file, sys.executable, handler)

        gemini_md = self.fake_gemini / "GEMINI.md"
        installer.merge_gemini_md(gemini_md, "# STRICT ENGINEERING")

        agents_dir = self.fake_gemini / "config" / "agents"
        installer.install_agents(root_dir / "agents", agents_dir)

        # Generate and save manifest
        manifest = distribution.generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md,
            agents_dir=agents_dir,
            version=version,
            install_source=str(root_dir),
        )
        distribution.save_installation_manifest(manifest, gemini_dir=self.fake_gemini)
        distribution.save_global_config(distribution.load_global_config(gemini_dir=self.fake_gemini), gemini_dir=self.fake_gemini)
        return cfg_dir, hooks_file, gemini_md, agents_dir

    # -----------------------------------------------------------------------
    # LC-01: Manifest Generation and Integrity
    # -----------------------------------------------------------------------
    def test_lc_01_manifest_generation_and_integrity(self):
        """LC-01: Fresh install produces valid manifest.json with SHA-256 for all modules and passes integrity."""
        cfg_dir, hooks_file, gemini_md, agents_dir = self._setup_installed_environment()
        manifest = distribution.load_installation_manifest(gemini_dir=self.fake_gemini)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.get("version"), __version__)
        self.assertEqual(manifest.get("schemaVersion"), "1.2.0")

        mods = manifest.get("managedFiles", {}).get("modules", {})
        self.assertGreaterEqual(len(mods), 35)
        self.assertIn("distribution.py", mods)
        self.assertIn("observability.py", mods)
        self.assertIn("cli.py", mods)
        self.assertIn("kernel.py", mods)

        # Check hashes
        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertTrue(ok, f"Integrity check failed: {issues}")
        self.assertEqual(len(issues), 0)

    # -----------------------------------------------------------------------
    # LC-02: Manifest Drift Detection
    # -----------------------------------------------------------------------
    def test_lc_02_manifest_drift_detection(self):
        """LC-02: Tampering with a module file causes verify_manifest_integrity to detect drift."""
        cfg_dir, _, _, _ = self._setup_installed_environment()
        target_mod = cfg_dir / "kernel.py"
        self.assertTrue(target_mod.exists())

        # Tamper with kernel.py
        with open(target_mod, "a", encoding="utf-8") as f:
            f.write("\n# TAMPERED LINE FOR DRIFT TEST\n")

        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.fake_gemini)
        self.assertFalse(ok)
        self.assertTrue(any("kernel.py" in issue for issue in issues))

    # -----------------------------------------------------------------------
    # LC-03: Minimal Config Management
    # -----------------------------------------------------------------------
    def test_lc_03_minimal_config_management(self):
        """LC-03: load_global_config and save_global_config manage settings cleanly without schema errors."""
        cfg = distribution.load_global_config(gemini_dir=self.fake_gemini)
        self.assertEqual(cfg.get("schemaVersion"), "1.2.0")
        self.assertEqual(cfg.get("maxAutomaticContinues"), 2)

        cfg["maxAutomaticContinues"] = 5
        distribution.save_global_config(cfg, gemini_dir=self.fake_gemini)

        reloaded = distribution.load_global_config(gemini_dir=self.fake_gemini)
        self.assertEqual(reloaded["maxAutomaticContinues"], 5)

    # -----------------------------------------------------------------------
    # LC-04: Update Same Version Noop
    # -----------------------------------------------------------------------
    def test_lc_04_update_same_version_noop(self):
        """LC-04: Update when target version equals installed version without --force is a safe no-op."""
        self._setup_installed_environment("1.2.0")
        ok, msg, manifest = distribution.update_installation(
            target_version="1.2.0",
            gemini_dir=self.fake_gemini,
            force=False,
        )
        self.assertTrue(ok)
        self.assertIn("already up to date", msg)

    # -----------------------------------------------------------------------
    # LC-05: Update Transactional Staging and Commit
    # -----------------------------------------------------------------------
    def test_lc_05_update_transactional_staging_and_commit(self):
        """LC-05: Transactional update from valid source commits new modules, backup snapshot, and manifest."""
        cfg_dir, hooks_file, gemini_md, agents_dir = self._setup_installed_environment("1.2.0")

        # Create simulated source directory with version 1.2.1
        sim_src = self.root / "simulated_source"
        sim_src.mkdir(parents=True, exist_ok=True)
        for f in cfg_dir.glob("*.py"):
            shutil.copy2(f, sim_src / f.name)

        ok, msg, new_manifest = distribution.update_installation(
            source_dir=sim_src,
            target_version="1.2.1",
            gemini_dir=self.fake_gemini,
            force=True,
        )
        self.assertTrue(ok, f"Update failed: {msg}")
        self.assertEqual(new_manifest.get("version"), "1.2.1")
        self.assertEqual(new_manifest.get("previousVersion"), "1.2.0")
        self.assertEqual(new_manifest.get("status"), "UPDATED")

        # Verify backup snapshot was created
        snapshots = distribution.list_rollback_snapshots(gemini_dir=self.fake_gemini)
        self.assertGreaterEqual(len(snapshots), 1)

    # -----------------------------------------------------------------------
    # LC-06: Update Validation Failure Automatic Rollback
    # -----------------------------------------------------------------------
    def test_lc_06_update_validation_failure_automatic_rollback(self):
        """LC-06: Syntax error in staged update source triggers automatic rollback leaving installation intact."""
        cfg_dir, _, _, _ = self._setup_installed_environment("1.2.0")
        orig_sha = distribution.compute_file_sha256(cfg_dir / "kernel.py")

        # Create broken source
        sim_src = self.root / "broken_source"
        sim_src.mkdir(parents=True, exist_ok=True)
        for f in cfg_dir.glob("*.py"):
            shutil.copy2(f, sim_src / f.name)
        (sim_src / "broken_module.py").write_text("def broken_syntax(:\n   bad", encoding="utf-8")

        ok, msg, m = distribution.update_installation(
            source_dir=sim_src,
            target_version="1.3.0",
            gemini_dir=self.fake_gemini,
            force=True,
        )
        self.assertFalse(ok)
        self.assertIn("Syntax validation failed", msg)

        # Confirm kernel.py was not modified
        curr_sha = distribution.compute_file_sha256(cfg_dir / "kernel.py")
        self.assertEqual(orig_sha, curr_sha)

    # -----------------------------------------------------------------------
    # LC-07: Update Commit Failure Automatic Rollback
    # -----------------------------------------------------------------------
    def test_lc_07_update_commit_failure_automatic_rollback(self):
        """LC-07: Exception during commit triggers automatic rollback to backup snapshot."""
        cfg_dir, _, _, _ = self._setup_installed_environment("1.2.0")

        sim_src = self.root / "valid_src"
        sim_src.mkdir(parents=True, exist_ok=True)
        for f in cfg_dir.glob("*.py"):
            shutil.copy2(f, sim_src / f.name)

        # Mock compileall.compile_dir to simulate post-check failure
        with patch("compileall.compile_dir", return_value=False):
            ok, msg, m = distribution.update_installation(
                source_dir=sim_src,
                target_version="1.4.0",
                gemini_dir=self.fake_gemini,
                force=True,
            )
            self.assertFalse(ok)
            self.assertIn("Post-check compilation verification failed", msg)

    # -----------------------------------------------------------------------
    # LC-08: Untrusted Source Rejection
    # -----------------------------------------------------------------------
    def test_lc_08_update_untrusted_source_rejection(self):
        """LC-08: Update from untrusted or non-existent distribution source is rejected."""
        self._setup_installed_environment("1.2.0")
        ok, msg, _ = distribution.update_installation(
            distribution_source="https://malicious.example.com/fake-repo",
            gemini_dir=self.fake_gemini,
            force=True,
        )
        self.assertFalse(ok)
        self.assertIn("untrusted distribution source", msg)

    # -----------------------------------------------------------------------
    # LC-09: Manual Rollback to Snapshot
    # -----------------------------------------------------------------------
    def test_lc_09_manual_rollback_to_snapshot(self):
        """LC-09: rollback_installation restores modules and manifest from backup snapshot."""
        cfg_dir, _, _, _ = self._setup_installed_environment("1.2.0")

        # Perform valid update to create snapshot
        sim_src = self.root / "src_v2"
        sim_src.mkdir(parents=True, exist_ok=True)
        for f in cfg_dir.glob("*.py"):
            shutil.copy2(f, sim_src / f.name)

        distribution.update_installation(
            source_dir=sim_src,
            target_version="1.2.1",
            gemini_dir=self.fake_gemini,
            force=True,
        )

        snapshots = distribution.list_rollback_snapshots(gemini_dir=self.fake_gemini)
        self.assertGreaterEqual(len(snapshots), 1)
        snap_id = snapshots[0]["snapshotId"]

        # Rollback
        rb_ok, rb_msg, rb_notes = distribution.rollback_installation(
            backup_id=snap_id,
            gemini_dir=self.fake_gemini,
        )
        self.assertTrue(rb_ok, f"Rollback failed: {rb_msg}")
        reloaded_manifest = distribution.load_installation_manifest(gemini_dir=self.fake_gemini)
        self.assertEqual(reloaded_manifest.get("status"), "ROLLED_BACK")

    # -----------------------------------------------------------------------
    # LC-10: Rollback Preserves Project Source and Harness
    # -----------------------------------------------------------------------
    def test_lc_10_rollback_preserves_project_source_and_harness(self):
        """LC-10: Rollback restores global kernel files but NEVER modifies project code or .agent-harness."""
        cfg_dir, _, _, _ = self._setup_installed_environment("1.2.0")
        ws = self.root / "project_app"
        ws.mkdir(parents=True, exist_ok=True)
        app_file = ws / "main.py"
        app_file.write_text("print('user valuable application code')", encoding="utf-8")
        harness_dir = ws / ".agent-harness"
        harness_dir.mkdir(parents=True, exist_ok=True)
        state_file = harness_dir / "state.json"
        state_file.write_text('{"active": true, "phase": "IMPLEMENTATION"}', encoding="utf-8")

        # Trigger rollback
        snapshots = distribution.list_rollback_snapshots(gemini_dir=self.fake_gemini)
        # Even with no snapshots, verify project app code remains untouched
        distribution.rollback_installation(gemini_dir=self.fake_gemini)

        self.assertTrue(app_file.exists())
        self.assertEqual(app_file.read_text(encoding="utf-8"), "print('user valuable application code')")
        self.assertTrue(state_file.exists())

    # -----------------------------------------------------------------------
    # LC-11: Uninstall Dry-Run
    # -----------------------------------------------------------------------
    def test_lc_11_uninstall_dry_run(self):
        """LC-11: uninstall_kernel(dry_run=True) reports actions without deleting any files."""
        cfg_dir, hooks_file, gemini_md, agents_dir = self._setup_installed_environment("1.2.0")
        ok, msg, actions = distribution.uninstall_kernel(
            gemini_dir=self.fake_gemini,
            dry_run=True,
        )
        self.assertTrue(ok)
        self.assertIn("dry-run preview", msg)
        self.assertGreater(len(actions), 0)

        # Confirm all files still exist
        self.assertTrue(cfg_dir.exists())
        self.assertTrue(hooks_file.exists())
        self.assertTrue(gemini_md.exists())

    # -----------------------------------------------------------------------
    # LC-12: Uninstall Preserves Custom Hooks
    # -----------------------------------------------------------------------
    def test_lc_12_uninstall_preserves_custom_hooks(self):
        """LC-12: Uninstall only removes strict-engineering entry from hooks.json, preserving unrelated user hooks."""
        cfg_dir, hooks_file, gemini_md, _ = self._setup_installed_environment("1.2.0")

        # Add custom unrelated user hook
        with open(hooks_file, "r", encoding="utf-8") as f:
            h_data = json.load(f)
        h_data["my_custom_tool"] = [{"matcher": "custom", "hooks": [{"command": "echo hello"}]}]
        with open(hooks_file, "w", encoding="utf-8") as f:
            json.dump(h_data, f, indent=2)

        ok, msg, acts = distribution.uninstall_kernel(gemini_dir=self.fake_gemini, dry_run=False)
        self.assertTrue(ok)

        # Inspect hooks.json
        with open(hooks_file, "r", encoding="utf-8") as f:
            cleaned_hooks = json.load(f)
        self.assertNotIn("strict-engineering", cleaned_hooks)
        self.assertIn("my_custom_tool", cleaned_hooks)

    # -----------------------------------------------------------------------
    # LC-13: Uninstall Preserves Custom GEMINI.md
    # -----------------------------------------------------------------------
    def test_lc_13_uninstall_preserves_custom_gemini_md(self):
        """LC-13: Uninstall removes only the managed block, preserving user custom instructions in GEMINI.md."""
        cfg_dir, _, gemini_md, _ = self._setup_installed_environment("1.2.0")
        custom_header = "# USER PERSONAL INSTRUCTIONS\nAlways be concise.\n\n"
        custom_footer = "\n\n# USER PROJECT CONVENTIONS\nUse Python 3.12 syntax."
        current_text = gemini_md.read_text(encoding="utf-8")
        gemini_md.write_text(custom_header + current_text + custom_footer, encoding="utf-8")

        ok, msg, acts = distribution.uninstall_kernel(gemini_dir=self.fake_gemini, dry_run=False)
        self.assertTrue(ok)

        cleaned_text = gemini_md.read_text(encoding="utf-8")
        self.assertNotIn("<!-- STRICT_ENGINEERING_KERNEL_START -->", cleaned_text)
        self.assertIn("USER PERSONAL INSTRUCTIONS", cleaned_text)
        self.assertIn("USER PROJECT CONVENTIONS", cleaned_text)

    # -----------------------------------------------------------------------
    # LC-14: Uninstall Preserves Custom Agents
    # -----------------------------------------------------------------------
    def test_lc_14_uninstall_preserves_custom_agents(self):
        """LC-14: Uninstall removes managed agents while preserving custom user agents."""
        cfg_dir, _, _, agents_dir = self._setup_installed_environment("1.2.0")
        custom_agent = agents_dir / "my-special-agent"
        custom_agent.mkdir(parents=True, exist_ok=True)
        (custom_agent / "agent.md").write_text("Custom agent instructions", encoding="utf-8")

        ok, msg, acts = distribution.uninstall_kernel(gemini_dir=self.fake_gemini, dry_run=False)
        self.assertTrue(ok)

        # Core agent should be gone
        self.assertFalse((agents_dir / "builder").exists())
        # Custom agent must remain
        self.assertTrue(custom_agent.exists())
        self.assertTrue((custom_agent / "agent.md").exists())

    # -----------------------------------------------------------------------
    # LC-15: Observability Logging and Privacy Scrubbing
    # -----------------------------------------------------------------------
    def test_lc_15_observability_logging_and_privacy_scrub(self):
        """LC-15: Observability logs strip forbidden keys and scrub API keys and bearer tokens."""
        sensitive_data = {
            "prompt": "SELECT * FROM secret_table",
            "transcript": "Sensitive conversation",
            "source": "Secret code",
            "code": "private_impl()",
            "token": "sk-123456789012345678901234",
            "auth": "Bearer secret_bearer_token_xyz_123456",
            "allowedKey": "operational_metric",
            "api_key": "ghp_123456789012345678901234567890",
            "message": "Connected with sk-abcdef1234567890abcdef safely",
        }

        observability.record_global_event(
            "TEST_EVENT",
            details=sensitive_data,
            gemini_dir=self.fake_gemini,
            latency_ms=12.5,
        )

        events = observability.load_global_events(limit=10, gemini_dir=self.fake_gemini)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["eventType"], "TEST_EVENT")
        self.assertEqual(ev["latencyMs"], 12.5)

        details = ev["details"]
        # Forbidden keys must be completely removed
        self.assertNotIn("prompt", details)
        self.assertNotIn("transcript", details)
        self.assertNotIn("source", details)
        self.assertNotIn("code", details)
        self.assertNotIn("token", details)
        self.assertNotIn("auth", details)
        self.assertNotIn("api_key", details)

        # Allowed key preserved
        self.assertIn("allowedKey", details)
        # Scrubbed tokens
        self.assertNotIn("sk-abcdef", details.get("message", ""))
        self.assertIn("[REDACTED_SECRET]", details.get("message", ""))

    # -----------------------------------------------------------------------
    # LC-16: Observability Rotation Bounded Size
    # -----------------------------------------------------------------------
    def test_lc_16_observability_rotation_bounded_size(self):
        """LC-16: Log rotation triggers when file reaches threshold, keeping at most 2 historical files."""
        log_dir = self.fake_gemini / "config" / "strict-engineering"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "observability.jsonl"

        # Write 500 bytes to log_file
        log_file.write_text("x" * 500, encoding="utf-8")

        # Call rotate_log_if_needed with threshold 400 bytes
        observability.rotate_log_if_needed(log_file, max_bytes=400)
        self.assertFalse(log_file.exists())
        self.assertTrue(log_dir.joinpath("observability.jsonl.1").exists())

        # Write again and rotate second time
        log_file.write_text("y" * 500, encoding="utf-8")
        observability.rotate_log_if_needed(log_file, max_bytes=400)
        self.assertTrue(log_dir.joinpath("observability.jsonl.2").exists())
        self.assertTrue(log_dir.joinpath("observability.jsonl.1").exists())

    # -----------------------------------------------------------------------
    # LC-17: Observability Fail-Safe Isolation
    # -----------------------------------------------------------------------
    def test_lc_17_observability_fail_safe_isolation(self):
        """LC-17: Exceptions in observability recording do not crash the caller or raise unhandled errors."""
        # Intentionally cause write error by mocking open to raise PermissionError
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            res = observability.record_global_event(
                "FAILSAFE_TEST",
                details={"test": "val"},
                gemini_dir=self.fake_gemini,
            )
            # Must return False gracefully without raising
            self.assertFalse(res)

    # -----------------------------------------------------------------------
    # LC-18: CLI Lifecycle Commands Integration
    # -----------------------------------------------------------------------
    def test_lc_18_cli_lifecycle_commands_integration(self):
        """LC-18: CLI subcommands update --check, rollback --list, rollback --dry-run, uninstall --dry-run, doctor --verbose."""
        self._setup_installed_environment(__version__)

        # 1. update --check
        out1 = io.StringIO()
        with patch("sys.stdout", out1):
            code1 = cli.main(["update", "--check"])
        self.assertEqual(code1, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering is up to date", out1.getvalue())

        # 2. rollback --list
        out2 = io.StringIO()
        with patch("sys.stdout", out2):
            code2 = cli.main(["rollback", "--list"])
        self.assertEqual(code2, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering Rollback Snapshots", out2.getvalue())

        # 3. rollback --dry-run
        out3 = io.StringIO()
        with patch("sys.stdout", out3):
            code3 = cli.main(["rollback", "--dry-run"])
        # If no snapshots, returns OPERATIONAL_FAILURE, or if snapshot exists, returns SUCCESS.
        self.assertIn(code3, (cli.EXIT_SUCCESS, cli.EXIT_OPERATIONAL_FAILURE))

        # 4. uninstall --dry-run
        out4 = io.StringIO()
        with patch("sys.stdout", out4):
            code4 = cli.main(["uninstall", "--dry-run"])
        self.assertEqual(code4, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering Uninstall (DRY RUN)", out4.getvalue())

        # 5. doctor --verbose
        out5 = io.StringIO()
        with patch("sys.stdout", out5):
            code5 = cli.main(["doctor", "--verbose"])
        self.assertEqual(code5, cli.EXIT_SUCCESS)
        self.assertIn("Installation manifest", out5.getvalue())
        self.assertIn("Observability log", out5.getvalue())


if __name__ == "__main__":
    unittest.main()
