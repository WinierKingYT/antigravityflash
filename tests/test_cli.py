"""
Strict Engineering Kernel V1.1.0 - Operational CLI Test Suite
Verifies all strict-engineering subcommands, exit codes, edge cases,
doctor checks, reversibility, and Windows path handling.
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
from unittest.mock import patch

# Ensure src is in sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from strict_engineering import (
    __version__,
    cli,
    kernel,
    installer,
    runtime_safety,
)


class CLITestSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_cli_test_")
        self.root = Path(self.temp_dir).resolve()
        self.fake_gemini = self.root / ".gemini"
        self.fake_gemini.mkdir(parents=True, exist_ok=True)
        (self.fake_gemini / "config").mkdir(parents=True, exist_ok=True)

        # Patch get_default_gemini_dir to use fake_gemini
        self.gemini_patcher = patch.object(cli, "get_default_gemini_dir", return_value=self.fake_gemini)
        self.gemini_patcher.start()

    def tearDown(self):
        self.gemini_patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_01_help_and_empty_args(self):
        """CLI-01: --help and empty args exit with code 0 and display usage."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code_empty = cli.main([])
            code_help = cli.main(["--help"])
        self.assertEqual(code_empty, cli.EXIT_SUCCESS)
        self.assertEqual(code_help, cli.EXIT_SUCCESS)
        self.assertIn("usage: strict-engineering", out.getvalue())

    def test_cli_02_version_command_no_mutation(self):
        """CLI-02: version displays version, Python info, and install status without mutation."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["version"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn(f"Kernel Version:             {__version__}", output)
        self.assertIn("Python Version:", output)
        self.assertIn("Global Modules:", output)
        # Ensure no files were created in a clean temp root
        created = list(self.root.iterdir())
        self.assertEqual(created, [self.fake_gemini])

    def test_cli_03_install_command_concise_checks(self):
        """CLI-03: install command copies modules, merges hooks, GEMINI block, and agents."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["install"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("[OK] Kernel modules:", output)
        self.assertIn("[OK] PreToolUse hook:", output)
        self.assertIn("[OK] PreInvocation hook:", output)
        self.assertIn("[OK] Stop hook:", output)

        # Verify filesystem artifacts
        mod_dir = self.fake_gemini / "config" / "strict-engineering"
        self.assertTrue(mod_dir.exists())
        self.assertTrue((mod_dir / "kernel.py").exists())
        self.assertTrue((mod_dir / "cli.py").exists())

        hooks_file = self.fake_gemini / "config" / "hooks.json"
        self.assertTrue(hooks_file.exists())
        hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
        self.assertIn("strict-engineering", hooks_data)

    def test_cli_04_init_in_clean_git_repo_with_intent(self):
        """CLI-04: init initializes .agent-harness and sets SPECIFICATION phase with intent."""
        repo = self.root / "clean_repo"
        repo.mkdir(parents=True, exist_ok=True)
        # Init dummy git repo
        (repo / ".git").mkdir()

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["init", "--workspace", str(repo), "--intent", "Build a calculator CLI"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("Strict Engineering Harness initialized successfully", output)

        harness_dir = repo / ".agent-harness"
        self.assertTrue(harness_dir.exists())
        state = json.loads((harness_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state.get("phase"), "SPECIFICATION")
        self.assertEqual(state.get("runtimeStatus"), "RUNNING")
        self.assertTrue(kernel.verify_original_intent_integrity(repo))

    def test_cli_05_init_in_dirty_repo_reports_warning(self):
        """CLI-05: init detects uncommitted files in a git repo and issues a warning."""
        repo = self.root / "dirty_repo"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / ".git").mkdir()

        # Mock git status returning dirty files
        mock_proc = subprocess.CompletedProcess(
            args=["git", "status", "--porcelain"],
            returncode=0,
            stdout=" M dirty_file.py\n?? untracked.txt\n",
            stderr="",
        )
        out = io.StringIO()
        with patch("subprocess.run", return_value=mock_proc):
            with patch("sys.stdout", out):
                code = cli.main(["init", "--workspace", str(repo), "--intent", "Clean feature"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("[WARN] Workspace has 2 uncommitted change(s)", out.getvalue())

    def test_cli_06_init_existing_harness_blocked_without_force(self):
        """CLI-06: init on an existing active harness without --force is blocked with exit code 3."""
        repo = self.root / "existing_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Existing goal")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["init", "--workspace", str(repo), "--intent", "New goal"])
        self.assertEqual(code, cli.EXIT_HARNESS_BLOCKED)
        self.assertIn("[BLOCKED] Strict Engineering harness already exists", out.getvalue())

    def test_cli_07_init_existing_harness_with_force_succeeds(self):
        """CLI-07: init with --force overwrites existing harness cleanly."""
        repo = self.root / "force_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Old goal")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["init", "--workspace", str(repo), "--intent", "Overwritten goal", "--force"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering Harness initialized successfully", out.getvalue())
        req_content = (repo / ".agent-harness" / "original-request.md").read_text(encoding="utf-8").strip()
        self.assertEqual(req_content, "Overwritten goal")

    def test_cli_08_init_without_intent_in_non_interactive_fails(self):
        """CLI-08: init without intent in non-interactive environment rejects fabrication (exit code 2)."""
        repo = self.root / "no_intent_repo"
        repo.mkdir(parents=True, exist_ok=True)

        out = io.StringIO()
        with patch("sys.stdin.isatty", return_value=False):
            with patch("sys.stdout", out):
                code = cli.main(["init", "--workspace", str(repo)])
        self.assertEqual(code, cli.EXIT_INVALID_USAGE)
        output = out.getvalue()
        self.assertIn("[ERROR] No project intent provided", output)
        self.assertIn("refuses to invent synthetic user intent", output)

    def test_cli_09_init_with_await_intent_flag(self):
        """CLI-09: init --await-intent initializes in safe AWAITING_INTENT phase."""
        repo = self.root / "await_intent_repo"
        repo.mkdir(parents=True, exist_ok=True)

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["init", "--workspace", str(repo), "--await-intent"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        state = kernel.load_state(repo)
        self.assertEqual(state.get("phase"), "AWAITING_INTENT")
        self.assertTrue(state.get("active"))

    def test_cli_10_status_inactive(self):
        """CLI-10: status reports INACTIVE when .agent-harness is absent."""
        repo = self.root / "inactive_repo"
        repo.mkdir(parents=True, exist_ok=True)

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["status", "--workspace", str(repo)])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering Status: INACTIVE", out.getvalue())

    def test_cli_11_status_active_human_readable(self):
        """CLI-11: status reports comprehensive phase, requirements, locks, and blocker details."""
        repo = self.root / "active_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Active status project")

        # Add dummy requirements
        kernel.save_requirements(repo, [
            {"id": "REQ-001", "status": "PASS"},
            {"id": "REQ-002", "status": "IN_PROGRESS"},
        ])

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["status", "--workspace", str(repo)])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("Strict Engineering Status: ACTIVE", output)
        self.assertIn("Lifecycle Phase:      SPECIFICATION", output)
        self.assertIn("Runtime Status:       RUNNING", output)
        self.assertIn("Requirements:         Total=2", output)
        self.assertIn("Completion Readiness: BLOCKED", output)
        self.assertIn("requirement(s) not in PASS status", output)

    def test_cli_12_status_json_output(self):
        """CLI-12: status --json returns valid parseable JSON with all fields."""
        repo = self.root / "json_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="JSON project")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["status", "--workspace", str(repo), "--json"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        data = json.loads(out.getvalue())
        self.assertTrue(data.get("active"))
        self.assertEqual(data.get("phase"), "SPECIFICATION")
        self.assertEqual(data.get("runtimeStatus"), "RUNNING")
        self.assertIn("requirements", data)
        self.assertIn("blockedReasons", data)
        self.assertFalse(data.get("completionReady"))

    def test_cli_13_doctor_healthy(self):
        """CLI-13: doctor on fully configured environment returns PASS across core checks."""
        # Install global hooks and modules first
        cli.main(["install"])

        repo = self.root / "doctor_repo"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / ".git").mkdir()
        kernel.initialize_harness(repo, original_intent="Doctor verified project")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["doctor", "--workspace", str(repo)])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("[PASS]           Python compatibility:", output)
        self.assertIn("[PASS]           Global kernel install:", output)
        self.assertIn("[PASS]           Hook configuration:", output)
        self.assertIn("[PASS]           GEMINI managed block:", output)
        self.assertIn("[PASS]           Project harness integrity:", output)
        self.assertIn("[PASS]           State/evidence integrity:", output)

    def test_cli_14_doctor_broken_hook_target_fails(self):
        """CLI-14: doctor with missing hook target reports FAIL and returns code 1."""
        cli.main(["install"])
        # Delete the installed hooks_handler.py to simulate broken hook target
        handler = self.fake_gemini / "config" / "strict-engineering" / "hooks_handler.py"
        if handler.exists():
            handler.unlink()

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["doctor", "--workspace", str(self.root)])
        self.assertEqual(code, cli.EXIT_OPERATIONAL_FAILURE)
        self.assertIn("[FAIL]           Hook target files:", out.getvalue())

    def test_cli_15_doctor_version_drift(self):
        """CLI-15: doctor detects version mismatch between installed file and package."""
        cli.main(["install"])
        # Alter the version in installed __init__.py
        installed_init = self.fake_gemini / "config" / "strict-engineering" / "__init__.py"
        installed_init.write_text('__version__ = "0.9.0"\n', encoding="utf-8")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["doctor", "--workspace", str(self.root)])
        self.assertIn("[WARN]           Version drift:", out.getvalue())
        self.assertIn("Installed version 0.9.0 differs from package version", out.getvalue())

    def test_cli_16_pause_operation_and_state_preservation(self):
        """CLI-16: pause sets PAUSED_USER_REQUEST and preserves requirements without altering them."""
        repo = self.root / "pause_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Pause project")
        kernel.save_requirements(repo, [{"id": "REQ-P1", "status": "PASS"}])

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["pause", "--workspace", str(repo), "--reason", "User requested pause"])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("[OK]", out.getvalue())

        state = kernel.load_state(repo)
        self.assertEqual(state.get("runtimeStatus"), "PAUSED_USER_REQUEST")
        self.assertEqual(state.get("pauseReason"), "User requested pause")
        self.assertEqual(state.get("phase"), "SPECIFICATION")

        # Invariant: requirements remain unaltered
        reqs = kernel.load_requirements(repo)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["status"], "PASS")

    def test_cli_17_resume_operation(self):
        """CLI-17: resume restores RUNNING status using V1.0.2 semantics."""
        repo = self.root / "resume_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Resume project")
        runtime_safety.pause_harness(repo, reason="Paused before resume")

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["resume", "--workspace", str(repo)])
        self.assertEqual(code, cli.EXIT_SUCCESS)
        self.assertIn("[OK]", out.getvalue())

        state = kernel.load_state(repo)
        self.assertEqual(state.get("runtimeStatus"), "RUNNING")
        self.assertIsNone(state.get("pauseReason"))

    def test_cli_18_disable_and_enable_hooks_reversible(self):
        """CLI-18: disable and enable reversibly toggle hooks preserving other keys in hooks.json."""
        cli.main(["install"])
        hooks_file = self.fake_gemini / "config" / "hooks.json"

        # Inject unrelated custom setting
        data = json.loads(hooks_file.read_text(encoding="utf-8"))
        data["unrelated_custom_tool"] = {"setting": "preserve_me"}
        hooks_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Disable
        out_dis = io.StringIO()
        with patch("sys.stdout", out_dis):
            code_dis = cli.main(["disable"])
        self.assertEqual(code_dis, cli.EXIT_SUCCESS)
        self.assertIn("successfully disabled", out_dis.getvalue())

        data_dis = json.loads(hooks_file.read_text(encoding="utf-8"))
        self.assertNotIn("strict-engineering", data_dis)
        self.assertIn("_disabled_strict-engineering", data_dis)
        self.assertIn("unrelated_custom_tool", data_dis)
        self.assertEqual(data_dis["unrelated_custom_tool"]["setting"], "preserve_me")

        # Enable
        out_en = io.StringIO()
        with patch("sys.stdout", out_en):
            code_en = cli.main(["enable"])
        self.assertEqual(code_en, cli.EXIT_SUCCESS)
        self.assertIn("successfully enabled", out_en.getvalue())

        data_en = json.loads(hooks_file.read_text(encoding="utf-8"))
        self.assertIn("strict-engineering", data_en)
        self.assertNotIn("_disabled_strict-engineering", data_en)
        self.assertIn("unrelated_custom_tool", data_en)

    def test_cli_19_status_shows_disabled_when_hooks_disabled(self):
        """CLI-19: status clearly reflects disabled state when hooks are disabled."""
        cli.main(["install"])
        cli.main(["disable"])

        repo = self.root / "disabled_status_repo"
        repo.mkdir(parents=True, exist_ok=True)
        kernel.initialize_harness(repo, original_intent="Disabled status check")

        out = io.StringIO()
        with patch("sys.stdout", out):
            cli.main(["status", "--workspace", str(repo)])
        output = out.getvalue()
        self.assertIn("Global Hooks:         DISABLED", output)
        self.assertIn("Hooks are globally disabled in ~/.gemini/config/hooks.json", output)

    def test_cli_20_paths_with_spaces_and_windows_slashes(self):
        """CLI-20: paths with spaces and Windows backslashes are handled cleanly."""
        spaced_repo = self.root / "path with spaces" / "sub folder"
        spaced_repo.mkdir(parents=True, exist_ok=True)

        out = io.StringIO()
        with patch("sys.stdout", out):
            code = cli.main(["init", "--workspace", str(spaced_repo), "--intent", "Project with spaced path"])
        self.assertEqual(code, cli.EXIT_SUCCESS)

        out_stat = io.StringIO()
        with patch("sys.stdout", out_stat):
            code_stat = cli.main(["status", "--workspace", str(spaced_repo)])
        self.assertEqual(code_stat, cli.EXIT_SUCCESS)
        self.assertIn("Strict Engineering Status: ACTIVE", out_stat.getvalue())


if __name__ == "__main__":
    unittest.main()
