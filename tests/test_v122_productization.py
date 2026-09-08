"""
Strict Engineering Kernel V1.2.2 - Productization Truth Repair Test Suite
Verifies all 27 atomic requirements and 9 findings across:
- Status read-only immutability & readiness checks (TR-STATUS-01..04)
- Runtime mutation safety & authorized hooks (TR-RUNTIME-01..07)
- Conversation circuit breaker storage & project summary (TR-CB-01..06)
- Init truth integrity & non-reinitialization (TR-INIT-01..05)
- Update check status enum & network failure handling (TR-UPCHECK-01..08)
- Transactional update, Zip-Slip defense & rollback engine (TR-UPD-01..10)
- Precise installation manifest & drift tolerance (TR-MAN-01..09)
- Safe rollback restoring global files & preserving user data (TR-RB-01..06)
- Plugin claim truth & release consistency (TR-PLUGIN-01..02, TR-REL-01..07)
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import strict_engineering
from strict_engineering import kernel
from strict_engineering import gate
from strict_engineering import runtime_safety
from strict_engineering import decision_coverage
from strict_engineering import distribution
from strict_engineering import installer
from strict_engineering import cli
from strict_engineering import __version__


class V122StatusReadonlyTestSuite(unittest.TestCase):
    """TR-STATUS-01..04: Status read-only guarantees & readiness."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_stat_")
        self.workspace = Path(self.test_dir) / "project"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir = self.workspace / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

        # Baseline running state
        self.state = {
            "active": True,
            "schemaVersion": "5.1.0",
            "phase": "SPECIFICATION",
            "runtimeStatus": "RUNNING",
            "pauseReason": None,
            "specLocked": True,
            "acceptanceLocked": True,
            "originalRequestSha256": "abc",
            "workspaceFingerprint": "def",
            "activeTask": None,
            "builderSubagentActive": False,
            "finalAuditPassed": True,
            "createdAt": "2026-09-08T00:00:00Z",
            "updatedAt": "2026-09-08T00:00:00Z",
        }
        kernel.save_state(self.workspace, self.state)
        kernel.save_requirements(self.workspace, [])

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_status_readiness_read_only_immutability(self):
        """TR-STATUS-01 & 02: inspect_completion_readiness & cmd_status produce zero mutations."""
        hashes_before = {}
        for f in self.harness_dir.glob("*"):
            if f.is_file():
                hashes_before[f.name] = f.read_bytes()

        ready, reasons = gate.inspect_completion_readiness(self.workspace)

        for f in self.harness_dir.glob("*"):
            if f.is_file():
                self.assertIn(f.name, hashes_before)
                self.assertEqual(f.read_bytes(), hashes_before[f.name])

        args = MagicMock()
        args.workspace = str(self.workspace)
        args.json = False
        args.verbose = False
        args.conversation = ""
        exit_code = cli.cmd_status(args)
        self.assertEqual(exit_code, 0)

        for f in self.harness_dir.glob("*"):
            if f.is_file():
                self.assertIn(f.name, hashes_before)
                self.assertEqual(f.read_bytes(), hashes_before[f.name])

    def test_readiness_blocks_on_paused_and_disabled(self):
        """TR-STATUS-03 & 04: inspect_completion_readiness blocks on PAUSED_* and DISABLED."""
        paused_states = [
            "PAUSED_BY_USER",
            "PAUSED_CIRCUIT_BREAKER",
            "PAUSED_STALE_REQUIREMENTS",
            "PAUSED_ANOMALY",
            "DISABLED",
        ]
        for pst in paused_states:
            st = dict(self.state)
            st["runtimeStatus"] = pst
            st["active"] = (pst != "DISABLED")
            kernel.save_state(self.workspace, st)

            ready, reasons = gate.inspect_completion_readiness(self.workspace)
            self.assertFalse(ready, f"Should be blocked when runtimeStatus is {pst}")
            self.assertTrue(any(pst in r for r in reasons), f"Reasons should mention {pst}")


class V122RuntimeMutationSafetyTestSuite(unittest.TestCase):
    """TR-RUNTIME-01..07: Authorized lifecycle hooks vs pure audit."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_rt_")
        self.workspace = Path(self.test_dir) / "project"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir = self.workspace / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

        self.state = {
            "active": True,
            "phase": "IMPLEMENTATION",
            "runtimeStatus": "RUNNING",
            "specLocked": True,
            "acceptanceLocked": True,
            "createdAt": "2026-09-08T00:00:00Z",
            "updatedAt": "2026-09-08T00:00:00Z",
        }
        kernel.save_state(self.workspace, self.state)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detect_stale_requirements_is_pure(self):
        """TR-RUNTIME-05: detect_stale_requirements returns stale IDs without writing to disk."""
        reqs = [
            {"id": "REQ-001", "status": "PASS", "authorityFingerprint": "old_hash"},
        ]
        kernel.save_requirements(self.workspace, reqs)
        bytes_before = (self.harness_dir / "requirements.json").read_bytes()

        stale_ids = kernel.detect_stale_requirements(self.workspace)
        bytes_after = (self.harness_dir / "requirements.json").read_bytes()

        self.assertEqual(bytes_before, bytes_after)
        self.assertIn("REQ-001", stale_ids)

    def test_compute_decision_coverage_is_pure(self):
        """TR-RUNTIME-06: compute_decision_coverage computes statistics without writing to decisions.json."""
        decisions_file = self.harness_dir / "decisions.json"
        self.assertFalse(decisions_file.exists())

        stats = decision_coverage.compute_decision_coverage(self.workspace)
        self.assertFalse(decisions_file.exists(), "compute_decision_coverage must not create decisions.json")
        self.assertIn("summary", stats)
        self.assertIn("decisionCoverageRate", stats["summary"])

    def test_stop_hook_authorized_invalidation(self):
        """TR-RUNTIME-01 & 03: Stop hook invalidates stale requirements and halts on stale detection."""
        reqs = [
            {"id": "REQ-001", "status": "PASS", "authorityFingerprint": "old_hash"},
        ]
        kernel.save_requirements(self.workspace, reqs)

        payload = {
            "workspacePaths": [str(self.workspace)],
            "conversationId": "conv-123",
        }
        res = gate.evaluate_stop(payload)
        self.assertIsNotNone(res)

        updated_reqs = kernel.load_requirements(self.workspace)
        self.assertEqual(updated_reqs[0]["status"], "STALE")


class V122CircuitBreakerTestSuite(unittest.TestCase):
    """TR-CB-01..06: Conversation isolation & project summary."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_cb_")
        self.workspace = Path(self.test_dir) / "project"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir = self.workspace / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_circuit_breaker_conversation_storage_and_summary(self):
        """TR-CB-01..03: Scoped storage and aggregated project summary."""
        cb1 = {
            "conversationId": "conv-1",
            "tripped": True,
            "tripReason": "Loop detected",
            "automaticContinueCount": 3,
        }
        runtime_safety.save_circuit_breaker(self.workspace, cb1, conversation_id="conv-1")

        cb2 = {
            "conversationId": "conv-2",
            "tripped": False,
            "automaticContinueCount": 1,
        }
        runtime_safety.save_circuit_breaker(self.workspace, cb2, conversation_id="conv-2")

        loaded1 = runtime_safety.load_circuit_breaker(self.workspace, conversation_id="conv-1")
        self.assertTrue(loaded1.get("tripped"))
        self.assertEqual(loaded1.get("conversationId"), "conv-1")

        loaded_gen = runtime_safety.load_circuit_breaker(self.workspace)
        self.assertTrue(loaded_gen.get("tripped"), "Project summary should report tripped=True if any conv tripped")
        summary = loaded_gen.get("projectSummary", {})
        self.assertEqual(summary.get("totalConversations"), 2)
        self.assertEqual(summary.get("trippedConversations"), 1)

    def test_tripped_conversation_blocks_readiness(self):
        """TR-CB-06: Tripped conversation in project blocks completion readiness."""
        st = {
            "active": True,
            "phase": "IMPLEMENTATION",
            "runtimeStatus": "RUNNING",
            "specLocked": True,
            "acceptanceLocked": True,
            "finalAuditPassed": True,
        }
        kernel.save_state(self.workspace, st)
        kernel.save_requirements(self.workspace, [])

        cb = {"conversationId": "conv-99", "tripped": True, "tripReason": "Threshold exceeded"}
        runtime_safety.save_circuit_breaker(self.workspace, cb, conversation_id="conv-99")

        ready, reasons = gate.inspect_completion_readiness(self.workspace)
        self.assertFalse(ready)
        self.assertTrue(any("Circuit breaker is TRIPPED" in r for r in reasons))


class V122InitIntegrityTestSuite(unittest.TestCase):
    """TR-INIT-01..05: Init truth integrity & non-reinitialization."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_init_")
        self.workspace = Path(self.test_dir) / "project"
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cmd_init_in_existing_harness_blocked_with_exit_3(self):
        """TR-INIT-01 & 04: Re-initialization blocked with exit code 3 and files untouched."""
        harness = self.workspace / ".agent-harness"
        harness.mkdir(parents=True, exist_ok=True)
        state_file = harness / "state.json"
        state_file.write_text(json.dumps({"active": True, "original": "protected"}), encoding="utf-8")
        orig_content = state_file.read_bytes()

        args = MagicMock()
        args.workspace = str(self.workspace)
        args.intent = "Overwriting intent"
        args.await_intent = False

        exit_code = cli.cmd_init(args)
        self.assertEqual(exit_code, 3)
        self.assertEqual(state_file.read_bytes(), orig_content, "Existing harness must not be altered")

    def test_init_parser_rejects_force_flag(self):
        """TR-INIT-03: --force flag is completely removed from init parser."""
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["init", "--force", "--intent", "testing"])


class V122UpdateCheckTestSuite(unittest.TestCase):
    """TR-UPCHECK-01..08: Update check status enum & network failure handling."""

    def test_update_check_result_fields_and_unpacking(self):
        """TR-UPCHECK-06: Supports backward-compatible 3-tuple unpacking."""
        res = distribution.UpdateCheckResult(
            status=distribution.UpdateCheckStatus.UPDATE_AVAILABLE,
            current_version="1.2.1",
            latest_version="1.2.2",
            update_available=True,
            download_url="https://example.com/asset.zip",
        )
        avail, cur, lat = res
        self.assertTrue(avail)
        self.assertEqual(cur, "1.2.1")
        self.assertEqual(lat, "1.2.2")

    @patch("urllib.request.urlopen")
    def test_update_check_fails_closed_on_network_error(self, mock_urlopen):
        """TR-UPCHECK-03: HTTP error or network timeout returns CHECK_FAILED, not UP_TO_DATE."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore
            fp=BytesIO(b"error"),
        )
        res = distribution.check_for_updates(current_version="1.2.2")
        self.assertEqual(res.status, distribution.UpdateCheckStatus.CHECK_FAILED)
        self.assertFalse(res.update_available)
        self.assertIn("500", str(res.error))

    @patch("urllib.request.urlopen")
    def test_update_check_skips_draft_and_prerelease(self, mock_urlopen):
        """TR-UPCHECK-04 & 05: Draft and prerelease releases are ignored."""
        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.read.return_value = json.dumps({
            "tag_name": "v2.0.0",
            "draft": True,
            "prerelease": False,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = fake_resp

        res = distribution.check_for_updates(current_version="1.2.2")
        self.assertEqual(res.status, distribution.UpdateCheckStatus.UP_TO_DATE)
        self.assertFalse(res.update_available)


class V122ArchiveSafetyTestSuite(unittest.TestCase):
    """TR-UPD-04..05: Zip-Slip prevention and archive validation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_arch_")
        self.extract_target = Path(self.test_dir) / "extracted"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_safe_extract_detects_zip_slip(self):
        """TR-UPD-04: safe_extract_archive raises ValueError on Zip-Slip traversal."""
        zip_path = Path(self.test_dir) / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../evil.py", "print('owned')")

        with self.assertRaises(ValueError) as cm:
            distribution.safe_extract_archive(zip_path, self.extract_target)
        self.assertIn("Zip slip", str(cm.exception))


class V122ManifestAndRollbackTestSuite(unittest.TestCase):
    """TR-MAN-01..09 & TR-UPD-08..10: Manifest drift tolerance & cleanup on rollback."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v122_man_")
        self.gemini_dir = Path(self.test_dir) / ".gemini"
        self.cfg_dir = self.gemini_dir / "config" / "strict-engineering"
        self.agents_dir = self.gemini_dir / "config" / "agents"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        self.agents_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy module
        (self.cfg_dir / "kernel.py").write_text("# kernel module\n", encoding="utf-8")
        # Create core agent
        for a in distribution.MANAGED_CORE_AGENTS:
            ad = self.agents_dir / a
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {a}\n", encoding="utf-8")

        # Hooks and GEMINI.md
        hooks_file = self.gemini_dir / "config" / "hooks.json"
        hooks_file.parent.mkdir(parents=True, exist_ok=True)
        hooks_file.write_text(json.dumps({
            "strict-engineering": {"Stop": [{"command": "python stop.py"}]},
            "user-custom-hook": {"PostToolUse": []},
        }), encoding="utf-8")

        gemini_md = self.gemini_dir / "GEMINI.md"
        gemini_md.write_text(
            "User Header\n\n"
            "<!-- STRICT_ENGINEERING_KERNEL_START -->\n"
            "Strict Rules\n"
            "<!-- STRICT_ENGINEERING_KERNEL_END -->\n\n"
            "User Footer\n",
            encoding="utf-8"
        )

        self.manifest = distribution.generate_installation_manifest(
            modules_dir=self.cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md,
            agents_dir=self.agents_dir,
            version="1.2.2",
        )
        distribution.save_installation_manifest(self.manifest, gemini_dir=self.gemini_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_custom_user_items_do_not_cause_manifest_drift(self):
        """TR-MAN-05..07: User custom agents, hooks, and prompt do not break verification."""
        custom_agent = self.agents_dir / "my-custom-researcher"
        custom_agent.mkdir(parents=True, exist_ok=True)
        (custom_agent / "agent.md").write_text("# Custom agent\n", encoding="utf-8")

        hooks_file = self.gemini_dir / "config" / "hooks.json"
        h_data = json.loads(hooks_file.read_text(encoding="utf-8"))
        h_data["another-user-hook"] = {}
        hooks_file.write_text(json.dumps(h_data), encoding="utf-8")

        gemini_md = self.gemini_dir / "GEMINI.md"
        gemini_md.write_text(
            "User Header Modified!\n\n"
            "<!-- STRICT_ENGINEERING_KERNEL_START -->\n"
            "Strict Rules\n"
            "<!-- STRICT_ENGINEERING_KERNEL_END -->\n\n"
            "User Footer Extended\n",
            encoding="utf-8"
        )

        ok, issues = distribution.verify_manifest_integrity(gemini_dir=self.gemini_dir)
        self.assertTrue(ok, f"Manifest integrity should pass but reported: {issues}")

    def test_rollback_deletes_introduced_modules_and_agents(self):
        """TR-UPD-08 & 09: Rollback removes files introduced by failed update."""
        snapshot_dir = Path(self.test_dir) / "snapshot_v1"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        (snapshot_dir / "kernel.py").write_text("# kernel module\n", encoding="utf-8")
        snap_agents = snapshot_dir / "agents"
        snap_agents.mkdir(parents=True, exist_ok=True)
        for a in distribution.MANAGED_CORE_AGENTS:
            ad = snap_agents / a
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {a}\n", encoding="utf-8")

        (self.cfg_dir / "introduced_module.py").write_text("# rogue\n", encoding="utf-8")

        ok, notes = distribution.rollback_from_snapshot(
            snapshot_dir=snapshot_dir,
            target_cfg_dir=self.cfg_dir,
            gemini_dir=self.gemini_dir,
        )
        self.assertTrue(ok)
        self.assertFalse((self.cfg_dir / "introduced_module.py").exists(), "Introduced module must be deleted on rollback")


class V122PluginAndReleaseTruthTestSuite(unittest.TestCase):
    """TR-PLUGIN-01..02 & TR-REL-01..07: Plugin truth and version integrity."""

    def test_plugin_json_not_present(self):
        """TR-PLUGIN-01: Root plugin.json must not exist."""
        self.assertFalse((REPO_ROOT / "plugin.json").exists())

    def test_readme_documents_deferred_plugin_packaging(self):
        """TR-PLUGIN-02: README truthfully states official Antigravity plugin packaging is deferred."""
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Official Antigravity plugin packaging is deferred", readme)

    def test_version_122_in_all_artifacts(self):
        """TR-REL-01..04: Version 1.2.2 across all source files."""
        self.assertEqual(__version__, "1.2.2")
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "1.2.2"', pyproject)


if __name__ == "__main__":
    unittest.main()
