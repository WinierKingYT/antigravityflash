import os
import sys
import json
import shutil
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))

from strict_engineering import kernel, gate, concern, runtime_safety, distribution, cli, installer


class TestV121Productization(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict_v121_test_")
        self.workspace = Path(self.test_dir) / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.gemini_dir = Path(self.test_dir) / ".gemini"
        self.gemini_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_circuit_breaker_conversation_isolation(self):
        kernel.initialize_harness(self.workspace, original_intent="Test circuit breaker isolation")

        conv_a = "conv-session-alpha"
        conv_b = "conv-session-beta"

        # Initially, neither should be tripped
        cb_a = runtime_safety.load_circuit_breaker(self.workspace, conversation_id=conv_a)
        self.assertFalse(cb_a.get("tripped"))
        self.assertEqual(cb_a.get("automaticContinueCount"), 0)

        # First evaluation: progress detected (initialization)
        can_cont, count, _ = runtime_safety.evaluate_circuit_breaker(
            self.workspace,
            conversation_id=conv_a,
            max_continues=3,
        )
        self.assertTrue(can_cont)
        self.assertEqual(count, 0)

        # 1st continue without progress -> count=1
        can_cont, count, _ = runtime_safety.evaluate_circuit_breaker(
            self.workspace,
            conversation_id=conv_a,
            max_continues=3,
        )
        self.assertTrue(can_cont)
        self.assertEqual(count, 1)

        # 2nd continue without progress -> count=2
        can_cont, count, _ = runtime_safety.evaluate_circuit_breaker(
            self.workspace,
            conversation_id=conv_a,
            max_continues=3,
        )
        self.assertTrue(can_cont)
        self.assertEqual(count, 2)

        # 3rd continue without progress -> count=3 >= max_continues -> TRIPPED!
        can_cont, count, _ = runtime_safety.evaluate_circuit_breaker(
            self.workspace,
            conversation_id=conv_a,
            max_continues=3,
        )
        self.assertFalse(can_cont)
        self.assertEqual(count, 3)

        # Conv A should now be tripped
        state_a = runtime_safety.load_circuit_breaker(self.workspace, conversation_id=conv_a)
        self.assertTrue(state_a.get("tripped"))
        self.assertTrue(state_a.get("circuitBreakerTripped"))
        self.assertEqual(state_a.get("automaticContinueCount"), 3)

        # Conv B MUST remain untripped with 0 continues
        state_b = runtime_safety.load_circuit_breaker(self.workspace, conversation_id=conv_b)
        self.assertFalse(state_b.get("tripped"))
        self.assertFalse(state_b.get("circuitBreakerTripped"))
        self.assertEqual(state_b.get("automaticContinueCount"), 0)

        # Evaluate conv_b, should be allowed
        can_cont_b, count_b, _ = runtime_safety.evaluate_circuit_breaker(
            self.workspace,
            conversation_id=conv_b,
            max_continues=3,
        )
        self.assertTrue(can_cont_b)

        # Reset conv_a, ensure conv_a is cleared
        runtime_safety.reset_circuit_breaker(self.workspace, conversation_id=conv_a)
        reset_a = runtime_safety.load_circuit_breaker(self.workspace, conversation_id=conv_a)
        self.assertFalse(reset_a.get("tripped"))
        self.assertEqual(reset_a.get("automaticContinueCount"), 0)

    def test_status_matches_gate_inspect_completion_readiness(self):
        kernel.initialize_harness(self.workspace, original_intent="Test status gate inspection")

        ready_gate, reasons_gate = gate.inspect_completion_readiness(self.workspace)
        self.assertFalse(ready_gate)
        self.assertTrue(any("specLocked=false" in r for r in reasons_gate))

        args = MagicMock()
        args.workspace = str(self.workspace)
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = cli.cmd_status(args)

        self.assertEqual(exit_code, 0)
        status_data = json.loads(f.getvalue())

        self.assertEqual(status_data["completionReady"], ready_gate)
        for r in reasons_gate:
            self.assertIn(r, status_data["blockedReasons"])

    def test_concern_risk_and_cb_alias_normalization(self):
        c1 = {"id": "C-001", "riskLevel": "HIGH", "status": "ACTIVE"}
        c2 = {"id": "C-002", "risk": "CRITICAL", "status": "ACTIVE"}
        c3 = {"id": "C-003", "status": "ACTIVE"}

        self.assertEqual(concern.get_concern_risk(c1), "HIGH")
        self.assertEqual(concern.get_concern_risk(c2), "CRITICAL")
        self.assertEqual(concern.get_concern_risk(c3), "LOW")

        new_c = concern.create_concern(
            id="CONC-001",
            title="Database Connection Pool Sizing",
            description="Determine max connections and pool timeout policy",
            category="TECHNICAL_ARCHITECTURE",
            source={"type": "ORIGINAL_INTENT", "reference": "INTENT-001"},
            risk="HIGH",
        )
        self.assertEqual(new_c.get("risk"), "HIGH")
        self.assertEqual(new_c.get("riskLevel"), "HIGH")

        ok, errors = concern.validate_concern(new_c)
        self.assertTrue(ok)
        self.assertEqual(len(errors), 0)

        kernel.initialize_harness(self.workspace, original_intent="Test CB Aliases")
        cb = runtime_safety.load_circuit_breaker(self.workspace)
        self.assertIn("tripped", cb)
        self.assertIn("circuitBreakerTripped", cb)
        self.assertIn("automaticContinueCount", cb)
        self.assertIn("consecutiveContinuesWithoutProgress", cb)
        self.assertEqual(cb["tripped"], cb["circuitBreakerTripped"])
        self.assertEqual(cb["automaticContinueCount"], cb["consecutiveContinuesWithoutProgress"])


    def test_init_blocks_on_existing_harness(self):
        kernel.initialize_harness(self.workspace, original_intent="Initial intent v1")
        harness_dir = self.workspace / ".agent-harness"

        marker = harness_dir / "custom_evidence.log"
        marker.write_text("critical execution proof", encoding="utf-8")

        args = MagicMock()
        args.workspace = str(self.workspace)
        args.intent = "Overwriting intent v2"
        args.await_intent = False

        exit_code = cli.cmd_init(args)
        self.assertEqual(exit_code, 3)
        self.assertEqual(marker.read_text(encoding="utf-8"), "critical execution proof")

        state = kernel.load_state(self.workspace)
        # Verify state was NOT updated to intent v2
        expected_sha_v1 = hashlib.sha256("Initial intent v1".encode("utf-8")).hexdigest()
        self.assertEqual(state.get("originalRequestSha256"), expected_sha_v1)

    def test_version_parsing_and_local_update_check(self):
        self.assertGreater(
            distribution.parse_version_tuple("1.2.1"),
            distribution.parse_version_tuple("1.2.0"),
        )
        self.assertGreater(
            distribution.parse_version_tuple("v2.0.0"),
            distribution.parse_version_tuple("1.9.9"),
        )
        self.assertEqual(
            distribution.parse_version_tuple("1.2.1"),
            distribution.parse_version_tuple("1.2.1"),
        )

        mock_src = Path(self.test_dir) / "mock_src"
        mock_src.mkdir(parents=True, exist_ok=True)
        init_file = mock_src / "__init__.py"
        init_file.write_text('__version__ = "2.0.0"\n', encoding="utf-8")

        avail, cur, lat = distribution.check_for_updates(
            current_version="1.2.1",
            distribution_source=str(mock_src),
        )
        self.assertTrue(avail)
        self.assertEqual(cur, "1.2.1")
        self.assertEqual(lat, "2.0.0")

    def test_agent_snapshot_and_rollback(self):
        cfg_dir = self.gemini_dir / "config" / "strict-engineering"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        agents_dir = self.gemini_dir / "config" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)

        builder_agent = agents_dir / "builder"
        builder_agent.mkdir(parents=True, exist_ok=True)
        (builder_agent / "agent.json").write_text('{"name": "builder-v1"}', encoding="utf-8")

        backup_dir = cfg_dir / ".backups" / "test-backup-001"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_agents = backup_dir / "agents"
        backup_agents.mkdir(parents=True, exist_ok=True)
        shutil.copytree(builder_agent, backup_agents / "builder", dirs_exist_ok=True)

        (builder_agent / "agent.json").write_text('{"name": "builder-mutated"}', encoding="utf-8")
        self.assertIn("builder-mutated", (builder_agent / "agent.json").read_text(encoding="utf-8"))

        ok, notes = distribution.rollback_from_snapshot(backup_dir, cfg_dir, self.gemini_dir)
        self.assertTrue(ok)
        self.assertIn('{"name": "builder-v1"}', (builder_agent / "agent.json").read_text(encoding="utf-8"))

    def test_fail_closed_uninstall_success_and_preservation(self):
        cfg_dir = self.gemini_dir / "config" / "strict-engineering"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "kernel.py").write_text("# kernel", encoding="utf-8")

        hooks_file = self.gemini_dir / "config" / "hooks.json"
        hooks_file.parent.mkdir(parents=True, exist_ok=True)
        hooks_data = {
            "user-custom-hook": [{"event": "PreInvocation", "command": "echo custom"}],
            "strict-engineering": {"PreInvocation": []},
        }
        with open(hooks_file, "w", encoding="utf-8") as f:
            json.dump(hooks_data, f, indent=2)

        gemini_md = self.gemini_dir / "GEMINI.md"
        gemini_md.write_text(
            "User custom prompt text\n\n"
            f"{installer.MANAGED_START_MARKER}\nManaged Kernel Rules\n{installer.MANAGED_END_MARKER}\n"
            "More user text",
            encoding="utf-8",
        )

        agents_dir = self.gemini_dir / "config" / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        custom_agent = agents_dir / "my-custom-assistant"
        custom_agent.mkdir(parents=True, exist_ok=True)
        (custom_agent / "agent.json").write_text("{}", encoding="utf-8")

        managed_agent = agents_dir / "builder"
        managed_agent.mkdir(parents=True, exist_ok=True)
        (managed_agent / "agent.json").write_text("{}", encoding="utf-8")

        ok, msg, actions = distribution.uninstall_kernel(gemini_dir=self.gemini_dir)
        self.assertTrue(ok)

        self.assertFalse(cfg_dir.exists())

        with open(hooks_file, "r", encoding="utf-8") as f:
            clean_hooks = json.load(f)
        self.assertIn("user-custom-hook", clean_hooks)
        self.assertNotIn("strict-engineering", clean_hooks)

        g_clean = gemini_md.read_text(encoding="utf-8")
        self.assertIn("User custom prompt text", g_clean)
        self.assertIn("More user text", g_clean)
        self.assertNotIn(installer.MANAGED_START_MARKER, g_clean)

        self.assertTrue(custom_agent.exists())
        self.assertFalse(managed_agent.exists())


if __name__ == "__main__":
    unittest.main()
