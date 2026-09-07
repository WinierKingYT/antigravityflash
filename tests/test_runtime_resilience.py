"""
Strict Engineering Kernel V1.0.2 - Runtime Resilience & Hook Safety Test Suite
Verifies RT-01 through RT-15 covering:
- Termination normalization across 7 canonical classes
- External/network error protection without retry loops or false complete
- User cancellation and max-steps handling
- Bounded automatic-continue circuit breaker with state progress fingerprinting
- Safe pause and deterministic resume semantics
- Privacy-safe append-only SHA-256 chained runtime event ledger
- Hook crash fail-safe isolation
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and strict_engineering to sys.path
root = Path(__file__).parent.parent
sys.path.insert(0, str(root / "src" / "strict_engineering"))
sys.path.insert(0, str(root / "strict_engineering"))
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root))

import kernel
import gate
import runtime_safety
import fingerprint


class TestRuntimeResilienceV102(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="strict_rt_test_")).resolve()
        self.ws = self.test_dir
        self.intent = "Build a reliable distributed data worker with strict safety guarantees."
        self.initial_state = kernel.initialize_harness(self.ws, self.intent)
        self.harness_dir = self.ws / ".agent-harness"

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # RT-01: Normal model stop + incomplete harness permits bounded continuation
    # -------------------------------------------------------------------------
    def test_rt_01_normal_model_stop_permits_bounded_continuation(self):
        """RT-01: Normal model stop with incomplete harness permits bounded continuation."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Core worker loop", "required": True, "status": "IN_PROGRESS"}
        ])
        payload = {
            "workspacePaths": [str(self.ws)],
            "terminationReason": "model_stop",
            "conversationId": "conv-rt-01",
        }
        res = gate.evaluate_stop(payload)
        self.assertEqual(res["decision"], "continue")
        self.assertIn("Strict Engineering Completion Gate BLOCKED", res["reason"])

        # Verify runtime event was recorded
        valid, errors = runtime_safety.verify_runtime_events_integrity(self.ws)
        self.assertTrue(valid, f"Runtime events ledger integrity violated: {errors}")

        ev_path = runtime_safety.get_runtime_events_path(self.ws)
        self.assertTrue(ev_path.exists())
        with open(ev_path, "r", encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
        self.assertTrue(any(e["eventType"] == "AUTO_CONTINUE_ISSUED" for e in events))

    # -------------------------------------------------------------------------
    # RT-02: External error never auto-continues
    # -------------------------------------------------------------------------
    def test_rt_02_external_error_never_auto_continues(self):
        """RT-02: External/network errors never return continue and never cause an auto-continue loop."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Core", "required": True, "status": "IN_PROGRESS"}
        ])

        error_payloads = [
            {"workspacePaths": [str(self.ws)], "terminationReason": "network_error"},
            {"workspacePaths": [str(self.ws)], "terminationReason": "server_error"},
            {"workspacePaths": [str(self.ws)], "terminationReason": "timeout"},
            {"workspacePaths": [str(self.ws)], "terminationReason": "econnreset"},
            {"workspacePaths": [str(self.ws)], "error": "Connection reset by peer"},
            {"workspacePaths": [str(self.ws)], "error": {"message": "503 Service Unavailable"}},
            {"workspacePaths": [str(self.ws)], "status": "error"},
        ]

        for p in error_payloads:
            res = gate.evaluate_stop(p)
            self.assertEqual(
                res["decision"], "allow",
                f"External error payload {p} must return allow to prevent execution loop"
            )
            st = kernel.load_state(self.ws)
            self.assertEqual(st.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_EXTERNAL_ERROR)
            # Phase must NOT be mutated to COMPLETE or FAILED
            self.assertEqual(st.get("phase"), "SPECIFICATION")

    # -------------------------------------------------------------------------
    # RT-03: User cancellation never auto-continues
    # -------------------------------------------------------------------------
    def test_rt_03_user_cancellation_never_auto_continues(self):
        """RT-03: User cancellation never auto-continues and sets PAUSED_USER_CANCEL."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Core", "required": True, "status": "IN_PROGRESS"}
        ])

        cancel_reasons = ["user_abort", "cancelled", "user_cancelled", "user_canceled", "aborted"]
        for r in cancel_reasons:
            p = {"workspacePaths": [str(self.ws)], "terminationReason": r}
            res = gate.evaluate_stop(p)
            self.assertEqual(res["decision"], "allow")
            st = kernel.load_state(self.ws)
            self.assertEqual(st.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_USER_CANCEL)
            self.assertEqual(st.get("phase"), "SPECIFICATION")

    # -------------------------------------------------------------------------
    # RT-04: Max-steps termination never auto-continues
    # -------------------------------------------------------------------------
    def test_rt_04_max_steps_termination_never_auto_continues(self):
        """RT-04: Max-steps termination (including max_steps_exceeded) never auto-continues."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Core", "required": True, "status": "IN_PROGRESS"}
        ])

        step_reasons = ["max_steps", "max_steps_exceeded", "step_limit_reached", "max_turns"]
        for r in step_reasons:
            p = {"workspacePaths": [str(self.ws)], "terminationReason": r}
            res = gate.evaluate_stop(p)
            self.assertEqual(res["decision"], "allow")
            st = kernel.load_state(self.ws)
            self.assertEqual(st.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_MAX_STEPS)

    # -------------------------------------------------------------------------
    # RT-05: Unknown abnormal termination fails conservatively
    # -------------------------------------------------------------------------
    def test_rt_05_unknown_abnormal_termination_fails_conservatively(self):
        """RT-05: Unrecognized abnormal termination token halts conservatively without retry loop."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Core", "required": True, "status": "IN_PROGRESS"}
        ])

        p = {"workspacePaths": [str(self.ws)], "terminationReason": "unknown_anomaly_crash_xyz"}
        res = gate.evaluate_stop(p)
        self.assertEqual(res["decision"], "allow")
        st = kernel.load_state(self.ws)
        self.assertEqual(st.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_UNKNOWN)

    # -------------------------------------------------------------------------
    # RT-06: Two identical no-progress automatic continues trip circuit breaker
    # -------------------------------------------------------------------------
    def test_rt_06_no_progress_automatic_continues_trip_circuit_breaker(self):
        """RT-06: Consecutive continue calls with identical state progress fingerprint trip the circuit breaker."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Worker", "required": True, "status": "IN_PROGRESS"}
        ])

        payload = {"workspacePaths": [str(self.ws)], "terminationReason": "model_stop"}

        # Call 1: progress reset / first evaluation -> continue allowed (count=0)
        r1 = gate.evaluate_stop(payload)
        self.assertEqual(r1["decision"], "continue")

        # Call 2: identical fingerprint -> continue allowed (count=1)
        r2 = gate.evaluate_stop(payload)
        self.assertEqual(r2["decision"], "continue")

        # Call 3: identical fingerprint -> count reaches 2 -> circuit breaker TRIPS!
        r3 = gate.evaluate_stop(payload)
        self.assertEqual(r3["decision"], "allow")
        self.assertIn("Circuit Breaker TRIPPED", r3["reason"])

        st = kernel.load_state(self.ws)
        self.assertEqual(st.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_CIRCUIT_BREAKER)
        self.assertIn("Maximum automatic continues without progress", st.get("pauseReason", ""))

    # -------------------------------------------------------------------------
    # RT-07: Real progress resets/advances circuit breaker safely
    # -------------------------------------------------------------------------
    def test_rt_07_real_progress_resets_circuit_breaker(self):
        """RT-07: Engineering state progress resets the circuit breaker continue counter."""
        kernel.save_requirements(self.ws, [
            {"id": "REQ-001", "description": "Worker", "required": True, "status": "IN_PROGRESS"}
        ])

        payload = {"workspacePaths": [str(self.ws)], "terminationReason": "model_stop"}

        # Call 1: initial -> continue (count=0)
        r1 = gate.evaluate_stop(payload)
        self.assertEqual(r1["decision"], "continue")

        # Call 2: no progress -> continue (count=1)
        r2 = gate.evaluate_stop(payload)
        self.assertEqual(r2["decision"], "continue")

        # Now introduce real progress: add a new verified source file
        src_file = self.ws / "worker.py"
        src_file.write_text("def run():\n    return True\n", encoding="utf-8")

        # Call 3: progress was made -> counter resets to 0 -> continue allowed!
        r3 = gate.evaluate_stop(payload)
        self.assertEqual(r3["decision"], "continue")
        cb_data = runtime_safety.load_circuit_breaker(self.ws)
        self.assertEqual(cb_data["automaticContinueCount"], 0)
        self.assertFalse(cb_data["tripped"])

    # -------------------------------------------------------------------------
    # RT-08: External error does not change PASS requirement to FAILED
    # -------------------------------------------------------------------------
    def test_rt_08_external_error_does_not_change_pass_requirement_to_failed(self):
        """RT-08: External/network failure must never mutate valid PASS requirements into FAILED."""
        reqs = [
            {"id": "REQ-001", "description": "Auth component", "required": True, "status": "PASS"},
            {"id": "REQ-002", "description": "Worker component", "required": True, "status": "IN_PROGRESS"},
        ]
        kernel.save_requirements(self.ws, reqs)

        payload = {"workspacePaths": [str(self.ws)], "terminationReason": "network_error"}
        res = gate.evaluate_stop(payload)
        self.assertEqual(res["decision"], "allow")

        loaded_reqs = kernel.load_requirements(self.ws)
        r1 = next(r for r in loaded_reqs if r["id"] == "REQ-001")
        self.assertEqual(r1["status"], "PASS")

    # -------------------------------------------------------------------------
    # RT-09: External error preserves IN_PROGRESS engineering state
    # -------------------------------------------------------------------------
    def test_rt_09_external_error_preserves_in_progress_state(self):
        """RT-09: External error preserves current engineering phase and active state."""
        st = kernel.load_state(self.ws)
        st["phase"] = "IMPLEMENTATION"
        st["active"] = True
        kernel.save_state(self.ws, st)

        payload = {"workspacePaths": [str(self.ws)], "error": "Server disconnected"}
        res = gate.evaluate_stop(payload)
        self.assertEqual(res["decision"], "allow")

        reloaded = kernel.load_state(self.ws)
        self.assertEqual(reloaded["phase"], "IMPLEMENTATION")
        self.assertTrue(reloaded["active"])
        self.assertEqual(reloaded["runtimeStatus"], runtime_safety.RuntimeStatus.PAUSED_EXTERNAL_ERROR)

    # -------------------------------------------------------------------------
    # RT-10: Restart/resume preserves original-request integrity
    # -------------------------------------------------------------------------
    def test_rt_10_resume_preserves_original_request_integrity(self):
        """RT-10: Resuming verifies original request integrity and rejects tampered intent."""
        # 1. Normal resume succeeds
        ok, msg, resumed_st = kernel.resume_execution(self.ws)
        self.assertTrue(ok)
        self.assertEqual(resumed_st.get("runtimeStatus"), runtime_safety.RuntimeStatus.RUNNING)

        # 2. Tampered request is detected and resume is rejected
        orig_file = self.harness_dir / "original-request.md"
        orig_file.write_text("Tampered intent", encoding="utf-8")
        ok_tampered, msg_tampered, _ = kernel.resume_execution(self.ws)
        self.assertFalse(ok_tampered)
        self.assertIn("original-request.md SHA-256 integrity check failed", msg_tampered)

    # -------------------------------------------------------------------------
    # RT-11: Resume does not duplicate requirements
    # -------------------------------------------------------------------------
    def test_rt_11_resume_does_not_duplicate_requirements(self):
        """RT-11: Resume operation is idempotent and never duplicates requirements."""
        reqs = [
            {"id": "REQ-001", "description": "Req 1", "required": True, "status": "PASS"},
            {"id": "REQ-002", "description": "Req 2", "required": True, "status": "IN_PROGRESS"},
            {"id": "REQ-003", "description": "Req 3", "required": True, "status": "NOT_STARTED"},
        ]
        kernel.save_requirements(self.ws, reqs)

        # Pause
        st = kernel.load_state(self.ws)
        st["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_EXTERNAL_ERROR
        kernel.save_state(self.ws, st)

        # Resume twice
        kernel.resume_execution(self.ws)
        kernel.resume_execution(self.ws)

        loaded = kernel.load_requirements(self.ws)
        self.assertEqual(len(loaded), 3)
        self.assertEqual([r["id"] for r in loaded], ["REQ-001", "REQ-002", "REQ-003"])

    # -------------------------------------------------------------------------
    # RT-12: Hook internal exception cannot produce false COMPLETE
    # -------------------------------------------------------------------------
    def test_rt_12_hook_internal_exception_cannot_produce_false_complete(self):
        """RT-12: An exception during Stop hook handling never produces false COMPLETE or retry loop."""
        import subprocess

        hooks_script = root / "src" / "strict_engineering" / "hooks_handler.py"

        # Execute hook CLI where evaluate_stop throws an unhandled crash
        code = (
            "import sys, json\n"
            f"sys.path.insert(0, r'{root}/src/strict_engineering')\n"
            f"sys.path.insert(0, r'{root}/src')\n"
            "import gate, hooks_handler\n"
            "def crashing_eval(p):\n"
            "    raise RuntimeError('Simulated internal crash in evaluate_stop')\n"
            "gate.evaluate_stop = crashing_eval\n"
            "sys.argv = ['hooks_handler.py', 'stop']\n"
            "hooks_handler.main()\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            input=json.dumps({"workspacePaths": [str(self.ws)]}),
            text=True,
            capture_output=True,
        )

        self.assertEqual(proc.returncode, 0)
        output_data = json.loads(proc.stdout)

        # Must return 'allow' (NOT continue!) to prevent retry loop
        self.assertEqual(output_data.get("decision"), "allow")
        self.assertIn("internal error", output_data.get("reason", "").lower())

        st = kernel.load_state(self.ws)
        self.assertNotEqual(st.get("phase"), "COMPLETE")

    # -------------------------------------------------------------------------
    # RT-13: PreToolUse security fail-closed behavior is unchanged
    # -------------------------------------------------------------------------
    def test_rt_13_pre_tool_use_security_fail_closed_unchanged(self):
        """RT-13: PreToolUse continues to strictly block writes to protected artifacts including new ones."""
        protected_targets = [
            ".agent-harness/requirements.json",
            ".agent-harness/circuit-breaker.json",
            ".agent-harness/runtime-events.jsonl",
            ".agent-harness/state.json",
        ]

        for target in protected_targets:
            payload = {
                "workspacePaths": [str(self.ws)],
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(self.ws / target)},
                },
            }
            res = gate.evaluate_pre_tool_use(payload)
            self.assertEqual(
                res["decision"], "deny",
                f"Direct mutation of {target} must be denied by PreToolUse gate"
            )

    # -------------------------------------------------------------------------
    # RT-14: Stop incomplete-harness completion protection is unchanged
    # -------------------------------------------------------------------------
    def test_rt_14_stop_incomplete_harness_completion_protection_unchanged(self):
        """RT-14: Incomplete harness cannot be marked COMPLETE via Stop gate."""
        # Requirements missing, coverage missing, locks missing
        payload = {"workspacePaths": [str(self.ws)], "terminationReason": "model_stop"}
        res = gate.evaluate_stop(payload)
        self.assertEqual(res["decision"], "continue")

        st = kernel.load_state(self.ws)
        self.assertNotEqual(st.get("phase"), "COMPLETE")

    # -------------------------------------------------------------------------
    # RT-15: Conversation/workspace isolation prevents cross-project circuit trip
    # -------------------------------------------------------------------------
    def test_rt_15_workspace_isolation_prevents_cross_circuit_trip(self):
        """RT-15: Circuit breaker state is strictly isolated per workspace."""
        ws2_dir = Path(tempfile.mkdtemp(prefix="strict_rt_ws2_")).resolve()
        try:
            kernel.initialize_harness(ws2_dir, "Project 2")
            kernel.save_requirements(self.ws, [{"id": "REQ-1", "required": True, "status": "IN_PROGRESS"}])
            kernel.save_requirements(ws2_dir, [{"id": "REQ-1", "required": True, "status": "IN_PROGRESS"}])

            # Trip circuit breaker in ws 1
            payload1 = {"workspacePaths": [str(self.ws)], "terminationReason": "model_stop"}
            gate.evaluate_stop(payload1)
            gate.evaluate_stop(payload1)
            r1_trip = gate.evaluate_stop(payload1)
            self.assertEqual(r1_trip["decision"], "allow")
            st1 = kernel.load_state(self.ws)
            self.assertEqual(st1.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_CIRCUIT_BREAKER)

            # In ws 2: circuit breaker must NOT be tripped!
            payload2 = {"workspacePaths": [str(ws2_dir)], "terminationReason": "model_stop"}
            r2_first = gate.evaluate_stop(payload2)
            self.assertEqual(r2_first["decision"], "continue")
            st2 = kernel.load_state(ws2_dir)
            self.assertNotEqual(st2.get("runtimeStatus"), runtime_safety.RuntimeStatus.PAUSED_CIRCUIT_BREAKER)
        finally:
            shutil.rmtree(ws2_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
