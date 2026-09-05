"""
Strict Engineering Kernel V4 - Automated Validation Test Suite
Tests all safety invariants, policy gates, regression detection, and CASE A - L.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure strict-engineering package is on sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import fingerprint
import baseline
import kernel
import gate


class StrictEngineeringV4TestSuite(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test workspace
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_v4_test_"))
        self.src_file = self.test_dir / "src" / "app.py"
        self.src_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.src_file, "w", encoding="utf-8") as f:
            f.write("# Clean production application code\ndef main():\n    return 42\n")

    def tearDown(self):
        # Clean up temporary test workspace
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_case_a_no_harness(self):
        """CASE A: No .agent-harness -> ordinary stop allowed"""
        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "allow")

    def test_case_b_harness_inactive(self):
        """CASE B: Harness active=false -> ordinary stop allowed"""
        kernel.initialize_harness(self.test_dir, "Build a test feature")
        state = kernel.load_state(self.test_dir)
        state["active"] = False
        kernel.save_state(self.test_dir, state)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "allow")

    def test_case_c_required_req_failed(self):
        """CASE C: Harness active, required REQ FAILED -> Stop gate returns continue"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "FAILED",
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        # Set coverage 100%
        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100}, f)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "continue")
        self.assertIn("FAILED", result.get("reason", ""))

    def test_case_d_required_req_implemented_unverified(self):
        """CASE D: Required REQ IMPLEMENTED_UNVERIFIED -> Stop gate returns continue"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "IMPLEMENTED_UNVERIFIED",
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100}, f)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "continue")
        self.assertIn("IMPLEMENTED_UNVERIFIED", result.get("reason", ""))

    def test_case_e_required_req_stale(self):
        """CASE E: Required REQ STALE -> Stop gate returns continue"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "STALE",
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100}, f)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "continue")
        self.assertIn("STALE", result.get("reason", ""))

    def test_case_f_required_req_blocked(self):
        """CASE F: Required REQ BLOCKED without authorized deferral -> Stop gate returns continue"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "BLOCKED",
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100}, f)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "continue")
        self.assertIn("BLOCKED", result.get("reason", ""))

    def test_case_g_all_pass_clean_completion(self):
        """CASE G: All required requirements PASS, fresh fingerprint, final audit PASS -> stop allowed"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")

        file_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)
        curr_fp = fingerprint.compute_workspace_fingerprint(self.test_dir, file_hashes)

        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "PASS",
                "lastVerifiedFingerprint": curr_fp,
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100, "uncoveredStatements": []}, f)

        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["finalAuditPassed"] = True
        kernel.save_state(self.test_dir, state)

        payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}
        result = gate.evaluate_stop(payload)
        self.assertEqual(result.get("decision"), "allow")

    def test_case_h_specification_phase_protection(self):
        """CASE H: Specification phase tries to modify application source -> PreToolUse gate denies"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["phase"] = "SPECIFICATION"
        kernel.save_state(self.test_dir, state)

        payload = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(self.src_file),
                },
            },
        }
        result = gate.evaluate_pre_tool_use(payload)
        self.assertEqual(result.get("decision"), "deny")
        self.assertIn("Phase Gate Deny", result.get("reason", ""))

    def test_case_i_implementation_phase_permitted_source_modification(self):
        """CASE I: Implementation phase modifies permitted application source -> PreToolUse gate allows"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["phase"] = "IMPLEMENTATION"
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        payload = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(self.src_file),
                },
            },
        }
        result = gate.evaluate_pre_tool_use(payload)
        self.assertEqual(result.get("decision"), "allow")

    def test_case_j_tamper_locked_original_request(self):
        """CASE J: Attempt to alter immutable original-request while locked -> PreToolUse denies"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")
        state = kernel.load_state(self.test_dir)
        state["phase"] = "IMPLEMENTATION"
        state["specLocked"] = True
        kernel.save_state(self.test_dir, state)

        orig_req_file = kernel.get_harness_dir(self.test_dir) / "original-request.md"
        payload = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(orig_req_file),
                },
            },
        }
        result = gate.evaluate_pre_tool_use(payload)
        self.assertEqual(result.get("decision"), "deny")
        self.assertIn("Security Gate Deny", result.get("reason", ""))

    def test_case_k_baseline_regression_detection(self):
        """CASE K: Baseline has pre-existing failures but post-change adds a new failure -> Regression detected"""
        base_data = {
            "tests": {
                "executed": True,
                "passed": False,
                "failed_count": 2,
                "failed_tests": ["test_legacy_a", "test_legacy_b"],
            }
        }
        current_tests = {
            "executed": True,
            "passed": False,
            "failed_count": 3,
            "failed_tests": ["test_legacy_a", "test_legacy_b", "test_new_feature_regression"],
        }
        regression_eval = baseline.evaluate_regression(base_data, current_tests)
        self.assertTrue(regression_eval.get("has_regression"))
        self.assertGreater(regression_eval.get("regression_count", 0), 0)
        self.assertIn("test_new_feature_regression", str(regression_eval.get("regressions")))

    def test_case_l_stale_invalidation_on_source_change(self):
        """CASE L: Verified affected source changes -> affected PASS becomes STALE"""
        kernel.initialize_harness(self.test_dir, "Build auth feature")

        file_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)
        initial_fp = fingerprint.compute_workspace_fingerprint(self.test_dir, file_hashes)

        # Record requirement as PASS with initial fingerprint
        reqs = [
            {
                "id": "REQ-001",
                "description": "User login functionality",
                "required": True,
                "status": "PASS",
                "affectedPaths": ["src/app.py"],
                "lastVerifiedFingerprint": initial_fp,
            }
        ]
        kernel.save_requirements(self.test_dir, reqs)

        # Mutate src/app.py
        with open(self.src_file, "a", encoding="utf-8") as f:
            f.write("\n# Additional change\ndef new_func(): pass\n")

        # Run stale check
        stale_ids = kernel.check_and_invalidate_stale(self.test_dir)
        self.assertIn("REQ-001", stale_ids)

        updated_reqs = kernel.load_requirements(self.test_dir)
        self.assertEqual(updated_reqs[0]["status"], "STALE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
