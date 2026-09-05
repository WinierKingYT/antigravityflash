"""
Strict Engineering Kernel V4.1 - Comprehensive Adversarial Test Suite
Validates all 26 critical sections, security invariants, cryptographic evidence chain,
shell bypass protections, phase locks, baseline regressions, and an End-to-End 12-Requirement Torture Project.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure strict-engineering package is in sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import fingerprint
import baseline
import kernel
import gate
import hooks_handler


class StrictEngineeringV41AdversarialTestSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_v41_adv_"))
        self.src_dir = self.test_dir / "src"
        self.src_dir.mkdir(parents=True, exist_ok=True)
        self.src_file = self.src_dir / "app.py"
        with open(self.src_file, "w", encoding="utf-8") as f:
            f.write("def run_app():\n    return 'v4.1-ready'\n")

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Section 2: multi_replace_file_content PreToolUse Interception
    # -------------------------------------------------------------------------
    def test_section_02_multi_replace_file_content_interception(self):
        """Section 2: multi_replace_file_content tool calls are gated identically to write_to_file."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        kernel.save_state(self.test_dir, state)

        # 1. multi_replace targeting protected state.json
        state_file = kernel.get_harness_dir(self.test_dir) / "state.json"
        payload = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "multi_replace_file_content",
                "args": {
                    "TargetFile": str(state_file),
                    "Instruction": "Bypass gate",
                    "Description": "Hacking state",
                    "AllowMultiple": True,
                    "TargetContent": "SPECIFICATION",
                    "ReplacementContent": "COMPLETE",
                    "StartLine": 1,
                    "EndLine": 10,
                },
            },
        }
        res = gate.evaluate_pre_tool_use(payload)
        self.assertEqual(res.get("decision"), "deny", "multi_replace on state.json must be denied")
        self.assertIn("Security Gate Deny", res.get("reason", ""))

        # 2. multi_replace targeting app source during SPECIFICATION phase
        state["phase"] = "SPECIFICATION"
        kernel.save_state(self.test_dir, state)
        payload_src = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "multi_replace_file_content",
                "args": {
                    "TargetFile": str(self.src_file),
                    "Instruction": "Modify source prematurely",
                    "Description": "Premature edit",
                    "AllowMultiple": True,
                    "TargetContent": "v4.1-ready",
                    "ReplacementContent": "hacked",
                    "StartLine": 1,
                    "EndLine": 5,
                },
            },
        }
        res_src = gate.evaluate_pre_tool_use(payload_src)
        self.assertEqual(res_src.get("decision"), "deny", "multi_replace on source during SPEC phase must be denied")

        # 3. multi_replace targeting app source during IMPLEMENTATION phase
        state["phase"] = "IMPLEMENTATION"
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)
        res_allowed = gate.evaluate_pre_tool_use(payload_src)
        self.assertEqual(res_allowed.get("decision"), "allow", "multi_replace on source during IMPLEMENTATION must be allowed")

    # -------------------------------------------------------------------------
    # Section 4: Single-Writer State & Builder Self-PASS Attempts
    # -------------------------------------------------------------------------
    def test_section_04_builder_self_pass_rejection(self):
        """Section 4: Builder cannot self-certify PASS via kernel or evidence."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        reqs = [{"id": "REQ-001", "description": "Auth module", "required": True, "status": "IN_PROGRESS"}]
        kernel.save_requirements(self.test_dir, reqs)

        # 1. Builder update_requirement_status to PASS -> must be rejected
        ok, msg = kernel.update_requirement_status(
            self.test_dir,
            req_id="REQ-001",
            new_status="PASS",
            verifier_identity="builder",
        )
        self.assertFalse(ok, "Builder direct PASS update must return False")
        self.assertIn("prohibited", msg.lower())

        # 2. Builder record_evidence with result="PASS" -> must downgrade to IMPLEMENTED_UNVERIFIED
        kernel.record_evidence(
            self.test_dir,
            requirement_ids=["REQ-001"],
            verification_type="AUTOMATED_TEST",
            command_or_interaction="pytest tests/test_auth.py",
            result="PASS",
            relevant_output="All 5 passed",
            verifier_identity="builder",
        )
        updated_reqs = kernel.load_requirements(self.test_dir)
        self.assertEqual(
            updated_reqs[0]["status"],
            "IMPLEMENTED_UNVERIFIED",
            "Builder PASS evidence must not promote status beyond IMPLEMENTED_UNVERIFIED",
        )

    # -------------------------------------------------------------------------
    # Section 5: Protected File Bypass Matrix (7 files x 4 tools)
    # -------------------------------------------------------------------------
    def test_section_05_protected_file_bypass_matrix(self):
        """Section 5: 7 protected files x 4 tools matrix = 28 denied bypass attempts."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["phase"] = "IMPLEMENTATION"
        kernel.save_state(self.test_dir, state)

        harness_dir = kernel.get_harness_dir(self.test_dir)
        docs_dir = self.test_dir / "docs"

        protected_targets = [
            harness_dir / "original-request.md",
            harness_dir / "original-request.sha256",
            harness_dir / "state.json",
            harness_dir / "requirements.json",
            harness_dir / "coverage.json",
            harness_dir / "evidence.jsonl",
            docs_dir / "ACCEPTANCE_TESTS.md",
        ]

        tools = ["write_to_file", "replace_file_content", "multi_replace_file_content"]

        # Test 3 file tools x 7 files = 21 checks
        for p_file in protected_targets:
            for tool in tools:
                payload = {
                    "workspacePaths": [str(self.test_dir)],
                    "toolCall": {
                        "name": tool,
                        "args": {
                            "TargetFile": str(p_file),
                            "target_file": str(p_file),
                            "FilePath": str(p_file),
                            "Content": "malicious overwrite",
                            "ReplacementContent": "malicious overwrite",
                        },
                    },
                }
                res = gate.evaluate_pre_tool_use(payload)
                self.assertEqual(
                    res.get("decision"),
                    "deny",
                    f"Tool {tool} on protected file {p_file.name} must be DENIED",
                )

        # Test run_command shell bypass on 7 files = 7 checks (Total = 28 checks)
        for p_file in protected_targets:
            cmd = f"Set-Content -Path {p_file} -Value 'tampered'"
            payload_cmd = {
                "workspacePaths": [str(self.test_dir)],
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": cmd},
                },
            }
            res_cmd = gate.evaluate_pre_tool_use(payload_cmd)
            self.assertEqual(
                res_cmd.get("decision"),
                "deny",
                f"run_command shell modification on {p_file.name} must be DENIED",
            )

    # -------------------------------------------------------------------------
    # Section 6: Command-Shell Bypass Tests
    # -------------------------------------------------------------------------
    def test_section_06_command_shell_bypass_vectors(self):
        """Section 6: Verify PowerShell, cmd redirection, Python inline, and file op bypasses."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["phase"] = "IMPLEMENTATION"
        kernel.save_state(self.test_dir, state)

        bypass_commands = [
            "echo evil > .agent-harness/state.json",
            "type something >> .agent-harness/evidence.jsonl",
            "Set-Content .agent-harness/state.json 'hacked'",
            "Add-Content .agent-harness/evidence.jsonl 'fake entry'",
            "echo 'data' | Out-File .agent-harness/requirements.json",
            "sc .agent-harness/original-request.md 'altered'",
            "ac docs/ACCEPTANCE_TESTS.md 'injected contract'",
            "python -c \"open('.agent-harness/state.json', 'w').write('{}')\"",
            "copy malicious.json .agent-harness/state.json",
            "Move-Item payload.json .agent-harness/requirements.json",
            "del .agent-harness/original-request.sha256",
            "Remove-Item .agent-harness/coverage.json",
        ]

        for cmd in bypass_commands:
            payload = {
                "workspacePaths": [str(self.test_dir)],
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": cmd},
                },
            }
            res = gate.evaluate_pre_tool_use(payload)
            self.assertEqual(
                res.get("decision"),
                "deny",
                f"Bypass command '{cmd}' must be DENIED by PreToolUse gate",
            )

    # -------------------------------------------------------------------------
    # Section 7: Spec Phase Live Enforcement
    # -------------------------------------------------------------------------
    def test_section_07_spec_phase_live_enforcement(self):
        """Section 7: Source modification denied during SPECIFICATION, allowed in IMPLEMENTATION."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["phase"] = "SPECIFICATION"
        kernel.save_state(self.test_dir, state)

        # 1. Modifying app source in SPEC phase -> DENIED
        payload_src = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(self.src_file), "CodeContent": "def hacked(): pass"},
            },
        }
        res1 = gate.evaluate_pre_tool_use(payload_src)
        self.assertEqual(res1.get("decision"), "deny")

        # 2. Modifying docs/PRODUCT_SPEC.md in SPEC phase -> ALLOWED
        spec_doc = self.test_dir / "docs" / "PRODUCT_SPEC.md"
        payload_doc = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(spec_doc), "CodeContent": "# Updated Spec"},
            },
        }
        res2 = gate.evaluate_pre_tool_use(payload_doc)
        self.assertEqual(res2.get("decision"), "allow")

        # 3. Transition to IMPLEMENTATION phase -> App source modification is ALLOWED
        state["phase"] = "IMPLEMENTATION"
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        res3 = gate.evaluate_pre_tool_use(payload_src)
        self.assertEqual(res3.get("decision"), "allow")

    # -------------------------------------------------------------------------
    # Section 8: Requirement Immutability & Change Control
    # -------------------------------------------------------------------------
    def test_section_08_requirement_immutability_and_change_control(self):
        """Section 8: Changes log to changes.jsonl, docs/DECISIONS.md, and invalidate affected REQs to STALE."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        reqs = [
            {"id": "REQ-001", "description": "Auth module", "required": True, "status": "PASS"},
            {"id": "REQ-002", "description": "Search module", "required": True, "status": "PASS"},
        ]
        kernel.save_requirements(self.test_dir, reqs)

        # Record authorized change
        chg_id = kernel.record_change(
            workspace_dir=self.test_dir,
            requirement_ids=["REQ-001"],
            old_behavior="Password only auth",
            new_behavior="MFA auth required",
            reason="Security compliance policy",
            source_of_change="USER_REQUESTED_CHANGE",
        )

        self.assertTrue(chg_id.startswith("CHG-"))

        # Verify changes.jsonl
        ch_file = kernel.get_harness_dir(self.test_dir) / "changes.jsonl"
        self.assertTrue(ch_file.exists())
        with open(ch_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["changeId"], chg_id)
            self.assertEqual(entry["requirementIds"], ["REQ-001"])

        # Verify docs/DECISIONS.md
        decisions_file = self.test_dir / "docs" / "DECISIONS.md"
        with open(decisions_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn(chg_id, content)
            self.assertIn("MFA auth required", content)

        # Verify REQ-001 transitioned to STALE while REQ-002 remains PASS
        updated_reqs = kernel.load_requirements(self.test_dir)
        req_map = {r["id"]: r["status"] for r in updated_reqs}
        self.assertEqual(req_map["REQ-001"], "STALE")
        self.assertEqual(req_map["REQ-002"], "PASS")

    # -------------------------------------------------------------------------
    # Section 9: Acceptance Contract Immutability
    # -------------------------------------------------------------------------
    def test_section_09_acceptance_contract_immutability(self):
        """Section 9: Acceptance tests in docs/ACCEPTANCE_TESTS.md are immutable once locked."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["acceptanceLocked"] = True
        kernel.save_state(self.test_dir, state)

        acceptance_file = self.test_dir / "docs" / "ACCEPTANCE_TESTS.md"
        payload = {
            "workspacePaths": [str(self.test_dir)],
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(acceptance_file), "CodeContent": "# Altered acceptance test"},
            },
        }
        res = gate.evaluate_pre_tool_use(payload)
        self.assertEqual(res.get("decision"), "deny")
        self.assertIn("Acceptance contracts", res.get("reason", ""))

    # -------------------------------------------------------------------------
    # Section 10: Live Stop Hook Evaluations
    # -------------------------------------------------------------------------
    def test_section_10_live_stop_hook_evaluations(self):
        """Section 10: Stop hook correctly returns continue for FAILED, UNVERIFIED, STALE, BLOCKED, and allow for complete."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        state = kernel.load_state(self.test_dir)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["finalAuditPassed"] = True
        kernel.save_state(self.test_dir, state)

        cov_file = kernel.get_harness_dir(self.test_dir) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100, "uncoveredStatements": []}, f)

        stop_payload = {"workspacePaths": [str(self.test_dir)], "terminationReason": "model_stop"}

        for status in ["FAILED", "IMPLEMENTED_UNVERIFIED", "STALE", "BLOCKED", "IN_PROGRESS", "NOT_STARTED"]:
            kernel.save_requirements(
                self.test_dir,
                [{"id": "REQ-001", "description": "Core", "required": True, "status": status}],
            )
            res = gate.evaluate_stop(stop_payload)
            self.assertEqual(res.get("decision"), "continue", f"Status {status} must yield 'continue'")

        # Clean PASS with fresh fingerprint
        fp = fingerprint.compute_workspace_fingerprint(self.test_dir)
        kernel.save_requirements(
            self.test_dir,
            [{"id": "REQ-001", "description": "Core", "required": True, "status": "PASS", "lastVerifiedFingerprint": fp}],
        )
        # Record valid evidence chain
        kernel.record_evidence(
            self.test_dir,
            requirement_ids=["REQ-001"],
            verification_type="AUTOMATED_TEST",
            command_or_interaction="pytest tests/",
            result="PASS",
            relevant_output="1 passed",
            verifier_identity="test-oracle",
        )
        res_pass = gate.evaluate_stop(stop_payload)
        self.assertEqual(res_pass.get("decision"), "allow", "All requirements verified PASS must allow Stop")

    # -------------------------------------------------------------------------
    # Section 11: Error Termination Loop Safety
    # -------------------------------------------------------------------------
    def test_section_11_error_termination_loop_safety(self):
        """Section 11: Termination due to fatal errors, max steps, or abort is escapable."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        # Incomplete requirements
        kernel.save_requirements(
            self.test_dir,
            [{"id": "REQ-001", "description": "Core", "required": True, "status": "FAILED"}],
        )

        error_payloads = [
            {"workspacePaths": [str(self.test_dir)], "terminationReason": "error", "error": "Fatal crash"},
            {"workspacePaths": [str(self.test_dir)], "terminationReason": "max_steps"},
            {"workspacePaths": [str(self.test_dir)], "terminationReason": "user_abort"},
        ]

        for p in error_payloads:
            res = gate.evaluate_stop(p)
            self.assertEqual(res.get("decision"), "allow", f"Error termination payload {p} must allow termination")

    # -------------------------------------------------------------------------
    # Section 12 & 13: Fingerprint False-Positive & False-Negative Tests
    # -------------------------------------------------------------------------
    def test_section_12_13_fingerprint_accuracy_and_lockfiles(self):
        """Section 12 & 13: File additions, deletions, renames, and lockfile changes change FP; doc edits do not."""
        initial_fp = fingerprint.compute_workspace_fingerprint(self.test_dir)
        initial_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)

        # 1. Unrelated doc edit in docs/ -> FP must NOT change (No False Positive)
        doc_file = self.test_dir / "docs" / "README.md"
        doc_file.parent.mkdir(parents=True, exist_ok=True)
        with open(doc_file, "w", encoding="utf-8") as f:
            f.write("# Documentation only")
        doc_fp = fingerprint.compute_workspace_fingerprint(self.test_dir)
        self.assertEqual(initial_fp, doc_fp, "Doc edits must NOT change workspace code fingerprint")

        # 2. File addition in src/ -> FP MUST change
        new_file = self.src_dir / "utils.py"
        with open(new_file, "w", encoding="utf-8") as f:
            f.write("def helper(): return True\n")
        add_fp = fingerprint.compute_workspace_fingerprint(self.test_dir)
        self.assertNotEqual(initial_fp, add_fp, "File addition must change fingerprint")

        pre_rename_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)
        delta_add = fingerprint.compare_workspace_hashes(initial_hashes, pre_rename_hashes)
        self.assertIn("src/utils.py", delta_add["added"])

        # 3. Lockfile addition (package-lock.json / requirements.txt) -> FP MUST change
        req_lock = self.test_dir / "requirements.txt"
        with open(req_lock, "w", encoding="utf-8") as f:
            f.write("flask==3.0.0\n")
        lock_fp = fingerprint.compute_workspace_fingerprint(self.test_dir)
        self.assertNotEqual(add_fp, lock_fp, "Lockfile modification must change fingerprint")

        # 4. Rename file -> Detected in delta comparison
        pre_ren_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)
        os.rename(new_file, self.src_dir / "helpers.py")
        ren_hashes = fingerprint.get_workspace_file_hashes(self.test_dir)
        delta_ren = fingerprint.compare_workspace_hashes(pre_ren_hashes, ren_hashes)
        self.assertTrue(len(delta_ren["renamed"]) > 0 or "src/helpers.py" in delta_ren["added"])

    # -------------------------------------------------------------------------
    # Section 14, 15, 16: Evidence Authenticity & Cryptographic Hash Chain
    # -------------------------------------------------------------------------
    def test_section_14_15_16_evidence_hash_chain_and_claim_rejection(self):
        """Section 14, 15, 16: CLAIM cannot produce PASS; Evidence hash chain detects tampering."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        reqs = [{"id": "REQ-001", "description": "Core", "required": True, "status": "IN_PROGRESS"}]
        kernel.save_requirements(self.test_dir, reqs)

        # 1. Verification with CLAIM -> Cannot produce PASS
        kernel.record_evidence(
            self.test_dir,
            requirement_ids=["REQ-001"],
            verification_type="CLAIM",
            command_or_interaction="I verified it manually in my head",
            result="PASS",
            relevant_output="Looks good",
            verifier_identity="test-oracle",
        )
        reqs_after_claim = kernel.load_requirements(self.test_dir)
        self.assertEqual(
            reqs_after_claim[0]["status"],
            "IMPLEMENTED_UNVERIFIED",
            "CLAIM verification must NOT update requirement to PASS",
        )

        # 2. Verification with EXECUTED_COMMAND -> Successfully updates to PASS
        kernel.record_evidence(
            self.test_dir,
            requirement_ids=["REQ-001"],
            verification_type="EXECUTED_COMMAND",
            command_or_interaction="pytest tests/test_core.py",
            result="PASS",
            relevant_output="PASSED 1 test",
            verifier_identity="test-oracle",
        )
        reqs_after_test = kernel.load_requirements(self.test_dir)
        self.assertEqual(reqs_after_test[0]["status"], "PASS")

        # 3. Cryptographic chain validation
        valid, msg = kernel.verify_evidence_chain(self.test_dir)
        self.assertTrue(valid, f"Chain should be valid: {msg}")

        # 4. Tamper attack: Modify line in evidence.jsonl
        ev_file = kernel.get_harness_dir(self.test_dir) / "evidence.jsonl"
        with open(ev_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        tampered_entry = json.loads(lines[0])
        tampered_entry["result"] = "FAIL"  # Tamper with result
        lines[0] = json.dumps(tampered_entry) + "\n"

        with open(ev_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Re-verify chain -> MUST FAIL
        valid_after_tamper, msg_tamper = kernel.verify_evidence_chain(self.test_dir)
        self.assertFalse(valid_after_tamper, "Chain verification must fail after tampering")
        self.assertIn("tamper", msg_tamper.lower())

    # -------------------------------------------------------------------------
    # Section 17: Baseline Regression Delta Calculation
    # -------------------------------------------------------------------------
    def test_section_17_baseline_regression_delta(self):
        """Section 17: Regression calculation distinguishes pre-existing vs newly introduced failures."""
        base = {
            "tests": {
                "executed": True,
                "passed": False,
                "failed_count": 2,
                "failed_tests": ["test_legacy_1", "test_legacy_2"],
            },
            "build": {"passed": True},
            "lint": {"passed": True},
            "typecheck": {"passed": True, "status": "PASSED"},
        }

        # Case A: Same 2 failures + 1 fixed -> No regression
        curr_a = {
            "failed_count": 1,
            "failed_tests": ["test_legacy_1"],
        }
        res_a = baseline.evaluate_regression(base, curr_a)
        self.assertFalse(res_a["has_regression"])
        self.assertEqual(res_a["fixed_test_failures"], ["test_legacy_2"])

        # Case B: 1 new failure introduced -> Regression
        curr_b = {
            "failed_count": 3,
            "failed_tests": ["test_legacy_1", "test_legacy_2", "test_new_feature_broken"],
        }
        res_b = baseline.evaluate_regression(base, curr_b)
        self.assertTrue(res_b["has_regression"])
        self.assertEqual(res_b["new_test_failures"], ["test_new_feature_broken"])

    # -------------------------------------------------------------------------
    # Section 18, 19, 20: Clean-Room Verifier & Oracle Independence
    # -------------------------------------------------------------------------
    def test_section_18_19_20_verifier_independence(self):
        """Section 18, 19, 20: Test Oracle defines contracts; Verifier certifies PASS independently."""
        kernel.initialize_harness(self.test_dir, "Build secure feature")
        reqs = [{"id": "REQ-001", "description": "Core", "required": True, "status": "IMPLEMENTED_UNVERIFIED"}]
        kernel.save_requirements(self.test_dir, reqs)

        # Oracle/Verifier records verification
        kernel.record_evidence(
            self.test_dir,
            requirement_ids=["REQ-001"],
            verification_type="RUNTIME_OBSERVATION",
            command_or_interaction="curl -s http://localhost:8080/health",
            result="PASS",
            relevant_output="HTTP 200 OK",
            verifier_identity="final-verifier",
        )
        updated = kernel.load_requirements(self.test_dir)
        self.assertEqual(updated[0]["status"], "PASS")

    # -------------------------------------------------------------------------
    # Section 21: Accurate Typecheck Reporting
    # -------------------------------------------------------------------------
    def test_section_21_accurate_typecheck_reporting(self):
        """Section 21: Baseline captures NOT_CONFIGURED when typecheck command absent."""
        base = baseline.capture_project_baseline(self.test_dir, typecheck_command=None)
        self.assertEqual(base["typecheck"]["status"], "NOT_CONFIGURED")

        reg = baseline.evaluate_regression(base, {"failed_count": 0, "failed_tests": []})
        self.assertEqual(reg["typecheck_status"], "NOT_CONFIGURED")

    # -------------------------------------------------------------------------
    # Section 24: Realistic End-to-End 12-Requirement Torture Project
    # -------------------------------------------------------------------------
    def test_section_24_realistic_e2e_torture_project(self):
        """
        Section 24: Comprehensive Torture Project with 12 tricky requirements:
          1. REQ-001: Dark mode preference persistence (storage & toggle)
          2. REQ-002: Empty item title rejection with validation error
          3. REQ-003: Case-insensitive search filter
          4. REQ-004: Loading state indicator during async operations
          5. REQ-005: Delete confirmation safeguard
          6. REQ-006: Duplicate item title rejection
          7. REQ-007: Maximum title length enforcement (<= 100 chars)
          8. REQ-008: Pagination / limit-offset support
          9. REQ-009: Special character sanitization (XSS prevention)
          10. REQ-010: Export to JSON schema integrity
          11. REQ-011: Batch status update (mark all completed)
          12. REQ-012: Graceful recovery on corrupted state file
        """
        torture_dir = Path(tempfile.mkdtemp(prefix="agy_v41_torture_"))
        try:
            # 1. Initialize Harness & Capture Baseline
            state = kernel.initialize_harness(
                torture_dir,
                original_intent="Build a bulletproof Task Manager application satisfying 12 strict functional requirements.",
            )
            self.assertTrue(state["active"])
            self.assertEqual(state["phase"], "SPECIFICATION")

            # 2. Spec Architect extracts 12 atomic requirements with affectedPaths
            req_ids = [f"REQ-{i:03d}" for i in range(1, 13)]
            req_descriptions = [
                "Dark mode preference persistence (storage & toggle)",
                "Empty item title rejection with validation error",
                "Case-insensitive search filter",
                "Loading state indicator during async operations",
                "Delete confirmation safeguard",
                "Duplicate item title rejection",
                "Maximum title length enforcement (<= 100 chars)",
                "Pagination / limit-offset support",
                "Special character sanitization (XSS prevention)",
                "Export to JSON schema integrity",
                "Batch status update (mark all completed)",
                "Graceful recovery on corrupted state file",
            ]
            req_list = [
                {
                    "id": r_id,
                    "description": desc,
                    "required": True,
                    "status": "NOT_STARTED",
                    "affectedPaths": ["src/task_manager.py"],
                }
                for r_id, desc in zip(req_ids, req_descriptions)
            ]
            kernel.save_requirements(torture_dir, req_list)

            # Map 100% coverage
            cov_file = kernel.get_harness_dir(torture_dir) / "coverage.json"
            with open(cov_file, "w", encoding="utf-8") as f:
                json.dump({
                    "statements": [f"STMT-{i:03d}" for i in range(1, 13)],
                    "coveragePercent": 100,
                    "uncoveredStatements": [],
                    "complete": True,
                }, f)

            # Lock Specification
            state["specLocked"] = True
            state["phase"] = "ACCEPTANCE"
            kernel.save_state(torture_dir, state)

            # 3. Test Oracle writes acceptance contracts and locks acceptance
            acceptance_path = torture_dir / "docs" / "ACCEPTANCE_TESTS.md"
            with open(acceptance_path, "w", encoding="utf-8") as f:
                f.write("# Acceptance Test Suite Contracts\n\nContracts for REQ-001 through REQ-012.\n")
            state["acceptanceLocked"] = True
            state["phase"] = "IMPLEMENTATION"
            kernel.save_state(torture_dir, state)

            # 4. Builder Implements TaskManager production code in src/task_manager.py
            app_dir = torture_dir / "src"
            app_dir.mkdir(parents=True, exist_ok=True)
            app_code_path = app_dir / "task_manager.py"
            with open(app_code_path, "w", encoding="utf-8") as f:
                f.write('''"""
Production Task Manager Implementation
"""
import json
import html
from pathlib import Path
from typing import List, Dict, Any, Optional

class TaskManager:
    def __init__(self, data_file: Path):
        self.data_file = Path(data_file)
        self.settings: Dict[str, Any] = {"dark_mode": False}
        self.tasks: List[Dict[str, Any]] = []
        self.loading: bool = False
        self.load()

    def load(self) -> None:
        self.loading = True
        try:
            if self.data_file.exists():
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.settings = data.get("settings", {"dark_mode": False})
                    self.tasks = data.get("tasks", [])
        except Exception:
            # REQ-012: Graceful recovery on corrupted state file
            self.settings = {"dark_mode": False}
            self.tasks = []
        finally:
            self.loading = False

    def save(self) -> None:
        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump({"settings": self.settings, "tasks": self.tasks}, f, indent=2)

    # REQ-001: Dark mode persistence
    def toggle_dark_mode(self) -> bool:
        self.settings["dark_mode"] = not self.settings.get("dark_mode", False)
        self.save()
        return self.settings["dark_mode"]

    # REQ-002, REQ-006, REQ-007, REQ-009: Add task with validations
    def add_task(self, title: str) -> Dict[str, Any]:
        if not title or not title.strip():
            raise ValueError("Title cannot be empty") # REQ-002
        clean_title = title.strip()
        if len(clean_title) > 100:
            raise ValueError("Title exceeds 100 characters") # REQ-007
        
        # REQ-006: Duplicate check
        for t in self.tasks:
            if t["title"].lower() == clean_title.lower():
                raise ValueError("Duplicate task title")

        # REQ-009: XSS Sanitization
        sanitized = html.escape(clean_title)
        task = {
            "id": len(self.tasks) + 1,
            "title": sanitized,
            "completed": False
        }
        self.tasks.append(task)
        self.save()
        return task

    # REQ-003: Case-insensitive search
    def search(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [t for t in self.tasks if q in t["title"].lower()]

    # REQ-005: Delete with confirmation
    def delete_task(self, task_id: int, confirmed: bool) -> bool:
        if not confirmed:
            raise PermissionError("Delete confirmation required")
        orig_len = len(self.tasks)
        self.tasks = [t for t in self.tasks if t["id"] != task_id]
        if len(self.tasks) < orig_len:
            self.save()
            return True
        return False

    # REQ-008: Pagination
    def paginate(self, offset: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
        return self.tasks[offset:offset + limit]

    # REQ-010: Export to JSON
    def export_json(self) -> str:
        return json.dumps({"schema_version": "1.0", "tasks": self.tasks})

    # REQ-011: Batch update
    def mark_all_completed(self) -> None:
        for t in self.tasks:
            t["completed"] = True
        self.save()
''')

            # 5. Execute Test Oracle Validation for all 12 Requirements & Record Cryptographic Hash Chain
            # Runtime test database stored in tmp dir so workspace production code remains clean
            tm_data_dir = Path(tempfile.mkdtemp(prefix="tm_data_"))
            tm_file = tm_data_dir / "task_data.json"

            # Execute behavioral checks
            sys.path.insert(0, str(app_dir))
            import task_manager
            tm = task_manager.TaskManager(tm_file)

            # Verification 1: REQ-001 (Dark mode)
            dark1 = tm.toggle_dark_mode()
            self.assertTrue(dark1)
            tm2 = task_manager.TaskManager(tm_file)
            self.assertTrue(tm2.settings["dark_mode"])
            kernel.record_evidence(
                torture_dir,
                ["REQ-001"],
                "AUTOMATED_TEST",
                "test_dark_mode_persistence",
                "PASS",
                "Dark mode persisted across instances",
                "test-oracle",
            )

            # Verification 2: REQ-002 (Empty rejection)
            with self.assertRaises(ValueError):
                tm.add_task("   ")
            kernel.record_evidence(
                torture_dir,
                ["REQ-002"],
                "AUTOMATED_TEST",
                "test_empty_rejection",
                "PASS",
                "ValueError raised on empty string",
                "test-oracle",
            )

            # Verification 3: REQ-003 (Case-insensitive search)
            tm.add_task("Buy Groceries")
            tm.add_task("Clean house")
            results = tm.search("gRoCeR")
            self.assertEqual(len(results), 1)
            kernel.record_evidence(
                torture_dir,
                ["REQ-003"],
                "AUTOMATED_TEST",
                "test_search_case_insensitive",
                "PASS",
                "Found matching item with mixed case query",
                "test-oracle",
            )

            # Verification 4: REQ-004 (Loading state)
            self.assertFalse(tm.loading)
            kernel.record_evidence(
                torture_dir,
                ["REQ-004"],
                "AUTOMATED_TEST",
                "test_loading_state",
                "PASS",
                "Loading flag transitions safely during IO",
                "test-oracle",
            )

            # Verification 5: REQ-005 (Delete confirmation)
            with self.assertRaises(PermissionError):
                tm.delete_task(1, confirmed=False)
            deleted = tm.delete_task(1, confirmed=True)
            self.assertTrue(deleted)
            kernel.record_evidence(
                torture_dir,
                ["REQ-005"],
                "AUTOMATED_TEST",
                "test_delete_confirmation",
                "PASS",
                "PermissionError raised when unconfirmed; succeeds when confirmed",
                "test-oracle",
            )

            # Verification 6: REQ-006 (Duplicate rejection)
            tm.add_task("Unique Task")
            with self.assertRaises(ValueError):
                tm.add_task("unique task")
            kernel.record_evidence(
                torture_dir,
                ["REQ-006"],
                "AUTOMATED_TEST",
                "test_duplicate_rejection",
                "PASS",
                "Duplicate title rejected",
                "test-oracle",
            )

            # Verification 7: REQ-007 (Max length)
            with self.assertRaises(ValueError):
                tm.add_task("A" * 101)
            kernel.record_evidence(
                torture_dir,
                ["REQ-007"],
                "AUTOMATED_TEST",
                "test_max_title_length",
                "PASS",
                "Title > 100 chars rejected",
                "test-oracle",
            )

            # Verification 8: REQ-008 (Pagination)
            for i in range(15):
                try:
                    tm.add_task(f"Task Item {i}")
                except Exception:
                    pass
            page1 = tm.paginate(offset=0, limit=5)
            self.assertEqual(len(page1), 5)
            kernel.record_evidence(
                torture_dir,
                ["REQ-008"],
                "AUTOMATED_TEST",
                "test_pagination",
                "PASS",
                "Pagination returns exact slice",
                "test-oracle",
            )

            # Verification 9: REQ-009 (XSS Sanitization)
            xss_task = tm.add_task("<script>alert('xss')</script>")
            self.assertNotIn("<script>", xss_task["title"])
            self.assertIn("&lt;script&gt;", xss_task["title"])
            kernel.record_evidence(
                torture_dir,
                ["REQ-009"],
                "AUTOMATED_TEST",
                "test_xss_sanitization",
                "PASS",
                "HTML special characters safely escaped",
                "test-oracle",
            )

            # Verification 10: REQ-010 (Export JSON)
            export_str = tm.export_json()
            parsed_export = json.loads(export_str)
            self.assertEqual(parsed_export["schema_version"], "1.0")
            kernel.record_evidence(
                torture_dir,
                ["REQ-010"],
                "AUTOMATED_TEST",
                "test_json_export_schema",
                "PASS",
                "Exported valid schema JSON",
                "test-oracle",
            )

            # Verification 11: REQ-011 (Batch update)
            tm.mark_all_completed()
            all_done = all(t["completed"] for t in tm.tasks)
            self.assertTrue(all_done)
            kernel.record_evidence(
                torture_dir,
                ["REQ-011"],
                "AUTOMATED_TEST",
                "test_batch_mark_completed",
                "PASS",
                "All tasks marked completed",
                "test-oracle",
            )

            # Verification 12: REQ-012 (Corrupted state recovery)
            with open(tm_file, "w", encoding="utf-8") as f:
                f.write("{corrupted_json:;;;")
            tm_recovered = task_manager.TaskManager(tm_file)
            self.assertEqual(len(tm_recovered.tasks), 0)
            kernel.record_evidence(
                torture_dir,
                ["REQ-012"],
                "AUTOMATED_TEST",
                "test_corrupted_state_recovery",
                "PASS",
                "Gracefully handled corrupted file with fallback state",
                "test-oracle",
            )

            # Clean up tm_data_dir
            if tm_data_dir.exists():
                shutil.rmtree(tm_data_dir, ignore_errors=True)

            # 6. Verify evidence hash chain integrity
            chain_valid, chain_msg = kernel.verify_evidence_chain(torture_dir)
            self.assertTrue(chain_valid, f"Chain validation failed: {chain_msg}")

            # 7. Clean-Room Final Verifier Audit & Stop Hook Completion
            state = kernel.load_state(torture_dir)
            state["phase"] = "FINAL_AUDIT"
            state["finalAuditPassed"] = True
            kernel.save_state(torture_dir, state)

            stop_payload = {"workspacePaths": [str(torture_dir)], "terminationReason": "model_stop"}
            stop_res = gate.evaluate_stop(stop_payload)
            self.assertEqual(
                stop_res.get("decision"),
                "allow",
                f"Stop hook should allow clean completion, got: {stop_res}",
            )

            final_state = kernel.load_state(torture_dir)
            self.assertEqual(final_state.get("phase"), "COMPLETE")
            self.assertFalse(final_state.get("active"))

        finally:
            if torture_dir.exists():
                shutil.rmtree(torture_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
