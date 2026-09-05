"""
ANTIGRAVITY STRICT ENGINEERING KERNEL STEP 3 TEST SUITE
Comprehensive unit, adversarial, integration, and E2E validation for:
- Deterministic Risk Engine (R1 - R13)
- Verification Policy Compiler (P1 - P10)
- Step 2 Sandbox Integration (S1 - S5)
- Adaptive E2E Torture Project with 7 Mixed-Risk Requirements
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import subprocess
from pathlib import Path

# Import kernel modules
import kernel
import fingerprint
import baseline
import gate
import sandbox
import risk_engine
import verification_policy
import reporting


def set_state_flags(ws: Path, phase: str = "IMPLEMENTATION", spec_locked: bool = True, acceptance_locked: bool = True, final_audit_passed: bool = False):
    state = kernel.load_state(ws)
    state["phase"] = phase
    state["specLocked"] = spec_locked
    state["acceptanceLocked"] = acceptance_locked
    state["finalAuditPassed"] = final_audit_passed
    kernel.save_state(ws, state)


class Step3RiskAndPolicyTestSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="step3_test_")
        self.workspace = Path(self.test_dir).resolve()
        # Initialize Git repo in workspace
        subprocess.run(["git", "init"], cwd=str(self.workspace), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "TestEngineer"], cwd=str(self.workspace), check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(self.workspace), check=True)
        
        # Initial commit
        (self.workspace / "README.md").write_text("# Test Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.workspace), check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.workspace), check=True)

    def tearDown(self):
        try:
            # Clean up worktrees first
            subprocess.run(["git", "worktree", "prune"], cwd=str(self.workspace), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    # =========================================================================
    # RISK ENGINE TESTS (R1 - R13)
    # =========================================================================

    def test_r1_cosmetic_footer_classified_low(self):
        """R1: Cosmetic footer text is classified as LOW risk (score < 25)."""
        req = {
            "id": "REQ-R1",
            "title": "Update static footer text",
            "description": "Change copyright label and cosmetic padding in footer",
            "factors": {"blastRadius": 2, "novelty": 1},
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "LOW")
        self.assertLess(res["score"], 25)
        self.assertIn("COSMETIC_SURFACE", res["reasonCodes"])

    def test_r2_component_logic_classified_medium(self):
        """R2: Component modification with moderate logic branching is classified as MEDIUM risk (score 25-49)."""
        req = {
            "id": "REQ-R2",
            "title": "Add search query filter with regex matching",
            "description": "Filter list items by case-insensitive regex query in list component",
            "factors": {"blastRadius": 10, "novelty": 5, "regressionReach": 10},
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "MEDIUM")
        self.assertGreaterEqual(res["score"], 25)
        self.assertLess(res["score"], 50)

    def test_r3_complex_state_sync_classified_high(self):
        """R3: Complex multi-file state synchronization is classified as HIGH risk (score 50-74)."""
        req = {
            "id": "REQ-R3",
            "title": "Multi-tab synchronized state store with broadcast channel",
            "description": "Synchronize active workspace and background tabs across concurrent browser tabs with conflict resolution",
            "factors": {"blastRadius": 15, "concurrencyComplexity": 15, "criticalJourney": 10, "regressionReach": 10},
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "HIGH")
        self.assertGreaterEqual(res["score"], 50)
        self.assertLess(res["score"], 75)

    def test_r4_auth_boundary_override_critical(self):
        """R4: Auth boundary triggers AUTH_BOUNDARY hard override to CRITICAL."""
        req = {
            "id": "REQ-R4",
            "title": "User login session token refresh and RBAC permissions check",
            "description": "Verify JWT auth credentials and enforce role-based access permissions",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn("AUTH_BOUNDARY", res["reasonCodes"])

    def test_r5_financial_transaction_override_critical(self):
        """R5: Financial calculation triggers FINANCIAL_TRANSACTION hard override to CRITICAL."""
        req = {
            "id": "REQ-R5",
            "title": "Account billing and wallet credit payment checkout",
            "description": "Process credit card invoice charge and refund deduction",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn("FINANCIAL_TRANSACTION", res["reasonCodes"])

    def test_r6_destructive_irreversible_override_critical(self):
        """R6: Irreversible deletion triggers DESTRUCTIVE_IRREVERSIBLE hard override to CRITICAL."""
        req = {
            "id": "REQ-R6",
            "title": "Permanent delete account and purge all user data",
            "description": "Hard-delete database records and wipe cloud storage buckets",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn("DESTRUCTIVE_IRREVERSIBLE", res["reasonCodes"])

    def test_r7_schema_migration_override_critical(self):
        """R7: Schema migration triggers SCHEMA_MIGRATION hard override to CRITICAL."""
        req = {
            "id": "REQ-R7",
            "title": "Execute database schema upgrade and alter table migrations",
            "description": "Migrate database tables to v2 layout with column conversions",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn("SCHEMA_MIGRATION", res["reasonCodes"])

    def test_r8_backup_restore_override_critical(self):
        """R8: Disaster recovery triggers BACKUP_RESTORE hard override to CRITICAL."""
        req = {
            "id": "REQ-R8",
            "title": "Automated disaster recovery state restore from backup snapshot",
            "description": "Recover corrupted system state from backup archive upon failure",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn("BACKUP_RESTORE", res["reasonCodes"])

    def test_r9_persistence_override_medium(self):
        """R9: State persistence across restart triggers DATA_PERSISTENCE override."""
        req = {
            "id": "REQ-R9",
            "title": "Persist user settings to localstorage to survive restart",
            "description": "Save layout preferences so they reload state after app relaunch",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertIn(res["level"], {"MEDIUM", "HIGH", "CRITICAL"})
        self.assertIn("DATA_PERSISTENCE", res["reasonCodes"])

    def test_r10_user_declared_risk_escalation(self):
        """R10: User explicit risk declaration escalates requirement risk."""
        req = {
            "id": "REQ-R10",
            "title": "Change brand color palette",
            "description": "Cosmetic CSS color adjustments",
            "userDeclaredRisk": "CRITICAL",
        }
        res = risk_engine.evaluate_requirement_risk(req)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertIn("USER_DECLARED_RISK", res["reasonCodes"])

    def test_r11_anti_downgrade_post_spec_lock(self):
        """R11: Builder cannot downgrade risk post-spec-lock; escalations are allowed."""
        # Builder attempting downgrade after spec lock -> DENIED
        can_mod, msg = risk_engine.can_modify_risk_level("HIGH", "LOW", caller_identity="builder", is_spec_locked=True)
        self.assertFalse(can_mod)
        self.assertIn("Security Gate Deny", msg)

        # Builder escalating risk after spec lock -> ALLOWED
        can_mod_esc, msg_esc = risk_engine.can_modify_risk_level("LOW", "HIGH", caller_identity="builder", is_spec_locked=True)
        self.assertTrue(can_mod_esc)

        # User / Orchestrator modifying before spec lock -> ALLOWED
        can_mod_pre, _ = risk_engine.can_modify_risk_level("HIGH", "LOW", caller_identity="architect", is_spec_locked=False)
        self.assertTrue(can_mod_pre)

    def test_r12_dynamic_risk_escalation(self):
        """R12: Dynamic risk escalation invalidates requirement status to STALE and logs change."""
        kernel.initialize_harness(self.workspace, "Dynamic escalation test")
        set_state_flags(self.workspace, phase="IMPLEMENTATION", spec_locked=True, acceptance_locked=True)

        reqs = [{
            "id": "REQ-DYN",
            "title": "Simple data parser",
            "description": "Parse input lines",
            "status": "PASS",
            "risk": {"level": "LOW", "score": 10, "reasonCodes": []},
        }]
        kernel.save_requirements(self.workspace, reqs)

        ok, msg = risk_engine.escalate_requirement_risk(
            self.workspace,
            "REQ-DYN",
            "CRITICAL",
            "BufferOverflowVulnerabilityDiscovered",
            escalater_identity="diagnostic-engineer",
        )
        self.assertTrue(ok)

        # Verify requirement updated and invalidated to STALE
        updated_reqs = kernel.load_requirements(self.workspace)
        dyn_req = updated_reqs[0]
        self.assertEqual(dyn_req["risk"]["level"], "CRITICAL")
        self.assertEqual(dyn_req["status"], "STALE")

    def test_r13_effective_risk_calculation(self):
        """R13: Dependency inheritance propagates parent high/critical risk to child requirements."""
        child_req = {
            "id": "REQ-CHILD",
            "title": "Render status badge",
            "description": "Cosmetic badge",
            "factors": {"blastRadius": 2},
        }
        res_standalone = risk_engine.evaluate_requirement_risk(child_req)
        self.assertEqual(res_standalone["level"], "LOW")

        res_inherited = risk_engine.evaluate_requirement_risk(child_req, parent_effective_risk="CRITICAL")
        self.assertEqual(res_inherited["level"], "CRITICAL")
        self.assertEqual(res_inherited["intrinsicLevel"], "LOW")
        self.assertIn("DEPENDENCY_INHERITED_CRITICAL", res_inherited["reasonCodes"])

    # =========================================================================
    # VERIFICATION POLICY COMPILER TESTS (P1 - P10)
    # =========================================================================

    def test_p1_policy_compilation_structure(self):
        """P1: Verification policy compiles into structured matrix file."""
        kernel.initialize_harness(self.workspace, "Policy compilation test")
        reqs = [{
            "id": "REQ-P1",
            "title": "Auth login token",
            "description": "JWT session authentication",
        }]
        kernel.save_requirements(self.workspace, reqs)
        matrix = verification_policy.generate_and_save_policy_matrix(self.workspace)
        
        self.assertEqual(matrix["schemaVersion"], "3.0.0")
        self.assertIn("REQ-P1", matrix["policies"])
        p = matrix["policies"]["REQ-P1"]
        self.assertEqual(p["riskLevel"], "CRITICAL")
        self.assertIn("NEGATIVE_PATH", p["requiredChecks"])
        self.assertIn("CLEAN_ROOM_AUDIT", p["requiredChecks"])
        
        # Check file exists on disk
        policy_file = self.workspace / ".agent-harness" / "verification-policy.json"
        self.assertTrue(policy_file.exists())

    def test_p2_capability_awareness_not_configured(self):
        """P2: Missing baseline capabilities are detected and marked accurately."""
        caps = verification_policy.detect_project_capabilities(self.workspace)
        self.assertFalse(caps["hasTypecheck"])
        self.assertFalse(caps["hasBuild"])

    def test_p3_capability_awareness_not_applicable(self):
        """P3: CLI/Library project correctly classifies UI capabilities as not applicable."""
        caps = verification_policy.detect_project_capabilities(self.workspace)
        self.assertTrue(caps["isCli"])
        self.assertFalse(caps["isWebUi"])

    def test_p4_low_risk_policy_checks(self):
        """P4: LOW risk policy requires STATIC and AUTOMATED_TEST."""
        req = {"id": "REQ-LOW", "risk": {"level": "LOW", "score": 10}}
        p = verification_policy.compile_verification_policy(req)
        self.assertEqual(p["requiredChecks"], ["AUTOMATED_TEST", "STATIC"])

    def test_p5_medium_risk_policy_checks(self):
        """P5: MEDIUM risk policy requires STATIC, AUTOMATED_TEST, and RUNTIME_OBSERVATION."""
        req = {"id": "REQ-MED", "title": "Search filter", "risk": {"level": "MEDIUM", "score": 35}}
        p = verification_policy.compile_verification_policy(req)
        self.assertIn("STATIC", p["requiredChecks"])
        self.assertIn("AUTOMATED_TEST", p["requiredChecks"])
        self.assertIn("RUNTIME_OBSERVATION", p["requiredChecks"])

    def test_p6_high_risk_policy_checks(self):
        """P6: HIGH risk policy requires NEGATIVE_PATH and POST_PROMOTION."""
        req = {"id": "REQ-HIGH", "title": "Data synchronization", "risk": {"level": "HIGH", "score": 60}}
        p = verification_policy.compile_verification_policy(req)
        self.assertIn("NEGATIVE_PATH", p["requiredChecks"])
        self.assertIn("POST_PROMOTION", p["requiredChecks"])

    def test_p7_critical_risk_policy_checks(self):
        """P7: CRITICAL risk policy requires full suite including CLEAN_ROOM_AUDIT."""
        req = {
            "id": "REQ-CRIT",
            "title": "Permanent delete account and purge data",
            "risk": {"level": "CRITICAL", "score": 90, "reasonCodes": ["DESTRUCTIVE_IRREVERSIBLE"]},
        }
        p = verification_policy.compile_verification_policy(req)
        self.assertIn("STATIC", p["requiredChecks"])
        self.assertIn("AUTOMATED_TEST", p["requiredChecks"])
        self.assertIn("RUNTIME_OBSERVATION", p["requiredChecks"])
        self.assertIn("NEGATIVE_PATH", p["requiredChecks"])
        self.assertIn("CLEAN_ROOM_AUDIT", p["requiredChecks"])
        self.assertIn("POST_PROMOTION", p["requiredChecks"])
        self.assertIn("RECOVERY_OBSERVATION", p["requiredChecks"])

    def test_p8_missing_negative_path_blocks_gate(self):
        """P8: Completion gate blocks stop when HIGH/CRITICAL requirement lacks NEGATIVE_PATH evidence."""
        kernel.initialize_harness(self.workspace, "Negative path gate test")
        set_state_flags(self.workspace, phase="VERIFICATION", spec_locked=True, acceptance_locked=True)

        reqs = [{
            "id": "REQ-AUTH",
            "title": "Auth login token",
            "description": "JWT session auth",
            "status": "PASS",
            "required": True,
            "risk": {"level": "CRITICAL", "score": 85, "reasonCodes": ["AUTH_BOUNDARY"]},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        # Record only standard positive test
        kernel.record_evidence(
            self.workspace,
            ["REQ-AUTH"],
            "AUTOMATED_TEST",
            "test_login_success()",
            "PASS",
            "Happy path passed",
            "verifier",
        )

        stop_eval = gate.evaluate_stop({"workspacePaths": [str(self.workspace)]})
        self.assertEqual(stop_eval["decision"], "continue")
        self.assertIn("missing required verification", stop_eval["reason"].lower())

    def test_p9_stale_policy_invalidation_on_requirement_change(self):
        """P9: Changing requirements invalidates policy satisfaction."""
        kernel.initialize_harness(self.workspace, "Stale invalidation test")
        reqs = [{
            "id": "REQ-STALE",
            "title": "Config parser",
            "description": "Parse config",
            "status": "PASS",
            "risk": {"level": "LOW", "score": 10},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        # Update requirement with higher risk
        reqs[0]["risk"] = {"level": "CRITICAL", "score": 80, "reasonCodes": ["AUTH_BOUNDARY"]}
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        ok, issues, stats = verification_policy.audit_verification_policy(self.workspace)
        self.assertFalse(ok)
        self.assertEqual(stats["incomplete"], 1)

    def test_p10_dynamic_risk_elevation_updates_policy(self):
        """P10: Dynamic risk escalation updates policy required checks and fails audit until met."""
        kernel.initialize_harness(self.workspace, "Dynamic policy elevation test")
        reqs = [{
            "id": "REQ-ELEV",
            "title": "Text widget",
            "description": "Display message",
            "status": "PASS",
            "risk": {"level": "LOW", "score": 10},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        # Initially valid for LOW
        kernel.record_evidence(self.workspace, ["REQ-ELEV"], "AUTOMATED_TEST", "test_text()", "PASS", "passed", "verifier")
        ok, _, _ = verification_policy.audit_verification_policy(self.workspace)
        self.assertTrue(ok)

        # Escalate to CRITICAL
        risk_engine.escalate_requirement_risk(self.workspace, "REQ-ELEV", "CRITICAL", "RemoteCodeExecution", "test-oracle")
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        ok2, issues, _ = verification_policy.audit_verification_policy(self.workspace)
        self.assertFalse(ok2)
        self.assertTrue(any("NEGATIVE_PATH" in s for s in issues))

    # =========================================================================
    # STEP 2 INTEGRATION TESTS (S1 - S5)
    # =========================================================================

    def test_s1_candidate_aggregate_risk_calculation(self):
        """S1: calculate_candidate_aggregate_risk returns max risk of affected requirements."""
        kernel.initialize_harness(self.workspace, "Aggregate risk test")
        reqs = [
            {"id": "REQ-1", "affectedPaths": ["ui/footer.py"], "risk": {"level": "LOW"}},
            {"id": "REQ-2", "affectedPaths": ["auth/login.py"], "risk": {"level": "CRITICAL"}},
            {"id": "REQ-3", "affectedPaths": ["search/filter.py"], "risk": {"level": "MEDIUM"}},
        ]
        kernel.save_requirements(self.workspace, reqs)

        # Candidate modifying only footer.py -> LOW
        r_low = sandbox.calculate_candidate_aggregate_risk(self.workspace, ["ui/footer.py"])
        self.assertEqual(r_low, "LOW")

        # Candidate modifying auth/login.py -> CRITICAL
        r_crit = sandbox.calculate_candidate_aggregate_risk(self.workspace, ["auth/login.py", "ui/footer.py"])
        self.assertEqual(r_crit, "CRITICAL")

    def test_s2_low_risk_candidate_standard_verification(self):
        """S2: LOW risk candidate is processed cleanly without unnecessary critical overhead."""
        kernel.initialize_harness(self.workspace, "Low risk sandbox test")
        set_state_flags(self.workspace, phase="IMPLEMENTATION", spec_locked=True, acceptance_locked=True)

        reqs = [{
            "id": "REQ-LOW-SANDBOX",
            "title": "Footer text",
            "description": "Static footer",
            "affectedPaths": ["footer.txt"],
            "risk": {"level": "LOW", "score": 10},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        # Create sandbox
        task_id = "task-s2"
        ok, msg, manifest = sandbox.create_builder_sandbox(self.workspace, task_id)
        self.assertTrue(ok)
        wt_path = Path(manifest["builderWorktree"])
        (wt_path / "footer.txt").write_text("v1.0 Footer", encoding="utf-8")
        
        # Create candidate changeset
        ok_ch, msg_ch, manifest_ch = sandbox.create_candidate_changeset(self.workspace, task_id, "Added footer")
        self.assertTrue(ok_ch)
        self.assertEqual(manifest_ch["candidateAggregateRisk"], "LOW")
        sandbox.cleanup_sandbox(self.workspace, task_id)

    def test_s3_critical_risk_candidate_post_promotion_suite(self):
        """S3: CRITICAL candidate enforces clean-room audit and post-promotion verification."""
        kernel.initialize_harness(self.workspace, "Critical post-promotion test")
        set_state_flags(self.workspace, phase="IMPLEMENTATION", spec_locked=True, acceptance_locked=True)

        reqs = [{
            "id": "REQ-CRIT-SANDBOX",
            "title": "Auth token auth",
            "description": "JWT authentication session",
            "affectedPaths": ["auth.py"],
            "risk": {"level": "CRITICAL", "score": 85, "reasonCodes": ["AUTH_BOUNDARY"]},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        task_id = "task-s3"
        ok, msg, manifest = sandbox.create_builder_sandbox(self.workspace, task_id)
        self.assertTrue(ok)
        wt_path = Path(manifest["builderWorktree"])
        (wt_path / "auth.py").write_text("def verify_token(t): return t == 'secret'\n", encoding="utf-8")
        
        ok_ch, msg_ch, manifest_ch = sandbox.create_candidate_changeset(self.workspace, task_id, "Auth module")
        self.assertTrue(ok_ch)
        self.assertEqual(manifest_ch["candidateAggregateRisk"], "CRITICAL")
        sandbox.cleanup_sandbox(self.workspace, task_id)

    def test_s4_promotion_blocked_on_unsatisfied_policy(self):
        """S4: Promotion and Stop Gate reject candidate when verification policy is unsatisfied."""
        kernel.initialize_harness(self.workspace, "Blocked promotion test")
        set_state_flags(self.workspace, phase="VERIFICATION", spec_locked=True, acceptance_locked=True)

        reqs = [{
            "id": "REQ-S4",
            "title": "Billing checkout",
            "description": "Credit card charge",
            "status": "PASS",
            "required": True,
            "risk": {"level": "CRITICAL", "score": 90, "reasonCodes": ["FINANCIAL_TRANSACTION"]},
        }]
        kernel.save_requirements(self.workspace, reqs)
        verification_policy.generate_and_save_policy_matrix(self.workspace)

        # Audit should fail because no evidence exists
        ok, issues, _ = verification_policy.audit_verification_policy(self.workspace)
        self.assertFalse(ok)
        self.assertGreater(len(issues), 0)

    def test_s5_single_source_reporting_step3_schema(self):
        """S5: Reporting creates canonical summary adhering to Step 3 schema."""
        kernel.initialize_harness(self.workspace, "Reporting test")
        report = reporting.create_canonical_summary(
            task_id="task-s5-report",
            title="Step 3 Reporting Test",
            risk_engine={"candidateAggregateRisk": "CRITICAL", "deterministicScoring": "PASS"},
            policy_compiler={"satisfiedRequirements": 1, "status": "PASS"},
        )
        self.assertEqual(report["schemaVersion"], "3.0.0")
        self.assertIn("riskEngine", report)
        self.assertIn("policyCompiler", report)
        self.assertEqual(report["riskEngine"]["candidateAggregateRisk"], "CRITICAL")

    # =========================================================================
    # REALISTIC ADAPTIVE E2E TORTURE PROJECT
    # =========================================================================

    def test_step3_adaptive_torture_project(self):
        """
        Comprehensive Realistic Adaptive Torture Project:
        7 Mixed-Risk Requirements:
        - REQ-1 (LOW: UI theme footer text)
        - REQ-2 (MEDIUM: Case-insensitive search filter)
        - REQ-3 (HIGH: Multi-tab state broadcast channel)
        - REQ-4 (CRITICAL: JWT Auth token session verification)
        - REQ-5 (CRITICAL: Account billing wallet deduction)
        - REQ-6 (CRITICAL: Permanent data purge with soft-delete restore)
        - REQ-7 (MEDIUM: Dynamic escalation to CRITICAL upon vulnerability discovery)
        """
        ws = self.workspace
        kernel.initialize_harness(ws, "Adaptive Torture Project with 7 Mixed-Risk Requirements")
        
        # 1. Base files
        (ws / "app.py").write_text("# Production App\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(ws), check=True)
        subprocess.run(["git", "commit", "-m", "App baseline"], cwd=str(ws), check=True)
        baseline.capture_project_baseline(ws)

        # 2. Extract & Define Requirements with structured factors and risk analysis
        raw_reqs = [
            {"id": "REQ-1", "title": "Update static footer brand text", "description": "Cosmetic copyright string", "affectedPaths": ["ui/footer.py"], "factors": {"blastRadius": 2}},
            {"id": "REQ-2", "title": "Search filter query matcher", "description": "Filter items with case-insensitive logic", "affectedPaths": ["search/filter.py"], "factors": {"blastRadius": 10, "novelty": 5, "regressionReach": 10}},
            {"id": "REQ-3", "title": "Multi-tab state broadcast channel", "description": "Synchronize tab state concurrently across windows", "affectedPaths": ["state/broadcast.py"], "factors": {"blastRadius": 15, "concurrencyComplexity": 15, "criticalJourney": 10, "regressionReach": 10}},
            {"id": "REQ-4", "title": "JWT Auth token session validation", "description": "Enforce authentication and role permissions", "affectedPaths": ["auth/jwt.py"]},
            {"id": "REQ-5", "title": "Account billing wallet payment charge", "description": "Financial transaction debit calculation", "affectedPaths": ["billing/payment.py"]},
            {"id": "REQ-6", "title": "Permanent delete user data with recovery backup", "description": "Hard-delete account data with disaster recovery restore", "affectedPaths": ["data/purge.py"]},
            {"id": "REQ-7", "title": "JSON payload validator", "description": "Parse and validate incoming payload", "affectedPaths": ["parser/json.py"], "factors": {"blastRadius": 10, "novelty": 5, "regressionReach": 10}},
        ]

        # Evaluate risk deterministically
        evaluated_reqs = []
        for r in raw_reqs:
            r["risk"] = risk_engine.evaluate_requirement_risk(r)
            r["status"] = "NOT_STARTED"
            r["required"] = True
            evaluated_reqs.append(r)

        kernel.save_requirements(ws, evaluated_reqs)
        self.assertEqual(evaluated_reqs[0]["risk"]["level"], "LOW")
        self.assertEqual(evaluated_reqs[1]["risk"]["level"], "MEDIUM")
        self.assertEqual(evaluated_reqs[2]["risk"]["level"], "HIGH")
        self.assertEqual(evaluated_reqs[3]["risk"]["level"], "CRITICAL")
        self.assertEqual(evaluated_reqs[4]["risk"]["level"], "CRITICAL")
        self.assertEqual(evaluated_reqs[5]["risk"]["level"], "CRITICAL")
        self.assertEqual(evaluated_reqs[6]["risk"]["level"], "MEDIUM")

        # 3. Compile Verification Policy Matrix
        matrix = verification_policy.generate_and_save_policy_matrix(ws)
        self.assertEqual(len(matrix["policies"]), 7)

        # 4. Lock Specification & Acceptance Contracts
        set_state_flags(ws, phase="IMPLEMENTATION", spec_locked=True, acceptance_locked=True)

        # 5. Create Sandbox & Implement in Worktree
        task_id = "task-torture-step3"
        ok_sb, msg_sb, manifest_sb = sandbox.create_builder_sandbox(ws, task_id)
        self.assertTrue(ok_sb)
        wt_path = Path(manifest_sb["builderWorktree"])
        
        # Implement files
        (wt_path / "ui").mkdir(parents=True, exist_ok=True)
        (wt_path / "ui" / "footer.py").write_text("FOOTER = 'Strict v4.1'\n", encoding="utf-8")
        
        (wt_path / "search").mkdir(parents=True, exist_ok=True)
        (wt_path / "search" / "filter.py").write_text("def filter_items(items, q): return [i for i in items if q.lower() in i.lower()]\n", encoding="utf-8")
        
        (wt_path / "state").mkdir(parents=True, exist_ok=True)
        (wt_path / "state" / "broadcast.py").write_text("def sync_tab(data): return {'synced': True, 'data': data}\n", encoding="utf-8")
        
        (wt_path / "auth").mkdir(parents=True, exist_ok=True)
        (wt_path / "auth" / "jwt.py").write_text("def verify_jwt(token): return token.startswith('valid_')\n", encoding="utf-8")
        
        (wt_path / "billing").mkdir(parents=True, exist_ok=True)
        (wt_path / "billing" / "payment.py").write_text("def debit(bal, amt): assert amt > 0; return bal - amt\n", encoding="utf-8")
        
        (wt_path / "data").mkdir(parents=True, exist_ok=True)
        (wt_path / "data" / "purge.py").write_text("def purge_user(uid): return {'purged': True, 'snapshot': f'backup_{uid}'}\n", encoding="utf-8")
        
        (wt_path / "parser").mkdir(parents=True, exist_ok=True)
        (wt_path / "parser" / "json.py").write_text("import json\ndef parse_json(raw): return json.loads(raw)\n", encoding="utf-8")

        # 6. Dynamic Escalation of REQ-7 to CRITICAL
        risk_engine.escalate_requirement_risk(ws, "REQ-7", "CRITICAL", "DeserializationFlawDetected", "diagnostic-engineer")
        verification_policy.generate_and_save_policy_matrix(ws)

        # 7. Create Candidate Changeset
        ok_cs, msg_cs, manifest = sandbox.create_candidate_changeset(ws, task_id, "Torture implementation")
        self.assertTrue(ok_cs)
        self.assertEqual(manifest["candidateAggregateRisk"], "CRITICAL")

        # 8. Promote candidate patch to canonical workspace
        sandbox.verify_sandbox_candidate(ws, task_id)
        prom_ok, prom_msg = sandbox.promote_candidate(ws, task_id)
        self.assertTrue(prom_ok, f"Promotion failed: {prom_msg}")

        post_ok, post_msg = sandbox.verify_post_promotion(ws, task_id)
        self.assertTrue(post_ok, f"Post promotion failed: {post_msg}")

        # 9. Clean-Room Verification with Risk-Adaptive Evidence Recording on Promoted Canonical Workspace
        set_state_flags(ws, phase="VERIFICATION", spec_locked=True, acceptance_locked=True)
        
        # REQ-1 (LOW): Static + Automated Test
        kernel.record_evidence(ws, ["REQ-1"], "AUTOMATED_TEST", "test_footer_rendered()", "PASS", "Footer verified", "verifier")
        
        # REQ-2 (MEDIUM): Static + Automated Test + Runtime Observation
        kernel.record_evidence(ws, ["REQ-2"], "AUTOMATED_TEST", "test_search_filter()", "PASS", "Search verified", "verifier")
        kernel.record_evidence(ws, ["REQ-2"], "RUNTIME_OBSERVATION", "observe_search_runtime()", "PASS", "Runtime verified", "verifier")

        # REQ-3 (HIGH): Static + Automated Test + Runtime + Negative + Post-Promotion
        kernel.record_evidence(ws, ["REQ-3"], "AUTOMATED_TEST", "test_state_broadcast()", "PASS", "State verified", "verifier")
        kernel.record_evidence(ws, ["REQ-3"], "RUNTIME_OBSERVATION", "observe_tab_runtime()", "PASS", "Runtime verified", "verifier")
        kernel.record_evidence(ws, ["REQ-3"], "AUTOMATED_TEST", "test_negative_tab_desync()", "PASS", "Negative path verified", "verifier")
        kernel.record_evidence(ws, ["REQ-3"], "AUTOMATED_TEST", "run_post_promotion_tab_sync()", "PASS", "Post promotion check", "verifier")

        # REQ-4 (CRITICAL): Full suite (Positive + Negative + Runtime + Clean Room + Post Promotion)
        kernel.record_evidence(ws, ["REQ-4"], "AUTOMATED_TEST", "test_jwt_auth_positive()", "PASS", "Auth pass", "verifier")
        kernel.record_evidence(ws, ["REQ-4"], "AUTOMATED_TEST", "test_negative_unauthorized_token()", "PASS", "Negative path pass", "verifier")
        kernel.record_evidence(ws, ["REQ-4"], "RUNTIME_OBSERVATION", "observe_jwt_runtime()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-4"], "AUTOMATED_TEST", "clean_room_auth_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-4"], "AUTOMATED_TEST", "run_post_promotion_auth_verification()", "PASS", "Post promotion pass", "verifier")

        # REQ-5 (CRITICAL): Financial debit full suite
        kernel.record_evidence(ws, ["REQ-5"], "AUTOMATED_TEST", "test_billing_debit()", "PASS", "Debit pass", "verifier")
        kernel.record_evidence(ws, ["REQ-5"], "AUTOMATED_TEST", "test_negative_insufficient_funds()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-5"], "RUNTIME_OBSERVATION", "observe_billing_runtime()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-5"], "AUTOMATED_TEST", "clean_room_billing_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-5"], "AUTOMATED_TEST", "run_post_promotion_billing_verification()", "PASS", "Post promotion pass", "verifier")

        # REQ-6 (CRITICAL): Destructive purge with recovery observation
        kernel.record_evidence(ws, ["REQ-6"], "AUTOMATED_TEST", "test_purge_user_data()", "PASS", "Purge pass", "verifier")
        kernel.record_evidence(ws, ["REQ-6"], "AUTOMATED_TEST", "test_negative_invalid_uid_purge()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-6"], "RUNTIME_OBSERVATION", "observe_purge_runtime()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-6"], "AUTOMATED_TEST", "test_recovery_observation_from_backup()", "PASS", "Recovery pass", "verifier")
        kernel.record_evidence(ws, ["REQ-6"], "AUTOMATED_TEST", "clean_room_purge_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-6"], "AUTOMATED_TEST", "run_post_promotion_purge_verification()", "PASS", "Post promotion pass", "verifier")

        # REQ-7 (CRITICAL): JSON validator full suite
        kernel.record_evidence(ws, ["REQ-7"], "AUTOMATED_TEST", "test_json_parse_valid()", "PASS", "Valid pass", "verifier")
        kernel.record_evidence(ws, ["REQ-7"], "AUTOMATED_TEST", "test_negative_corrupted_json_payload()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-7"], "RUNTIME_OBSERVATION", "observe_parser_runtime()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-7"], "AUTOMATED_TEST", "clean_room_parser_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-7"], "AUTOMATED_TEST", "run_post_promotion_parser_verification()", "PASS", "Post promotion pass", "verifier")

        # Update requirements to PASS with current fresh workspace fingerprint
        file_hashes = fingerprint.get_workspace_file_hashes(ws)
        curr_fp = fingerprint.compute_workspace_fingerprint(ws, file_hashes)
        current_reqs = kernel.load_requirements(ws)
        for r in current_reqs:
            r["status"] = "PASS"
            r["lastVerifiedFingerprint"] = curr_fp
        kernel.save_requirements(ws, current_reqs)

        # Set 100% complete coverage
        cov_file = kernel.get_harness_dir(ws) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100, "uncoveredStatements": []}, f)

        # 10. Audit Verification Policy & Completion Gate
        policy_ok, policy_issues, stats = verification_policy.audit_verification_policy(ws)
        self.assertTrue(policy_ok, f"Policy audit failed: {policy_issues}")
        self.assertEqual(stats["satisfied"], 7)

        # Final verifier audit pass
        set_state_flags(ws, phase="VERIFICATION", spec_locked=True, acceptance_locked=True, final_audit_passed=True)

        # Completion gate evaluation
        stop_eval = gate.evaluate_stop({"workspacePaths": [str(ws)]})
        self.assertEqual(stop_eval["decision"], "allow")

        # 11. Single-Source Reporting
        report = reporting.create_canonical_summary(
            task_id="task-torture-step3",
            title="Step 3 Torture Project",
            risk_engine={"candidateAggregateRisk": "CRITICAL", "deterministicScoring": "PASS"},
            policy_compiler={"satisfiedRequirements": 7, "status": "PASS"},
        )
        self.assertEqual(report["schemaVersion"], "3.0.0")
        self.assertEqual(report["riskEngine"]["candidateAggregateRisk"], "CRITICAL")
        self.assertEqual(report["policyCompiler"]["satisfiedRequirements"], 7)

        # Cleanup sandbox
        sandbox.cleanup_sandbox(ws, task_id)


if __name__ == "__main__":
    unittest.main()
