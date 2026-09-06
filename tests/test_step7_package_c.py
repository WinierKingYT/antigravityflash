"""
Unit tests for Step 7 Package C:
Stopping Engine, Consistency Reviewer, and Decision Coverage Matrix.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure paths
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
STRICT_PATH = SRC_PATH / "strict_engineering"

for p in [str(REPO_ROOT), str(SRC_PATH), str(STRICT_PATH)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import stopping_engine
import consistency_reviewer
import decision_coverage
import decision_graph
import frame
import concern
import decision


class TestStep7PackageC(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ws = Path(self.test_dir)
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. STOPPING ENGINE TESTS
    # -------------------------------------------------------------------------

    def test_stopping_engine_default_status(self):
        status = stopping_engine.load_decision_status(self.ws)
        self.assertFalse(status["canProceedToSpec"])
        self.assertEqual(status["unresolvedConcernsCount"], 0)
        self.assertEqual(status["stoppingThreshold"], stopping_engine.DEFAULT_MIN_QUESTION_UTILITY)

    def test_stopping_engine_all_resolved(self):
        concerns = [
            {"id": "CONC-001", "status": "RESOLVED", "riskLevel": "LOW"},
            {"id": "CONC-002", "status": "DEFERRED", "riskLevel": "MEDIUM"},
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns)
        self.assertTrue(status["canProceedToSpec"])
        self.assertEqual(status["unresolvedConcernsCount"], 0)
        self.assertEqual(status["resolvedConcernsCount"], 2)
        self.assertTrue(status["stoppingConditionsMet"]["noUnresolvedConcerns"])

    def test_stopping_engine_blocking_critical_concern_blocks_spec(self):
        concerns = [
            {"id": "CONC-001", "status": "RESOLVED", "riskLevel": "LOW"},
            {"id": "CONC-002", "status": "ACTIVE", "riskLevel": "CRITICAL"},
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("CONC-002", status["blockingConcerns"])
        self.assertIn("Unresolved blocking/critical concerns remain", status["reason"])

    def test_stopping_engine_blocking_flag_blocks_spec(self):
        concerns = [
            {"id": "CONC-001", "status": "ACTIVE", "riskLevel": "MEDIUM", "isBlocking": True},
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("CONC-001", status["blockingConcerns"])

    def test_stopping_engine_utility_below_threshold_allows_stop(self):
        # Concern with low utility: LOW risk, repeated, low uncertainty, no reach
        concerns = [
            {
                "id": "CONC-001",
                "status": "ACTIVE",
                "riskLevel": "LOW",
                "uncertainty": 0.1,
                "downstreamImpact": 0.1,
                "expectedDiscrimination": 0.1,
                "questionCost": 0.9,
                "userEffort": 0.9,
                "isBlocking": False,
            }
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns, threshold=0.35)
        self.assertTrue(status["canProceedToSpec"])
        self.assertTrue(status["stoppingConditionsMet"]["remainingUtilityBelowThreshold"])
        self.assertIn("below threshold", status["reason"])

    def test_stopping_engine_utility_above_threshold_continues_discovery(self):
        concerns = [
            {
                "id": "CONC-001",
                "status": "ACTIVE",
                "riskLevel": "MEDIUM",
                "uncertainty": 0.9,
                "downstreamImpact": 0.9,
                "expectedDiscrimination": 0.9,
                "questionCost": 0.1,
                "userEffort": 0.1,
                "isBlocking": False,
            }
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns, threshold=0.35)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("unresolved concerns remain with highest utility", status["reason"])

    def test_stopping_engine_unresolved_high_risk_blocks(self):
        concerns = [
            {
                "id": "CONC-001",
                "status": "ACTIVE",
                "riskLevel": "HIGH",
                "uncertainty": 0.1,
                "downstreamImpact": 0.1,
                "isBlocking": False,
            }
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns, threshold=0.35)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("CONC-001", status["blockingConcerns"])
        self.assertIn("Unresolved blocking/critical concerns remain", status["reason"])

    def test_stopping_engine_session_fatigue_limit(self):
        # Case 1: Fatigue reached and remaining concern has high utility -> PAUSES with SESSION_QUESTION_BUDGET_REACHED
        concerns_high = [
            {
                "id": "CONC-001",
                "status": "ACTIVE",
                "riskLevel": "MEDIUM",
                "uncertainty": 0.9,
                "downstreamImpact": 0.9,
                "questionCost": 0.1,
                "userEffort": 0.1,
                "isBlocking": False,
            }
        ]
        fake_asked = [{"question": f"Q{i}", "topic": "T"} for i in range(15)]
        status_high = stopping_engine.evaluate_stopping_conditions(
            concerns_high,
            asked_questions=fake_asked,
            max_questions=15,
        )
        self.assertFalse(status_high["canProceedToSpec"])
        self.assertEqual(status_high["reason"], "SESSION_QUESTION_BUDGET_REACHED")

        # Case 2: Fatigue reached and all remaining concerns have low utility -> allows proceed
        concerns_low = [
            {
                "id": "CONC-002",
                "status": "ACTIVE",
                "riskLevel": "LOW",
                "uncertainty": 0.1,
                "downstreamImpact": 0.1,
                "expectedDiscrimination": 0.1,
                "questionCost": 0.9,
                "userEffort": 0.9,
                "isBlocking": False,
            }
        ]
        status_low = stopping_engine.evaluate_stopping_conditions(
            concerns_low,
            asked_questions=fake_asked,
            max_questions=15,
        )
        self.assertTrue(status_low["canProceedToSpec"])
        self.assertTrue(status_low["stoppingConditionsMet"]["sessionFatigueReached"])

    def test_stopping_engine_invalid_graph_blocks_spec(self):
        # Create an invalid cyclic graph
        cyclic_graph = {
            "nodes": {
                "CONC-001": {"id": "CONC-001", "type": "CONCERN"},
                "DEC-001": {"id": "DEC-001", "type": "DECISION"},
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "DEC-001", "target": "CONC-001", "relationship": "AFFECTS"},
            ],
            "metadata": {"version": "7.0"},
        }
        concerns = [{"id": "CONC-001", "status": "RESOLVED", "riskLevel": "LOW"}]
        status = stopping_engine.evaluate_stopping_conditions(concerns, graph_data=cyclic_graph)
        self.assertFalse(status["canProceedToSpec"])
        self.assertFalse(status["stoppingConditionsMet"]["graphValid"])
        self.assertIn("Decision graph validation failed", status["reason"])

    def test_stopping_engine_sync_persistence(self):
        # Save concerns file in harness
        concerns_path = self.harness_dir / "concerns.json"
        with open(concerns_path, "w", encoding="utf-8") as f:
            json.dump([{"id": "CONC-001", "status": "RESOLVED", "riskLevel": "LOW"}], f)

        status = stopping_engine.sync_decision_status(self.ws)
        self.assertTrue(status["canProceedToSpec"])

        # Check saved file
        saved_file = stopping_engine.get_decision_status_path(self.ws)
        self.assertTrue(saved_file.exists())
        loaded = stopping_engine.load_decision_status(self.ws)
        self.assertEqual(loaded["canProceedToSpec"], True)

    # -------------------------------------------------------------------------
    # 2. CONSISTENCY REVIEWER TESTS
    # -------------------------------------------------------------------------

    def test_consistency_clean_audit(self):
        f = {
            "goals": ["Build a fast local note-taking desktop app"],
            "constraints": ["Run 100% offline"],
            "nonGoals": ["No multi-user sync"],
        }
        c = [
            {"id": "CONC-001", "category": "PERSISTENCE", "riskLevel": "MEDIUM", "status": "RESOLVED"}
        ]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Use SQLite for local file storage",
                "chosenOption": "SQLite embedded database",
                "authority": "USER_DIRECT",
                "status": "ACTIVE",
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertTrue(is_consistent)
        self.assertEqual(len(issues), 0)

    def test_consistency_frame_non_goal_contradiction(self):
        f = {
            "goals": ["Local desktop tool"],
            "nonGoals": ["No multi-user real-time collaboration"],
        }
        c = [{"id": "CONC-001", "category": "WORKFLOW"}]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Implement multi-user collaboration",
                "chosenOption": "Enable real-time collaboration with WebSockets",
                "authority": "USER_DIRECT",
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        contradiction_issues = [i for i in issues if i["code"] == "FRAME_CONTRADICTION"]
        self.assertEqual(len(contradiction_issues), 1)
        self.assertEqual(contradiction_issues[0]["severity"], "BLOCKING")
        self.assertIn("DEC-001", contradiction_issues[0]["affectedNodes"])

    def test_consistency_frame_constraint_violation(self):
        f = {
            "goals": ["Local note-taking"],
            "constraints": ["Must work 100% offline"],
        }
        c = [{"id": "CONC-001", "category": "PERSISTENCE"}]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Store notes in AWS S3 remote cloud",
                "chosenOption": "Use AWS cloud backend for note storage",
                "authority": "USER_DIRECT",
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        violation_issues = [i for i in issues if i["code"] == "FRAME_CONTRADICTION"]
        self.assertEqual(len(violation_issues), 1)

    def test_consistency_unsafe_model_inference_rejected(self):
        f = {"goals": ["User account manager"]}
        c = [{"id": "CONC-001", "category": "AUTHORIZATION", "riskLevel": "CRITICAL"}]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Default user permissions",
                "chosenOption": "Grant full admin role without password",
                "authority": "MODEL_DEFAULT",  # Model decided unsafe topic!
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        unsafe_issues = [i for i in issues if i["code"] == "UNSAFE_INFERENCE"]
        self.assertEqual(len(unsafe_issues), 1)
        self.assertEqual(unsafe_issues[0]["severity"], "BLOCKING")

    def test_consistency_conflicting_active_decisions(self):
        f = {"goals": ["Database selection"]}
        c = [{"id": "CONC-001", "category": "DATA"}]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Use SQLite",
                "chosenOption": "SQLite file",
                "authority": "USER_DIRECT",
                "status": "ACTIVE",
            },
            {
                "id": "DEC-002",
                "concernId": "CONC-001",
                "title": "Use PostgreSQL",
                "chosenOption": "PostgreSQL server",
                "authority": "USER_DIRECT",
                "status": "ACTIVE",  # DEC-001 was NOT superseded!
            },
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        conflict_issues = [i for i in issues if i["code"] == "CONFLICTING_DECISIONS"]
        self.assertEqual(len(conflict_issues), 1)
        self.assertEqual(conflict_issues[0]["severity"], "BLOCKING")

    def test_consistency_broken_dependency(self):
        f = {"goals": ["App"]}
        c = [{"id": "CONC-001", "category": "TECHNICAL_ARCHITECTURE"}]
        d = [
            {
                "id": "DEC-002",
                "concernId": "CONC-001",
                "title": "Configure Auth Client",
                "chosenOption": "JWT Client",
                "authority": "USER_DIRECT",
                "dependsOn": ["DEC-999"],  # Non-existent decision
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        dep_issues = [i for i in issues if i["code"] == "BROKEN_DEPENDENCY"]
        self.assertEqual(len(dep_issues), 1)

    def test_consistency_superseded_dependency_triggers_broken(self):
        f = {"goals": ["App"]}
        c = [{"id": "CONC-001", "category": "TECHNICAL_ARCHITECTURE"}]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Initial Database",
                "chosenOption": "SQLite",
                "authority": "USER_DIRECT",
                "supersededBy": "DEC-003",
            },
            {
                "id": "DEC-002",
                "concernId": "CONC-001",
                "title": "Cache Layer",
                "chosenOption": "Redis",
                "authority": "USER_DIRECT",
                "dependsOn": ["DEC-001"],  # Depends on superseded decision
            },
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        dep_issues = [i for i in issues if i["code"] == "BROKEN_DEPENDENCY"]
        self.assertEqual(len(dep_issues), 1)

    # -------------------------------------------------------------------------
    # 3. DECISION COVERAGE MATRIX TESTS
    # -------------------------------------------------------------------------

    def test_coverage_empty_matrix(self):
        cov = decision_coverage.load_decision_coverage(self.ws)
        self.assertEqual(cov["schemaVersion"], "7.0")
        self.assertEqual(cov["orphanedRequirements"], [])

    def test_coverage_full_matrix_pass(self):
        f = {
            "goals": ["Build a fast local note app"],
            "constraints": ["Keep offline"],
            "nonGoals": [],
        }
        c = [
            {
                "id": "CONC-001",
                "title": "Fast local note storage",
                "sourceText": "Build a fast local note app",
                "status": "RESOLVED",
            },
            {
                "id": "CONC-002",
                "title": "Offline network behavior",
                "sourceText": "Keep offline",
                "status": "RESOLVED",
            },
        ]
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Store notes locally in SQLite",
                "status": "ACTIVE",
            },
            {
                "id": "DEC-002",
                "concernId": "CONC-002",
                "title": "Disable all outbound network requests",
                "status": "ACTIVE",
            },
        ]
        r = [
            {
                "id": "REQ-001",
                "decisionId": "DEC-001",
                "description": "App must store notes in SQLite database on disk",
            },
            {
                "id": "REQ-002",
                "decisionId": "DEC-002",
                "description": "App must not initiate outbound network sockets",
            },
        ]
        cov = decision_coverage.build_decision_coverage_matrix(f, c, d, r)
        summary = cov["summary"]
        self.assertEqual(summary["intentCoverageRate"], 1.0)
        self.assertEqual(summary["concernCoverageRate"], 1.0)
        self.assertEqual(summary["decisionCoverageRate"], 1.0)
        self.assertEqual(summary["requirementTraceabilityRate"], 1.0)
        self.assertTrue(summary["isFullyCovered"])
        self.assertEqual(cov["orphanedRequirements"], [])
        self.assertEqual(cov["uncoveredIntents"], [])
        self.assertEqual(cov["uncoveredConcerns"], [])

    def test_coverage_orphaned_requirement_fails(self):
        f = {"goals": ["Simple App"]}
        c = [{"id": "CONC-001", "title": "Simple App", "status": "RESOLVED"}]
        d = [{"id": "DEC-001", "concernId": "CONC-001", "status": "ACTIVE"}]
        r = [
            {"id": "REQ-001", "decisionId": "DEC-001"},
            # Orphaned requirement with no source/decision/concern
            {"id": "REQ-002", "description": "Unprompted crypto miner"},
        ]
        cov = decision_coverage.build_decision_coverage_matrix(f, c, d, r)
        self.assertFalse(cov["summary"]["isFullyCovered"])
        self.assertIn("REQ-002", cov["orphanedRequirements"])
        self.assertLess(cov["summary"]["requirementTraceabilityRate"], 1.0)

    def test_coverage_uncovered_concern_detected(self):
        f = {"goals": ["App"]}
        c = [
            {"id": "CONC-001", "title": "Database concern", "status": "ACTIVE"},  # Not resolved, no decision
        ]
        d = []
        cov = decision_coverage.build_decision_coverage_matrix(f, c, d)
        self.assertFalse(cov["summary"]["isFullyCovered"])
        self.assertIn("CONC-001", cov["uncoveredConcerns"])
        self.assertEqual(cov["summary"]["concernCoverageRate"], 0.0)

    def test_coverage_sync_workspace_persistence(self):
        # Create frame, concerns, decisions, requirements files in harness
        frame_data = {"goals": ["Local notes"], "constraints": [], "nonGoals": []}
        concerns_data = [{"id": "CONC-001", "title": "Local notes", "status": "RESOLVED"}]
        decisions_data = [{"id": "DEC-001", "concernId": "CONC-001", "status": "ACTIVE"}]
        reqs_data = [{"id": "REQ-001", "decisionId": "DEC-001"}]

        with open(self.harness_dir / "frame.json", "w", encoding="utf-8") as f:
            json.dump(frame_data, f)
        with open(self.harness_dir / "concerns.json", "w", encoding="utf-8") as f:
            json.dump(concerns_data, f)
        with open(self.harness_dir / "decisions.json", "w", encoding="utf-8") as f:
            json.dump(decisions_data, f)
        with open(self.harness_dir / "requirements.json", "w", encoding="utf-8") as f:
            json.dump(reqs_data, f)

        cov = decision_coverage.sync_decision_coverage(self.ws)
        self.assertTrue(cov["summary"]["isFullyCovered"])
        cov_file = decision_coverage.get_decision_coverage_path(self.ws)
        self.assertTrue(cov_file.exists())
        loaded = decision_coverage.load_decision_coverage(self.ws)
        self.assertEqual(loaded["summary"]["isFullyCovered"], True)


if __name__ == "__main__":
    unittest.main()
