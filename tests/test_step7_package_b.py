"""
Strict Engineering Kernel Step 7 - Package B (Graph Topology & Utility Engine) Test Suite
Validates Decision Graph (DAG construction, reachability, validation rules, cycle detection),
Deterministic Question Utility Engine (calibration, fatigue control, discrimination, reach),
and Interaction Policy (4 modes, unsafe inference rejection, reversibility escalation).
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Add src and strict_engineering to sys.path
test_dir = Path(__file__).parent.resolve()
root_dir = test_dir.parent
sys.path.insert(0, str(root_dir / "src" / "strict_engineering"))
sys.path.insert(0, str(root_dir / "src"))

import concern
import decision
import decision_graph
import question_utility
import interaction_policy


class TestStep7PackageB(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="strict_eng_pkg_b_"))
        self.harness_dir = self.tmp_dir / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. DECISION_GRAPH: CONSTRUCTION & DAG REACH
    # -------------------------------------------------------------------------

    def test_graph_construction_and_dag_navigation(self):
        """Test building decision graph and verifying node/edge structure."""
        concerns = [
            concern.create_concern(
                id="CONC-001",
                title="Authentication Architecture",
                description="Determine session management and auth token mechanism.",
                category="AUTHORIZATION",
                source={"type": "ORIGINAL_INTENT", "reference": "spec.md"},
                risk_level="CRITICAL",
            ),
            concern.create_concern(
                id="CONC-002",
                title="Rate Limiting",
                description="Prevent brute-force login attempts.",
                category="SECURITY",
                source={"type": "DERIVED_DECISION", "reference": "DEC-001"},
                risk_level="HIGH",
                depends_on=["CONC-001"],
            ),
        ]

        decisions = [
            decision.create_decision(
                id="DEC-001",
                concern_id="CONC-001",
                question="Which token strategy?",
                selected_option={"title": "JWT with httpOnly cookie"},
                decision_type="USER_EXPLICIT",
                authority="USER",
                rationale_summary="Stateless, secure against XSS via httpOnly cookies.",
                source_reference="USER_PROMPT_L42",
                affected_concerns=["CONC-002"],
                affected_requirements=["REQ-001"],
                risk_level="CRITICAL",
            )
        ]

        requirements = [
            {
                "id": "REQ-001",
                "text": "System shall issue JWT tokens in httpOnly Secure cookies.",
                "decisionId": "DEC-001",
                "status": "PASS",
            }
        ]

        graph = decision_graph.build_decision_graph(concerns, decisions, requirements)
        self.assertEqual(graph["metadata"]["version"], "7.0")
        self.assertEqual(len(graph["nodes"]), 4)
        self.assertIn("CONC-001", graph["nodes"])
        self.assertIn("CONC-002", graph["nodes"])
        self.assertIn("DEC-001", graph["nodes"])
        self.assertIn("REQ-001", graph["nodes"])

        # Check node types
        self.assertEqual(graph["nodes"]["CONC-001"]["type"], "CONCERN")
        self.assertEqual(graph["nodes"]["DEC-001"]["type"], "DECISION")
        self.assertEqual(graph["nodes"]["REQ-001"]["type"], "REQUIREMENT")

        # Verify edges
        edges = graph["edges"]
        rel_pairs = [(e["source"], e["target"], e["relationship"]) for e in edges]
        self.assertIn(("CONC-001", "CONC-002", "DEPENDS_ON"), rel_pairs)
        self.assertIn(("CONC-001", "DEC-001", "RESOLVES"), rel_pairs)
        self.assertIn(("DEC-001", "CONC-002", "AFFECTS"), rel_pairs)
        self.assertIn(("DEC-001", "REQ-001", "DERIVES"), rel_pairs)

        # Validate graph
        valid, errors = decision_graph.validate_decision_graph(graph)
        self.assertTrue(valid, f"Graph validation failed: {errors}")
        self.assertEqual(errors, [])

    def test_compute_downstream_reach(self):
        """Test transitive closure calculation of downstream nodes."""
        graph_data = {
            "nodes": {
                "CONC-001": {"type": "CONCERN"},
                "DEC-001": {"type": "DECISION"},
                "CONC-002": {"type": "CONCERN"},
                "DEC-002": {"type": "DECISION"},
                "REQ-001": {"type": "REQUIREMENT"},
                "REQ-002": {"type": "REQUIREMENT"},
                "ISOLATED": {"type": "CONCERN"},
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "DEC-001", "target": "CONC-002", "relationship": "AFFECTS"},
                {"source": "DEC-001", "target": "REQ-001", "relationship": "DERIVES"},
                {"source": "CONC-002", "target": "DEC-002", "relationship": "RESOLVES"},
                {"source": "DEC-002", "target": "REQ-002", "relationship": "DERIVES"},
            ],
            "metadata": {"version": "7.0"},
        }

        # CONC-001 reaches DEC-001, CONC-002, REQ-001, DEC-002, REQ-002 -> 5 nodes
        reach_root = decision_graph.compute_downstream_reach(graph_data, "CONC-001")
        self.assertEqual(reach_root, 5)

        # DEC-001 reaches CONC-002, REQ-001, DEC-002, REQ-002 -> 4 nodes
        reach_dec1 = decision_graph.compute_downstream_reach(graph_data, "DEC-001")
        self.assertEqual(reach_dec1, 4)

        # CONC-002 reaches DEC-002, REQ-002 -> 2 nodes
        reach_conc2 = decision_graph.compute_downstream_reach(graph_data, "CONC-002")
        self.assertEqual(reach_conc2, 2)

        # Leaf nodes have 0 downstream reach
        reach_leaf = decision_graph.compute_downstream_reach(graph_data, "REQ-001")
        self.assertEqual(reach_leaf, 0)

        # Isolated node has 0 reach
        reach_iso = decision_graph.compute_downstream_reach(graph_data, "ISOLATED")
        self.assertEqual(reach_iso, 0)

        # Nonexistent node returns 0
        self.assertEqual(decision_graph.compute_downstream_reach(graph_data, "NONEXISTENT"), 0)

    # -------------------------------------------------------------------------
    # 2. DECISION_GRAPH: VALIDATION RULES & CORRUPTION HANDLING
    # -------------------------------------------------------------------------

    def test_cycle_detection_fails_validation(self):
        """Graph with directed cycles must fail validation."""
        cyclic_graph = {
            "nodes": {
                "CONC-001": {"type": "CONCERN", "data": {"title": "Auth"}},
                "DEC-001": {"type": "DECISION", "data": {"sourceReference": "USER", "concernId": "CONC-001"}},
                "CONC-002": {"type": "CONCERN", "data": {"title": "Storage"}},
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "DEC-001", "target": "CONC-002", "relationship": "AFFECTS"},
                {"source": "CONC-002", "target": "CONC-001", "relationship": "DEPENDS_ON"},  # CYCLE!
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(cyclic_graph)
        self.assertFalse(valid)
        self.assertTrue(any("cycle detected" in err.lower() for err in errors), f"Expected cycle error, got: {errors}")

    def test_dangling_references_fail_validation(self):
        """Edges pointing to nonexistent node IDs must fail validation."""
        dangling_graph = {
            "nodes": {
                "CONC-001": {"type": "CONCERN"},
            },
            "edges": [
                {"source": "CONC-001", "target": "GHOST-NODE", "relationship": "DEPENDS_ON"},
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(dangling_graph)
        self.assertFalse(valid)
        self.assertTrue(any("dangling reference" in err.lower() for err in errors))

    def test_missing_source_provenance_in_decisions_fails(self):
        """Decisions lacking sourceReference must fail validation."""
        no_provenance_graph = {
            "nodes": {
                "DEC-001": {
                    "type": "DECISION",
                    "status": "ACTIVE",
                    "data": {
                        "id": "DEC-001",
                        "concernId": "CONC-001",
                        "sourceReference": "",  # Empty provenance!
                    },
                },
            },
            "edges": [],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(no_provenance_graph)
        self.assertFalse(valid)
        self.assertTrue(any("missing source provenance" in err.lower() for err in errors))

    def test_multiple_active_conflicting_decisions_fail(self):
        """Two active decisions for the same concern must fail validation."""
        conflict_graph = {
            "nodes": {
                "CONC-001": {"type": "CONCERN"},
                "DEC-001": {
                    "type": "DECISION",
                    "status": "ACTIVE",
                    "data": {"concernId": "CONC-001", "sourceReference": "REF-1"},
                },
                "DEC-002": {
                    "type": "DECISION",
                    "status": "ACTIVE",
                    "data": {"concernId": "CONC-001", "sourceReference": "REF-2"},
                },
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "CONC-001", "target": "DEC-002", "relationship": "RESOLVES"},
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(conflict_graph)
        self.assertFalse(valid)
        self.assertTrue(any("multiple active conflicting decisions" in err.lower() for err in errors))

    def test_superseded_decisions_marked_active_fail(self):
        """A decision with supersededBy set but status=ACTIVE must fail validation."""
        bad_super_graph = {
            "nodes": {
                "DEC-001": {
                    "type": "DECISION",
                    "status": "ACTIVE",  # Should be SUPERSEDED!
                    "data": {
                        "concernId": "CONC-001",
                        "sourceReference": "REF-1",
                        "supersededBy": "DEC-002",
                    },
                },
                "DEC-002": {
                    "type": "DECISION",
                    "status": "ACTIVE",
                    "data": {"concernId": "CONC-001", "sourceReference": "REF-2"},
                },
            },
            "edges": [
                {"source": "DEC-001", "target": "DEC-002", "relationship": "SUPERSEDES"},
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(bad_super_graph)
        self.assertFalse(valid)
        self.assertTrue(any("superseded decision" in err.lower() for err in errors))

    def test_orphaned_requirement_fails_validation(self):
        """Active requirement with no decision or concern trace fails validation."""
        orphan_graph = {
            "nodes": {
                "REQ-999": {
                    "type": "REQUIREMENT",
                    "status": "PASS",
                    "data": {"id": "REQ-999", "text": "Something with no origin"},
                },
            },
            "edges": [],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(orphan_graph)
        self.assertFalse(valid)
        self.assertTrue(any("orphaned requirement" in err.lower() for err in errors))

    def test_graph_corruption_fails_closed(self):
        """Corrupt input structures must fail closed immediately."""
        self.assertFalse(decision_graph.validate_decision_graph("not a dict")[0])
        self.assertFalse(decision_graph.validate_decision_graph({"nodes": []})[0])
        self.assertFalse(decision_graph.validate_decision_graph({"nodes": {}, "edges": "bad"})[0])

    def test_sync_decision_graph_atomic_save(self):
        """Test sync_decision_graph loads from workspace and saves atomically."""
        # Create a concern in concerns.json
        c = concern.create_concern(
            id="CONC-001",
            title="Database Choice",
            description="Pick SQLite vs Postgres",
            category="PERSISTENCE",
            source={"type": "ORIGINAL_INTENT", "reference": "frame"},
            risk_level="MEDIUM",
        )
        concern.save_concerns(self.tmp_dir, [c])

        # Create a decision in decisions.json
        d = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            question="Which database?",
            selected_option={"title": "SQLite"},
            decision_type="USER_EXPLICIT",
            authority="USER",
            rationale_summary="Local file embedded simplicity.",
            source_reference="USER_STATEMENT",
            risk_level="MEDIUM",
        )
        decision.save_decisions(self.tmp_dir, [d])

        synced = decision_graph.sync_decision_graph(self.tmp_dir)
        self.assertIn("CONC-001", synced["nodes"])
        self.assertIn("DEC-001", synced["nodes"])

        # Check persisted file
        graph_file = decision_graph.get_decision_graph_path(self.tmp_dir)
        self.assertTrue(graph_file.exists())
        loaded = decision_graph.load_decision_graph(self.tmp_dir)
        self.assertEqual(len(loaded["nodes"]), 2)

    # -------------------------------------------------------------------------
    # 3. QUESTION_UTILITY ENGINE TESTS
    # -------------------------------------------------------------------------

    def test_utility_formula_calibration_critical_vs_low(self):
        """Security/Auth concern (Critical) must rank substantially higher than minor button padding (Low)."""
        critical_auth_concern = concern.create_concern(
            id="CONC-001",
            title="Multi-factor Authentication Protocol",
            description="Determine whether to enforce TOTP or WebAuthn for all admin users.",
            category="AUTHORIZATION",
            source={"type": "ORIGINAL_INTENT", "reference": "spec.md"},
            risk_level="CRITICAL",
            uncertainty=0.9,
            downstream_impact=0.9,
            risk_reduction_potential=0.8,
            expected_discrimination=0.9,
            user_effort=0.3,
            question_cost=0.3,
        )

        low_ui_concern = concern.create_concern(
            id="CONC-002",
            title="Button Border Padding",
            description="Determine whether padding is 8px or 10px.",
            category="CORE_BEHAVIOR",
            source={"type": "ORIGINAL_INTENT", "reference": "mockup.png"},
            risk_level="LOW",
            uncertainty=0.3,
            downstream_impact=0.1,
            risk_reduction_potential=0.2,
            expected_discrimination=0.2,
            user_effort=0.3,
            question_cost=0.3,
        )

        score_critical = question_utility.calculate_question_utility(critical_auth_concern)
        score_low = question_utility.calculate_question_utility(low_ui_concern)

        self.assertGreater(score_critical, score_low)
        self.assertGreater(score_critical, 0.40)
        self.assertLess(score_low, 0.05)

        # Ranked list ordering
        ranked = question_utility.rank_concerns_by_utility([low_ui_concern, critical_auth_concern])
        self.assertEqual(ranked[0][0]["id"], "CONC-001")
        self.assertEqual(ranked[1][0]["id"], "CONC-002")

    def test_same_answer_discrimination_suppresses_utility(self):
        """Low discrimination (options collapse to identical consequences) must suppress utility."""
        high_disc_concern = {
            "id": "CONC-001",
            "title": "Data Storage Backend",
            "category": "PERSISTENCE",
            "riskLevel": "HIGH",
            "uncertainty": 0.8,
            "downstreamImpact": 0.8,
            "expectedDiscrimination": 0.9,  # High discrimination
            "riskReductionPotential": 0.8,
        }

        low_disc_concern = {
            "id": "CONC-002",
            "title": "Color Scheme Variant",
            "category": "CORE_BEHAVIOR",
            "riskLevel": "HIGH",
            "uncertainty": 0.8,
            "downstreamImpact": 0.8,
            "expectedDiscrimination": 0.1,  # Low discrimination: options lead to same result
            "riskReductionPotential": 0.8,
        }

        score_high = question_utility.calculate_question_utility(high_disc_concern)
        score_low = question_utility.calculate_question_utility(low_disc_concern)

        self.assertGreater(score_high, score_low)
        # Ratio should reflect ~9x difference
        self.assertGreater(score_high / max(score_low, 0.0001), 5.0)

    def test_architecture_branch_high_discrimination_promotes_utility(self):
        """Candidate options with materially different consequences yield high discrimination and high utility."""
        branching_concern = {
            "id": "CONC-001",
            "title": "Synchronous vs Event-Driven Architecture",
            "category": "TECHNICAL_ARCHITECTURE",
            "riskLevel": "HIGH",
            "uncertainty": 0.85,
            "downstreamImpact": 0.9,
            "candidateOptions": [
                {"id": "OPT-1", "title": "REST Synch", "consequences": ["REQ-SYNC-01", "BLOCKING_IO"]},
                {"id": "OPT-2", "title": "Kafka Events", "consequences": ["REQ-ASYNC-01", "EVENT_BUS", "DEAD_LETTER"]},
            ],
        }
        score = question_utility.calculate_question_utility(branching_concern)
        self.assertGreaterEqual(score, 0.40)

    def test_dependency_reach_raises_utility(self):
        """Concerns with high downstream graph reach must receive elevated utility."""
        graph_data = {
            "nodes": {
                "CONC-ROOT": {"type": "CONCERN"},
                "DEC-ROOT": {"type": "DECISION"},
                "CONC-A": {"type": "CONCERN"},
                "CONC-B": {"type": "CONCERN"},
                "CONC-C": {"type": "CONCERN"},
                "DEC-C": {"type": "DECISION"},
                "REQ-1": {"type": "REQUIREMENT"},
                "CONC-LEAF": {"type": "CONCERN"},
            },
            "edges": [
                {"source": "CONC-ROOT", "target": "DEC-ROOT"},
                {"source": "DEC-ROOT", "target": "CONC-A"},
                {"source": "DEC-ROOT", "target": "CONC-B"},
                {"source": "DEC-ROOT", "target": "CONC-C"},
                {"source": "CONC-C", "target": "DEC-C"},
                {"source": "DEC-C", "target": "REQ-1"},
            ],
        }

        concern_root = {
            "id": "CONC-ROOT",
            "title": "Foundational Schema",
            "category": "TECHNICAL_ARCHITECTURE",
            "riskLevel": "MEDIUM",
            "uncertainty": 0.7,
            "downstreamImpact": 0.7,
        }

        concern_leaf = {
            "id": "CONC-LEAF",
            "title": "Isolated Leaf Feature",
            "category": "TECHNICAL_ARCHITECTURE",
            "riskLevel": "MEDIUM",
            "uncertainty": 0.7,
            "downstreamImpact": 0.7,
        }

        score_root = question_utility.calculate_question_utility(concern_root, graph_data=graph_data)
        score_leaf = question_utility.calculate_question_utility(concern_leaf, graph_data=graph_data)

        self.assertGreater(score_root, score_leaf)

    def test_repetition_penalty_suppresses_utility(self):
        """Previously asked questions must be heavily penalized with RepetitionRisk=5.0."""
        c = {
            "id": "CONC-001",
            "title": "Payment Provider Selection",
            "category": "FINANCIAL",
            "riskLevel": "CRITICAL",
            "uncertainty": 0.8,
            "downstreamImpact": 0.8,
        }

        # First time: not asked
        fresh_score = question_utility.calculate_question_utility(c, asked_questions=[])

        # Record question in asked_questions
        record = question_utility.record_asked_question(
            workspace_dir=self.tmp_dir,
            question_text="Payment Provider Selection",
            topic="FINANCIAL",
            concern_id="CONC-001",
        )
        self.assertEqual(record["concernId"], "CONC-001")
        self.assertTrue(len(record["fingerprint"]) == 64)

        asked = question_utility.load_asked_questions(self.tmp_dir)
        self.assertEqual(len(asked), 1)

        # Re-evaluating with asked questions list
        repeated_score = question_utility.calculate_question_utility(c, asked_questions=asked)

        self.assertLess(repeated_score, fresh_score)
        # Should be suppressed by ~5x
        self.assertAlmostEqual(fresh_score / max(repeated_score, 0.0001), 5.0, delta=1.0)

    # -------------------------------------------------------------------------
    # 4. INTERACTION_POLICY: MODES, INFERENCE REJECTION & ESCALATION
    # -------------------------------------------------------------------------

    def test_interaction_mode_selection(self):
        """Test selection between ASK, SUGGEST, CHALLENGE, and SAFE-INFER."""
        # 1. ASK: High utility / Critical Risk
        critical_c = {
            "id": "CONC-001",
            "title": "Root Credential Storage",
            "category": "SECURITY",
            "riskLevel": "CRITICAL",
            "uncertainty": 0.9,
            "downstreamImpact": 0.9,
        }
        res_ask = interaction_policy.determine_interaction_mode(critical_c, utility=0.75)
        self.assertEqual(res_ask["mode"], "ASK")

        # 2. SUGGEST: Moderate utility with recommended option
        moderate_c = {
            "id": "CONC-002",
            "title": "Database Connection Pool Size",
            "category": "PERFORMANCE_EXPECTATION",
            "riskLevel": "MEDIUM",
            "uncertainty": 0.5,
            "downstreamImpact": 0.4,
        }
        res_suggest = interaction_policy.determine_interaction_mode(moderate_c, utility=0.45)
        self.assertEqual(res_suggest["mode"], "SUGGEST")
        self.assertIsNotNone(res_suggest["recommendedOption"])

        # 3. CHALLENGE: Conflict with existing constraints
        contradictory_c = {
            "id": "CONC-003",
            "title": "Skip authentication checks for testing",
            "category": "AUTHORIZATION",
            "riskLevel": "CRITICAL",
        }
        constraints = [{"text": "Enforce mandatory authentication on all routes"}]
        res_challenge = interaction_policy.determine_interaction_mode(
            contradictory_c, utility=0.8, existing_constraints=constraints
        )
        self.assertEqual(res_challenge["mode"], "CHALLENGE")
        self.assertIsNotNone(res_challenge["challengeDetails"])

        # 4. SAFE-INFER: Low risk, reversible candidate
        safe_c = {
            "id": "CONC-004",
            "title": "Default logging level for dev mode",
            "category": "IMPLEMENTATION_CONSTRAINT",
            "riskLevel": "LOW",
            "downstreamImpact": 0.1,
            "uncertainty": 0.2,
        }
        res_safe = interaction_policy.determine_interaction_mode(safe_c, utility=0.15)
        self.assertEqual(res_safe["mode"], "SAFE-INFER")
        self.assertIsNotNone(res_safe.get("inferenceRecord"))

    def test_unsafe_inference_rejection_mandatory(self):
        """Attempting to safe-infer sensitive topics must be rejected under INV-7-06."""
        sensitive_cases = [
            {"title": "User Authentication Protocol", "category": "AUTHORIZATION", "riskLevel": "CRITICAL"},
            {"title": "Permanent Data Deletion Policy", "category": "IRREVERSIBILITY", "riskLevel": "CRITICAL"},
            {"title": "Payment Billing Gateway", "category": "FINANCIAL", "riskLevel": "CRITICAL"},
            {"title": "Customer Privacy & PII Access", "category": "PRIVACY", "riskLevel": "HIGH"},
            {"title": "Admin Role Permissions and RBAC", "category": "AUTHORIZATION", "riskLevel": "CRITICAL"},
            {"title": "Data persistence across restart", "category": "PERSISTENCE", "riskLevel": "MEDIUM"},
            {"title": "Scope expansion for new analytics dashboard", "category": "SCOPE", "riskLevel": "MEDIUM"},
        ]

        for case in sensitive_cases:
            is_safe, reason = interaction_policy.is_safe_to_infer(case)
            self.assertFalse(is_safe, f"Sensitive case should NOT be safe to infer: {case['title']}")
            self.assertTrue("unsafe" in reason.lower() or "strictly prohibited" in reason.lower() or "restricted" in reason.lower())

            # Mode selection must never return SAFE-INFER
            mode_result = interaction_policy.determine_interaction_mode(case, utility=0.1)
            self.assertNotEqual(mode_result["mode"], "SAFE-INFER", f"Mode must not be SAFE-INFER for {case['title']}")

    def test_safe_inference_reversibility_escalation(self):
        """Safe inference can be escalated to CONFIRMATION_REQUIRED if downstream risk increases."""
        safe_c = {
            "id": "CONC-005",
            "title": "Internal ID prefix for task tracking",
            "category": "IMPLEMENTATION_CONSTRAINT",
            "riskLevel": "LOW",
            "downstreamImpact": 0.1,
        }
        is_safe, _ = interaction_policy.is_safe_to_infer(safe_c)
        self.assertTrue(is_safe)

        mode_res = interaction_policy.determine_interaction_mode(safe_c, utility=0.1)
        self.assertEqual(mode_res["mode"], "SAFE-INFER")
        record = mode_res["inferenceRecord"]
        self.assertEqual(record["status"], "INFERRED")
        self.assertEqual(record["reversibility"], "HIGH")

        # Escalate inference record
        escalated = interaction_policy.escalate_safe_inference_to_confirmation(record)
        self.assertEqual(escalated["status"], "CONFIRMATION_REQUIRED")
        self.assertIn("escalatedAt", escalated)
        self.assertEqual(escalated["previousStatus"], "INFERRED")

    def test_candidate_options_generation(self):
        """Candidate options generator produces 2-4 discriminative options with recommended flag."""
        test_c = {
            "id": "CONC-010",
            "title": "Cache Storage Strategy",
            "category": "TECHNICAL_ARCHITECTURE",
        }
        opts = interaction_policy.generate_candidate_options(test_c)
        self.assertGreaterEqual(len(opts), 2)
        self.assertLessEqual(len(opts), 4)

        # Check structure
        for o in opts:
            self.assertIn("id", o)
            self.assertIn("title", o)
            self.assertIn("description", o)
            self.assertIn("tradeoffs", o)
            self.assertIn("consequences", o)
            self.assertIn("isRecommended", o)

        # Exactly one recommendation
        recs = [o for o in opts if o["isRecommended"]]
        self.assertEqual(len(recs), 1)

    def test_format_recommendation_invariants(self):
        """format_recommendation outputs text noting INV-7-01 and INV-7-06."""
        c = {"id": "CONC-011", "title": "Session Expiration Duration"}
        opt = {"title": "30 minutes rolling", "description": "Standard OWASP session timeout."}
        text = interaction_policy.format_recommendation(c, opt, rationale="Matches security baseline.")
        self.assertIn("INV-7-01", text)
        self.assertIn("INV-7-06", text)
        self.assertIn("30 minutes rolling", text)


if __name__ == "__main__":
    unittest.main()
