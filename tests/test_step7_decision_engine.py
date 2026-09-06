"""
ANTIGRAVITY STRICT ENGINEERING KERNEL - STEP 7 COMPREHENSIVE ACCEPTANCE SUITE
Covers Acceptance Requirements D7-01 through D7-30:
  D7-01: Schema 7.0 conformance across all discovery artifacts
  D7-02: Structured Project Frame construction & provenance
  D7-03: Strict provenance types enforcement
  D7-04: Structured Concern Model (22 categories & 11 lifecycle states)
  D7-05: Risk Engine baseline category integration & hard overrides
  D7-06: Canonical Decision Model fields, types, and authorities
  D7-07: Robust User Response Parser (ordinals, letters, delegations, rejections, fuzzy)
  D7-08: Decision supersession links and timestamp tracking
  D7-09: Append-only cryptographic decision event ledger with SHA-256 chaining
  D7-10: Tamper-evidence detection in decision event ledger
  D7-11: Directed Acyclic Graph construction and synchronization
  D7-12: Transitive downstream reach computation in decision graph
  D7-13: Cycle detection in decision graph (fails closed on cycle)
  D7-14: Dangling reference detection in decision graph
  D7-15: Missing source provenance detection in decision graph
  D7-16: Multiple active conflicting decisions detection in decision graph
  D7-17: Superseded decision marked active detection in decision graph
  D7-18: Question utility deterministic calculation & formula calibration
  D7-19: Same-answer discrimination suppresses question utility
  D7-20: Architecture-branch discrimination promotes question utility
  D7-21: Question fatigue tracking & repetition penalty (5x suppression)
  D7-22: Interaction policy 4 modes (ASK, SUGGEST, CHALLENGE, SAFE-INFER)
  D7-23: Mandatory rejection of unsafe inferences (auth, deletion, financial, privacy, rbac)
  D7-24: Safe inference candidate execution & reversibility escalation
  D7-25: Candidate options generation with discriminative consequences
  D7-26: Stopping engine evaluation (all resolved or remaining utility < threshold)
  D7-27: Blocking critical overrides prevent discovery stopping
  D7-28: Consistency reviewer audits (frame contradictions, unsafe inferences, broken dependencies)
  D7-29: 4-tier decision coverage matrix (INTENT -> CONCERN -> DECISION -> REQ) & orphaned requirement detection
  D7-30: Requirement compiler from decisions, suggestion sandbox (SUG-xxx), gate integration & change propagation
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

import frame
import concern
import decision
import decision_events
import decision_graph
import question_utility
import interaction_policy
import stopping_engine
import consistency_reviewer
import decision_coverage
import requirement_generator
import decision_engine
import gate
import kernel
import risk_engine


class TestStep7DecisionEngineComprehensive(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ws = Path(self.test_dir)
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # D7-01: Schema 7.0 conformance across all discovery artifacts
    # -------------------------------------------------------------------------
    def test_d7_01_schema_7_0_conformance(self):
        f_data = frame.create_initial_frame("Schema test goal")
        self.assertEqual(f_data["schemaVersion"], "7.0")

        c = concern.create_concern(
            id="CONC-001",
            title="Test concern",
            description="Test description",
            category="DATA",
            status="ACTIVE",
            source={"type": "ORIGINAL_INTENT", "reference": "intent"},
        )
        is_c_valid, c_errors = concern.validate_concern(c)
        self.assertTrue(is_c_valid, f"Concern schema invalid: {c_errors}")

        d = decision.create_decision(
            concern_id="CONC-001",
            title="Test decision",
            chosen_option="Option A",
            authority="USER",
        )
        is_d_valid, d_errors = decision.validate_decision(d)
        self.assertTrue(is_d_valid, f"Decision schema invalid: {d_errors}")

        g = decision_graph.build_decision_graph([c], [d])
        self.assertEqual(g["metadata"]["version"], "7.0")

        cov = decision_coverage.build_decision_coverage_matrix(f_data, [c], [d])
        self.assertEqual(cov["schemaVersion"], "7.0")

    # -------------------------------------------------------------------------
    # D7-02: Structured Project Frame construction & provenance
    # -------------------------------------------------------------------------
    def test_d7_02_frame_construction_and_provenance(self):
        raw_text = (
            "# Project Goal: Build a fast local note-taking application\n"
            "# Constraints: Must run offline without internet\n"
            "# Non-Goals: No multi-user real-time collaboration\n"
        )
        f_data = frame.extract_frame_from_intent(raw_text)
        self.assertIn("fast local note-taking", f_data["projectGoal"].lower())
        self.assertTrue(any("offline" in str(c).lower() for c in f_data["constraints"]))
        self.assertTrue(any("multi-user" in str(ng).lower() for ng in f_data["nonGoals"]))
        self.assertTrue(all("provenance" in item for item in f_data["constraints"]))

    # -------------------------------------------------------------------------
    # D7-03: Strict provenance types enforcement
    # -------------------------------------------------------------------------
    def test_d7_03_provenance_types_enforced(self):
        valid_provs = [
            "USER_EXPLICIT",
            "EXTRACTED_FROM_DOC",
            "INTERVIEW_CONFIRMED",
            "CODEBASE_OBSERVED",
            "POLICY_DERIVED",
            "SAFE_INFERENCE",
        ]
        for vp in valid_provs:
            item = frame.normalize_text_provenance("sample text", default_provenance=vp)
            self.assertEqual(item["provenance"], vp)

        # Unknown provenance falls back safely to default valid type
        invalid_item = frame.normalize_text_provenance({"text": "test", "provenance": "FABRICATED_SOURCE"}, default_provenance="EXTRACTED_FROM_DOC")
        self.assertEqual(invalid_item["provenance"], "EXTRACTED_FROM_DOC")

    # -------------------------------------------------------------------------
    # D7-04: Structured Concern Model (22 categories & 11 lifecycle states)
    # -------------------------------------------------------------------------
    def test_d7_04_concern_model_22_categories_11_states(self):
        self.assertEqual(len(concern.CONCERN_CATEGORIES), 22)
        self.assertEqual(len(concern.CONCERN_STATES), 11)

        # Check all 22 categories are accepted
        for cat in concern.CONCERN_CATEGORIES:
            c = concern.create_concern(
                id="CONC-001",
                title=f"Concern {cat}",
                description="desc",
                category=cat,
                status="ACTIVE",
                source={"type": "ORIGINAL_INTENT", "reference": "ref"},
            )
            valid, errors = concern.validate_concern(c)
            self.assertTrue(valid, f"Category {cat} failed: {errors}")

        # Check invalid category is rejected
        invalid_c = concern.create_concern(
            id="CONC-001",
            title="Bad",
            description="desc",
            category="INVALID_CATEGORY_XYZ",
            status="ACTIVE",
            source={"type": "ORIGINAL_INTENT", "reference": "ref"},
        )
        valid, errors = concern.validate_concern(invalid_c)
        self.assertFalse(valid)

    # -------------------------------------------------------------------------
    # D7-05: Risk Engine baseline category integration & hard overrides
    # -------------------------------------------------------------------------
    def test_d7_05_risk_engine_baseline_and_hard_overrides(self):
        # Category baseline: AUTHORIZATION -> CRITICAL
        auth_level, _ = concern.evaluate_concern_risk("Login", "User auth", "AUTHORIZATION")
        self.assertEqual(auth_level, "CRITICAL")

        # Hard override pattern: "wipe database" in LOW category -> escalates to CRITICAL
        wipe_level, codes = concern.evaluate_concern_risk("Reset tool", "Permanently wipe database disk", "PRODUCT_GOAL")
        self.assertEqual(wipe_level, "CRITICAL")
        self.assertTrue(any("DESTRUCT" in c for c in codes))


    # -------------------------------------------------------------------------
    # D7-06: Canonical Decision Model fields, types, and authorities
    # -------------------------------------------------------------------------
    def test_d7_06_canonical_decision_model_fields_and_authorities(self):
        self.assertEqual(len(decision.DECISION_TYPES), 6)
        self.assertEqual(len(decision.AUTHORITIES), 4)

        d = decision.create_decision(
            concern_id="CONC-001",
            title="Select embedded DB",
            chosen_option="SQLite 3",
            decision_type="TECHNICAL_DECISION",
            authority="USER",
            rationale_summary="Single-file local ACID storage",
        )
        valid, errors = decision.validate_decision(d)
        self.assertTrue(valid, f"Decision validation failed: {errors}")
        self.assertEqual(d["decisionType"], "TECHNICAL_DECISION")
        self.assertEqual(d["authority"], "USER")

    # -------------------------------------------------------------------------
    # D7-07: Robust User Response Parser (ordinals, letters, delegations, rejections, fuzzy)
    # -------------------------------------------------------------------------
    def test_d7_07_user_response_parser(self):
        candidate_options = [
            {"id": "OPT-1", "title": "SQLite Embedded", "isRecommended": True},
            {"id": "OPT-2", "title": "PostgreSQL Server"},
            {"id": "OPT-3", "title": "In-Memory RAM Only"},
        ]

        # 1. Option Letter
        res = decision.parse_user_response("Option B", candidate_options)
        self.assertEqual(res["matchedOptionIndex"], 1)

        # 2. Ordinal
        res = decision.parse_user_response("The first one please", candidate_options)
        self.assertEqual(res["matchedOptionIndex"], 0)

        # 3. Delegation
        res = decision.parse_user_response("Whatever you recommend is fine", candidate_options)
        self.assertEqual(res["type"], "DELEGATION")

        # 4. Rejection
        res = decision.parse_user_response("None of these work, I want Flat JSON files", candidate_options)
        self.assertEqual(res["type"], "REJECTION")

        # 5. Fuzzy / Substring
        res = decision.parse_user_response("Let's go with postgres", candidate_options)
        self.assertEqual(res["matchedOptionIndex"], 1)

    # -------------------------------------------------------------------------
    # D7-08: Decision supersession links and timestamp tracking
    # -------------------------------------------------------------------------
    def test_d7_08_decision_supersession(self):
        d1 = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            title="Database engine",
            chosen_option="SQLite",
            authority="USER",
        )
        decision.save_decisions(self.ws, [d1])

        # Supersede with Postgres
        new_d = decision.supersede_decision(
            workspace_dir=self.ws,
            old_decision_id="DEC-001",
            new_decision_data={
                "id": "DEC-002",
                "concernId": "CONC-001",
                "title": "Database engine",
                "chosenOption": "PostgreSQL",
                "authority": "USER",
                "rationale": "High concurrency needed",
            },
        )

        all_d = decision.load_decisions(self.ws)
        self.assertEqual(len(all_d), 2)
        old_d = next(d for d in all_d if d["id"] == "DEC-001")
        self.assertEqual(old_d["supersededBy"], "DEC-002")
        self.assertEqual(old_d["status"], "SUPERSEDED")

    # -------------------------------------------------------------------------
    # D7-09: Append-only cryptographic decision event ledger with SHA-256 chaining
    # -------------------------------------------------------------------------
    def test_d7_09_decision_event_ledger_hash_chain(self):
        e1 = decision_events.record_decision_event(self.ws, "FRAME_CREATED", {"goal": "App"})
        e2 = decision_events.record_decision_event(self.ws, "CONCERN_DISCOVERED", {"cid": "CONC-001"})
        e3 = decision_events.record_decision_event(self.ws, "USER_DECISION_RECORDED", {"did": "DEC-001"})

        self.assertEqual(e1["previousHash"], decision_events.GENESIS_HASH)
        self.assertEqual(e2["previousHash"], e1["eventHash"])
        self.assertEqual(e3["previousHash"], e2["eventHash"])

        valid, errors = decision_events.verify_decision_events_integrity(self.ws)
        self.assertTrue(valid, f"Ledger integrity failed: {errors}")

    # -------------------------------------------------------------------------
    # D7-10: Tamper-evidence detection in decision event ledger
    # -------------------------------------------------------------------------
    def test_d7_10_decision_event_ledger_tamper_detection(self):
        decision_events.record_decision_event(self.ws, "FRAME_CREATED", {"goal": "Initial"})
        decision_events.record_decision_event(self.ws, "CONCERN_DISCOVERED", {"cid": "CONC-001"})

        ledger_path = decision_events.get_decision_events_path(self.ws)
        with open(ledger_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Tamper payload without updating hash
        entry = json.loads(lines[0])
        entry["payload"]["goal"] = "HACKED_GOAL"
        lines[0] = json.dumps(entry) + "\n"

        with open(ledger_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        valid, errors = decision_events.verify_decision_events_integrity(self.ws)
        self.assertFalse(valid)
        self.assertTrue(any("tamper" in err.lower() or "mismatch" in err.lower() for err in errors))

    # -------------------------------------------------------------------------
    # D7-11: Directed Acyclic Graph construction and synchronization
    # -------------------------------------------------------------------------
    def test_d7_11_decision_graph_dag_construction(self):
        c = {"id": "CONC-001", "category": "DATA", "status": "ACTIVE"}
        d = {"id": "DEC-001", "concernId": "CONC-001", "status": "ACTIVE", "sourceReference": "user"}
        r = {"id": "REQ-001", "decisionId": "DEC-001"}

        g = decision_graph.build_decision_graph([c], [d], [r])
        self.assertEqual(len(g["nodes"]), 3)
        self.assertTrue(any(e["relationship"] == "RESOLVES" for e in g["edges"]))
        self.assertTrue(any(e["relationship"] == "DERIVES" for e in g["edges"]))

    # -------------------------------------------------------------------------
    # D7-12: Transitive downstream reach computation in decision graph
    # -------------------------------------------------------------------------
    def test_d7_12_decision_graph_downstream_reach(self):
        # Chain: CONC-001 -> DEC-001 -> REQ-001 -> REQ-002
        graph_data = {
            "nodes": {
                "CONC-001": {"id": "CONC-001", "type": "CONCERN"},
                "DEC-001": {"id": "DEC-001", "type": "DECISION", "data": {"sourceReference": "usr"}},
                "REQ-001": {"id": "REQ-001", "type": "REQUIREMENT"},
                "REQ-002": {"id": "REQ-002", "type": "REQUIREMENT"},
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "DEC-001", "target": "REQ-001", "relationship": "DERIVES"},
                {"source": "REQ-001", "target": "REQ-002", "relationship": "DERIVES"},
            ],
            "metadata": {"version": "7.0"},
        }
        reach = decision_graph.compute_downstream_reach(graph_data, "CONC-001")
        self.assertEqual(reach, 3)

    # -------------------------------------------------------------------------
    # D7-13: Cycle detection in decision graph (fails closed on cycle)
    # -------------------------------------------------------------------------
    def test_d7_13_decision_graph_cycle_detection(self):
        cyclic_graph = {
            "nodes": {
                "CONC-001": {"id": "CONC-001", "type": "CONCERN"},
                "CONC-002": {"id": "CONC-002", "type": "CONCERN"},
            },
            "edges": [
                {"source": "CONC-001", "target": "CONC-002", "relationship": "DEPENDS_ON"},
                {"source": "CONC-002", "target": "CONC-001", "relationship": "DEPENDS_ON"},
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(cyclic_graph)
        self.assertFalse(valid)
        self.assertTrue(any("cycle detected" in e.lower() for e in errors))

    # -------------------------------------------------------------------------
    # D7-14: Dangling reference detection in decision graph
    # -------------------------------------------------------------------------
    def test_d7_14_decision_graph_dangling_reference(self):
        graph_data = {
            "nodes": {"CONC-001": {"id": "CONC-001", "type": "CONCERN"}},
            "edges": [{"source": "CONC-001", "target": "NON_EXISTENT", "relationship": "DEPENDS_ON"}],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(graph_data)
        self.assertFalse(valid)
        self.assertTrue(any("dangling reference" in e.lower() for e in errors))

    # -------------------------------------------------------------------------
    # D7-15: Missing source provenance detection in decision graph
    # -------------------------------------------------------------------------
    def test_d7_15_decision_graph_missing_provenance(self):
        graph_data = {
            "nodes": {
                "DEC-001": {
                    "id": "DEC-001",
                    "type": "DECISION",
                    "status": "ACTIVE",
                    "data": {"sourceReference": ""},  # Empty provenance!
                }
            },
            "edges": [],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(graph_data)
        self.assertFalse(valid)
        self.assertTrue(any("missing source provenance" in e.lower() for e in errors))

    # -------------------------------------------------------------------------
    # D7-16: Multiple active conflicting decisions detection in decision graph
    # -------------------------------------------------------------------------
    def test_d7_16_decision_graph_multiple_conflicting_active_decisions(self):
        graph_data = {
            "nodes": {
                "CONC-001": {"id": "CONC-001", "type": "CONCERN"},
                "DEC-001": {"id": "DEC-001", "type": "DECISION", "status": "ACTIVE", "data": {"concernId": "CONC-001", "sourceReference": "u"}},
                "DEC-002": {"id": "DEC-002", "type": "DECISION", "status": "ACTIVE", "data": {"concernId": "CONC-001", "sourceReference": "u"}},
            },
            "edges": [
                {"source": "CONC-001", "target": "DEC-001", "relationship": "RESOLVES"},
                {"source": "CONC-001", "target": "DEC-002", "relationship": "RESOLVES"},
            ],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(graph_data)
        self.assertFalse(valid)
        self.assertTrue(any("multiple active" in e.lower() for e in errors))


    # -------------------------------------------------------------------------
    # D7-17: Superseded decision marked active detection in decision graph
    # -------------------------------------------------------------------------
    def test_d7_17_decision_graph_superseded_active_rejected(self):
        graph_data = {
            "nodes": {
                "DEC-001": {
                    "id": "DEC-001",
                    "type": "DECISION",
                    "status": "ACTIVE",  # Marked active despite being superseded!
                    "data": {"supersededBy": "DEC-002", "sourceReference": "u"},
                }
            },
            "edges": [],
            "metadata": {"version": "7.0"},
        }
        valid, errors = decision_graph.validate_decision_graph(graph_data)
        self.assertFalse(valid)
        self.assertTrue(any("superseded" in e.lower() and "active" in e.lower() for e in errors))

    # -------------------------------------------------------------------------
    # D7-18: Question utility deterministic calculation & formula calibration
    # -------------------------------------------------------------------------
    def test_d7_18_question_utility_formula_calibration(self):
        # Critical security concern
        critical_c = {
            "id": "CONC-001",
            "category": "AUTHORIZATION",
            "riskLevel": "CRITICAL",
            "uncertainty": 0.9,
            "downstreamImpact": 0.9,
            "expectedDiscrimination": 0.9,
        }
        # Low padding/color concern
        low_c = {
            "id": "CONC-002",
            "category": "PRODUCT_GOAL",
            "riskLevel": "LOW",
            "uncertainty": 0.2,
            "downstreamImpact": 0.1,
            "expectedDiscrimination": 0.2,
        }
        crit_util = question_utility.calculate_question_utility(critical_c)
        low_util = question_utility.calculate_question_utility(low_c)

        self.assertGreater(crit_util, low_util)
        self.assertGreater(crit_util, 0.4)
        self.assertLess(low_util, 0.1)

    # -------------------------------------------------------------------------
    # D7-19: Same-answer discrimination suppresses question utility
    # -------------------------------------------------------------------------
    def test_d7_19_question_utility_same_answer_discrimination(self):
        concern_same = {
            "id": "CONC-001",
            "riskLevel": "HIGH",
            "candidateOptions": [
                {"title": "Option 1", "consequences": ["same architecture", "same tests"]},
                {"title": "Option 2", "consequences": ["same architecture", "same tests"]},
            ],
        }
        concern_diff = {
            "id": "CONC-002",
            "riskLevel": "HIGH",
            "candidateOptions": [
                {"title": "Option 1", "consequences": ["embedded sqlite", "zero network"]},
                {"title": "Option 2", "consequences": ["distributed postgres", "cloud rbac"]},
            ],
        }
        util_same = question_utility.calculate_question_utility(concern_same)
        util_diff = question_utility.calculate_question_utility(concern_diff)
        self.assertLess(util_same, util_diff)

    # -------------------------------------------------------------------------
    # D7-20: Architecture-branch discrimination promotes question utility
    # -------------------------------------------------------------------------
    def test_d7_20_question_utility_architecture_branch_discrimination(self):
        concern_branching = {
            "id": "CONC-001",
            "riskLevel": "CRITICAL",
            "uncertainty": 0.9,
            "downstreamImpact": 0.9,
            "expectedDiscrimination": 0.95,
        }
        util = question_utility.calculate_question_utility(concern_branching)
        self.assertGreater(util, 0.5)

    # -------------------------------------------------------------------------
    # D7-21: Question fatigue tracking & repetition penalty (5x suppression)
    # -------------------------------------------------------------------------
    def test_d7_21_question_fatigue_and_repetition_penalty(self):
        c = {"id": "CONC-001", "question": "What database should we use?", "category": "DATA"}
        # First time utility
        util_fresh = question_utility.calculate_question_utility(c, asked_questions=[])

        # After question has been recorded
        question_utility.record_asked_question(self.ws, c["question"], c["category"], c["id"])
        asked = question_utility.load_asked_questions(self.ws)
        util_repeated = question_utility.calculate_question_utility(c, asked_questions=asked)

        # Repetition risk penalty reduces utility by approx 5x
        self.assertLess(util_repeated, util_fresh * 0.3)

    # -------------------------------------------------------------------------
    # D7-22: Interaction policy 4 modes (ASK, SUGGEST, CHALLENGE, SAFE-INFER)
    # -------------------------------------------------------------------------
    def test_d7_22_interaction_policy_4_modes(self):
        # 1. ASK: High utility, high uncertainty
        c_ask = {"category": "DATA", "riskLevel": "CRITICAL", "uncertainty": 0.9}
        mode_ask = interaction_policy.determine_interaction_mode(c_ask, utility=0.8)
        self.assertEqual(mode_ask["mode"], "ASK")

        # 2. SUGGEST: Recommended option exists with high confidence
        c_sug = {
            "category": "TECHNICAL_ARCHITECTURE",
            "candidateOptions": [
                {"title": "Standard CLI", "isRecommended": True, "confidence": 0.9},
                {"title": "Custom GUI"},
            ],
        }
        mode_sug = interaction_policy.determine_interaction_mode(c_sug, utility=0.5)
        self.assertEqual(mode_sug["mode"], "SUGGEST")

        # 3. CHALLENGE: Violates an existing constraint
        c_chal = {"category": "SCOPE", "title": "Add Cloud Sync"}
        mode_chal = interaction_policy.determine_interaction_mode(
            c_chal,
            utility=0.7,
            existing_constraints=["100% offline local only"],
        )
        self.assertEqual(mode_chal["mode"], "CHALLENGE")

        # 4. SAFE-INFER: Low utility, safe reversible technical default
        c_infer = {"category": "PLATFORM", "title": "Default temp file directory", "riskLevel": "LOW"}
        mode_infer = interaction_policy.determine_interaction_mode(c_infer, utility=0.1)
        self.assertEqual(mode_infer["mode"], "SAFE-INFER")

    # -------------------------------------------------------------------------
    # D7-23: Mandatory rejection of unsafe inferences (auth, deletion, financial, privacy, rbac)
    # -------------------------------------------------------------------------
    def test_d7_23_mandatory_rejection_of_unsafe_inferences(self):
        unsafe_concerns = [
            {"category": "AUTHORIZATION", "title": "User login session timeout"},
            {"category": "FINANCIAL", "title": "Payment gateway billing retry"},
            {"category": "PRIVACY", "title": "Anonymize user IP addresses"},
            {"category": "SECURITY", "title": "Password hashing algorithm"},
            {"category": "DATA", "title": "Permanent wipe and purge customer database"},
        ]
        for uc in unsafe_concerns:
            is_safe, reason = interaction_policy.is_safe_to_infer(uc)
            self.assertFalse(is_safe, f"Unsafe concern allowed: {uc}")
            self.assertIn("unsafe", reason.lower())

    # -------------------------------------------------------------------------
    # D7-24: Safe inference candidate execution & reversibility escalation
    # -------------------------------------------------------------------------
    def test_d7_24_safe_inference_execution_and_reversibility_escalation(self):
        safe_c = {"category": "IMPLEMENTATION_CONSTRAINT", "title": "Internal log file naming format", "riskLevel": "LOW"}
        is_safe, _ = interaction_policy.is_safe_to_infer(safe_c)
        self.assertTrue(is_safe)

        # Reversibility escalation if downstream risk escalates
        inf_record = {
            "concernId": "CONC-010",
            "chosenOption": "Format YYYY-MM-DD.log",
            "reversibility": "HIGH",
            "status": "SAFE_INFERRED",
        }
        escalated = interaction_policy.escalate_safe_inference_to_confirmation(inf_record)
        self.assertEqual(escalated["status"], "CONFIRMATION_REQUIRED")

    # -------------------------------------------------------------------------
    # D7-25: Candidate options generation with discriminative consequences
    # -------------------------------------------------------------------------
    def test_d7_25_candidate_options_generator(self):
        c = {"id": "CONC-001", "category": "DATA", "title": "Data Storage Backend"}
        options = interaction_policy.generate_candidate_options(c)
        self.assertGreaterEqual(len(options), 2)
        self.assertLessEqual(len(options), 4)
        for opt in options:
            self.assertIn("title", opt)
            self.assertIn("tradeoffs", opt)
            self.assertIn("consequences", opt)
        # At least one recommended option
        self.assertTrue(any(opt.get("isRecommended") for opt in options))

    # -------------------------------------------------------------------------
    # D7-26: Stopping engine evaluation (all resolved or remaining utility < threshold)
    # -------------------------------------------------------------------------
    def test_d7_26_stopping_engine_evaluation(self):
        concerns = [
            {"id": "CONC-001", "status": "RESOLVED", "riskLevel": "LOW"},
            {"id": "CONC-002", "status": "RESOLVED", "riskLevel": "MEDIUM"},
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns)
        self.assertTrue(status["canProceedToSpec"])
        self.assertEqual(status["unresolvedConcernsCount"], 0)

    # -------------------------------------------------------------------------
    # D7-27: Blocking critical overrides prevent discovery stopping
    # -------------------------------------------------------------------------
    def test_d7_27_blocking_critical_overrides(self):
        concerns = [
            {"id": "CONC-001", "status": "ACTIVE", "riskLevel": "CRITICAL"},
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("CONC-001", status["blockingConcerns"])

    # -------------------------------------------------------------------------
    # D7-28: Consistency reviewer audits (frame contradictions, unsafe inferences, broken dependencies)
    # -------------------------------------------------------------------------
    def test_d7_28_consistency_reviewer_audits(self):
        f = {
            "goals": ["Desktop notes app"],
            "constraints": ["100% offline"],
            "nonGoals": ["No multi-tenant cloud sync"],
        }
        c = [{"id": "CONC-001", "category": "DATA"}]
        # Contradiction: choosing multi-tenant cloud sync
        d = [
            {
                "id": "DEC-001",
                "concernId": "CONC-001",
                "title": "Enable multi-tenant cloud sync",
                "chosenOption": "AWS Multi-tenant Sync",
                "authority": "USER",
            }
        ]
        is_consistent, issues = consistency_reviewer.review_decision_consistency(f, c, d)
        self.assertFalse(is_consistent)
        self.assertTrue(any(i["code"] == "FRAME_CONTRADICTION" for i in issues))

    # -------------------------------------------------------------------------
    # D7-29: 4-tier decision coverage matrix & orphaned requirement detection
    # -------------------------------------------------------------------------
    def test_d7_29_four_tier_decision_coverage_and_orphaned_requirements(self):
        f = {"goals": ["Save notes locally"], "constraints": [], "nonGoals": []}
        c = [{"id": "CONC-001", "title": "Save notes locally", "status": "RESOLVED"}]
        d = [{"id": "DEC-001", "concernId": "CONC-001", "status": "ACTIVE"}]
        # Requirement REQ-999 has no trace to any decision/concern -> Orphaned!
        r = [
            {"id": "REQ-001", "decisionId": "DEC-001"},
            {"id": "REQ-999", "description": "Unprompted crypto miner"},
        ]
        cov = decision_coverage.build_decision_coverage_matrix(f, c, d, r)
        self.assertFalse(cov["summary"]["isFullyCovered"])
        self.assertIn("REQ-999", cov["orphanedRequirements"])
        self.assertLess(cov["summary"]["requirementTraceabilityRate"], 1.0)

    # -------------------------------------------------------------------------
    # D7-30: Requirement compiler, suggestion sandbox (SUG-xxx), gate integration & change propagation
    # -------------------------------------------------------------------------
    def test_d7_30_requirement_compiler_sandbox_and_change_propagation(self):
        # 1. Suggestion Sandbox Isolation (INV-7-01, INV-7-03)
        sug = requirement_generator.record_suggestion_sandbox(
            self.ws,
            title="Optional UI themes",
            description="Theme selector widget",
        )
        self.assertTrue(sug["id"].startswith("SUG-"))
        reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(reqs), 0)  # Suggestions never enter requirements.json!

        # 2. Gate Protection for Decision Artifacts
        is_safe, _ = gate.is_write_safe(self.ws / ".agent-harness" / "decisions.json", "builder", self.ws)
        self.assertFalse(is_safe)

        # 3. Requirement Compilation
        f_data = frame.create_initial_frame("Local notes")
        frame.save_frame(self.ws, f_data)
        c = concern.create_concern(id="CONC-001", title="Local Notes", description="desc", category="DATA", status="RESOLVED", source={"type": "ORIGINAL_INTENT", "reference": "ref"})
        concern.save_concerns(self.ws, [c])
        d = decision.create_decision(id="DEC-001", concern_id="CONC-001", title="Use SQLite", chosen_option="SQLite DB", authority="USER")
        decision.save_decisions(self.ws, [d])
        stopping_engine.save_decision_status(self.ws, {"canProceedToSpec": True})

        success, msg, compiled_reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success, f"Compilation failed: {msg}")
        self.assertEqual(len(compiled_reqs), 1)
        self.assertEqual(compiled_reqs[0]["decisionId"], "DEC-001")

        # Mark PASS
        compiled_reqs[0]["status"] = "PASS"
        kernel.save_requirements(self.ws, compiled_reqs)

        # 4. Change Propagation & Staleness Invalidation
        engine = decision_engine.DecisionEngine(self.ws)
        res = engine.supersede_decision(
            old_decision_id="DEC-001",
            new_chosen_option="PostgreSQL Server",
            rationale="Need enterprise scaling",
        )
        self.assertIn(compiled_reqs[0]["id"], res["invalidatedRequirements"])
        reloaded = kernel.load_requirements(self.ws)
        self.assertEqual(reloaded[0]["status"], "STALE")


if __name__ == "__main__":
    unittest.main()
