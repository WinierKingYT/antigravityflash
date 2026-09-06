"""
Strict Engineering Kernel Step 7 - Package A (Data Models & Storage) Test Suite
Validates Project Frame, Structured Concern Model, Canonical Decision Model,
User Response Parsing, and Cryptographic Decision Events Ledger.
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

import frame
import concern
import decision
import decision_events


class TestStep7PackageA(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="strict_eng_pkg_a_"))
        self.harness_dir = self.tmp_dir / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. FRAME.PY TESTS
    # -------------------------------------------------------------------------

    def test_create_and_validate_frame_defaults(self):
        f = frame.create_initial_frame(
            project_goal="Implement Payment Gateway",
            primary_user="merchant",
            problem_statement="Allow merchants to process card transactions safely.",
            explicit_constraints=["PCI-DSS compliance required", {"text": "Zero data loss", "provenance": "EXPLICIT_USER_STATEMENT"}],
            explicit_non_goals=["Do not support cryptocurrency"],
            known_facts=["Running Python 3.13 on Windows"],
        )
        self.assertEqual(f["schemaVersion"], "7.0")
        self.assertEqual(f["projectGoal"], "Implement Payment Gateway")
        self.assertEqual(f["primaryUser"], "merchant")
        self.assertEqual(len(f["explicitConstraints"]), 2)
        self.assertEqual(f["explicitConstraints"][0]["provenance"], "EXPLICIT_USER_STATEMENT")
        self.assertEqual(f["explicitConstraints"][0]["text"], "PCI-DSS compliance required")
        self.assertEqual(len(f["explicitNonGoals"]), 1)
        self.assertEqual(f["explicitNonGoals"][0]["text"], "Do not support cryptocurrency")

        is_valid, errors = frame.validate_frame(f)
        self.assertTrue(is_valid, f"Validation failed: {errors}")
        self.assertEqual(errors, [])

    def test_validate_frame_failures(self):
        # Invalid schemaVersion
        bad_frame = frame.create_initial_frame(project_goal="Test Goal")
        bad_frame["schemaVersion"] = "6.0"
        is_valid, errors = frame.validate_frame(bad_frame)
        self.assertFalse(is_valid)
        self.assertTrue(any("schemaVersion" in err for err in errors))

        # Empty projectGoal
        bad_frame2 = frame.create_initial_frame(project_goal="")
        is_valid, errors = frame.validate_frame(bad_frame2)
        self.assertFalse(is_valid)
        self.assertTrue(any("projectGoal" in err for err in errors))

        # Invalid provenance
        bad_frame3 = frame.create_initial_frame(project_goal="Valid Goal")
        bad_frame3["explicitConstraints"] = [{"text": "Something", "provenance": "INVALID_PROV"}]
        is_valid, errors = frame.validate_frame(bad_frame3)
        self.assertFalse(is_valid)
        self.assertTrue(any("provenance" in err for err in errors))

    def test_save_and_load_frame_atomic(self):
        f = frame.create_initial_frame(
            project_goal="Build SQLite Query Engine",
            primary_user="data-analyst",
        )
        frame.save_frame(self.tmp_dir, f)

        frame_path = frame.get_frame_path(self.tmp_dir)
        self.assertTrue(frame_path.exists())

        loaded = frame.load_frame(self.tmp_dir)
        self.assertEqual(loaded["projectGoal"], "Build SQLite Query Engine")
        self.assertEqual(loaded["primaryUser"], "data-analyst")
        self.assertEqual(loaded["schemaVersion"], "7.0")

    def test_extract_frame_from_structured_markdown(self):
        markdown_intent = """# Project Goal
Build high-throughput telemetry collector.

## Primary User
Site Reliability Engineer

## Problem Statement
Legacy collector drops UDP packets under high load.

## Explicit Constraints
- Must sustain 100,000 events/sec without memory leak
- Must run in Python 3.13 without C extensions

## Explicit Non-Goals
- Do not build a dashboard UI
- No distributed cluster coordination

## Known Facts
- Server has 16GB RAM and 8 CPU cores
- OS is Linux Ubuntu 22.04

## Success Definition
- Verified by load testing with 0 packet drops
"""
        extracted = frame.extract_frame_from_raw_request(markdown_intent)
        is_valid, errors = frame.validate_frame(extracted)
        self.assertTrue(is_valid, f"Validation failed: {errors}")

        self.assertIn("telemetry collector", extracted["projectGoal"])
        self.assertIn("reliability engineer", extracted["primaryUser"].lower())
        self.assertIn("drops udp packets", extracted["problemStatement"].lower())

        non_goals = [ng["text"] for ng in extracted["explicitNonGoals"]]
        self.assertTrue(any("dashboard UI" in ng for ng in non_goals))
        self.assertTrue(any("distributed cluster" in ng for ng in non_goals))

        constraints = [c["text"] for c in extracted["explicitConstraints"]]
        self.assertTrue(any("100,000 events/sec" in c for c in constraints))

        facts = [f["text"] for f in extracted["knownFacts"]]
        self.assertTrue(any("16GB RAM" in f for f in facts))

    def test_extract_frame_from_unstructured_intent(self):
        raw_intent = "We need an authentication service for customers. Do not implement social logins. Must use bcrypt for password hashing. We currently have SQLite database."
        extracted = frame.extract_frame_from_raw_request(raw_intent)
        is_valid, errors = frame.validate_frame(extracted)
        self.assertTrue(is_valid, f"Validation failed: {errors}")
        self.assertTrue(len(extracted["explicitNonGoals"]) >= 1)
        self.assertTrue(len(extracted["explicitConstraints"]) >= 1)

    # -------------------------------------------------------------------------
    # 2. CONCERN.PY TESTS
    # -------------------------------------------------------------------------

    def test_concern_categories_and_states(self):
        self.assertEqual(len(concern.CONCERN_CATEGORIES), 22)
        self.assertEqual(len(concern.CONCERN_STATES), 11)
        self.assertIn("AUTHORIZATION", concern.CONCERN_CATEGORIES)
        self.assertIn("IRREVERSIBILITY", concern.CONCERN_CATEGORIES)
        self.assertIn("DISCOVERED", concern.CONCERN_STATES)
        self.assertIn("RESOLVED", concern.CONCERN_STATES)

    def test_create_and_validate_concern(self):
        c = concern.create_concern(
            id="CONC-001",
            title="User Session Invalidation on Password Reset",
            description="All active JWT sessions must be invalidated when a user resets credentials.",
            category="AUTHORIZATION",
            source={"type": "ORIGINAL_INTENT", "reference": "REQ-002"},
            uncertainty=0.2,
            downstream_impact=0.9,
            criticality=0.95,
        )
        self.assertEqual(c["id"], "CONC-001")
        self.assertEqual(c["category"], "AUTHORIZATION")
        self.assertEqual(c["status"], "DISCOVERED")
        self.assertEqual(c["riskLevel"], "CRITICAL")  # AUTHORIZATION category baseline is CRITICAL

        is_valid, errors = concern.validate_concern(c)
        self.assertTrue(is_valid, f"Validation errors: {errors}")

    def test_evaluate_concern_risk_hard_overrides(self):
        # Auth pattern -> CRITICAL
        level, reasons = concern.evaluate_concern_risk(
            title="OAuth token refresh flow",
            description="Manage refresh tokens securely with automatic revocation.",
            category="CORE_BEHAVIOR",
        )
        self.assertEqual(level, "CRITICAL")
        self.assertIn("AUTH_BOUNDARY", reasons)

        # Financial pattern -> CRITICAL
        level, reasons = concern.evaluate_concern_risk(
            title="Billing Checkout",
            description="Process credit card checkout transactions.",
            category="CORE_BEHAVIOR",
        )
        self.assertEqual(level, "CRITICAL")
        self.assertIn("FINANCIAL_TRANSACTION", reasons)

        # Irreversible deletion -> CRITICAL
        level, reasons = concern.evaluate_concern_risk(
            title="Account removal",
            description="Drop table or permanent delete account data.",
            category="CORE_BEHAVIOR",
        )
        self.assertEqual(level, "CRITICAL")
        self.assertIn("DESTRUCTIVE_IRREVERSIBLE", reasons)

        # Persistence pattern -> MEDIUM
        level, reasons = concern.evaluate_concern_risk(
            title="Save user preferences",
            description="Persist theme settings to local storage across restarts.",
            category="WORKFLOW",
        )
        self.assertEqual(level, "MEDIUM")
        self.assertIn("DATA_PERSISTENCE", reasons)

        # Pure cosmetic -> LOW
        level, reasons = concern.evaluate_concern_risk(
            title="Button padding",
            description="Adjust padding and icon alignment on submit button.",
            category="PRODUCT_GOAL",
        )
        self.assertEqual(level, "LOW")

    def test_save_load_and_update_concern_status(self):
        c1 = concern.create_concern(
            id="CONC-001",
            title="Database Connection Pool Sizing",
            description="Determine max pool connections.",
            category="PERSISTENCE",
            source={"type": "FRAME", "reference": "frame.json"},
        )
        c2 = concern.create_concern(
            id="CONC-002",
            title="Audit Logging Format",
            description="JSON vs plain text audit logs.",
            category="SECURITY",
            source={"type": "FRAME", "reference": "frame.json"},
        )

        concern.save_concerns(self.tmp_dir, [c1, c2])
        loaded = concern.load_concerns(self.tmp_dir)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0]["id"], "CONC-001")
        self.assertEqual(loaded[1]["id"], "CONC-002")

        # Update CONC-001 to RESOLVED
        success, msg = concern.update_concern_status(self.tmp_dir, "CONC-001", "RESOLVED")
        self.assertTrue(success)
        reloaded = concern.load_concerns(self.tmp_dir)
        self.assertEqual(reloaded[0]["status"], "RESOLVED")
        self.assertIsNotNone(reloaded[0]["resolvedAt"])

        # Invalid status
        bad_success, bad_msg = concern.update_concern_status(self.tmp_dir, "CONC-001", "NON_EXISTENT_STATUS")
        self.assertFalse(bad_success)

        # Non-existent ID
        missing_success, missing_msg = concern.update_concern_status(self.tmp_dir, "CONC-999", "RESOLVED")
        self.assertFalse(missing_success)

    # -------------------------------------------------------------------------
    # 3. DECISION.PY TESTS
    # -------------------------------------------------------------------------

    def test_create_and_validate_decision(self):
        d = decision.create_decision(
            concern_id="CONC-001",
            question="Which database should be used for storing session tokens?",
            selected_option={"id": "OPT-REDIS", "title": "Redis Cache Store"},
            decision_type="USER_EXPLICIT",
            authority="USER",
            rationale_summary="Redis provides sub-millisecond lookups and native TTL expiry.",
            alternatives_considered=["PostgreSQL with cron cleanup", "In-memory LRU cache"],
            consequences=["Requires Redis container in docker-compose"],
            risk_level="MEDIUM",
        )
        self.assertEqual(d["concernId"], "CONC-001")
        self.assertEqual(d["decisionType"], "USER_EXPLICIT")
        self.assertEqual(d["authority"], "USER")
        self.assertEqual(d["confidence"], 1.0)
        self.assertIsNone(d["supersededBy"])

        is_valid, errors = decision.validate_decision(d)
        self.assertTrue(is_valid, f"Validation failed: {errors}")

    def test_save_load_and_supersede_decision(self):
        d1 = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            question="Session store?",
            selected_option="SQLite",
            decision_type="TECHNICAL_DECISION",
            authority="ARCHITECT_AUTHORIZED",
            rationale_summary="Initial local development simplicity.",
        )
        decision.save_decisions(self.tmp_dir, [d1])

        d2 = decision.create_decision(
            id="DEC-002",
            concern_id="CONC-001",
            question="Session store upgraded?",
            selected_option="Redis",
            decision_type="CHANGE_DECISION",
            authority="USER",
            rationale_summary="Production scale requires distributed cache.",
        )
        decisions = decision.load_decisions(self.tmp_dir)
        decisions.append(d2)
        decision.save_decisions(self.tmp_dir, decisions)

        # Supersede DEC-001 with DEC-002
        ok, msg = decision.supersede_decision(self.tmp_dir, "DEC-001", "DEC-002")
        self.assertTrue(ok)

        reloaded = decision.load_decisions(self.tmp_dir)
        self.assertEqual(reloaded[0]["supersededBy"], "DEC-002")
        self.assertIsNone(reloaded[1]["supersededBy"])

    def test_parse_user_response_options_and_ordinals(self):
        candidate_options = [
            {"id": "OPT-1", "title": "PostgreSQL Database", "description": "Relational storage"},
            {"id": "OPT-2", "title": "SQLite Embedded", "description": "Local zero-config storage"},
            {"id": "OPT-3", "title": "DuckDB Analytics", "description": "Fast OLAP query engine"},
        ]

        # Option A -> index 0
        res = decision.parse_user_response("Option A", candidate_options)
        self.assertEqual(res["status"], "MATCHED")
        self.assertEqual(res["optionIndex"], 0)
        self.assertEqual(res["selectedOption"]["id"], "OPT-1")
        self.assertEqual(res["authority"], "USER")

        # Just "B" -> index 1
        res = decision.parse_user_response("B", candidate_options)
        self.assertEqual(res["status"], "MATCHED")
        self.assertEqual(res["optionIndex"], 1)
        self.assertEqual(res["selectedOption"]["id"], "OPT-2")

        # "the second one" -> index 1
        res = decision.parse_user_response("the second one", candidate_options)
        self.assertEqual(res["status"], "MATCHED")
        self.assertEqual(res["optionIndex"], 1)
        self.assertEqual(res["selectedOption"]["id"], "OPT-2")

        # "Option 3" -> index 2
        res = decision.parse_user_response("Option 3", candidate_options)
        self.assertEqual(res["status"], "MATCHED")
        self.assertEqual(res["optionIndex"], 2)
        self.assertEqual(res["selectedOption"]["id"], "OPT-3")

        # "the last one" -> index 2
        res = decision.parse_user_response("the last one", candidate_options)
        self.assertEqual(res["status"], "MATCHED")
        self.assertEqual(res["optionIndex"], 2)

    def test_parse_user_response_delegation_uncertainty_rejection(self):
        candidate_options = [
            {"id": "OPT-1", "title": "Strict Mode", "isRecommended": True},
            {"id": "OPT-2", "title": "Permissive Mode"},
        ]

        # Delegation
        res = decision.parse_user_response("Whatever you think is best, up to you", candidate_options)
        self.assertEqual(res["status"], "DELEGATED")
        self.assertEqual(res["authority"], "USER_DELEGATED")
        self.assertEqual(res["intent"], "DELEGATION")
        self.assertEqual(res["selectedOption"]["id"], "OPT-1")  # Selected recommended

        # Uncertainty
        res = decision.parse_user_response("I'm really not sure, don't know yet", candidate_options)
        self.assertEqual(res["status"], "UNCERTAIN")
        self.assertEqual(res["intent"], "UNCERTAINTY")
        self.assertIsNone(res["selectedOption"])

        # Rejection
        res = decision.parse_user_response("None of these options work for us", candidate_options)
        self.assertEqual(res["status"], "REJECTED")
        self.assertEqual(res["intent"], "REJECTION")
        self.assertIsNone(res["selectedOption"])

    def test_parse_user_response_yes_no_and_fuzzy(self):
        binary_options = [
            {"id": "OPT-YES", "title": "Enable Strict Security Mode"},
            {"id": "OPT-NO", "title": "Disable Strict Security Mode"},
        ]
        # Test "Yes" -> matches positive option
        res_yes = decision.parse_user_response("yes, please", binary_options)
        self.assertEqual(res_yes["status"], "MATCHED")
        self.assertEqual(res_yes["optionIndex"], 0)
        self.assertEqual(res_yes["selectedOption"]["id"], "OPT-YES")

        # Test "No" -> matches negative option
        res_no = decision.parse_user_response("no, keep it disabled", binary_options)
        self.assertEqual(res_no["status"], "MATCHED")
        self.assertEqual(res_no["optionIndex"], 1)
        self.assertEqual(res_no["selectedOption"]["id"], "OPT-NO")

        # Test title fuzzy match
        candidate_options = [
            {"id": "OPT-PG", "title": "PostgreSQL Database"},
            {"id": "OPT-REDIS", "title": "Redis In-Memory Store"},
        ]
        res_fuzzy = decision.parse_user_response("I prefer PostgreSQL Database for ACID", candidate_options)
        self.assertEqual(res_fuzzy["status"], "MATCHED")
        self.assertEqual(res_fuzzy["optionIndex"], 0)
        self.assertEqual(res_fuzzy["selectedOption"]["id"], "OPT-PG")

    def test_all_decision_event_types_recorded_and_verified(self):
        # Verify every event type from DECISION_EVENT_TYPES can be recorded in sequence
        for evt_type in decision_events.DECISION_EVENT_TYPES:
            decision_events.record_decision_event(
                self.tmp_dir,
                event_type=evt_type,
                payload={"info": f"Testing {evt_type}"},
            )

        events = decision_events.load_decision_events(self.tmp_dir)
        self.assertEqual(len(events), len(decision_events.DECISION_EVENT_TYPES))

        valid, errors = decision_events.verify_decision_events_integrity(self.tmp_dir)
        self.assertTrue(valid, f"All event types chain failed: {errors}")
        self.assertEqual(errors, [])

    # -------------------------------------------------------------------------
    # 4. DECISION_EVENTS.PY TESTS
    # -------------------------------------------------------------------------


    def test_decision_events_empty_integrity(self):
        # Empty workspace has valid integrity
        valid, errors = decision_events.verify_decision_events_integrity(self.tmp_dir)
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_decision_events_chain_recording_and_integrity(self):
        # 1. Record FRAME_CREATED
        e1 = decision_events.record_decision_event(
            workspace_dir=self.tmp_dir,
            event_type="FRAME_CREATED",
            payload={"goal": "Build Payment Engine"},
            actor="spec-architect",
        )
        self.assertEqual(e1["previousHash"], decision_events.GENESIS_HASH)
        self.assertTrue(e1["eventId"].startswith("DEV-"))
        self.assertTrue(len(e1["eventHash"]) == 64)

        # 2. Record CONCERN_DISCOVERED
        e2 = decision_events.record_decision_event(
            workspace_dir=self.tmp_dir,
            event_type="CONCERN_DISCOVERED",
            payload={"concernId": "CONC-001", "category": "FINANCIAL"},
            actor="decision-engine",
        )
        self.assertEqual(e2["previousHash"], e1["eventHash"])

        # 3. Record QUESTION_ASKED
        e3 = decision_events.record_decision_event(
            workspace_dir=self.tmp_dir,
            event_type="QUESTION_ASKED",
            payload={"concernId": "CONC-001", "question": "Payment provider?"},
            actor="decision-engine",
        )
        self.assertEqual(e3["previousHash"], e2["eventHash"])

        # 4. Record USER_DECISION_RECORDED
        e4 = decision_events.record_decision_event(
            workspace_dir=self.tmp_dir,
            event_type="USER_DECISION_RECORDED",
            payload={"decisionId": "DEC-001", "selected": "Stripe"},
            actor="decision-engine",
        )
        self.assertEqual(e4["previousHash"], e3["eventHash"])

        # Load events
        loaded = decision_events.load_decision_events(self.tmp_dir)
        self.assertEqual(len(loaded), 4)
        self.assertEqual(loaded[0]["eventType"], "FRAME_CREATED")
        self.assertEqual(loaded[3]["eventType"], "USER_DECISION_RECORDED")

        # Verify integrity
        valid, errors = decision_events.verify_decision_events_integrity(self.tmp_dir)
        self.assertTrue(valid, f"Chain validation failed: {errors}")
        self.assertEqual(errors, [])

    def test_decision_events_tamper_detection(self):
        # Record two events
        decision_events.record_decision_event(
            self.tmp_dir,
            "FRAME_CREATED",
            {"goal": "Initial Goal"},
        )
        decision_events.record_decision_event(
            self.tmp_dir,
            "CONCERN_DISCOVERED",
            {"concernId": "CONC-001"},
        )

        events_file = decision_events.get_decision_events_path(self.tmp_dir)
        with open(events_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Tamper payload in first event without recomputing hash
        tampered_entry = json.loads(lines[0])
        tampered_entry["payload"]["goal"] = "TAMPERED_GOAL"
        lines[0] = json.dumps(tampered_entry) + "\n"

        with open(events_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        valid, errors = decision_events.verify_decision_events_integrity(self.tmp_dir)
        self.assertFalse(valid)
        self.assertTrue(any("tamper detected" in err.lower() for err in errors))


if __name__ == "__main__":
    unittest.main()
