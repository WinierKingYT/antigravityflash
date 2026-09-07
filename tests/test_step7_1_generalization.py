"""
ANTIGRAVITY STRICT ENGINEERING KERNEL
STEP 7.1 — GENERALIZATION & DECISION TRUTH CLOSURE TEST SUITE

Tests:
- D71-AUTH-01 through D71-AUTH-06: User authority state machine (UNCERTAIN, REJECTION, DELEGATION, SELECTION)
- D71-STOP-01 through D71-STOP-02: Safe stopping invariants (unconditional HIGH blocking, budget fatigue pause)
- D71-REQ-01 through D71-REQ-06: Requirement compilation (INTENT->REQ, 0/1/N cardinality, non-destructive merge, quality validator, gate bypass)
- D71-DOMAIN-01 through D71-DOMAIN-06: 6-Domain matrix (Notes, CLI, Inventory, Image, Game, REST)
- D71-FRAME-01: Authentic SHA-256 fingerprint and canonical intent model
"""

import os
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from src.strict_engineering import frame
from src.strict_engineering import concern
from src.strict_engineering import decision
from src.strict_engineering import decision_engine
from src.strict_engineering import decision_graph
from src.strict_engineering import stopping_engine
from src.strict_engineering import question_utility
from src.strict_engineering import consistency_reviewer
from src.strict_engineering import requirement_generator
from src.strict_engineering import decision_events
from src.strict_engineering import kernel


class TestStep71Generalization(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_step7_1_test_"))
        self.ws = self.test_dir
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.engine = decision_engine.DecisionEngine(self.ws)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # USER AUTHORITY TESTS (D71-AUTH)
    # -------------------------------------------------------------------------

    def test_d71_auth_01_uncertainty_preservation(self):
        """D71-AUTH-01: UNCERTAIN response must NOT create decision and must NOT resolve concern."""
        init = self.engine.initialize_discovery("Build an inventory tracker for warehouse goods.")
        concerns = init["concerns"]
        target = concerns[0]
        cid = target["id"]

        res = self.engine.record_user_decision(
            concern_id=cid,
            user_response="I don't know, not sure yet",
        )

        self.assertEqual(res["action"], "UNCERTAINTY_PRESERVED")
        self.assertIn("Concern remains unresolved", res["message"])

        # Verify no decision was created
        decisions = decision.load_decisions(self.ws)
        self.assertEqual(len(decisions), 0)

        # Verify concern is NOT resolved
        updated_concerns = concern.load_concerns(self.ws)
        c_found = next(c for c in updated_concerns if c["id"] == cid)
        self.assertNotEqual(c_found["status"], "RESOLVED")

        # Verify event ledger recorded uncertainty
        events = decision_events.load_decision_events(self.ws)
        uncert_events = [e for e in events if e.get("eventType") == "USER_UNCERTAINTY_RECORDED"]
        self.assertEqual(len(uncert_events), 1)
        self.assertEqual(uncert_events[0]["payload"]["concernId"], cid)

    def test_d71_auth_02_bare_rejection_preservation(self):
        """D71-AUTH-02: Bare rejection must NOT create decision and must NOT resolve concern."""
        init = self.engine.initialize_discovery("Build a task management service.")
        concerns = init["concerns"]
        target = concerns[0]
        cid = target["id"]

        res = self.engine.record_user_decision(
            concern_id=cid,
            user_response="none of these",
        )

        self.assertEqual(res["action"], "REJECTION_RECORDED")
        self.assertIn("Concern remains unresolved", res["message"])

        # No decision created
        decisions = decision.load_decisions(self.ws)
        self.assertEqual(len(decisions), 0)

        # Concern remains unresolved
        updated_concerns = concern.load_concerns(self.ws)
        c_found = next(c for c in updated_concerns if c["id"] == cid)
        self.assertNotEqual(c_found["status"], "RESOLVED")

        # Event recorded
        events = decision_events.load_decision_events(self.ws)
        rej_events = [e for e in events if e.get("eventType") == "USER_REJECTION_RECORDED"]
        self.assertEqual(len(rej_events), 1)

    def test_d71_auth_03_rejection_with_custom_alternative(self):
        """D71-AUTH-03: Rejection with explicit custom alternative creates custom decision."""
        init = self.engine.initialize_discovery("Build a data store for customer logs.")
        # Find persistence concern
        concerns = init["concerns"]
        target = next((c for c in concerns if c.get("category") == "PERSISTENCE"), concerns[0])
        cid = target["id"]

        res = self.engine.record_user_decision(
            concern_id=cid,
            user_response="none of these, use PostgreSQL instead",
        )

        self.assertIn("decision", res)
        dec = res["decision"]
        self.assertEqual(dec["authority"], "USER")
        self.assertEqual(dec["decisionType"], "USER_EXPLICIT")
        self.assertIn("PostgreSQL", dec["chosenOption"])

        # Concern is RESOLVED
        updated_concerns = concern.load_concerns(self.ws)
        c_found = next(c for c in updated_concerns if c["id"] == cid)
        self.assertEqual(c_found["status"], "RESOLVED")
        self.assertEqual(c_found["chosenDecisionId"], dec["id"])

    def test_d71_auth_04_user_delegation_low_medium_risk(self):
        """D71-AUTH-04: User delegation on low/medium risk concern retains USER_DELEGATED authority."""
        f_data = frame.create_initial_frame("Build a lightweight terminal log viewer.")
        frame.save_frame(self.ws, f_data)

        c = concern.create_concern(
            id="CONC-001",
            title="Log formatting display style",
            description="Determine visual output presentation format for log records.",
            category="CORE_BEHAVIOR",
            source={"type": "FRAME_GOAL", "reference": "log viewer"},
            risk_level="MEDIUM",
            status="ACTIVE",
            candidate_options=[
                {"id": "OPT-1", "title": "Colored ANSI Table", "description": "Structured columns with ANSI colors", "isRecommended": True},
                {"id": "OPT-2", "title": "Raw NDJSON Streams", "description": "Single line raw json", "isRecommended": False},
            ],
        )
        concern.save_concerns(self.ws, [c])

        res = self.engine.record_user_decision(
            concern_id="CONC-001",
            user_response="you decide, whichever you prefer",
        )

        self.assertIn("decision", res)
        dec = res["decision"]
        self.assertEqual(dec["authority"], "USER_DELEGATED")
        self.assertEqual(dec["decisionType"], "USER_EXPLICIT")
        self.assertIn("Colored ANSI Table", dec["chosenOption"])

        # Concern resolved
        c_loaded = concern.load_concerns(self.ws)[0]
        self.assertEqual(c_loaded["status"], "RESOLVED")

    def test_d71_auth_05_user_delegation_high_risk_blocked(self):
        """D71-AUTH-05: High/Critical risk concern cannot be silently delegated without direct user confirmation."""
        f_data = frame.create_initial_frame("Build an enterprise customer account portal.")
        frame.save_frame(self.ws, f_data)

        c = concern.create_concern(
            id="CONC-001",
            title="Authentication & Password Policy",
            description="Establish master credential authentication protocol and hashing boundary.",
            category="AUTHORIZATION",
            source={"type": "FRAME_GOAL", "reference": "account portal"},
            risk_level="CRITICAL",
            status="ACTIVE",
            candidate_options=[
                {"id": "OPT-1", "title": "OAuth 2.0 with Argon2id", "description": "Standard OAuth with strong password hashing", "isRecommended": True},
                {"id": "OPT-2", "title": "Basic Auth", "description": "Simple HTTP basic auth", "isRecommended": False},
            ],
        )
        concern.save_concerns(self.ws, [c])

        res = self.engine.record_user_decision(
            concern_id="CONC-001",
            user_response="you choose, whatever you think is best",
        )

        self.assertEqual(res["action"], "DELEGATION_RESTRICTED")
        self.assertIn("Cannot delegate CRITICAL-risk architectural concern", res["message"])

        # No decision created
        decisions = decision.load_decisions(self.ws)
        self.assertEqual(len(decisions), 0)

        # Concern remains unresolved
        c_loaded = concern.load_concerns(self.ws)[0]
        self.assertNotEqual(c_loaded["status"], "RESOLVED")

    def test_d71_auth_06_normal_selection_direct_authority(self):
        """D71-AUTH-06: Normal user selection sets authority='USER' and decisionType='USER_EXPLICIT'."""
        f_data = frame.create_initial_frame("Build a local media player.")
        frame.save_frame(self.ws, f_data)

        c = concern.create_concern(
            id="CONC-001",
            title="Audio decoder backend",
            description="Select audio decoding library.",
            category="CORE_BEHAVIOR",
            source={"type": "FRAME_GOAL", "reference": "media player"},
            risk_level="MEDIUM",
            status="ACTIVE",
            candidate_options=[
                {"id": "OPT-1", "title": "FFmpeg Native Engine", "description": "Full format coverage"},
                {"id": "OPT-2", "title": "Miniaudio Embedded", "description": "Lightweight pure C engine"},
            ],
        )
        concern.save_concerns(self.ws, [c])

        res = self.engine.record_user_decision(
            concern_id="CONC-001",
            user_response="Option 2",
        )

        self.assertIn("decision", res)
        dec = res["decision"]
        self.assertEqual(dec["authority"], "USER")
        self.assertEqual(dec["decisionType"], "USER_EXPLICIT")
        self.assertIn("Miniaudio", dec["chosenOption"])

    # -------------------------------------------------------------------------
    # STOPPING ENGINE INVARIANTS (D71-STOP)
    # -------------------------------------------------------------------------

    def test_d71_stop_01_unresolved_high_risk_unconditionally_blocks(self):
        """D71-STOP-01: An unresolved concern with riskLevel='HIGH' unconditionally blocks stopping."""
        concerns = [
            {
                "id": "CONC-001",
                "status": "ACTIVE",
                "riskLevel": "HIGH",
                "isBlocking": False,  # Note: isBlocking is False, but risk is HIGH
                "uncertainty": 0.2,
                "downstreamImpact": 0.2,
            }
        ]
        status = stopping_engine.evaluate_stopping_conditions(concerns, threshold=0.35)
        self.assertFalse(status["canProceedToSpec"])
        self.assertIn("CONC-001", status["blockingConcerns"])
        self.assertIn("Unresolved blocking/critical concerns remain", status["reason"])

    def test_d71_stop_02_budget_fatigue_pauses_session_when_high_utility_remains(self):
        """D71-STOP-02: Fatigue reached with high-utility concerns remaining must PAUSE, not declare spec-ready."""
        concerns = [
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
        status = stopping_engine.evaluate_stopping_conditions(
            concerns,
            asked_questions=fake_asked,
            max_questions=15,
            threshold=0.35,
        )
        self.assertFalse(status["canProceedToSpec"])
        self.assertEqual(status["reason"], "SESSION_QUESTION_BUDGET_REACHED")

    # -------------------------------------------------------------------------
    # REQUIREMENT COMPILATION & MERGE (D71-REQ)
    # -------------------------------------------------------------------------

    def test_d71_req_01_direct_intent_requirement_compilation(self):
        """D71-REQ-01: Direct explicit requirements compiled directly from frame intents (INTENT -> REQ)."""
        f_data = frame.create_initial_frame(
            project_goal="Build a high-performance HTTP reverse proxy.",
            explicit_requirements=["Must forward HTTP/1.1 and HTTP/2 requests to configured upstream targets"],
            explicit_constraints=["Must support TLS 1.3 encryption"],
        )
        frame.save_frame(self.ws, f_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_intents(self.ws)
        self.assertTrue(success, f"Intent compilation failed: {msg}")
        self.assertGreaterEqual(len(reqs), 2)

        # Invariant 17: Broad goal is NOT an implementation requirement
        goal_req = next((r for r in reqs if r["category"] == "PRODUCT_GOAL"), None)
        self.assertIsNone(goal_req, "Broad project goal must not be compiled into requirements.json per Invariant 17")

        # Check explicit requirement
        core_req = next((r for r in reqs if r["category"] == "CORE_BEHAVIOR"), None)
        self.assertIsNotNone(core_req)
        self.assertEqual(core_req["intentId"], "INTENT-002")
        self.assertIn("forward HTTP/1.1", core_req["description"])

        # Check constraint requirement
        constr_req = next((r for r in reqs if r["category"] == "IMPLEMENTATION_CONSTRAINT"), None)
        self.assertIsNotNone(constr_req)
        self.assertEqual(constr_req["intentId"], "INTENT-003")
        self.assertIn("TLS 1.3", constr_req["description"])

    def test_d71_req_02_cardinality_0_operational_decision(self):
        """D71-REQ-02: Operational or process decisions produce 0 requirements."""
        f_data = frame.create_initial_frame("Build a CLI tool.")
        frame.save_frame(self.ws, f_data)

        c = concern.create_concern(
            id="CONC-001",
            title="Team sprint review schedule",
            description="Process workflow for development team meetings.",
            category="WORKFLOW",
            source={"type": "FRAME_GOAL", "reference": "CLI tool"},
            risk_level="LOW",
            status="RESOLVED",
        )
        concern.save_concerns(self.ws, [c])

        d = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            title="Bi-weekly review meetings",
            chosen_option="Review sprint every alternate Thursday",
            authority="USER_DIRECT",
            decision_type="TECHNICAL_DECISION",
            generates_requirements=False,
        )
        decision.save_decisions(self.ws, [d])

        status_data = {"canProceedToSpec": True, "reason": "All concerns resolved"}
        stopping_engine.save_decision_status(self.ws, status_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success)
        # Operational decision generates 0 requirements
        self.assertEqual(len(reqs), 0)

    def test_d71_req_03_cardinality_n_complex_decision(self):
        """D71-REQ-03: Complex architectural decision generates N sub-requirements."""
        f_data = frame.create_initial_frame("Build a database engine.")
        frame.save_frame(self.ws, f_data)

        c = concern.create_concern(
            id="CONC-001",
            title="Storage & durability architecture",
            description="Multi-faceted storage engine requirements.",
            category="PERSISTENCE",
            source={"type": "FRAME_GOAL", "reference": "database engine"},
            risk_level="HIGH",
            status="RESOLVED",
        )
        concern.save_concerns(self.ws, [c])

        d = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            title="Dual-Tier Storage Architecture",
            chosen_option="LSM-Tree with Write-Ahead Logging",
            authority="USER_DIRECT",
        )
        # Specify 2 distinct sub-requirements
        d["subRequirements"] = [
            {"title": "Append-Only Write-Ahead Log", "chosenOption": "Sequential sync to disk before memory commit"},
            {"title": "MemTable to SSTable Compaction", "chosenOption": "Asynchronous leveled compaction background thread"},
        ]
        decision.save_decisions(self.ws, [d])

        status_data = {"canProceedToSpec": True, "reason": "All concerns resolved"}
        stopping_engine.save_decision_status(self.ws, status_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success)
        self.assertEqual(len(reqs), 2)
        self.assertIn("Write-Ahead Log", reqs[0]["title"])
        self.assertIn("Compaction", reqs[1]["title"])

    def test_d71_req_04_non_destructive_merge_preserves_pre_existing_requirements(self):
        """D71-REQ-04: Non-destructive merge preserves pre-existing requirements not affected by compilation."""
        f_data = frame.create_initial_frame("Build an inventory tracker.")
        frame.save_frame(self.ws, f_data)

        # Seed pre-existing requirement (e.g. from an explicit legacy contract)
        legacy_req = {
            "id": "REQ-099",
            "title": "Legacy Warehouse Barcode Scanner Compatibility",
            "description": "The system shall interface with standard USB HID barcode scanners.",
            "category": "INTEGRATION",
            "status": "VERIFIED",
            "required": True,
            "riskLevel": "LOW",
            "sources": ["LEGACY_SPEC"],
            "authority": "USER_DIRECT",
            "acceptanceCriteria": [
                "Given a connected USB barcode scanner, When barcode is scanned, Then input stream is buffered into current active item form."
            ],
            "verificationContract": "Verify barcode scanner input simulation",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        kernel.save_requirements(self.ws, [legacy_req])

        # Add a new decision
        c = concern.create_concern(
            id="CONC-001",
            title="Stock quantity alert threshold",
            description="Alerting logic when stock drops below minimum safety margins.",
            category="CORE_BEHAVIOR",
            source={"type": "FRAME_GOAL", "reference": "inventory tracker"},
            risk_level="MEDIUM",
            status="RESOLVED",
        )
        concern.save_concerns(self.ws, [c])

        d = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            title="Low-stock visual badge",
            chosen_option="Display amber warning icon when count < 10",
            authority="USER_DIRECT",
        )
        decision.save_decisions(self.ws, [d])

        status_data = {"canProceedToSpec": True, "reason": "All concerns resolved"}
        stopping_engine.save_decision_status(self.ws, status_data)

        success, msg, compiled_reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success)

        # Load requirements from disk: REQ-099 MUST still exist!
        disk_reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(disk_reqs), 2)
        req_ids = [r["id"] for r in disk_reqs]
        self.assertIn("REQ-099", req_ids)
        legacy_found = next(r for r in disk_reqs if r["id"] == "REQ-099")
        self.assertEqual(legacy_found["status"], "VERIFIED")

    def test_d71_req_05_quality_validator_rejects_tautologies(self):
        """D71-REQ-05: Quality validator rejects tautological descriptions and criteria."""
        bad_req = {
            "id": "REQ-001",
            "title": "Implement DEC-001",
            "description": "Short",
            "acceptanceCriteria": ["Implementation satisfies Implement DEC-001"],
        }
        is_val, errors = requirement_generator.validate_requirement_quality(bad_req)
        self.assertFalse(is_val)
        self.assertGreater(len(errors), 0)

        good_req = {
            "id": "REQ-001",
            "title": "Record Mutation Durability Guarantee",
            "description": "The system shall write each mutation to durable disk storage before returning success.",
            "acceptanceCriteria": [
                "Given an incoming record mutation, When write is requested, Then the system syncs to disk and returns confirmation.",
                "Given an unexpected power loss during write, When system restarts, Then incomplete transactions are cleanly rolled back."
            ],
        }
        is_val, errors = requirement_generator.validate_requirement_quality(good_req)
        self.assertTrue(is_val, f"Validation failed: {errors}")

    def test_d71_req_06_gate_bypass_prevention(self):
        """D71-REQ-06: Gate cannot be bypassed when stopping conditions are unfulfilled."""
        f_data = frame.create_initial_frame("Build a secure file vault.")
        frame.save_frame(self.ws, f_data)

        # Unfulfilled stopping engine status
        status_data = {"canProceedToSpec": False, "reason": "Unresolved critical concerns"}
        stopping_engine.save_decision_status(self.ws, status_data)

        # Calling without satisfaction MUST fail
        success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertFalse(success)
        self.assertIn("Discovery stopping gate blocked", msg)

    # -------------------------------------------------------------------------
    # MULTI-DOMAIN GENERALIZATION MATRIX (D71-DOMAIN)
    # -------------------------------------------------------------------------

    def _verify_domain_generalization(self, raw_intent: str, domain_name: str):
        """Helper to run discovery on a domain and verify zero note/SQLite templates and 100% grounding."""
        ws_domain = self.test_dir / f"domain_{domain_name}"
        ws_domain.mkdir(parents=True, exist_ok=True)
        (ws_domain / ".agent-harness").mkdir(parents=True, exist_ok=True)

        engine = decision_engine.DecisionEngine(ws_domain)
        init = engine.initialize_discovery(raw_intent, project_name=domain_name)
        concerns = init["concerns"]
        self.assertGreater(len(concerns), 0)

        # Check each concern:
        for c in concerns:
            # 1. Zero hardcoded 'notes app' or 'note storage' text unless domain is actually notes
            if domain_name != "notes_app":
                c_corpus = f"{c.get('title', '')} {c.get('description', '')}".lower()
                self.assertNotIn("saved project notes", c_corpus)
                self.assertNotIn("note storage model", c_corpus)
                self.assertNotIn("note retrieval mechanism", c_corpus)

            # 2. Each concern must pass validate_proposed_concern
            is_valid, reason = concern.validate_proposed_concern(c, init["frame"])
            self.assertTrue(is_valid, f"Domain {domain_name} concern {c.get('id')} failed validation: {reason}")

    def test_d71_domain_01_notes_app(self):
        """Domain 1: Notes Application."""
        self._verify_domain_generalization(
            "Build a local desktop application to save project notes with SQLite and tags.",
            "notes_app",
        )

    def test_d71_domain_02_cli_log_tool(self):
        """Domain 2: CLI Log Analysis Tool."""
        self._verify_domain_generalization(
            "Build a command-line tool that parses JSON log streams from stdin, filters by loglevel, and prints summary tables to stdout.",
            "cli_log_tool",
        )

    def test_d71_domain_03_inventory_tracking(self):
        """Domain 3: Inventory Tracking Application."""
        self._verify_domain_generalization(
            "Build an inventory management system to monitor warehouse stock levels, record shipment transactions, and audit SKU items.",
            "inventory_tracking",
        )

    def test_d71_domain_04_image_organizer(self):
        """Domain 4: Local Image Organizer."""
        self._verify_domain_generalization(
            "Build an offline desktop photo manager to catalog EXIF metadata, tag images into albums, and detect duplicate image files.",
            "image_organizer",
        )

    def test_d71_domain_05_game_combat_system(self):
        """Domain 5: Turn-Based Game Combat System."""
        self._verify_domain_generalization(
            "Build a deterministic turn-based battle simulation engine with character action queues, hit calculations, and battle replay state recovery.",
            "game_combat",
        )

    def test_d71_domain_06_rest_service(self):
        """Domain 6: Minimal REST Service."""
        self._verify_domain_generalization(
            "Build a high-performance REST API microservice with bearer token authentication, rate limiting, and customer profile management endpoints.",
            "rest_service",
        )

    # -------------------------------------------------------------------------
    # AUTHENTIC HASHES & CANONICAL INTENT MODEL (D71-FRAME)
    # -------------------------------------------------------------------------

    def test_d71_frame_01_authentic_sha256_and_canonical_intents(self):
        """D71-FRAME-01: Authentic 64-character SHA-256 fingerprint and canonical intent model."""
        raw_text = "Build an accounting dashboard. Must comply with GAAP standards. Do not support cryptocurrency."
        f_data = frame.extract_frame_from_intent(raw_text)

        # Check authentic SHA-256 source reference
        src_refs = f_data.get("sourceReferences", [])
        self.assertGreater(len(src_refs), 0)
        self.assertTrue(src_refs[0].startswith("sha256:"))
        hash_val = src_refs[0].split("sha256:")[1]
        self.assertEqual(len(hash_val), 64)
        self.assertTrue(all(c in "0123456789abcdefABCDEF" for c in hash_val))
        self.assertNotIn("chars", src_refs[0])

        # Check canonical intents list
        intents = f_data.get("intents", [])
        self.assertGreaterEqual(len(intents), 3)  # goal + constraint + non-goal

        for it in intents:
            self.assertTrue(it["id"].startswith("INTENT-"))
            self.assertTrue(len(it["statementHash"]) == 64)
            self.assertTrue(all(c in "0123456789abcdefABCDEF" for c in it["statementHash"]))

        # Frame validation passes
        is_val, errors = frame.validate_frame(f_data)
        self.assertTrue(is_val, f"Frame validation failed: {errors}")


if __name__ == "__main__":
    unittest.main()
