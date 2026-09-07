"""
Unit tests for Step 7 Package D:
Requirement Generator, Decision Engine Facade, Gate Integration, and Kernel Change Propagation.
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

import requirement_generator
import decision_engine
import decision_events
import decision_graph
import decision_coverage
import stopping_engine
import gate
import kernel
import frame
import concern
import decision


class TestStep7PackageD(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ws = Path(self.test_dir)
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. REQUIREMENT GENERATOR TESTS
    # -------------------------------------------------------------------------

    def test_requirement_generator_transition_gate_blocks_when_unresolved(self):
        # Create unfulfilled decision-status
        status_data = {
            "canProceedToSpec": False,
            "reason": "Critical concerns unresolved",
        }
        stopping_engine.save_decision_status(self.ws, status_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertFalse(success)
        self.assertIn("Discovery stopping gate blocked", msg)
        self.assertEqual(len(reqs), 0)

    def test_requirement_generator_successful_compilation(self):
        # Setup clean frame, concerns, decisions, and ready status
        f_data = frame.create_initial_frame("Build a local notes app")
        frame.save_frame(self.ws, f_data)

        c1 = {
            "id": "CONC-001",
            "category": "PERSISTENCE",
            "title": "Local note storage",
            "riskLevel": "MEDIUM",
            "status": "RESOLVED",
        }
        concern.save_concerns(self.ws, [c1])

        d1 = decision.create_decision(
            concern_id="CONC-001",
            title="Use SQLite file storage",
            chosen_option="SQLite embedded database file",
            authority="USER_DIRECT",
            rationale="Zero setup and reliable offline transactions",
        )
        decision.save_decisions(self.ws, [d1])

        # Ready status
        status_data = {
            "canProceedToSpec": True,
            "reason": "All concerns resolved",
        }
        stopping_engine.save_decision_status(self.ws, status_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success, f"Compilation failed: {msg}")
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["id"], "REQ-001")
        self.assertEqual(reqs[0]["decisionId"], d1["id"])
        self.assertEqual(reqs[0]["concernId"], "CONC-001")
        self.assertEqual(reqs[0]["riskLevel"], "MEDIUM")
        self.assertIn("SQLite embedded database file", reqs[0]["description"])

        # Check requirements.json exists and is valid
        loaded_reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(loaded_reqs), 1)

        # Check decision coverage was synced and has 0 orphaned requirements
        cov = decision_coverage.load_decision_coverage(self.ws)
        self.assertEqual(cov["orphanedRequirements"], [])

    def test_requirement_generator_suggestion_sandbox_isolation(self):
        # Record a suggestion
        sug = requirement_generator.record_suggestion_sandbox(
            workspace_dir=self.ws,
            title="Add dark mode support",
            description="Nice to have color theme toggle",
            source_concern_id="CONC-005",
        )
        self.assertTrue(sug["id"].startswith("SUG-"))
        self.assertEqual(sug["status"], "SANDBOXED")

        # Verify suggestion is NOT in requirements.json
        reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(reqs), 0)

        # Verify suggestion is in suggestions.json
        suggestions = requirement_generator.load_suggestions(self.ws)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["id"], sug["id"])

    # -------------------------------------------------------------------------
    # 2. DECISION ENGINE FACADE TESTS
    # -------------------------------------------------------------------------

    def test_decision_engine_initialize_discovery(self):
        engine = decision_engine.DecisionEngine(self.ws)
        init_res = engine.initialize_discovery(
            raw_intent="Build a fast local desktop application for taking notes and organizing tasks.",
            project_name="Desktop Notes",
        )
        self.assertIn("frame", init_res)
        self.assertIn("concerns", init_res)
        self.assertEqual(len(init_res["concerns"]), 0)  # Canonical concerns are empty until semantic discovery or human creation
        self.assertIn("heuristicSeeds", init_res)
        self.assertGreater(len(init_res["heuristicSeeds"]), 0)

        # Check ledger has recorded FRAME_CREATED and CONCERN_DISCOVERED events
        events = decision_events.load_decision_events(self.ws)
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(events[0]["eventType"], "FRAME_CREATED")

        # Verify cryptographic integrity of initial ledger
        valid, errors = decision_events.verify_decision_events_integrity(self.ws)
        self.assertTrue(valid, f"Initial event ledger invalid: {errors}")

    def test_decision_engine_get_next_interaction_and_record_decision(self):
        engine = decision_engine.DecisionEngine(self.ws)
        engine.initialize_discovery(
            raw_intent="Build a local desktop application to save project notes with SQLite and tags."
        )

        interaction = engine.get_next_interaction()
        self.assertIn(interaction["action"], ["ASK", "SUGGEST", "CHALLENGE", "PROCEED_TO_SPEC", "RUN_SEMANTIC_DISCOVERY"])

        # Create canonical concern to test interaction and decision recording
        c = engine.create_human_concern(
            title="Note Storage Persistence",
            question="How should notes be stored on local disk?",
            candidate_options=[
                {"id": "OPT-1", "title": "SQLite Embedded Database", "description": "Local sqlite database", "isRecommended": True},
                {"id": "OPT-2", "title": "Plain Text Markdown Files", "description": "Flat files", "isRecommended": False},
            ],
        )
        interaction = engine.get_next_interaction()
        self.assertIn(interaction["action"], ["ASK", "SUGGEST", "CHALLENGE", "PROCEED_TO_SPEC"])

        if interaction["action"] != "PROCEED_TO_SPEC":
            cid = interaction["concernId"]
            # User responds with option selection
            res = engine.record_user_decision(
                concern_id=cid,
                user_response="Option 1",
            )
            self.assertIn("decision", res)
            self.assertEqual(res["decision"]["concernId"], cid)

            # Check concern is marked resolved
            concerns = concern.load_concerns(self.ws)
            resolved_c = next(c for c in concerns if c["id"] == cid)
            self.assertEqual(resolved_c["status"], "RESOLVED")

    def test_decision_engine_supersession_and_change_propagation(self):
        engine = decision_engine.DecisionEngine(self.ws)
        engine.initialize_discovery("Build offline notes app")

        # Manually create decision and compile requirement
        c1 = {"id": "CONC-001", "category": "DATA", "status": "RESOLVED"}
        concern.save_concerns(self.ws, [c1])

        d1 = decision.create_decision(
            concern_id="CONC-001",
            title="Database choice",
            chosen_option="SQLite embedded",
            authority="USER_DIRECT",
        )
        decision.save_decisions(self.ws, [d1])

        # Compile requirements
        stopping_engine.save_decision_status(self.ws, {"canProceedToSpec": True})
        success, _, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(success)
        self.assertEqual(len(reqs), 1)

        # Mark requirement as PASS to simulate prior verification
        reqs[0]["status"] = "PASS"
        kernel.save_requirements(self.ws, reqs)

        # Now supersede decision d1 with Postgres
        res = engine.supersede_decision(
            old_decision_id=d1["id"],
            new_chosen_option="PostgreSQL Server",
            rationale="Need multi-process server backend",
        )

        self.assertIn("newDecision", res)
        self.assertIn(reqs[0]["id"], res["invalidatedRequirements"])

        # Check requirement status is now STALE
        reloaded_reqs = kernel.load_requirements(self.ws)
        self.assertEqual(reloaded_reqs[0]["status"], "STALE")
        self.assertIn("Derives from superseded decision", reloaded_reqs[0]["stalenessReason"])

    # -------------------------------------------------------------------------
    # 3. GATE INTEGRATION TESTS
    # -------------------------------------------------------------------------

    def test_gate_protected_artifacts_includes_decision_files(self):
        expected_protected = {
            ".agent-harness/frame.json",
            ".agent-harness/concerns.json",
            ".agent-harness/decisions.json",
            ".agent-harness/decision-graph.json",
            ".agent-harness/decision-coverage.json",
            ".agent-harness/decision-events.jsonl",
            ".agent-harness/decision-status.json",
        }
        for p in expected_protected:
            self.assertIn(p, gate.PROTECTED_ARTIFACTS)

    def test_gate_builder_write_to_decision_artifacts_denied(self):
        target_path = self.ws / ".agent-harness" / "decisions.json"
        is_safe, reason = gate.is_write_safe(
            target_path=target_path,
            calling_role="builder",
            workspace_root=self.ws,
        )
        self.assertFalse(is_safe)
        self.assertIn("denied", reason.lower())

    def test_gate_tampered_decision_ledger_blocks_stop(self):
        # Create minimal valid active state
        state = kernel.load_state(self.ws)
        state["active"] = True
        state["phase"] = "VERIFICATION"
        state["finalAuditPassed"] = True
        kernel.save_state(self.ws, state)

        # Write tampered ledger
        decision_events.record_decision_event(self.ws, "FRAME_CREATED", {"goal": "test"})
        events_path = decision_events.get_decision_events_path(self.ws)
        with open(events_path, "w", encoding="utf-8") as f:
            f.write("corrupted non-json line\n")

        stop_eval = gate.evaluate_stop(self.ws)
        self.assertEqual(stop_eval["decision"], "continue")
        self.assertIn("Decision event ledger integrity violated", stop_eval["reason"])

    def test_kernel_propagate_decision_change(self):
        reqs = [
            {"id": "REQ-001", "decisionId": "DEC-001", "status": "PASS"},
            {"id": "REQ-002", "decisionId": "DEC-002", "status": "PASS"},
        ]
        kernel.save_requirements(self.ws, reqs)

        invalidated = kernel.propagate_decision_change(self.ws, "DEC-001", "DEC-003")
        self.assertEqual(invalidated, ["REQ-001"])

        reloaded = kernel.load_requirements(self.ws)
        self.assertEqual(reloaded[0]["status"], "STALE")
        self.assertEqual(reloaded[1]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
