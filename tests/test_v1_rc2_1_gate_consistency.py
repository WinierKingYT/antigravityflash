"""
Strict Engineering Kernel V1 Release Candidate 2.1
Semantic Gate Consistency Closure Test Suite

Covers:
  - RC21-01 .. RC21-12: Core gate consistency and semantic path authenticity
  - Section 16: Local desktop journal torture test (rejection of heuristic promotion, real semantic path)
  - Section 17: Test Oracle regression and fingerprint validation
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

try:
    from src.strict_engineering import (
        kernel,
        frame,
        concern,
        decision,
        decision_engine,
        decision_graph,
        stopping_engine,
        decision_coverage,
        decision_events,
        requirement_generator,
        discovery_protocol,
        acceptance_protocol,
        gate,
    )
except ImportError:
    from strict_engineering import (
        kernel,
        frame,
        concern,
        decision,
        decision_engine,
        decision_graph,
        stopping_engine,
        decision_coverage,
        decision_events,
        requirement_generator,
        discovery_protocol,
        acceptance_protocol,
        gate,
    )


class TestV1RC21GateConsistency(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_v1_rc21_test_"))
        self.ws = self.test_dir
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.engine = decision_engine.DecisionEngine(self.ws)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # RC21-01 .. RC21-12: CORE REGRESSION TESTS
    # -------------------------------------------------------------------------

    def test_rc21_01_ambiguous_project_blocked_from_spec(self):
        """RC21-01: Ambiguous project initialization produces canProceedToSpec=False, get_next_interaction is NOT PROCEED_TO_SPEC."""
        init = self.engine.initialize_discovery("Build an offline photo album organizer with duplicate detection.")
        
        self.assertEqual(init["canonicalConcerns"], [])
        self.assertGreater(len(init["heuristicSeeds"]), 0)
        self.assertFalse(init["status"]["canProceedToSpec"])

        interaction = self.engine.get_next_interaction()
        self.assertNotEqual(interaction["action"], "PROCEED_TO_SPEC")

    def test_rc21_02_explicit_discovery_action(self):
        """RC21-02: Next interaction action is RUN_SEMANTIC_DISCOVERY with machine-visible contract."""
        self.engine.initialize_discovery("Build an offline personal markdown editor with syntax highlighting.")

        interaction = self.engine.get_next_interaction()
        self.assertEqual(interaction["action"], "RUN_SEMANTIC_DISCOVERY")
        self.assertEqual(interaction["reason"], "HEURISTIC_DISCOVERY_ONLY")
        self.assertFalse(interaction["canProceedToSpec"])
        self.assertIn("discoveryRequest", interaction)
        self.assertTrue(Path(interaction["discoveryRequest"]).exists())

    def test_rc21_03_record_user_decision_rejects_heuristic_seed(self):
        """RC21-03: record_user_decision() called with heuristic seed ID raises HEURISTIC_SEED_NOT_CANONICAL and leaves concerns.json unchanged."""
        init = self.engine.initialize_discovery("Build an offline notes app.")
        seeds = init["heuristicSeeds"]
        self.assertGreater(len(seeds), 0)
        seed_id = seeds[0]["id"]

        with self.assertRaises(ValueError) as ctx:
            self.engine.record_user_decision(
                concern_id=seed_id,
                user_response="Option 1",
            )
        self.assertIn("HEURISTIC_SEED_NOT_CANONICAL", str(ctx.exception))

        # Canonical concerns must remain completely empty
        persisted = concern.load_concerns(self.ws)
        self.assertEqual(persisted, [])

    def test_rc21_04_heuristic_seed_cannot_be_appended_via_decision_api(self):
        """RC21-04: Heuristic seed cannot be appended into concerns.json through user-decision API."""
        init = self.engine.initialize_discovery("Build a task management system.")
        seed_id = init["heuristicSeeds"][0]["id"]

        # Attempt multiple times with different responses
        for resp in ["Option 1", "none of these", "I don't know"]:
            try:
                self.engine.record_user_decision(concern_id=seed_id, user_response=resp)
            except ValueError:
                pass

        # Zero canonical concerns and zero decisions
        self.assertEqual(concern.load_concerns(self.ws), [])
        self.assertEqual(decision.load_decisions(self.ws), [])

    def test_rc21_05_response_distinguishes_seeds_from_canonical_concerns(self):
        """RC21-05: initialize_discovery response clearly distinguishes heuristicSeeds from canonicalConcerns."""
        init = self.engine.initialize_discovery("Build an enterprise customer ledger.")
        
        self.assertIn("canonicalConcerns", init)
        self.assertIn("heuristicSeeds", init)
        self.assertEqual(init["canonicalConcerns"], [])
        self.assertGreater(len(init["heuristicSeeds"]), 0)

        for s in init["heuristicSeeds"]:
            self.assertTrue(s["id"].startswith("SEED-"), f"Expected SEED- prefix, got {s['id']}")
            self.assertEqual(s.get("artifactType"), "HEURISTIC_SEED")
            self.assertEqual(s.get("discoveryOrigin"), "HEURISTIC_SEED")

    def test_rc21_06_concerns_field_canonical_only(self):
        """RC21-06: Response field 'concerns', if retained, contains canonical concerns only ([] initially)."""
        init = self.engine.initialize_discovery("Build a local audio playback daemon.")
        self.assertIn("concerns", init)
        self.assertEqual(init["concerns"], [])
        self.assertEqual(len(init["concerns"]), 0)

    def test_rc21_07_validated_semantic_ingestion_creates_canonical_concern(self):
        """RC21-07: Validated Spec Architect + Scope Auditor ingestion creates canonical concern (CONC-xxx)."""
        self.engine.initialize_discovery("Build a high-performance network packet sniffer.")
        
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-BUFFER",
                    "title": "Packet Ring Buffer Overflow & Drop Policy",
                    "question": "How should incoming packets be handled when the buffer is saturated?",
                    "whyUnresolved": "Drop strategy not specified in raw intent",
                    "whyMaterial": "Directly governs throughput and packet loss behavior",
                    "category": "TECHNICAL_ARCHITECTURE",
                    "decisionLayer": "TECHNICAL",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.7,
                    "downstreamImpact": 0.8,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Tail-Drop", "behavioralMeaning": "Drop incoming packets when ring buffer is full", "tradeoffs": "Prevents overwriting existing frames"},
                        {"id": "OPT-2", "title": "Head-Drop", "behavioralMeaning": "Overwrite oldest unread packet", "tradeoffs": "Prioritizes freshest telemetry"},
                    ],
                }
            ],
        }
        review = {
            "schemaVersion": "7.2",
            "scopeAuditorVerdict": "APPROVED",
            "reviewedConcerns": [
                {"proposalId": "PROP-BUFFER", "verdict": "APPROVED", "rationale": "Grounded in packet buffer intent"}
            ],
        }

        success, msg, res = self.engine.ingest_agent_proposal(proposal, review_data=review, allow_simulated=True)
        self.assertTrue(success, f"Ingestion failed: {msg}")
        
        canonical_concerns = concern.load_concerns(self.ws)
        self.assertEqual(len(canonical_concerns), 1)
        c = canonical_concerns[0]
        self.assertTrue(c["id"].startswith("CONC-"), f"Expected CONC- prefix, got {c['id']}")
        self.assertEqual(c.get("artifactType"), "CANONICAL_CONCERN")
        self.assertEqual(c.get("discoveryOrigin"), "AGENT_PROPOSAL")

    def test_rc21_08_user_answers_canonical_concern_normally(self):
        """RC21-08: User can answer canonical concern normally and resolve it."""
        self.engine.initialize_discovery("Build an offline photo manager.")
        c = self.engine.create_human_concern(
            title="Photo Thumbnail Cache Persistence",
            question="Where should thumbnail cache files be stored?",
            candidate_options=[
                {"id": "OPT-1", "title": "SQLite Blob Database", "description": "Single file cache"},
                {"id": "OPT-2", "title": "Disk Directory Cache", "description": "Flat files in cache dir"},
            ],
        )
        cid = c["id"]
        self.assertTrue(cid.startswith("CONC-"))

        # Next interaction should be ASK on this canonical concern
        interaction = self.engine.get_next_interaction()
        self.assertIn(interaction["action"], ["ASK", "SUGGEST", "CHALLENGE"])
        self.assertEqual(interaction["concernId"], cid)

        res = self.engine.record_user_decision(cid, "Option 1")
        self.assertIn("decision", res)
        self.assertEqual(res["decision"]["concernId"], cid)

        # Concern is resolved
        concerns = concern.load_concerns(self.ws)
        self.assertEqual(concerns[0]["status"], "RESOLVED")

    def test_rc21_09_zero_decision_project_proceeds_with_stopping_approval(self):
        """RC21-09: Fully explicit zero-decision project with stopping approval returns PROCEED_TO_SPEC."""
        f_data = frame.create_initial_frame(
            project_goal="Run deterministic local MD5 checksum comparison on two files.",
            explicit_requirements=[
                "Read file A and compute MD5 digest",
                "Read file B and compute MD5 digest",
                "Output MATCH if equal, MISMATCH otherwise",
            ],
            explicit_constraints=["Standard library only", "Exit 0 on match, 1 on mismatch"],
            explicit_non_goals=["Network access", "Other hash algorithms"],
            unknowns=[],
        )
        frame.save_frame(self.ws, f_data)
        concern.save_concerns(self.ws, [])
        concern.save_heuristic_seeds(self.ws, [])

        # Mark discovery status complete for zero-decision project
        status_data = {
            "canProceedToSpec": True,
            "reason": "Fully explicit specification; zero architectural ambiguity",
            "readinessState": "READY_FOR_SPECIFICATION",
            "unresolvedConcernsCount": 0,
            "resolvedConcernsCount": 0,
            "totalConcernsCount": 0,
        }
        stopping_engine.save_decision_status(self.ws, status_data)

        interaction = self.engine.get_next_interaction()
        self.assertEqual(interaction["action"], "PROCEED_TO_SPEC")
        self.assertTrue(interaction["status"]["canProceedToSpec"])

    def test_rc21_10_stopping_engine_false_dominates_empty_concerns(self):
        """RC21-10: Stopping engine canProceedToSpec=False dominates empty-concern shortcut."""
        f_data = frame.create_initial_frame("Build an enterprise database engine.")
        frame.save_frame(self.ws, f_data)
        concern.save_concerns(self.ws, [])  # Empty canonical concerns

        # Stopping status says FALSE (blocked)
        status_data = {
            "canProceedToSpec": False,
            "reason": "Semantic discovery required: Heuristic discovery only",
            "readinessState": "SEMANTIC_DISCOVERY_REQUIRED",
        }
        stopping_engine.save_decision_status(self.ws, status_data)

        interaction = self.engine.get_next_interaction()
        self.assertNotEqual(interaction["action"], "PROCEED_TO_SPEC")
        self.assertFalse(interaction.get("canProceedToSpec", True))

    def test_rc21_11_stopping_engine_true_allows_proceed(self):
        """RC21-11: Stopping engine canProceedToSpec=True allows PROCEED_TO_SPEC."""
        f_data = frame.create_initial_frame("Build a local task runner.")
        frame.save_frame(self.ws, f_data)
        
        c = concern.create_concern(
            id="CONC-001",
            title="Execution engine",
            description="Process execution",
            category="CORE_BEHAVIOR",
            status="RESOLVED",
            source={"type": "FRAME_GOAL", "reference": "runner"},
        )
        concern.save_concerns(self.ws, [c])
        decision_graph.sync_decision_graph(self.ws)

        status_data = {
            "canProceedToSpec": True,
            "reason": "All discovered concerns have been resolved",
            "readinessState": "READY_FOR_SPECIFICATION",
            "unresolvedConcernsCount": 0,
            "resolvedConcernsCount": 1,
            "totalConcernsCount": 1,
        }
        stopping_engine.save_decision_status(self.ws, status_data)

        interaction = self.engine.get_next_interaction()
        self.assertEqual(interaction["action"], "PROCEED_TO_SPEC")

    def test_rc21_12_direct_requirement_compilation_zero_decision_project(self):
        """RC21-12: Direct requirement compilation for zero-decision explicit project succeeds."""
        f_data = frame.create_initial_frame(
            project_goal="Simple file byte counter.",
            explicit_requirements=["Read bytes from stdin", "Print count to stdout"],
            unknowns=[],
        )
        frame.save_frame(self.ws, f_data)
        concern.save_concerns(self.ws, [])
        stopping_engine.save_decision_status(self.ws, {
            "canProceedToSpec": True,
            "reason": "Zero-decision explicit project approved",
        })

        success, msg, _ = requirement_generator.compile_all_requirements(self.ws)
        self.assertTrue(success, f"Compilation failed: {msg}")
        saved_reqs = kernel.load_requirements(self.ws)
        self.assertGreater(len(saved_reqs), 0)
        for r in saved_reqs:
            self.assertEqual(r["status"], "DISCOVERED")
            self.assertEqual(r.get("acceptanceStatus"), "PENDING")

    # -------------------------------------------------------------------------
    # SECTION 16: TORTURE TEST
    # -------------------------------------------------------------------------

    def test_rc21_torture_desktop_journal_flow(self):
        """
        Section 16 Torture Test:
          RAW: "Build a local desktop journal where entries remain after closing and reopening the app."
          1. initialize_discovery -> heuristic persistence seed only, canonical concerns empty
          2. get_next_interaction -> RUN_SEMANTIC_DISCOVERY (NOT PROCEED_TO_SPEC)
          3. Malicious attempt: record_user_decision(SEED-ID, "Option 1") -> REJECTED, concerns.json empty
          4. Real semantic proposal + scope review -> canonical concern CONC-001 created
          5. User answers canonical concern -> marked RESOLVED
          6. Stopping evaluation -> canProceedToSpec=True
          7. Specification -> compile_requirements_from_decisions succeeds
        """
        # Step 1: Initialize
        raw_intent = "Build a local desktop journal where entries remain after closing and reopening the app."
        init = self.engine.initialize_discovery(raw_intent)
        
        self.assertEqual(init["canonicalConcerns"], [])
        self.assertEqual(init["concerns"], [])
        self.assertGreater(len(init["heuristicSeeds"]), 0)
        seed = init["heuristicSeeds"][0]
        self.assertTrue(seed["id"].startswith("SEED-"))
        self.assertEqual(seed.get("artifactType"), "HEURISTIC_SEED")

        # Step 2: Next interaction does NOT proceed
        interaction = self.engine.get_next_interaction()
        self.assertEqual(interaction["action"], "RUN_SEMANTIC_DISCOVERY")
        self.assertFalse(interaction["canProceedToSpec"])

        # Step 3: Malicious/incorrect flow: direct seed decision attempt
        with self.assertRaises(ValueError) as ctx:
            self.engine.record_user_decision(
                concern_id=seed["id"],
                user_response="Option 1: SQLite local database",
            )
        self.assertIn("HEURISTIC_SEED_NOT_CANONICAL", str(ctx.exception))
        
        # Verify concerns.json remains completely empty
        self.assertEqual(concern.load_concerns(self.ws), [])

        # Step 4: Real semantic proposal + scope review
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-JOURNAL-PERSIST",
                    "title": "Desktop Journal Entry Durability & Storage Architecture",
                    "question": "How should journal entries and edits be persisted to disk to guarantee survival across restarts?",
                    "whyUnresolved": "Storage format not chosen in raw user intent",
                    "whyMaterial": "Governs data loss risk, local schema, and offline reliability",
                    "category": "PERSISTENCE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.8,
                    "downstreamImpact": 0.8,
                    "isBlocking": True,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {
                            "id": "OPT-1",
                            "title": "Continuous Auto-Save Journal",
                            "behavioralMeaning": "Automatically streams journal entry edits to local disk on every modification.",
                            "tradeoffs": "Zero data loss; higher local disk write frequency.",
                            "consequences": ["Continuous disk writes on every keystroke", "Zero data loss on crash"],
                        },
                        {
                            "id": "OPT-2",
                            "title": "Explicit Save with Dirty Buffer Indicator",
                            "behavioralMeaning": "Keeps edits in memory until explicitly saved or session cleanly closed.",
                            "tradeoffs": "User control over saved revisions; unsaved edits lost on power cut.",
                            "consequences": ["Zero background disk I/O", "Unsaved modifications lost on abrupt crash"],
                        },
                    ],
                }
            ],
        }
        review = {
            "schemaVersion": "7.2",
            "scopeAuditorVerdict": "APPROVED",
            "reviewedConcerns": [
                {
                    "proposalId": "PROP-JOURNAL-PERSIST",
                    "verdict": "APPROVED",
                    "rationale": "Accurately targets journal persistence across sessions without technology overspecification.",
                }
            ],
        }

        success, msg, res = self.engine.ingest_agent_proposal(proposal, review_data=review, allow_simulated=True)
        self.assertTrue(success, f"Semantic proposal ingestion failed: {msg}")

        # Canonical concern now exists
        canonical_concerns = concern.load_concerns(self.ws)
        self.assertEqual(len(canonical_concerns), 1)
        canon_c = canonical_concerns[0]
        cid = canon_c["id"]
        self.assertTrue(cid.startswith("CONC-"))
        self.assertEqual(canon_c.get("artifactType"), "CANONICAL_CONCERN")

        # Step 5: User answers canonical concern
        interaction = self.engine.get_next_interaction()
        self.assertIn(interaction["action"], ["ASK", "SUGGEST", "CHALLENGE"])
        self.assertEqual(interaction["concernId"], cid)

        dec_res = self.engine.record_user_decision(
            concern_id=cid,
            user_response="Option 1: Continuous Auto-Save Journal",
        )
        self.assertIn("decision", dec_res)
        self.assertEqual(dec_res["decision"]["authority"], "USER")

        # Step 6: Stopping evaluation
        status = stopping_engine.sync_decision_status(self.ws)
        self.assertTrue(status["canProceedToSpec"], f"Stopping evaluation failed: {status}")
        self.assertEqual(status["readinessState"], "READY_FOR_SPECIFICATION")

        interaction = self.engine.get_next_interaction()
        self.assertEqual(interaction["action"], "PROCEED_TO_SPEC")

        # Step 7: Specification transition
        comp_success, comp_msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
        self.assertTrue(comp_success, f"Requirement compilation failed: {comp_msg}")
        self.assertGreater(len(reqs), 0)
        for r in reqs:
            self.assertEqual(r["status"], "DISCOVERED")
            self.assertEqual(r.get("acceptanceStatus"), "PENDING")

    # -------------------------------------------------------------------------
    # SECTION 17: TEST ORACLE REGRESSION
    # -------------------------------------------------------------------------

    def test_rc21_test_oracle_regression(self):
        """
        Section 17: Test Oracle Regression:
          - Requirements begin acceptance PENDING
          - Test Oracle locks acceptance via acceptance_protocol
          - Builder cannot edit locked acceptance (pre-tool use gate blocks writes)
          - Contract fingerprint updates
          - PASS/VERIFIED becomes STALE on semantic contract change
        """
        # Create a project with a compiled requirement
        f_data = frame.create_initial_frame("Build a local task runner.")
        frame.save_frame(self.ws, f_data)
        
        req = {
            "id": "REQ-001",
            "title": "Execute Task Process",
            "description": "Spawn child process and monitor exit code",
            "status": "VERIFIED",
            "required": True,
            "riskLevel": "MEDIUM",
            "intentId": "INTENT-001",
            "sources": ["INTENT-001"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "acceptanceStatus": "PENDING",
            "acceptanceCriteria": [],
            "category": "FUNCTIONAL",
            "verificationContract": "Verify process exits cleanly",
            "createdAt": "2026-09-07T12:00:00Z",
            "updatedAt": "2026-09-07T12:00:00Z",
        }
        req["contractFingerprint"] = requirement_generator.compute_requirement_contract_fingerprint(req)
        kernel.save_requirements(self.ws, [req])

        # Verify begins PENDING
        loaded_reqs = kernel.load_requirements(self.ws)
        self.assertEqual(loaded_reqs[0]["acceptanceStatus"], "PENDING")
        initial_fp = loaded_reqs[0]["contractFingerprint"]

        # Test Oracle locks acceptance via acceptance_protocol
        prop = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given a runnable task configuration, When executed, Then child process completes with exit code 0."
            ],
        }
        success, msg, updated = acceptance_protocol.ingest_acceptance_proposal(self.ws, prop, allow_simulated=True)
        self.assertTrue(success, f"Failed: {msg}")
        self.assertEqual(updated.get("acceptanceStatus"), "LOCKED")
        self.assertTrue(updated.get("acceptanceLocked"))
        self.assertEqual(updated.get("acceptanceAuthor"), "test-oracle")

        # Tampering attempt by builder role is rejected (gate blocks direct artifact tampering)
        safe, reason = gate.is_write_safe(
            self.ws / ".agent-harness" / "acceptance" / "request-REQ-001.json",
            workspace_root=self.ws,
        )
        self.assertFalse(safe)
        self.assertIn("protected harness artifact", reason)

        # Re-locking with new criteria updates fingerprint and invalidates prior VERIFIED to STALE
        new_prop = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given a runnable task configuration, When executed, Then child process completes with exit code 0 within 30 seconds."
            ],
        }
        success2, msg2, updated2 = acceptance_protocol.ingest_acceptance_proposal(self.ws, new_prop, allow_simulated=True)
        self.assertTrue(success2, f"Failed: {msg2}")
        self.assertEqual(updated2.get("status"), "STALE")
        self.assertIn("Test Oracle", updated2.get("stalenessReason", ""))
        self.assertNotEqual(updated2.get("contractFingerprint"), initial_fp)


if __name__ == "__main__":
    unittest.main()
