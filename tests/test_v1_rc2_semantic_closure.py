"""
Strict Engineering Kernel V1 Release Candidate 2
SEMANTIC PATH AUTHENTICITY & ACCEPTANCE CONTRACT CLOSURE TEST SUITE

Tests:
  - RC2-SD-01 .. RC2-SD-11: Discovery Authenticity, Heuristic Separation & Runtime Provenance
  - RC2-BF-01 .. RC2-BF-05: Behavior-First Invariants & Technology Prescription Rejection
  - RC2-ACC-01 .. RC2-ACC-08: Semantic Acceptance Protocol & Test Oracle Ownership
  - RC2-FP-01 .. RC2-FP-07: Requirement Contract Fingerprint V2, Staleness & Fail-Closed Sync
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

from src.strict_engineering import (
    kernel,
    frame,
    concern,
    decision,
    decision_engine,
    decision_graph,
    stopping_engine,
    consistency_reviewer,
    decision_coverage,
    decision_events,
    requirement_generator,
    gate,
    discovery_protocol,
    context_registry,
    acceptance_protocol,
)


class TestV1RC2SemanticClosure(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_v1_rc2_closure_"))
        self.ws = self.test_dir
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.engine = decision_engine.DecisionEngine(self.ws)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # PART 1: DISCOVERY AUTHENTICITY & RUNTIME PROVENANCE (RC2-SD)
    # -------------------------------------------------------------------------

    def test_rc2_sd_01_heuristic_seeds_separated_from_canonical_concerns(self):
        """RC2-SD-01: Heuristic seeds are in seeds.json; canonical concerns.json remains empty."""
        init = self.engine.initialize_discovery("Build an offline personal desktop markdown editor with live preview.")
        seeds_path = self.ws / ".agent-harness" / "discovery" / "seeds.json"
        concerns_path = self.ws / ".agent-harness" / "concerns.json"

        self.assertTrue(seeds_path.exists())
        with open(seeds_path, "r", encoding="utf-8") as f:
            seeds = json.load(f)
        self.assertTrue(len(seeds) > 0)

        # Canonical concerns must be strictly empty after initialization
        with open(concerns_path, "r", encoding="utf-8") as f:
            concerns = json.load(f)
        self.assertEqual(concerns, [])

    def test_rc2_sd_02_heuristic_seeds_have_empty_candidate_options(self):
        """RC2-SD-02: Heuristic seeds prescribe zero candidate options (candidateOptions: [])."""
        self.engine.initialize_discovery("Build a high-performance network packet filter.")
        seeds = concern.load_heuristic_seeds(self.ws)
        self.assertTrue(len(seeds) > 0)
        for s in seeds:
            self.assertEqual(s.get("candidateOptions"), [], f"Seed {s.get('id')} has prescribed candidate options!")
            self.assertEqual(s.get("discoveryOrigin"), "HEURISTIC_SEED")

    def test_rc2_sd_03_default_discovery_status_is_heuristic_only(self):
        """RC2-SD-03: load_discovery_status defaults to HEURISTIC_DISCOVERY_ONLY when no agent proposals ingested."""
        self.engine.initialize_discovery("Build a personal notes organizer.")
        d_status = discovery_protocol.load_discovery_status(self.ws)
        self.assertEqual(d_status.get("status"), "HEURISTIC_DISCOVERY_ONLY")
        self.assertEqual(d_status.get("discoveryOrigin"), "HEURISTIC_SEED")

    def test_rc2_sd_04_stopping_engine_blocks_on_heuristic_only_with_seeds(self):
        """RC2-SD-04: Stopping engine blocks transition to specification when discovery is HEURISTIC_DISCOVERY_ONLY."""
        self.engine.initialize_discovery("Build a secure multi-tenant cloud storage backend.")
        status_data = stopping_engine.sync_decision_status(self.ws)
        self.assertFalse(status_data["canProceedToSpec"])
        self.assertIn("HEURISTIC_DISCOVERY_ONLY", status_data["reason"])

    def test_rc2_sd_05_discovery_request_schema_7_2(self):
        """RC2-SD-05: create_discovery_request exports complete project frame context to discovery/request.json."""
        self.engine.initialize_discovery(
            raw_intent="Build a local desktop markdown editor.",
            project_name="EditorPro",
        )
        req_file = discovery_protocol.get_discovery_dir(self.ws) / "request.json"
        if not req_file.exists():
            files = list(discovery_protocol.get_discovery_dir(self.ws).glob("request-*.json"))
            self.assertTrue(len(files) > 0)
            req_file = files[0]

        with open(req_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("schemaVersion"), "7.2")
        self.assertIn("canonicalIntents", data)
        self.assertIn("currentFrame", data)

    def test_rc2_sd_06_caller_claimed_live_discovery_rejected_without_proof(self):
        """RC2-SD-06: Caller cannot claim LIVE_AGENT_DISCOVERY without verified context-registry proof."""
        self.engine.initialize_discovery("Build a database engine.")
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Database Buffer Pool Page Replacement Policy",
                    "question": "Which page replacement policy should the database buffer pool use?",
                    "whyUnresolved": "Page eviction behavior not specified",
                    "whyMaterial": "Governs disk I/O and latency under memory pressure",
                    "category": "TECHNICAL_ARCHITECTURE",
                    "decisionLayer": "TECHNICAL",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.5,
                    "downstreamImpact": 0.8,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "2Q Eviction", "behavioralMeaning": "Maintains two queues to prevent sequential scans from blowing out cache."},
                        {"id": "OPT-2", "title": "CLOCK Eviction", "behavioralMeaning": "Circular buffer bit check for low CPU overhead."},
                    ],
                }
            ],
        }
        # In live mode (allow_simulated=False), missing context proof must reject
        success, msg, _ = discovery_protocol.ingest_semantic_concern_proposal(
            self.ws, proposal, allow_simulated=False
        )
        self.assertFalse(success)
        self.assertTrue("review is required" in msg.lower() or "context proof failed" in msg.lower())

    def test_rc2_sd_07_context_isolation_enforces_pairwise_inequality(self):
        """RC2-SD-07: Pairwise conversation ID equality between Spec Architect and Scope Auditor is rejected."""
        self.engine.initialize_discovery("Build an offline password vault.")
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Password Vault Master Key Derivation Iteration Budget",
                    "question": "How should the offline password vault master key derivation handle computation cost versus unlock latency?",
                    "whyUnresolved": "Key derivation work factor not specified",
                    "whyMaterial": "Directly trades unlock speed for brute-force resistance",
                    "category": "SECURITY",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.5,
                    "downstreamImpact": 0.9,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "High Work Factor (500ms)", "behavioralMeaning": "Half-second unlock delay for maximum offline protection."},
                        {"id": "OPT-2", "title": "Low Work Factor (50ms)", "behavioralMeaning": "Near-instant unlock with lower brute-force resistance."},
                    ],
                }
            ],
        }
        prop_hash = discovery_protocol.compute_proposal_hash(proposal)
        review = {
            "schemaVersion": "7.2",
            "proposalHash": prop_hash,
            "evaluations": [
                {"proposalId": "PROP-001", "verdict": "ACCEPT", "rationale": "Well grounded."}
            ],
        }

        # Register context with identical conversation IDs (collusion)
        colliding_cid = "conv-reused-123"
        context_registry.register_simulated_context(
            workspace_dir=self.ws,
            hook_payload={
                "conversationId": colliding_cid,
                "transcriptPath": f"/logs/{colliding_cid}/transcript.jsonl",
                "artifactDirectoryPath": f"/artifacts/{colliding_cid}",
            },
            context_purpose="SPEC_ARCHITECT",
        )
        context_registry.register_simulated_context(
            workspace_dir=self.ws,
            hook_payload={
                "conversationId": colliding_cid,
                "transcriptPath": f"/logs/{colliding_cid}/transcript.jsonl",
                "artifactDirectoryPath": f"/artifacts/{colliding_cid}",
            },
            context_purpose="SCOPE_AUDITOR",
        )

        success, msg, _ = discovery_protocol.ingest_semantic_concern_proposal(
            self.ws, proposal, review_data=review, allow_simulated=True
        )
        self.assertFalse(success)
        self.assertIn("COLLIDES", msg.upper())

    def test_rc2_sd_08_scope_auditor_review_binds_proposal_hash(self):
        """RC2-SD-08: Ingestion fails with REVIEW_PROPOSAL_HASH_MISMATCH if proposal was mutated post-review."""
        self.engine.initialize_discovery("Build an offline personal markdown editor.")
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-SAVE",
                    "title": "Document State Retention & Auto-Save Policy",
                    "question": "How should document buffer state be saved to local disk?",
                    "whyUnresolved": "Save behavior not specified",
                    "whyMaterial": "Governs data loss risk on unexpected exit",
                    "category": "PERSISTENCE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.4,
                    "downstreamImpact": 0.7,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Continuous Auto-Save Journal", "behavioralMeaning": "Append edits continuously."},
                        {"id": "OPT-2", "title": "Explicit User Save", "behavioralMeaning": "Save only on manual trigger."},
                    ],
                }
            ],
        }
        # Review was computed on a different hash
        review = {
            "schemaVersion": "7.2",
            "proposalHash": "0000000000000000000000000000000000000000000000000000000000000000",
            "evaluations": [
                {"proposalId": "PROP-SAVE", "verdict": "ACCEPT", "rationale": "Acceptable."}
            ],
        }

        success, msg, _ = discovery_protocol.ingest_semantic_concern_proposal(
            self.ws, proposal, review_data=review, allow_simulated=True
        )
        self.assertFalse(success)
        self.assertIn("REVIEW_PROPOSAL_HASH_MISMATCH", msg)

    def test_rc2_sd_09_scope_auditor_review_required_for_high_and_critical(self):
        """RC2-SD-09: In live mode without review, HIGH/CRITICAL proposals are strictly rejected."""
        self.engine.initialize_discovery("Build a financial transaction ledger.")
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-FIN",
                    "title": "Double-Entry Transaction Invariance",
                    "question": "How should balanced double-entry accounting constraints be enforced?",
                    "whyUnresolved": "Balance enforcement timing not specified",
                    "whyMaterial": "Critical invariant for transaction integrity",
                    "category": "FINANCIAL",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "CRITICAL",
                    "uncertainty": 0.5,
                    "downstreamImpact": 1.0,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Strict Atomic Zero-Sum", "behavioralMeaning": "Reject any unbalanced batch immediately."},
                        {"id": "OPT-2", "title": "Reconciliation Journal", "behavioralMeaning": "Log discrepancies to suspense account."},
                    ],
                }
            ],
        }
        success, msg, _ = discovery_protocol.ingest_semantic_concern_proposal(
            self.ws, proposal, review_data=None, allow_simulated=False
        )
        self.assertFalse(success)
        self.assertIn("Scope Auditor review is required", msg)

    def test_rc2_sd_10_ingestion_persists_runtime_evidence(self):
        """RC2-SD-10: Ingesting an accepted proposal writes complete evidence to discovery/evidence.json."""
        self.engine.initialize_discovery("Build an offline document editor.")
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Document State Retention & Auto-Save Policy",
                    "question": "How should document buffer state be saved to local disk?",
                    "whyUnresolved": "Save behavior not specified",
                    "whyMaterial": "Governs data loss risk on unexpected exit",
                    "category": "PERSISTENCE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.4,
                    "downstreamImpact": 0.7,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Continuous Auto-Save Journal", "behavioralMeaning": "Append edits continuously."},
                        {"id": "OPT-2", "title": "Explicit User Save", "behavioralMeaning": "Save only on manual trigger."},
                    ],
                }
            ],
        }
        prop_hash = discovery_protocol.compute_proposal_hash(proposal)
        review = {
            "schemaVersion": "7.2",
            "proposalHash": prop_hash,
            "evaluations": [
                {"proposalId": "PROP-001", "verdict": "ACCEPT", "rationale": "Well grounded."}
            ],
        }

        success, msg, res = discovery_protocol.ingest_semantic_concern_proposal(
            self.ws, proposal, review_data=review, allow_simulated=True
        )
        self.assertTrue(success, f"Failed: {msg}")

        evidence_file = self.ws / ".agent-harness" / "discovery" / "evidence.json"
        self.assertTrue(evidence_file.exists())
        with open(evidence_file, "r", encoding="utf-8") as f:
            ev = json.load(f)
        self.assertEqual(ev.get("proposalHash"), prop_hash)
        self.assertIn("runtimeOriginStatuses", ev)

    def test_rc2_sd_11_pre_tool_use_gate_protects_discovery_and_acceptance(self):
        """RC2-SD-11: Gate denies direct write attempts to .agent-harness/discovery/* and acceptance/*."""
        safe_disc, _ = gate.is_write_safe(".agent-harness/discovery/status.json", workspace_root=self.ws)
        self.assertFalse(safe_disc)

        safe_seed, _ = gate.is_write_safe(".agent-harness/discovery/seeds.json", workspace_root=self.ws)
        self.assertFalse(safe_seed)

        safe_acc, _ = gate.is_write_safe(".agent-harness/acceptance/proposal-REQ-001.json", workspace_root=self.ws)
        self.assertFalse(safe_acc)

    # -------------------------------------------------------------------------
    # PART 2: BEHAVIOR-FIRST INVARIANTS & ANTI-PRESCRIPTION (RC2-BF)
    # -------------------------------------------------------------------------

    def test_rc2_bf_01_technology_prescriptions_rejected(self):
        """RC2-BF-01: Proposals prescribing specific database engines or auth libraries in options are rejected."""
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-TECH",
                    "title": "State Persistence Technology",
                    "question": "Which database engine should be used?",
                    "whyUnresolved": "No database specified",
                    "whyMaterial": "Architectural choice",
                    "category": "PERSISTENCE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.5,
                    "downstreamImpact": 0.7,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "SQLite Embedded Database", "behavioralMeaning": "Use SQLite file."},
                        {"id": "OPT-2", "title": "PostgreSQL Client Server", "behavioralMeaning": "Connect to Postgres."},
                    ],
                }
            ],
        }
        is_valid, errors, _ = discovery_protocol.validate_semantic_concern_proposal(proposal)
        self.assertFalse(is_valid)
        self.assertTrue(any("forbidden technology prescription" in e.lower() for e in errors))

    def test_rc2_bf_02_behavior_first_tradeoffs_accepted(self):
        """RC2-BF-02: Behavior-first trade-offs (e.g. journal vs snapshot) pass validation without technology names."""
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-BEH",
                    "title": "Document State Retention & Auto-Save Policy",
                    "question": "How should the editor retain unsaved document state?",
                    "whyUnresolved": "Retention policy not defined",
                    "whyMaterial": "Determines crash recovery capabilities and disk write frequency",
                    "category": "PERSISTENCE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.4,
                    "downstreamImpact": 0.7,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Continuous Append Journal", "behavioralMeaning": "Append every keystroke delta to local disk journal."},
                        {"id": "OPT-2", "title": "Periodic Snapshot on Idle", "behavioralMeaning": "Write full document snapshot after 2 seconds of keyboard inactivity."},
                    ],
                }
            ],
        }
        is_valid, errors, _ = discovery_protocol.validate_semantic_concern_proposal(proposal)
        self.assertTrue(is_valid, f"Validation failed: {errors}")

    def test_rc2_bf_03_candidate_options_describe_behavioral_tradeoffs(self):
        """RC2-BF-03: Candidate options require behavioral meaning and consequences rather than mechanism details."""
        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-BURST",
                    "title": "Ring Buffer Packet Drop & Overflow Policy",
                    "question": "How should bounded ring buffer handle burst saturation at wire speed?",
                    "whyUnresolved": "Drop policy undefined",
                    "whyMaterial": "Determines packet loss characteristics under wire speed",
                    "category": "TECHNICAL_ARCHITECTURE",
                    "decisionLayer": "TECHNICAL",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.3,
                    "downstreamImpact": 0.8,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Head-Drop (Drop Oldest)", "behavioralMeaning": "Overwrite oldest uninspected packets in circular queue."},
                        {"id": "OPT-2", "title": "Tail-Drop (Drop Newest)", "behavioralMeaning": "Reject incoming packets immediately when queue is full."},
                    ],
                }
            ],
        }
        is_valid, errors, _ = discovery_protocol.validate_semantic_concern_proposal(proposal)
        self.assertTrue(is_valid, f"Validation failed: {errors}")

    def test_rc2_bf_04_single_user_tools_eliminate_false_positive_auth(self):
        """RC2-BF-04: Single-user offline desktop tools generate zero authorization/RBAC heuristic seeds."""
        f_data = frame.create_initial_frame("Build an offline personal markdown notes editor for a single user.")
        seeds = concern.propose_heuristic_seeds(f_data)
        auth_seeds = [s for s in seeds if s.get("category") == "AUTHORIZATION"]
        self.assertEqual(len(auth_seeds), 0)

    def test_rc2_bf_05_pure_data_pipeline_eliminates_false_positive_persistence(self):
        """RC2-BF-05: Pure stdin-to-stdout stream pipeline generates zero persistence heuristic seeds."""
        f_data = frame.create_initial_frame("Stream JSON log records from stdin, filter by status, and print summary to stdout.")
        seeds = concern.propose_heuristic_seeds(f_data)
        persist_seeds = [s for s in seeds if s.get("category") == "PERSISTENCE"]
        self.assertEqual(len(persist_seeds), 0)

    # -------------------------------------------------------------------------
    # PART 3: ACCEPTANCE PROTOCOL & TEST ORACLE OWNERSHIP (RC2-ACC)
    # -------------------------------------------------------------------------

    def test_rc2_acc_01_requirements_start_with_pending_acceptance(self):
        """RC2-ACC-01: Requirement generator produces atomic requirements with acceptanceStatus='PENDING' and acceptanceCriteria=[]."""
        f_data = frame.create_initial_frame("Build a local markdown editor.")
        f_data["intents"] = [
            {"id": "INTENT-001", "text": "Auto-save document buffer to local disk", "category": "EXPLICIT_REQUIREMENT", "provenance": "USER_DIRECT"},
        ]
        frame.save_frame(self.ws, f_data)
        success, msg, reqs = requirement_generator.compile_requirements_from_intents(self.ws)
        self.assertTrue(success, f"Compilation failed: {msg}")
        self.assertEqual(len(reqs), 1)
        r = reqs[0]
        self.assertEqual(r.get("acceptanceStatus"), "PENDING")
        self.assertFalse(r.get("acceptanceLocked", False))
        self.assertEqual(r.get("acceptanceCriteria"), [])

    def test_rc2_acc_02_create_acceptance_request_emits_valid_artifact(self):
        """RC2-ACC-02: create_acceptance_request emits request-<reqId>.json with schema 7.2."""
        req = {
            "id": "REQ-001",
            "title": "Requirement: Auto-save document buffer to local disk",
            "description": "The system shall implement auto-save of document buffer.",
            "category": "CORE_BEHAVIOR",
            "riskLevel": "MEDIUM",
            "sources": ["INTENT-001"],
            "sourceIntentIds": ["INTENT-001"],
        }
        req_path = acceptance_protocol.create_acceptance_request(self.ws, req)
        self.assertTrue(req_path.exists())
        with open(req_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("schemaVersion"), "7.2")
        self.assertEqual(data.get("requirementId"), "REQ-001")
        self.assertIn("Auto-save", data.get("requirementTitle"))

    def test_rc2_acc_03_acceptance_proposal_rejects_generic_placeholders(self):
        """RC2-ACC-03: validate_acceptance_proposal rejects generic placeholders like 'expected behavior' or 'works correctly'."""
        proposal = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given a document buffer, When saved, Then works correctly as expected.",
            ],
        }
        is_valid, errors = acceptance_protocol.validate_acceptance_proposal(proposal)
        self.assertFalse(is_valid)
        self.assertTrue(any("generic placeholder" in e.lower() for e in errors))

    def test_rc2_acc_04_acceptance_proposal_enforces_gwt_structure_and_grounding(self):
        """RC2-ACC-04: validate_acceptance_proposal enforces Given-When-Then structure and requirement grounding."""
        # Non-GWT criterion
        proposal_bad = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": ["The system shall save document buffer every 5 seconds."],
        }
        is_valid, errors = acceptance_protocol.validate_acceptance_proposal(proposal_bad)
        self.assertFalse(is_valid)
        self.assertTrue(any("given-when-then" in e.lower() for e in errors))

        # Valid GWT criterion with domain grounding
        proposal_good = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given an active document buffer with unpersisted edits, When 500ms of user idle time elapses, Then the document buffer is atomically written to the local disk journal."
            ],
        }
        req_context = {
            "requirementId": "REQ-001",
            "requirementTitle": "Requirement: Auto-save document buffer to local disk",
            "requirementDescription": "The system shall implement auto-save of document buffer.",
        }
        is_valid, errors = acceptance_protocol.validate_acceptance_proposal(proposal_good, req_context)
        self.assertTrue(is_valid, f"Validation errors: {errors}")

    def test_rc2_acc_05_ingest_acceptance_proposal_rejects_builder_collision(self):
        """RC2-ACC-05: Ingestion rejects proposal if Test Oracle collides with Builder conversation ID."""
        req = {
            "id": "REQ-001",
            "title": "Requirement: Auto-save document buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "status": "DISCOVERED",
            "acceptanceStatus": "PENDING",
            "acceptanceCriteria": [],
        }
        kernel.save_requirements(self.ws, [req])

        colliding_cid = "conv-shared-builder-oracle"
        context_registry.register_simulated_context(
            workspace_dir=self.ws,
            hook_payload={
                "conversationId": colliding_cid,
                "transcriptPath": f"/logs/{colliding_cid}/transcript.jsonl",
                "artifactDirectoryPath": f"/artifacts/{colliding_cid}",
            },
            context_purpose="BUILDER",
        )
        context_registry.register_simulated_context(
            workspace_dir=self.ws,
            hook_payload={
                "conversationId": colliding_cid,
                "transcriptPath": f"/logs/{colliding_cid}/transcript.jsonl",
                "artifactDirectoryPath": f"/artifacts/{colliding_cid}",
            },
            context_purpose="TEST_ORACLE",
        )

        proposal = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given an active document buffer, When saved, Then the disk journal is updated with SHA-256 integrity hash."
            ],
        }
        success, msg, _ = acceptance_protocol.ingest_acceptance_proposal(self.ws, proposal, allow_simulated=True)
        self.assertFalse(success)
        self.assertIn("COLLIDES", msg.upper())

    def test_rc2_acc_06_ingest_acceptance_proposal_locks_contract(self):
        """RC2-ACC-06: Ingesting valid proposal locks acceptance contract in canonical requirements.json."""
        req = {
            "id": "REQ-001",
            "title": "Requirement: Auto-save document buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "status": "DISCOVERED",
            "acceptanceStatus": "PENDING",
            "acceptanceCriteria": [],
        }
        kernel.save_requirements(self.ws, [req])

        proposal = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given an active document buffer with unpersisted edits, When 500ms of user idle time elapses, Then the document buffer is atomically written to the local disk journal."
            ],
        }
        success, msg, updated = acceptance_protocol.ingest_acceptance_proposal(self.ws, proposal, allow_simulated=True)
        self.assertTrue(success, f"Failed: {msg}")
        self.assertEqual(updated.get("acceptanceStatus"), "LOCKED")
        self.assertTrue(updated.get("acceptanceLocked"))
        self.assertEqual(updated.get("acceptanceAuthor"), "test-oracle")
        self.assertTrue(len(updated.get("acceptanceCriteria")) == 1)

    def test_rc2_acc_07_ingest_acceptance_proposal_records_decision_event(self):
        """RC2-ACC-07: Locking an acceptance contract records an ACCEPTANCE_CONTRACT_LOCKED event."""
        req = {
            "id": "REQ-001",
            "title": "Requirement: Auto-save document buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "status": "DISCOVERED",
            "acceptanceStatus": "PENDING",
            "acceptanceCriteria": [],
        }
        kernel.save_requirements(self.ws, [req])
        proposal = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given an active document buffer with unpersisted edits, When 500ms of user idle time elapses, Then the document buffer is atomically written to the local disk journal."
            ],
        }
        success, msg, _ = acceptance_protocol.ingest_acceptance_proposal(self.ws, proposal, allow_simulated=True)
        self.assertTrue(success, f"Failed: {msg}")

        events = decision_events.load_decision_events(self.ws)
        lock_events = [e for e in events if e.get("eventType") == "ACCEPTANCE_CONTRACT_LOCKED"]
        self.assertEqual(len(lock_events), 1)
        self.assertEqual(lock_events[0]["payload"]["requirementId"], "REQ-001")

    def test_rc2_acc_08_acceptance_artifacts_protected_by_gate(self):
        """RC2-ACC-08: PreToolUse gate blocks direct write attempts to .agent-harness/acceptance/*."""
        safe, reason = gate.is_write_safe(
            self.ws / ".agent-harness" / "acceptance" / "request-REQ-001.json",
            workspace_root=self.ws,
        )
        self.assertFalse(safe)
        self.assertIn("protected harness artifact", reason)

    # -------------------------------------------------------------------------
    # PART 4: CONTRACT FINGERPRINT V2, STALENESS & FAIL-CLOSED SYNC (RC2-FP)
    # -------------------------------------------------------------------------

    def test_rc2_fp_01_deterministic_binding_of_authority_relevant_fields(self):
        """RC2-FP-01: Fingerprint V2 binds title, description, category, criteria, sources, risk, verificationContract."""
        req = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": ["DEC-001"],
            "sourceConcernIds": ["CONC-001"],
            "riskLevel": "MEDIUM",
            "verificationContract": "Verify X",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        fp1 = requirement_generator.compute_requirement_contract_fingerprint(req)
        fp2 = requirement_generator.compute_requirement_contract_fingerprint(req)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    def test_rc2_fp_02_timestamps_strictly_excluded_from_fingerprint(self):
        """RC2-FP-02: Modifying createdAt, updatedAt, lockedAt does not alter Fingerprint V2."""
        req_base = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": ["DEC-001"],
            "sourceConcernIds": ["CONC-001"],
            "riskLevel": "MEDIUM",
            "verificationContract": "Verify X",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        fp_original = requirement_generator.compute_requirement_contract_fingerprint(req_base)

        req_updated_times = dict(req_base)
        req_updated_times["createdAt"] = "2026-09-07T12:00:00Z"
        req_updated_times["updatedAt"] = "2026-09-07T12:00:01Z"
        req_updated_times["lockedAt"] = "2026-09-07T12:00:02Z"
        fp_new_times = requirement_generator.compute_requirement_contract_fingerprint(req_updated_times)

        self.assertEqual(fp_original, fp_new_times)

    def test_rc2_fp_03_acceptance_criteria_change_mutates_fingerprint(self):
        """RC2-FP-03: Adding, removing, or modifying acceptance criteria changes Fingerprint V2."""
        req = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "riskLevel": "MEDIUM",
            "verificationContract": "Verify X",
        }
        fp_orig = requirement_generator.compute_requirement_contract_fingerprint(req)

        req_mutated = dict(req)
        req_mutated["acceptanceCriteria"] = [
            "Given X When Y Then Z",
            "Given abnormal disk full condition When write attempted Then emit disk error.",
        ]
        fp_mutated = requirement_generator.compute_requirement_contract_fingerprint(req_mutated)

        self.assertNotEqual(fp_orig, fp_mutated)

    def test_rc2_fp_04_source_ids_change_mutates_fingerprint(self):
        """RC2-FP-04: Modifying sourceIntentIds, sourceDecisionIds, or sourceConcernIds changes Fingerprint V2."""
        req = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "riskLevel": "MEDIUM",
            "verificationContract": "Verify X",
        }
        fp_orig = requirement_generator.compute_requirement_contract_fingerprint(req)

        req_new_source = dict(req)
        req_new_source["sourceDecisionIds"] = ["DEC-002"]
        fp_new_source = requirement_generator.compute_requirement_contract_fingerprint(req_new_source)

        self.assertNotEqual(fp_orig, fp_new_source)

    def test_rc2_fp_05_risk_level_change_mutates_fingerprint(self):
        """RC2-FP-05: Modifying riskLevel from MEDIUM to CRITICAL changes Fingerprint V2."""
        req = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "riskLevel": "MEDIUM",
            "verificationContract": "Verify X",
        }
        fp_med = requirement_generator.compute_requirement_contract_fingerprint(req)

        req_crit = dict(req)
        req_crit["riskLevel"] = "CRITICAL"
        fp_crit = requirement_generator.compute_requirement_contract_fingerprint(req_crit)

        self.assertNotEqual(fp_med, fp_crit)

    def test_rc2_fp_06_verified_status_invalidates_to_stale_on_fingerprint_change(self):
        """RC2-FP-06: When a PASS/VERIFIED requirement's contract changes, status transitions to STALE."""
        req = {
            "id": "REQ-001",
            "title": "Auto-save buffer",
            "description": "Auto-save buffer to disk.",
            "category": "CORE_BEHAVIOR",
            "status": "VERIFIED",
            "required": True,
            "riskLevel": "MEDIUM",
            "decisionId": None,
            "concernId": None,
            "intentId": "INTENT-001",
            "sources": ["INTENT-001"],
            "sourceIntentIds": ["INTENT-001"],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "authority": "USER_DIRECT",
            "acceptanceCriteria": ["Given X When Y Then Z"],
            "verificationContract": "Verify X",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        req["contractFingerprint"] = requirement_generator.compute_requirement_contract_fingerprint(req)
        kernel.save_requirements(self.ws, [req])

        # Test Oracle updates acceptance criteria
        new_proposal = {
            "schemaVersion": "7.2",
            "requirementId": "REQ-001",
            "criteria": [
                "Given an active document buffer with unpersisted edits, When 500ms of user idle time elapses, Then the document buffer is atomically written to the local disk journal."
            ],
        }
        success, msg, updated = acceptance_protocol.ingest_acceptance_proposal(self.ws, new_proposal, allow_simulated=True)
        self.assertTrue(success, f"Failed: {msg}")
        self.assertEqual(updated.get("status"), "STALE")
        self.assertEqual(updated.get("previousStatus"), "VERIFIED")
        self.assertIn("Acceptance contract locked/updated", updated.get("stalenessReason", ""))

    def test_rc2_fp_07_sync_decision_intelligence_fails_closed_on_error(self):
        """RC2-FP-07: Compilation fails closed with visible error if downstream sync fails."""
        # Set up a decision and concern
        c = concern.create_concern(
            id="CONC-001",
            title="Persistence Mechanism",
            description="State persistence mechanism.",
            category="PERSISTENCE",
            source={"type": "FRAME_GOAL", "reference": "storage"},
            risk_level="MEDIUM",
            status="RESOLVED",
        )
        concern.save_concerns(self.ws, [c])
        d = decision.create_decision(
            id="DEC-001",
            concern_id="CONC-001",
            title="Local JSON Storage",
            chosen_option="Write state to local JSON file",
            authority="USER_DIRECT",
        )
        decision.save_decisions(self.ws, [d])
        stopping_engine.save_decision_status(self.ws, {"canProceedToSpec": True, "reason": "Resolved"})

        # Corrupt decision graph file to be read-only / unwriteable to cause sync failure
        graph_file = self.ws / ".agent-harness" / "decision-graph.json"
        # Temporarily monkey-patch sync_decision_graph to raise an error
        orig_sync = decision_graph.sync_decision_graph
        try:
            def broken_sync(ws):
                raise RuntimeError("Disk write I/O failure during graph synchronization")
            decision_graph.sync_decision_graph = broken_sync

            success, msg, reqs = requirement_generator.compile_requirements_from_decisions(self.ws)
            self.assertFalse(success)
            self.assertIn("Critical sync failed (decision_graph)", msg)
        finally:
            decision_graph.sync_decision_graph = orig_sync


if __name__ == "__main__":
    unittest.main()
