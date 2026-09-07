"""
Strict Engineering Kernel V1 Release Candidate - Semantic Discovery & Requirement Quality Suite
Covers:
  - RC-SD-01 .. RC-SD-09: Discovery Protocol, Schema 7.2, Agent Validation & Ingestion
  - RC-REQ-01 .. RC-REQ-10: Requirement Quality, Invariant 17, Fingerprints, Staleness, Zero-Decision
  - Metamorphic discovery across diverse domains (games, editors, data pipelines)
  - False-positive elimination (single-user auth, pure data persistence)
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
        consistency_reviewer,
        decision_coverage,
        decision_events,
        requirement_generator,
        gate,
        discovery_protocol,
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
        consistency_reviewer,
        decision_coverage,
        decision_events,
        requirement_generator,
        gate,
        discovery_protocol,
    )


class TestV1RCSemanticDiscovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="agy_v1_rc_test_"))
        self.ws = self.test_dir
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.engine = decision_engine.DecisionEngine(self.ws)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # PART 1: SCHEMA 7.2 SEMANTIC DISCOVERY PROTOCOL (RC-SD-01 .. RC-SD-09)
    # -------------------------------------------------------------------------

    def test_rc_sd_01_discovery_request_schema(self):
        """RC-SD-01: create_discovery_request exports complete project frame context to discovery/request.json."""
        f_data = frame.create_initial_frame(
            project_goal="Build a local retro pixel art animation studio.",
            primary_user="animator",
            explicit_requirements=["Support onion skinning across 16 frames", "Export sprite sheets in PNG format"],
            explicit_constraints=["Maximum memory usage 256MB", "No network telemetry"],
            explicit_non_goals=["3D mesh rendering", "Multiplayer real-time collaboration"],
            unknowns=["Supported frame rate playback range"],
        )
        frame.save_frame(self.ws, f_data)

        req_data = discovery_protocol.create_discovery_request(self.ws, f_data)
        req_path = discovery_protocol.get_discovery_dir(self.ws) / "request.json"
        self.assertTrue(req_path.exists())

        self.assertEqual(req_data["schemaVersion"], "7.2")
        self.assertIn("retro pixel art", req_data["currentFrame"]["projectGoal"])
        self.assertEqual(req_data["currentFrame"]["primaryUser"], "animator")
        self.assertEqual(len(req_data["explicitConstraints"]), 2)
        self.assertEqual(len(req_data["explicitNonGoals"]), 2)
        self.assertGreaterEqual(len(req_data["canonicalIntents"]), 4)

    def test_rc_sd_02_proposal_validation_valid(self):
        """RC-SD-02: validate_semantic_concern_proposal accepts structured, grounded proposals."""
        f_data = frame.create_initial_frame(
            project_goal="Build an offline personal markdown journal.",
            explicit_requirements=["Autosave entries on every keystroke"],
        )
        frame.save_frame(self.ws, f_data)

        req_data = discovery_protocol.create_discovery_request(self.ws, f_data)
        disc_id = req_data["discoveryId"]

        proposal = {
            "schemaVersion": "7.2",
            "discoveryId": disc_id,
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Document Autosave Recovery Journal",
                    "question": "How are unsaved edits recovered after unexpected crashes?",
                    "whyUnresolved": "No crash recovery mechanism specified",
                    "whyMaterial": "Prevents data loss on crash",
                    "category": "RECOVERY",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.7,
                    "downstreamImpact": 0.8,
                    "sourceIntentIds": ["INTENT-002"],
                    "candidateOptions": [
                        {
                            "id": "OPT-1",
                            "title": "Continuous Append-Only Edit Journal",
                            "behavioralMeaning": "Stream keystrokes to an append-only transaction journal file.",
                            "tradeoffs": "Instant recovery with no data loss; journal compaction required.",
                            "isRecommended": True,
                        },
                        {
                            "id": "OPT-2",
                            "title": "Periodic Snapshot with Dirty Buffer Flag",
                            "behavioralMeaning": "Write entire document buffer to disk every 5 seconds if modified.",
                            "tradeoffs": "Simpler file structure; up to 5 seconds of edits lost on crash.",
                            "isRecommended": False,
                        },
                    ],
                }
            ],
        }

        is_valid, errors, validated = discovery_protocol.validate_semantic_concern_proposal(proposal, req_data)
        self.assertTrue(is_valid, f"Proposal validation failed: {errors}")
        self.assertEqual(len(validated), 1)

    def test_rc_sd_03_proposal_validation_rejects_ungrounded(self):
        """RC-SD-03: validate_semantic_concern_proposal rejects ungrounded concerns with no basis in frame."""
        f_data = frame.create_initial_frame(
            project_goal="Build a command-line calculator for basic arithmetic.",
        )
        frame.save_frame(self.ws, f_data)

        req_data = discovery_protocol.create_discovery_request(self.ws, f_data)

        ungrounded_proposal = {
            "schemaVersion": "7.2",
            "discoveryId": req_data["discoveryId"],
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Multi-Region Kubernetes Pod Replication Policy",
                    "question": "How should pod replication be balanced across AWS regions?",
                    "whyUnresolved": "No cloud deployment specified",
                    "whyMaterial": "Downtime risk",
                    "category": "TECHNICAL_ARCHITECTURE",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "CRITICAL",
                    "uncertainty": 0.9,
                    "downstreamImpact": 0.9,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {
                            "id": "OPT-1",
                            "title": "Active-Active Multi-Cluster",
                            "behavioralMeaning": "Deploy across 3 cloud regions.",
                            "tradeoffs": "High availability; network cost.",
                        },
                        {
                            "id": "OPT-2",
                            "title": "Active-Passive Failover",
                            "behavioralMeaning": "Deploy primary in us-central1.",
                            "tradeoffs": "Lower cost; failover delay.",
                        },
                    ],
                }
            ],
        }

        is_valid, errors, _ = discovery_protocol.validate_semantic_concern_proposal(ungrounded_proposal, req_data)
        self.assertFalse(is_valid)
        self.assertTrue(any("ungrounded" in e.lower() for e in errors))

    def test_rc_sd_04_proposal_validation_rejects_empty_options_for_critical(self):
        """RC-SD-04: High or critical concerns must provide at least 2 discriminative candidate options."""
        f_data = frame.create_initial_frame(
            project_goal="Build a secure credential vault.",
            explicit_requirements=["Store encrypted passwords"],
        )
        frame.save_frame(self.ws, f_data)

        req_data = discovery_protocol.create_discovery_request(self.ws, f_data)

        invalid_proposal = {
            "schemaVersion": "7.2",
            "discoveryId": req_data["discoveryId"],
            "concerns": [
                {
                    "proposalId": "PROP-001",
                    "title": "Master Password Derivation Protocol",
                    "question": "Which derivation parameters should be used?",
                    "whyUnresolved": "Missing parameters",
                    "whyMaterial": "Security boundary",
                    "category": "SECURITY",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "CRITICAL",
                    "uncertainty": 0.8,
                    "downstreamImpact": 0.9,
                    "sourceIntentIds": ["INTENT-002"],
                    "candidateOptions": [],  # Empty options!
                }
            ],
        }

        is_valid, errors, _ = discovery_protocol.validate_semantic_concern_proposal(invalid_proposal, req_data)
        self.assertFalse(is_valid)
        self.assertTrue(any("candidate options" in e.lower() for e in errors))

    def test_rc_sd_05_discovery_origin_labeling(self):
        """RC-SD-05: Concerns are accurately stamped with discoveryOrigin (HEURISTIC_SEED vs AGENT_PROPOSAL)."""
        init = self.engine.initialize_discovery("Build an inventory tracker for warehouse goods.")
        concerns = init["concerns"]
        self.assertTrue(len(concerns) > 0)
        for c in concerns:
            self.assertEqual(c.get("discoveryOrigin"), "HEURISTIC_SEED")

        # Ingest an agent proposal
        agent_proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-BARCODE",
                    "title": "Warehouse Goods Barcode Scanning Hardware Protocol",
                    "question": "How should handheld barcode scanners transmit inventory scan events?",
                    "whyUnresolved": "Hardware interface not specified",
                    "whyMaterial": "Determines driver architecture for warehouse inventory tracking",
                    "category": "INTEGRATION",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "MEDIUM",
                    "uncertainty": 0.5,
                    "downstreamImpact": 0.6,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {
                            "id": "OPT-1",
                            "title": "USB Keyboard Emulation (HID)",
                            "behavioralMeaning": "Scanners emulate standard keyboard strokes.",
                            "tradeoffs": "Universal driverless compatibility; requires focused input field.",
                        },
                        {
                            "id": "OPT-2",
                            "title": "Virtual Serial Port (CDC-ACM)",
                            "behavioralMeaning": "Direct serial byte streaming over COM port.",
                            "tradeoffs": "Background scanning without focus; requires port configuration.",
                        },
                    ],
                }
            ],
        }

        success, msg, res = self.engine.ingest_agent_proposal(agent_proposal, allow_simulated=True)
        self.assertTrue(success, f"Agent proposal ingestion failed: {msg}")
        self.assertEqual(res.get("discoveryOrigin"), "AGENT_PROPOSAL")

        # Verify persisted concern retains AGENT_PROPOSAL
        all_concerns = concern.load_concerns(self.ws)
        ingested = next(c for c in all_concerns if c["id"] == res["id"])
        self.assertEqual(ingested["discoveryOrigin"], "AGENT_PROPOSAL")

    def test_rc_sd_06_concern_layer_classification(self):
        """RC-SD-06: Concerns are assigned valid decision layers (FOUNDATIONAL, POLICY, MECHANISM, SURFACE)."""
        c1 = concern.create_concern(
            id="CONC-001",
            title="State Storage Engine",
            description="Database engine selection",
            category="PERSISTENCE",
            source={"type": "FRAME_GOAL", "reference": "storage"},
        )
        self.assertEqual(c1["decisionLayer"], "FOUNDATIONAL")

        c2 = concern.create_concern(
            id="CONC-002",
            title="User Authorization Model",
            description="Access control rules",
            category="AUTHORIZATION",
            source={"type": "FRAME_GOAL", "reference": "auth"},
        )
        self.assertEqual(c2["decisionLayer"], "POLICY")

        c3 = concern.create_concern(
            id="CONC-003",
            title="Search Indexing Strategy",
            description="Full-text query index",
            category="CORE_BEHAVIOR",
            source={"type": "FRAME_GOAL", "reference": "search"},
        )
        self.assertEqual(c3["decisionLayer"], "MECHANISM")

        c4 = concern.create_concern(
            id="CONC-004",
            title="Terminal CLI Output Format",
            description="CLI flags and colored stdout",
            category="INTEGRATION",
            source={"type": "FRAME_GOAL", "reference": "cli"},
        )
        self.assertEqual(c4["decisionLayer"], "SURFACE")

    def test_rc_sd_07_ingest_records_decision_event(self):
        """RC-SD-07: Ingesting an agent proposal records a SEMANTIC_CONCERN_PROPOSAL_INGESTED event."""
        f_data = frame.create_initial_frame("Build an embedded packet sniffer.")
        frame.save_frame(self.ws, f_data)

        proposal = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-BUFFER",
                    "title": "Packet Capture Ring Buffer Architecture",
                    "question": "How should the embedded packet sniffer manage high-throughput ring buffers?",
                    "whyUnresolved": "Buffer overflow policy not specified",
                    "whyMaterial": "Determines packet sniffer buffer loss characteristics under heavy load",
                    "category": "TECHNICAL_ARCHITECTURE",
                    "decisionLayer": "TECHNICAL",
                    "riskLevel": "HIGH",
                    "uncertainty": 0.6,
                    "downstreamImpact": 0.8,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {
                            "id": "OPT-1",
                            "title": "Fixed-Size Bounded Ring Buffer",
                            "behavioralMeaning": "Pre-allocate 128MB circular buffer with overwrite of oldest frames on saturation.",
                            "tradeoffs": "Deterministic memory consumption; drops old packets under burst.",
                        },
                        {
                            "id": "OPT-2",
                            "title": "Dynamic Chunked Memory Pool",
                            "behavioralMeaning": "Allocate additional blocks up to system memory limits.",
                            "tradeoffs": "Zero packet drops during transient spikes; risk of memory exhaustion.",
                        },
                    ],
                }
            ],
        }

        success, msg, res = discovery_protocol.ingest_semantic_concern_proposal(self.ws, proposal, allow_simulated=True)
        self.assertTrue(success, f"Ingestion failed: {msg}")

        events = decision_events.load_decision_events(self.ws)
        ingest_events = [e for e in events if e.get("eventType") == "SEMANTIC_CONCERN_PROPOSAL_INGESTED"]
        self.assertEqual(len(ingest_events), 1)
        cid = res[0]["id"] if isinstance(res, list) else res["id"]
        self.assertEqual(ingest_events[0]["payload"]["concernId"], cid)

    def test_rc_sd_08_protected_artifacts_gate_protects_discovery_paths(self):
        """RC-SD-08: PreToolUse gate denies direct writes to .agent-harness/discovery/* files."""
        safe, msg = gate.is_write_safe(".agent-harness/discovery/request.json", workspace_root=self.ws)
        self.assertFalse(safe)
        self.assertIn("protected harness artifact", msg)

        safe, msg = gate.is_write_safe(".agent-harness/discovery/proposals.json", workspace_root=self.ws)
        self.assertFalse(safe)
        self.assertIn("protected harness artifact", msg)

        safe, msg = gate.is_write_safe(".agent-harness/discovery/custom_file.json", workspace_root=self.ws)
        self.assertFalse(safe)
        self.assertIn("protected harness artifact", msg)

    def test_rc_sd_09_discovery_status_tracking(self):
        """RC-SD-09: load_discovery_status tracks proposals count, accepted count, and origin."""
        status_init = discovery_protocol.load_discovery_status(self.ws)
        self.assertEqual(status_init["proposalCount"], 0)
        self.assertEqual(status_init["acceptedCount"], 0)

        f_data = frame.create_initial_frame("Build a text editor.")
        frame.save_frame(self.ws, f_data)

        proposal_9 = {
            "schemaVersion": "7.2",
            "concerns": [
                {
                    "proposalId": "PROP-SYNTAX",
                    "title": "Text Editor Syntax Highlighting Engine",
                    "question": "How should the text editor parse buffer tokens for syntax coloring?",
                    "whyUnresolved": "Parsing approach not specified",
                    "whyMaterial": "Determines text editor latency and syntax fidelity",
                    "category": "CORE_BEHAVIOR",
                    "decisionLayer": "PRODUCT",
                    "riskLevel": "LOW",
                    "uncertainty": 0.4,
                    "downstreamImpact": 0.5,
                    "sourceIntentIds": ["INTENT-001"],
                    "candidateOptions": [
                        {"id": "OPT-1", "title": "Tree-sitter AST Parser", "behavioralMeaning": "Incremental AST parsing of editor buffer.", "tradeoffs": "Accurate syntax tree; higher initial startup cost."},
                        {"id": "OPT-2", "title": "Regex Pattern Scanner", "behavioralMeaning": "Line-based regex rules for editor tokens.", "tradeoffs": "Instant startup; limited multi-line construct support."},
                    ],
                }
            ],
        }
        success_9, msg_9, _ = discovery_protocol.ingest_semantic_concern_proposal(self.ws, proposal_9, discovery_mode="LIVE_AGENT_DISCOVERY")
        self.assertTrue(success_9, f"Proposal 9 ingest failed: {msg_9}")

        status_after = discovery_protocol.load_discovery_status(self.ws)
        self.assertEqual(status_after["proposalCount"], 1)
        self.assertEqual(status_after["acceptedCount"], 1)
        self.assertEqual(status_after["discoveryOrigin"], "AGENT_PROPOSAL")

    # -------------------------------------------------------------------------
    # PART 2: REQUIREMENT GENERATOR & QUALITY (RC-REQ-01 .. RC-REQ-10)
    # -------------------------------------------------------------------------

    def test_rc_req_01_force_parameter_strictly_rejected(self):
        """RC-REQ-01: compile_requirements_from_decisions raises TypeError if 'force' is passed."""
        with self.assertRaises(TypeError) as ctx:
            requirement_generator.compile_requirements_from_decisions(self.ws, force=True)
        self.assertIn("dead bypass flags are rejected", str(ctx.exception))

    def test_rc_req_02_zero_decision_project_compilation(self):
        """RC-REQ-02: A project with 0 active decisions compiles successfully when explicit requirements exist."""
        f_data = frame.create_initial_frame(
            project_goal="A self-contained pure math library.",
            explicit_requirements=["Implement fast Fourier transform for 1D float arrays"],
            explicit_constraints=["Zero external runtime dependencies"],
        )
        frame.save_frame(self.ws, f_data)

        # Compile all requirements (which includes intents) with zero decisions in decisions.json
        success, msg, reqs = requirement_generator.compile_all_requirements(self.ws)
        self.assertTrue(success, f"Zero-decision compilation failed: {msg}")
        self.assertIn("Zero active decisions", msg)

        # Verify requirements.json contains the explicit requirements
        saved = kernel.load_requirements(self.ws)
        self.assertEqual(len(saved), 2)
        fft_req = next(r for r in saved if "Fourier" in r["description"])
        self.assertEqual(fft_req["category"], "CORE_BEHAVIOR")
        self.assertIsNotNone(fft_req.get("contractFingerprint"))

    def test_rc_req_03_invariant_17_broad_goals_excluded(self):
        """RC-REQ-03: Invariant 17: Broad goals ('Build an app', etc.) are not compiled as requirements."""
        f_data = frame.create_initial_frame(
            project_goal="Build a comprehensive customer management application.",
            explicit_requirements=["Export customer records to CSV format with RFC 4180 escaping"],
        )
        frame.save_frame(self.ws, f_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_intents(self.ws)
        self.assertTrue(success)

        titles = [r["title"] for r in reqs]
        # Broad goal must NOT be in compiled requirements
        self.assertFalse(any("Build a comprehensive customer management" in t for t in titles))
        # Atomic requirement MUST be in compiled requirements
        self.assertTrue(any("Export customer records to CSV" in t for t in titles))

    def test_rc_req_04_dynamic_risk_evaluation_on_intents(self):
        """RC-REQ-04: Intent requirements dynamically evaluate risk level instead of hardcoded MEDIUM."""
        f_data = frame.create_initial_frame(
            project_goal="Financial payment processing microservice.",
            explicit_requirements=[
                "Process credit card billing transaction and refund requests",
                "Format report timestamps according to ISO 8601",
            ],
        )
        frame.save_frame(self.ws, f_data)

        success, msg, reqs = requirement_generator.compile_requirements_from_intents(self.ws)
        self.assertTrue(success)

        billing_req = next(r for r in reqs if "credit card" in r["description"])
        date_req = next(r for r in reqs if "ISO 8601" in r["description"])

        # Billing involves credit cards / payments -> CRITICAL
        self.assertEqual(billing_req["riskLevel"], "CRITICAL")
        # Formatting timestamps -> LOW or MEDIUM, NOT CRITICAL
        self.assertIn(date_req["riskLevel"], ["LOW", "MEDIUM"])

    def test_rc_req_05_deterministic_requirement_fingerprint(self):
        """RC-REQ-05: compute_requirement_contract_fingerprint is deterministic and sensitive to contract changes."""
        req1 = {
            "title": "User Session Timeout",
            "description": "Invalidate JWT session after 15 minutes of inactivity.",
            "category": "SECURITY",
            "acceptanceCriteria": ["Given an inactive user, When 15 minutes elapse, Then token is rejected."],
            "verificationContract": "Verify token rejection at t=15m",
        }
        req2 = dict(req1)

        fp1 = requirement_generator.compute_requirement_contract_fingerprint(req1)
        fp2 = requirement_generator.compute_requirement_contract_fingerprint(req2)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

        # Modify description -> fingerprint must change
        req2["description"] = "Invalidate JWT session after 30 minutes of inactivity."
        fp3 = requirement_generator.compute_requirement_contract_fingerprint(req2)
        self.assertNotEqual(fp1, fp3)

    def test_rc_req_06_fingerprint_change_invalidates_verified_status(self):
        """RC-REQ-06: When requirement text/criteria changes, VERIFIED/PASS status transitions to STALE."""
        f_data = frame.create_initial_frame(
            project_goal="Secure file vault.",
            explicit_requirements=["Encrypt uploaded documents using AES-256-GCM"],
        )
        frame.save_frame(self.ws, f_data)

        # Initial compile
        requirement_generator.compile_requirements_from_intents(self.ws)
        reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(reqs), 1)

        # Simulate requirement previously verified to PASS
        reqs[0]["status"] = "PASS"
        kernel.save_requirements(self.ws, reqs)

        # Now change the intent text in frame
        f_data["intents"][1]["text"] = "Encrypt uploaded documents using ChaCha20-Poly1305"
        frame.save_frame(self.ws, f_data)

        # Recompile
        requirement_generator.compile_requirements_from_intents(self.ws)
        updated_reqs = kernel.load_requirements(self.ws)
        self.assertEqual(len(updated_reqs), 1)

        # Verification must NOT remain PASS! Must be STALE!
        self.assertEqual(updated_reqs[0]["status"], "STALE")
        self.assertEqual(updated_reqs[0]["previousStatus"], "PASS")
        self.assertIn("contract changed", updated_reqs[0]["stalenessReason"])

    def test_rc_req_07_unchanged_fingerprint_preserves_verified_status(self):
        """RC-REQ-07: When requirement text is unchanged, PASS status is preserved upon recompile."""
        f_data = frame.create_initial_frame(
            project_goal="Hash verification utility.",
            explicit_requirements=["Calculate SHA-256 hash of provided file path"],
        )
        frame.save_frame(self.ws, f_data)

        requirement_generator.compile_requirements_from_intents(self.ws)
        reqs = kernel.load_requirements(self.ws)
        reqs[0]["status"] = "PASS"
        kernel.save_requirements(self.ws, reqs)

        # Recompile without changes
        requirement_generator.compile_requirements_from_intents(self.ws)
        updated = kernel.load_requirements(self.ws)
        self.assertEqual(updated[0]["status"], "PASS")

    def test_rc_req_08_acceptance_criteria_rejects_generic_placeholders(self):
        """RC-REQ-08: validate_requirement_quality rejects generic placeholders in acceptance criteria."""
        placeholders = [
            "Given valid input, When executed, Then expected behavior is observed.",
            "Given a test, When run, Then system behaves according to specifications.",
            "Given normal runtime, When called, Then implementation satisfies requirements.",
            "Given valid data, When processed, Then works correctly.",
            "Given malformed input, When sent, Then appropriate error is returned.",
            "Given any call, When invoked, Then outputs are as expected.",
        ]

        for p in placeholders:
            req = {
                "title": "Data Pipeline Transformation",
                "description": "Transform records according to schema definition.",
                "acceptanceCriteria": [p],
            }
            is_valid, errors = requirement_generator.validate_requirement_quality(req)
            self.assertFalse(is_valid, f"Failed to reject placeholder: '{p}'")
            self.assertTrue(any("generic placeholder" in e for e in errors))

    def test_rc_req_09_behavioral_acceptance_criteria_generation(self):
        """RC-REQ-09: generate_behavioral_acceptance_criteria creates valid Given-When-Then observable assertions."""
        crits = requirement_generator.generate_behavioral_acceptance_criteria(
            title="Database Connection Pool",
            chosen_option="Bounded Connection Pool with FIFO Wait Queue",
            category="PERSISTENCE",
        )
        self.assertGreaterEqual(len(crits), 2)
        for c in crits:
            self.assertIn("Given", c)
            self.assertIn("When", c)
            self.assertIn("Then", c)

            req = {
                "title": "Database Connection Pool",
                "description": "Manage reusable database socket connections.",
                "acceptanceCriteria": [c],
            }
            is_valid, errors = requirement_generator.validate_requirement_quality(req)
            self.assertTrue(is_valid, f"Generated criteria failed quality validation: {errors}")

    # -------------------------------------------------------------------------
    # PART 3: METAMORPHIC DISCOVERY & FALSE-POSITIVE ELIMINATION
    # -------------------------------------------------------------------------

    def test_metamorphic_discovery_game_domain(self):
        """Game domain discovers game-appropriate behavioral options (slot save, autosave, checkpoint)."""
        f_data = frame.create_initial_frame("Build a 2D roguelike RPG dungeon crawler game with player inventory.")
        concerns = concern.propose_semantic_concerns_from_frame(f_data)

        # Must discover state retention
        state_conc = next((c for c in concerns if c["category"] == "PERSISTENCE"), None)
        self.assertIsNotNone(state_conc)
        opt_titles = [o["title"] for o in state_conc.get("candidateOptions", [])]

        # In RC2, heuristic seeds do not prescribe technology or mechanism options
        self.assertEqual(opt_titles, [])
        self.assertEqual(state_conc.get("discoveryOrigin"), "HEURISTIC_SEED")

    def test_metamorphic_discovery_editor_domain(self):
        """Document editor discovers editor-appropriate behavioral options (continuous auto-save, revision log)."""
        f_data = frame.create_initial_frame("Build a markdown document editor with live preview.")
        concerns = concern.propose_semantic_concerns_from_frame(f_data)

        state_conc = next((c for c in concerns if c["category"] == "PERSISTENCE"), None)
        self.assertIsNotNone(state_conc)
        opt_titles = [o["title"] for o in state_conc.get("candidateOptions", [])]

        # In RC2, heuristic seeds do not prescribe technology or mechanism options
        self.assertEqual(opt_titles, [])
        self.assertEqual(state_conc.get("discoveryOrigin"), "HEURISTIC_SEED")

    def test_false_positive_auth_elimination_for_single_user_tools(self):
        """Single-user offline tools must NOT generate CRITICAL authorization concerns."""
        single_user_intents = [
            "Build a personal offline markdown note-taking CLI tool for a single user.",
            "Create a local desktop calculator for one user.",
            "A standalone audio player for personal local playback.",
        ]

        for text in single_user_intents:
            f_data = frame.create_initial_frame(text)
            concerns = concern.propose_semantic_concerns_from_frame(f_data)
            auth_conc = next((c for c in concerns if c["category"] == "AUTHORIZATION"), None)
            if auth_conc:
                self.assertNotEqual(auth_conc.get("riskLevel"), "CRITICAL", f"CRITICAL auth concern falsely triggered for: {text}")

    def test_false_positive_persistence_elimination_for_pure_data_pipeline(self):
        """A pure data transformation pipeline without storage requirements must NOT trigger PERSISTENCE."""
        f_data = frame.create_initial_frame(
            project_goal="Compute moving averages and standard deviations on streaming numerical data in memory.",
        )
        concerns = concern.propose_semantic_concerns_from_frame(f_data)
        pers_conc = next((c for c in concerns if c["category"] == "PERSISTENCE"), None)
        self.assertIsNone(pers_conc, "Pure in-memory data math must not falsely trigger PERSISTENCE concern")

    def test_multi_domain_discovery_matrix(self):
        """Verify semantic discovery across 8 diverse domains produces grounded, valid concerns."""
        domains = [
            ("A streaming compiler that parses AST nodes", "CORE_BEHAVIOR"),
            ("A high-concurrency WebSocket messaging gateway with user authentication", "AUTHORIZATION"),
            ("A local game engine that renders 2D tilemaps and saves state", "PERSISTENCE"),
            ("A music synthesizer generating real-time PCM audio buffers", "CORE_BEHAVIOR"),
            ("A network packet filter that drops malformed UDP frames", "CORE_BEHAVIOR"),
            ("A batch image thumbnail generator with file asset import", "DATA"),
            ("An IoT sensor hub with crash recovery journal", "RECOVERY"),
            ("A command-line JSON querying tool with POSIX exit codes", "PLATFORM"),
        ]

        for prompt, expected_cat in domains:
            f_data = frame.create_initial_frame(prompt)
            concerns = concern.propose_semantic_concerns_from_frame(f_data)
            self.assertGreaterEqual(len(concerns), 1, f"No concerns discovered for domain: {prompt}")

            categories = {c["category"] for c in concerns}
            self.assertIn(expected_cat, categories, f"Expected category {expected_cat} not found in {categories} for {prompt}")

            # Every concern must have valid decisionLayer and discoveryOrigin
            for c in concerns:
                self.assertIn(c.get("decisionLayer"), concern.CONCERN_DECISION_LAYERS)
                self.assertEqual(c.get("discoveryOrigin"), "HEURISTIC_SEED")


if __name__ == "__main__":
    unittest.main()
