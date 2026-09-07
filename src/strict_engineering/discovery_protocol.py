"""
Strict Engineering Kernel - Semantic Discovery Protocol (Schema 7.2)
Machine-readable protocol between Antigravity agents (Spec Architect, Scope Auditor)
and the deterministic Strict Engineering Kernel.

Artifacts:
  .agent-harness/discovery/request-<discoveryId>.json
  .agent-harness/discovery/proposal-<discoveryId>.json
  .agent-harness/discovery/review-<discoveryId>.json
  .agent-harness/discovery/discovery-status.json
"""

import os
import re
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
    from . import question_utility
    from . import decision_graph
    from . import stopping_engine
    from . import decision_coverage
    from . import decision_events
    from . import risk_engine
except (ImportError, ValueError):
    try:
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
        import question_utility
        import decision_graph
        import stopping_engine
        import decision_coverage
        import decision_events
        import risk_engine
    except ImportError:
        frame_mod = None
        concern_mod = None
        decision_mod = None
        question_utility = None
        decision_graph = None
        stopping_engine = None
        decision_coverage = None
        decision_events = None
        risk_engine = None

DISCOVERY_SCHEMA_VERSION = "7.2"

# Forbidden technology prescriptions for general PRODUCT-layer concern candidate options
TECHNOLOGY_PRESCRIPTION_PATTERNS = [
    r"\bsqlite\b",
    r"\bpostgres(ql)?\b",
    r"\bmysql\b",
    r"\bredis\b",
    r"\bmongodb\b",
    r"\brbac\b",
    r"\bjwt\b",
    r"\boauth\b",
    r"\brest\s+api\b",
    r"\bgraphql\b",
    r"\binverted\s+index\b",
    r"\bwrite[- ]ahead\s+log(ging)?\b",
]

# Prohibited invented feature keywords absent source intent/decision support
UNAUTHORIZED_FEATURE_PATTERNS = [
    (r"\bcloud\s+sync\b", "cloud sync"),
    (r"\btelemetry|analytics\b", "analytics/telemetry"),
    (r"\bai\s+tagging|machine\s+learning\b", "AI/ML automation"),
    (r"\bsocial\s+sharing|share\s+to\s+social\b", "social sharing"),
    (r"\bbilling|monetization|subscription\b", "billing/monetization"),
    (r"\bteams|workspaces|collaborative\s+editing\b", "team collaboration"),
]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_discovery_dir(workspace_dir: Union[str, Path]) -> Path:
    """Return absolute path to .agent-harness/discovery directory."""
    d_dir = Path(workspace_dir).resolve() / ".agent-harness" / "discovery"
    d_dir.mkdir(parents=True, exist_ok=True)
    return d_dir


def generate_discovery_id(fingerprint: str) -> str:
    """Generate a unique deterministic or timestamped discovery ID."""
    ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    h = hashlib.sha256(f"{fingerprint}:{ts}".encode("utf-8")).hexdigest()[:8]
    return f"DISC-{ts}-{h}"


def create_discovery_request(
    workspace_dir: Union[str, Path],
    frame_data: Optional[Dict[str, Any]] = None,
    discovery_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construct and persist .agent-harness/discovery/request-<discoveryId>.json.
    Exposes only essential discovery context without Builder implementation details.
    """
    ws = Path(workspace_dir).resolve()
    f_data = frame_data or (frame_mod.load_frame(ws) if frame_mod else {})

    raw_fp = ""
    src_refs = f_data.get("sourceReferences", [])
    if src_refs and str(src_refs[0]).startswith("sha256:"):
        raw_fp = str(src_refs[0]).replace("sha256:", "")
    else:
        goal_text = str(f_data.get("projectGoal", ""))
        raw_fp = hashlib.sha256(goal_text.encode("utf-8")).hexdigest()

    disc_id = discovery_id or generate_discovery_id(raw_fp)

    existing_concerns = concern_mod.load_concerns(ws) if concern_mod else []
    known_decisions = decision_mod.load_decisions(ws) if decision_mod else []
    canonical_intents = f_data.get("intents", [])

    # Collect risk hints from goals/constraints
    risk_hints = []
    for g in f_data.get("goals", []):
        gt = g.get("text", str(g)) if isinstance(g, dict) else str(g)
        if any(w in gt.lower() for w in ["auth", "login", "password", "delete", "payment", "finance"]):
            risk_hints.append({"aspect": gt[:50], "hint": "HIGH/CRITICAL potential"})
    for c in f_data.get("constraints", []):
        ct = c.get("text", str(c)) if isinstance(c, dict) else str(c)
        if any(w in ct.lower() for w in ["offline", "local only", "single user", "no cloud", "no network"]):
            risk_hints.append({"aspect": ct[:50], "hint": "Strict local boundary constraint"})

    req_payload = {
        "schemaVersion": DISCOVERY_SCHEMA_VERSION,
        "discoveryId": disc_id,
        "originalRequestFingerprint": raw_fp,
        "canonicalIntents": canonical_intents,
        "currentFrame": {
            "projectName": f_data.get("projectName", ""),
            "projectGoal": f_data.get("projectGoal", ""),
            "primaryUser": f_data.get("primaryUser", ""),
            "problemStatement": f_data.get("problemStatement", ""),
            "constraints": f_data.get("constraints", []),
            "nonGoals": f_data.get("nonGoals", []),
            "knownFacts": f_data.get("knownFacts", []),
        },
        "existingConcerns": existing_concerns,
        "explicitConstraints": f_data.get("constraints", []),
        "explicitNonGoals": f_data.get("nonGoals", []),
        "knownDecisions": known_decisions,
        "riskHints": risk_hints,
        "createdAt": utc_now_iso(),
    }

    req_path = get_discovery_dir(ws) / f"request-{disc_id}.json"
    temp_path = req_path.with_suffix(".json.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(req_payload, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, req_path)

    # Also maintain canonical request.json
    canon_req_path = get_discovery_dir(ws) / "request.json"
    canon_tmp = canon_req_path.with_suffix(".json.tmp")
    with open(canon_tmp, "w", encoding="utf-8") as f:
        json.dump(req_payload, f, indent=2, ensure_ascii=False)
    os.replace(canon_tmp, canon_req_path)

    return req_payload


def validate_semantic_concern_proposal(
    proposal: Dict[str, Any],
    request_data: Dict[str, Any],
) -> Tuple[bool, List[str], List[Dict[str, Any]]]:
    """
    Deterministically validate Spec Architect concern proposal against request data.
    Enforces:
      1. Schema version == 7.2
      2. discoveryId matches request
      3. All referenced sourceIntentIds exist in canonicalIntents
      4. Grounding: concern has meaningful semantic basis in referenced intent
      5. No contradiction with explicit facts or non-goals
      6. No re-asking already-explicit facts/requirements
      7. PRODUCT concerns do not prescribe implementation technology (unless requested)
      8. No active duplicate concerns
    Returns: (is_valid, validation_errors, validated_concerns)
    """
    errors: List[str] = []
    validated_concerns: List[Dict[str, Any]] = []

    if not isinstance(proposal, dict):
        return False, ["Proposal must be a JSON dictionary."], []

    # Auto-wrap single concern proposal if concerns key is missing
    if "concerns" not in proposal and "title" in proposal:
        wrapped_c = dict(proposal)
        proposal = {
            "schemaVersion": proposal.get("schemaVersion", DISCOVERY_SCHEMA_VERSION),
            "discoveryId": proposal.get("discoveryId", request_data.get("discoveryId")),
            "concerns": [wrapped_c],
        }

    if proposal.get("schemaVersion") != DISCOVERY_SCHEMA_VERSION:
        errors.append(f"Invalid schemaVersion '{proposal.get('schemaVersion')}', expected '{DISCOVERY_SCHEMA_VERSION}'")

    req_disc_id = request_data.get("discoveryId")
    prop_disc_id = proposal.get("discoveryId")
    if req_disc_id and prop_disc_id and prop_disc_id != req_disc_id:
        errors.append(f"discoveryId mismatch: proposal '{prop_disc_id}' != request '{req_disc_id}'")

    raw_concerns = proposal.get("concerns", [])
    if not isinstance(raw_concerns, list):
        errors.append("Field 'concerns' must be a list.")
        return False, errors, []

    intents = request_data.get("canonicalIntents", [])
    intent_map = {it.get("id"): it for it in intents if isinstance(it, dict) and it.get("id")}

    frame_info = request_data.get("currentFrame", {})
    non_goals = [ng.get("text", str(ng)).lower() if isinstance(ng, dict) else str(ng).lower() for ng in frame_info.get("nonGoals", [])]
    known_facts = [kf.get("text", str(kf)).lower() if isinstance(kf, dict) else str(kf).lower() for kf in frame_info.get("knownFacts", [])]
    constraints = [c.get("text", str(c)).lower() if isinstance(c, dict) else str(c).lower() for c in frame_info.get("constraints", [])]

    existing_concerns = request_data.get("existingConcerns", [])
    active_titles = {c.get("title", "").strip().lower() for c in existing_concerns if str(c.get("status", "")).upper() not in {"SUPERSEDED", "DISMISSED_LOW_VALUE"}}

    # Track user request corpus to see if user explicitly asked for specific tech
    intent_corpus = " ".join([str(it.get("text", "")) for it in intents] + [str(frame_info.get("projectGoal", ""))]).lower()

    for idx, c in enumerate(raw_concerns):
        c_errors: List[str] = []
        if not isinstance(c, dict):
            errors.append(f"Concern at index {idx} must be a dictionary.")
            continue

        pid = c.get("proposalId") or f"PROP-C-{str(idx+1).zfill(3)}"
        title = str(c.get("title", "")).strip()
        question = str(c.get("question", "")).strip()
        decision_layer = str(c.get("decisionLayer", "PRODUCT")).upper().strip()
        category = str(c.get("category", "")).upper().strip()
        src_intent_ids = c.get("sourceIntentIds", [])
        c_corpus = f"{title} {question} {c.get('whyUnresolved', '')} {c.get('whyMaterial', '')}".lower()

        if not title:
            c_errors.append(f"{pid}: Missing title")
        if not question:
            c_errors.append(f"{pid}: Missing question")
        if decision_layer not in ("PRODUCT", "TECHNICAL"):
            c_errors.append(f"{pid}: Invalid decisionLayer '{decision_layer}'. Must be PRODUCT or TECHNICAL")

        # Intent Provenance Check (REQ-006)
        if not src_intent_ids or not isinstance(src_intent_ids, list):
            c_errors.append(f"{pid}: 'sourceIntentIds' must be a non-empty list of intent IDs")
        else:
            for sid in src_intent_ids:
                if sid not in intent_map:
                    c_errors.append(f"{pid}: References non-existent INTENT ID '{sid}'")

        # Semantic Grounding Check (REQ-007)
        if src_intent_ids and not c_errors:
            ref_texts = " ".join([str(intent_map[sid].get("text", "")).lower() for sid in src_intent_ids if sid in intent_map])
            ref_tokens = {w for w in re.findall(r"\b[a-z]{4,}\b", ref_texts)}
            c_tokens = {w for w in re.findall(r"\b[a-z]{4,}\b", c_corpus)}
            overlap = ref_tokens.intersection(c_tokens)
            if not overlap:
                c_errors.append(f"{pid}: Concern is semantically ungrounded in referenced intents {src_intent_ids} (zero token overlap)")

        # Contradiction with Non-Goals
        for ng in non_goals:
            ng_tokens = {w for w in re.findall(r"\b[a-z]{4,}\b", ng)}
            if ng_tokens and len(ng_tokens.intersection(c_tokens)) >= 2:
                if any(w in c_corpus for w in ["include", "implement", "support", "enable", "add"]):
                    c_errors.append(f"{pid}: Contradicts explicit non-goal '{ng}'")

        # Re-asking Explicit Facts (REQ-008, REQ-041)
        for kf in known_facts + constraints:
            kf_tokens = {w for w in re.findall(r"\b[a-z]{4,}\b", kf)}
            if kf_tokens and len(kf_tokens.intersection(c_tokens)) >= 3:
                # If question directly asks what is already stated as fact/constraint
                if any(q_start in question.lower() for q_start in ["who can", "what is", "where should", "which format", "should the system"]):
                    # Check if answer is already explicitly defined
                    if any(w in kf for w in ["only", "must", "strictly", "always"]):
                        c_errors.append(f"{pid}: Re-asks explicit fact/constraint '{kf}'")

        # Product Layer Technology Prescription Check (REQ-008, REQ-039)
        if decision_layer == "PRODUCT":
            options = c.get("candidateOptions", [])
            for opt in options:
                opt_title = str(opt.get("title", "") if isinstance(opt, dict) else str(opt)).lower()
                opt_desc = str(opt.get("behavioralMeaning", "") if isinstance(opt, dict) else "").lower()
                for pat in TECHNOLOGY_PRESCRIPTION_PATTERNS:
                    if re.search(pat, opt_title) or re.search(pat, opt_desc):
                        # Allowed only if user explicitly asked for this technology in intent
                        tech_match = re.search(pat, opt_title) or re.search(pat, opt_desc)
                        tech_word = tech_match.group(0) if tech_match else ""
                        if tech_word and tech_word not in intent_corpus:
                            c_errors.append(f"{pid}: PRODUCT concern candidate option prescribes implementation technology '{tech_word}' instead of product behavior")
                            break

        # Duplicate check
        if title.lower() in active_titles:
            c_errors.append(f"{pid}: Duplicate of existing active concern '{title}'")

        # Options check
        options = c.get("candidateOptions", [])
        if not isinstance(options, list) or len(options) < 2:
            c_errors.append(f"{pid}: Must provide at least 2 candidate options describing distinct behaviors")

        if c_errors:
            errors.extend(c_errors)
        else:
            validated_concerns.append(c)

    return len(errors) == 0, errors, validated_concerns


def ingest_semantic_concern_proposal(
    workspace_dir: Union[str, Path],
    proposal_data: Union[Dict[str, Any], str, Path],
    review_data: Optional[Union[Dict[str, Any], str, Path]] = None,
    discovery_mode: str = "LIVE_AGENT_DISCOVERY",
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Deterministic kernel API to validate and ingest a semantic concern proposal.
    The agent CANNOT directly edit concerns.json or decision-graph.json.
    Validation happens here.
    """
    ws = Path(workspace_dir).resolve()

    # Load proposal if path passed
    if isinstance(proposal_data, (str, Path)):
        p_path = Path(proposal_data).resolve()
        if not p_path.exists():
            return False, f"Proposal file not found: {p_path}", []
        with open(p_path, "r", encoding="utf-8") as f:
            p_data = json.load(f)
    else:
        p_data = proposal_data

    # Load review if path passed
    r_data: Optional[Dict[str, Any]] = None
    if review_data:
        if isinstance(review_data, (str, Path)):
            r_path = Path(review_data).resolve()
            if r_path.exists():
                with open(r_path, "r", encoding="utf-8") as f:
                    r_data = json.load(f)
        else:
            r_data = review_data

    disc_id = p_data.get("discoveryId", "")
    req_path = get_discovery_dir(ws) / f"request-{disc_id}.json"
    req_data = {}
    if req_path.exists():
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                req_data = json.load(f)
        except Exception:
            pass

    # If no stored request file, synthesize from frame
    if not req_data:
        f_data = frame_mod.load_frame(ws) if frame_mod else {}
        req_data = {
            "discoveryId": disc_id,
            "canonicalIntents": f_data.get("intents", []),
            "currentFrame": f_data,
            "existingConcerns": concern_mod.load_concerns(ws) if concern_mod else [],
        }

    is_valid, errors, validated = validate_semantic_concern_proposal(p_data, req_data)
    if not is_valid:
        return False, f"Semantic concern proposal validation failed: {'; '.join(errors)}", []

    # Apply Scope Auditor review filtering if available
    rejected_pids = set()
    if r_data:
        evals = r_data.get("evaluations", r_data.get("reviews", []))
        for ev in evals:
            if isinstance(ev, dict) and ev.get("verdict") == "REJECT":
                rejected_pids.add(ev.get("proposalId"))

    # Load existing concerns
    existing = concern_mod.load_concerns(ws) if concern_mod else []
    existing_ids = {c.get("id") for c in existing if c.get("id")}

    def next_cid() -> str:
        idx = 1
        while f"CONC-{str(idx).zfill(3)}" in existing_ids:
            idx += 1
        cid = f"CONC-{str(idx).zfill(3)}"
        existing_ids.add(cid)
        return cid

    ingested_concerns: List[Dict[str, Any]] = []

    for prop in validated:
        pid = prop.get("proposalId", "")
        if pid in rejected_pids:
            continue

        cid = next_cid()
        title = prop.get("title", "")
        question = prop.get("question", title)
        desc = f"{question} (Unresolved: {prop.get('whyUnresolved', '')}. Material Impact: {prop.get('whyMaterial', '')})"
        cat = prop.get("category", "CORE_BEHAVIOR")
        src_intents = prop.get("sourceIntentIds", [])
        dec_layer = prop.get("decisionLayer", "PRODUCT")

        # Evaluate authoritative risk level via risk engine
        calc_risk, _ = concern_mod.evaluate_concern_risk(title, desc, cat) if concern_mod else ("MEDIUM", [])

        # Convert candidate options to canonical schema
        canon_opts = []
        raw_opts = prop.get("candidateOptions", [])
        for o_idx, opt in enumerate(raw_opts):
            if isinstance(opt, dict):
                canon_opts.append({
                    "id": f"OPT-{o_idx+1}",
                    "title": opt.get("title", f"Option {o_idx+1}"),
                    "description": opt.get("behavioralMeaning", opt.get("description", "")),
                    "tradeoffs": opt.get("tradeoffs", "Standard behavioral tradeoffs"),
                    "consequences": opt.get("majorConsequences", opt.get("consequences", [])),
                    "isRecommended": bool(opt.get("isRecommended", o_idx == 0)),
                })

        canon_c = concern_mod.create_concern(
            id=cid,
            title=title,
            description=desc,
            category=cat,
            source={"type": "SEMANTIC_SPEC_ARCHITECT", "reference": f"proposal:{disc_id}/{pid}"},
            source_intent_ids=src_intents,
            status="ACTIVE",
            risk_level=calc_risk,
            uncertainty=float(prop.get("uncertainty", 0.8)),
            downstream_impact=float(prop.get("downstreamImpact", 0.8)),
            risk_reduction_potential=float(prop.get("riskReductionPotential", 0.7)),
            expected_discrimination=float(prop.get("expectedDiscrimination", 0.8)),
            candidate_options=canon_opts,
            decisionLayer=dec_layer,
            discovery_origin="AGENT_PROPOSAL",
        ) if concern_mod else {}

        # Kernel computes authoritative utility!
        if question_utility and canon_c:
            authoritative_utility = question_utility.calculate_question_utility(canon_c)
            canon_c["questionUtility"] = authoritative_utility

        ingested_concerns.append(canon_c)
        existing.append(canon_c)

    # Persist updated concerns
    if concern_mod:
        concern_mod.save_concerns(ws, existing)

    # Sandbox suggestions if present
    suggestions = p_data.get("possibleSuggestions", [])
    if suggestions:
        from . import requirement_generator
        for s in suggestions:
            stitle = s.get("title", str(s)) if isinstance(s, dict) else str(s)
            sdesc = s.get("description", stitle) if isinstance(s, dict) else stitle
            requirement_generator.record_suggestion_sandbox(ws, title=stitle, description=sdesc)

    # Save discovery status record with honest mode
    prop_list = p_data.get("concerns", [p_data] if "title" in p_data else [])
    disc_status = {
        "discoveryId": disc_id,
        "discoveryMode": discovery_mode,
        "status": "SEMANTIC_DISCOVERY_COMPLETED" if discovery_mode in ("LIVE_AGENT_DISCOVERY", "INTEGRATION_SIMULATED") else "HEURISTIC_DISCOVERY_ONLY",
        "discoveryOrigin": "AGENT_PROPOSAL" if (len(ingested_concerns) > 0 or discovery_mode in ("LIVE_AGENT_DISCOVERY", "AGENT_PROPOSAL", "INTEGRATION_SIMULATED")) else "HEURISTIC_SEED",
        "proposalCount": len(prop_list),
        "acceptedCount": len(ingested_concerns),
        "ingestedConcernsCount": len(ingested_concerns),
        "rejectedConcernsCount": len(rejected_pids),
        "ingestedConcernIds": [c["id"] for c in ingested_concerns],
        "completedAt": utc_now_iso(),
    }
    status_path = get_discovery_dir(ws) / "discovery-status.json"
    temp_path = status_path.with_suffix(".json.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(disc_status, f, indent=2)
    os.replace(temp_path, status_path)

    canon_status = get_discovery_dir(ws) / "status.json"
    temp_canon = canon_status.with_suffix(".json.tmp")
    with open(temp_canon, "w", encoding="utf-8") as f:
        json.dump(disc_status, f, indent=2)
    os.replace(temp_canon, canon_status)

    # Record event in ledger
    if decision_events:
        decision_events.record_decision_event(
            workspace_dir=ws,
            event_type="SEMANTIC_CONCERNS_INGESTED",
            payload={
                "discoveryId": disc_id,
                "discoveryMode": discovery_mode,
                "ingestedCount": len(ingested_concerns),
                "concernIds": [c["id"] for c in ingested_concerns],
            },
            actor="kernel-ingest",
        )
        for c in ingested_concerns:
            decision_events.record_decision_event(
                workspace_dir=ws,
                event_type="SEMANTIC_CONCERN_PROPOSAL_INGESTED",
                payload={
                    "discoveryId": disc_id,
                    "concernId": c["id"],
                    "title": c.get("title"),
                    "category": c.get("category"),
                    "decisionLayer": c.get("decisionLayer"),
                },
                actor="kernel-ingest",
            )

    # Synchronize downstream graph, stopping status, coverage
    if decision_graph:
        decision_graph.sync_decision_graph(ws)
    if stopping_engine:
        stopping_engine.sync_decision_status(ws)
    if decision_coverage:
        decision_coverage.sync_decision_coverage(ws)

    return True, f"Successfully ingested {len(ingested_concerns)} semantic concerns into canonical storage", ingested_concerns


def load_discovery_status(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """Load discovery status from .agent-harness/discovery/status.json or discovery-status.json."""
    ws = Path(workspace_dir).resolve()
    s_path = get_discovery_dir(ws) / "status.json"
    if not s_path.exists():
        s_path = get_discovery_dir(ws) / "discovery-status.json"
    if not s_path.exists():
        return {
            "discoveryMode": "SEMANTIC_DISCOVERY_NOT_EXECUTED",
            "status": "NOT_STARTED",
            "discoveryOrigin": "HEURISTIC_SEED",
            "proposalCount": 0,
            "acceptedCount": 0,
            "ingestedConcernsCount": 0,
        }
    try:
        with open(s_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            data.setdefault("proposalCount", data.get("ingestedConcernsCount", 0))
            data.setdefault("acceptedCount", data.get("ingestedConcernsCount", 0))
            return data
    except Exception:
        return {
            "discoveryMode": "SEMANTIC_DISCOVERY_NOT_EXECUTED",
            "status": "ERROR",
            "discoveryOrigin": "HEURISTIC_SEED",
            "proposalCount": 0,
            "acceptedCount": 0,
            "ingestedConcernsCount": 0,
        }
