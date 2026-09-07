"""
Strict Engineering Kernel - Semantic Acceptance Protocol (Schema 7.2)
Machine-readable protocol for Test Oracle to author, validate, and lock
behavior-specific Given-When-Then acceptance criteria into canonical requirements.

Artifacts:
  .agent-harness/acceptance/request-<requirementId>.json
  .agent-harness/acceptance/proposal-<requirementId>.json
"""

import os
import re
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import kernel
    from . import frame as frame_mod
    from . import decision_events
    from . import context_registry
    from . import requirement_generator
except (ImportError, ValueError):
    try:
        import kernel
        import frame as frame_mod
        import decision_events
        import context_registry
        import requirement_generator
    except ImportError:
        kernel = None
        frame_mod = None
        decision_events = None
        context_registry = None
        requirement_generator = None

ACCEPTANCE_SCHEMA_VERSION = "7.2"

FORBIDDEN_GENERIC_PLACEHOLDER_PATTERNS = [
    r"\bexpected\s+behavior\b",
    r"\bbehaves\s+according\s+to\b",
    r"\bworks\s+correctly\b",
    r"\bappropriate\s+error\b",
    r"\bhandles\s+gracefully\b",
    r"\breturn\s+success\b",
    r"\bselected\s+option\b",
    r"\bvalid\s+operational\s+runtime\s+environment\b",
    r"\bproduces\s+deterministic\s+outputs\b",
    r"\bas\s+expected\b",
    r"\bimplementation\s+satisfies\b",
]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_acceptance_dir(workspace_dir: Union[str, Path]) -> Path:
    """Return absolute path to .agent-harness/acceptance/ directory."""
    p = Path(workspace_dir).resolve() / ".agent-harness" / "acceptance"
    p.mkdir(parents=True, exist_ok=True)
    return p


def compute_acceptance_hash(proposal_data: Dict[str, Any]) -> str:
    """
    Compute a deterministic SHA-256 hash over acceptance proposal semantic fields:
    requirementId, criteria, negativePathCriteria, verificationContract.
    """
    req_id = str(proposal_data.get("requirementId", "")).strip()
    raw_crits = proposal_data.get("criteria", [])
    if isinstance(raw_crits, list):
        norm_crits = sorted(str(c).strip() for c in raw_crits if str(c).strip())
    else:
        norm_crits = [str(raw_crits).strip()]

    raw_neg = proposal_data.get("negativePathCriteria", [])
    if isinstance(raw_neg, list):
        norm_neg = sorted(str(c).strip() for c in raw_neg if str(c).strip())
    else:
        norm_neg = [str(raw_neg).strip()] if raw_neg else []

    vcontract = str(proposal_data.get("verificationContract", "")).strip()

    canonical_obj = {
        "requirementId": req_id,
        "criteria": norm_crits,
        "negativePathCriteria": norm_neg,
        "verificationContract": vcontract,
    }
    encoded = json.dumps(canonical_obj, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_acceptance_request(
    workspace_dir: Union[str, Path],
    requirement: Dict[str, Any],
    frame_data: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Emit a machine-readable acceptance request for Test Oracle:
    .agent-harness/acceptance/request-<requirementId>.json
    """
    ws = Path(workspace_dir).resolve()
    acc_dir = get_acceptance_dir(ws)
    req_id = requirement.get("id", "UNKNOWN")

    if frame_data is None and frame_mod is not None:
        frame_data = frame_mod.load_frame(ws)
    frame_data = frame_data or {}

    short_hash = hashlib.sha256(f"{req_id}:{utc_now_iso()}".encode("utf-8")).hexdigest()[:8]
    request_id = f"ACC-REQ-{req_id}-{short_hash}"

    # Extract source intents
    sources = requirement.get("sources", [])
    source_intents = requirement.get("sourceIntentIds", [s for s in sources if str(s).startswith("INTENT-")])
    source_decisions = requirement.get("sourceDecisionIds", [s for s in sources if str(s).startswith("DEC-")])
    source_concerns = requirement.get("sourceConcernIds", [s for s in sources if str(s).startswith("CONCERN-")])

    req_payload = {
        "schemaVersion": ACCEPTANCE_SCHEMA_VERSION,
        "requestId": request_id,
        "requirementId": req_id,
        "requirementTitle": requirement.get("title", ""),
        "requirementDescription": requirement.get("description", ""),
        "category": requirement.get("category", "CORE_BEHAVIOR"),
        "riskLevel": requirement.get("riskLevel", "MEDIUM"),
        "sourceIntentIds": source_intents,
        "sourceDecisionIds": source_decisions,
        "sourceConcernIds": source_concerns,
        "projectGoal": frame_data.get("projectGoal") or [g.get("text") if isinstance(g, dict) else str(g) for g in frame_data.get("goals", [])],
        "constraints": [c.get("text") if isinstance(c, dict) else str(c) for c in frame_data.get("constraints", [])],
        "instructions": (
            "Formulate behavioral Given-When-Then acceptance criteria specific to this requirement. "
            "Do NOT use generic placeholders ('expected behavior', 'works correctly', 'appropriate error', 'as expected'). "
            "Address both positive behavioral path and specific negative/boundary handling without inventing irrelevant errors."
        ),
        "createdAt": utc_now_iso(),
    }

    out_file = acc_dir / f"request-{req_id}.json"
    temp_file = out_file.with_suffix(".json.tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(req_payload, f, indent=2, sort_keys=True)
    os.replace(temp_file, out_file)
    return out_file


def create_acceptance_requests_for_all(workspace_dir: Union[str, Path]) -> List[Path]:
    """Create acceptance requests for all requirements that need acceptance contracts."""
    ws = Path(workspace_dir).resolve()
    reqs: List[Dict[str, Any]] = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        reqs = kernel.load_requirements(ws)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        if r_file.exists():
            try:
                with open(r_file, "r", encoding="utf-8") as f:
                    reqs = json.load(f)
            except Exception:
                reqs = []

    f_data = frame_mod.load_frame(ws) if frame_mod else {}
    created_paths = []
    for r in reqs:
        if isinstance(r, dict) and r.get("id"):
            p = create_acceptance_request(ws, r, f_data)
            created_paths.append(p)
    return created_paths


def validate_acceptance_proposal(
    proposal_data: Dict[str, Any],
    request_data: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate acceptance criteria proposal against strict quality criteria:
    - schemaVersion must be '7.2'
    - requirementId must be non-empty
    - criteria list must be non-empty
    - each criterion must follow Given-When-Then structure
    - no generic placeholder phrases ('works correctly', 'expected behavior', etc.)
    - semantic grounding: token overlap with requirement title/description
    """
    errors: List[str] = []
    if not isinstance(proposal_data, dict):
        return False, ["Acceptance proposal must be a dictionary."]

    schema_ver = str(proposal_data.get("schemaVersion", "")).strip()
    if schema_ver != ACCEPTANCE_SCHEMA_VERSION:
        errors.append(f"Invalid schemaVersion '{schema_ver}'; expected '{ACCEPTANCE_SCHEMA_VERSION}'.")

    req_id = str(proposal_data.get("requirementId", "")).strip()
    if not req_id:
        errors.append("Missing or empty 'requirementId' in acceptance proposal.")

    if request_data:
        exp_req_id = str(request_data.get("requirementId", "")).strip()
        if exp_req_id and req_id != exp_req_id:
            errors.append(f"Proposal requirementId '{req_id}' does not match request requirementId '{exp_req_id}'.")

    criteria = proposal_data.get("criteria", [])
    if not isinstance(criteria, list) or len(criteria) == 0:
        errors.append("Proposal 'criteria' must be a non-empty list of Given-When-Then assertions.")
    else:
        gwt_regex = re.compile(r"^\s*Given\b.*\bWhen\b.*\bThen\b", re.IGNORECASE | re.DOTALL)
        placeholder_regex = re.compile("|".join(FORBIDDEN_GENERIC_PLACEHOLDER_PATTERNS), re.IGNORECASE)

        for idx, crit in enumerate(criteria):
            if isinstance(crit, dict):
                g = str(crit.get("given", "")).strip()
                w = str(crit.get("when", "")).strip()
                t = str(crit.get("then", "")).strip()
                crit_text = f"Given {g} When {w} Then {t}"
                if not (g and w and t):
                    errors.append(f"Criterion at index {idx} dictionary missing 'given', 'when', or 'then'.")
            elif isinstance(crit, str):
                crit_text = crit.strip()
                if not gwt_regex.search(crit_text):
                    errors.append(f"Criterion at index {idx} does not follow Given-When-Then structure: '{crit_text[:60]}...'")
            else:
                errors.append(f"Criterion at index {idx} must be a string or GWT dictionary.")
                continue

            if placeholder_regex.search(crit_text):
                errors.append(f"Criterion at index {idx} contains forbidden generic placeholder: '{crit_text}'")

    # Semantic grounding check against request if provided
    if request_data:
        req_title = str(request_data.get("requirementTitle", "")).lower()
        req_desc = str(request_data.get("requirementDescription", "")).lower()
        words = set(re.findall(r"\b[a-z]{4,}\b", f"{req_title} {req_desc}"))
        # Exclude common meta words
        words -= {"requirement", "constraint", "system", "shall", "implement", "user", "core", "behavior"}
        if words and criteria:
            all_crits_text = " ".join(str(c) for c in criteria).lower()
            overlap = any(w in all_crits_text for w in words)
            if not overlap:
                errors.append("Criteria lack behavioral grounding with requirement title/description (zero token overlap).")

    return len(errors) == 0, errors


def ingest_acceptance_proposal(
    workspace_dir: Union[str, Path],
    proposal_data: Dict[str, Any],
    allow_simulated: bool = False,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Ingest and lock a Test Oracle acceptance proposal into canonical requirements.json.
    Verifies context isolation proof for TEST_ORACLE, validates criteria quality,
    updates requirement with acceptanceStatus='LOCKED', recomputes Fingerprint V2,
    and records ACCEPTANCE_CONTRACT_LOCKED event.
    """
    ws = Path(workspace_dir).resolve()
    acc_dir = get_acceptance_dir(ws)

    # 1. Verify Context Isolation for TEST_ORACLE
    if context_registry is not None:
        iso_status, iso_details = context_registry.evaluate_context_isolation(
            workspace_dir=ws,
            verifier_purpose="TEST_ORACLE",
            predecessor_purposes=["SPEC_ARCHITECT", "BUILDER"],
            allow_simulated=allow_simulated,
        )
        if allow_simulated and iso_status == "CONTEXT_ISOLATION_NOT_PROVEN":
            iso_details = {
                "runtime_origin_status": "ALLOW_SIMULATED",
                "context_proof_hash": "simulated",
                "verifier_conversation_id": "simulated-test-oracle",
            }
        elif iso_status not in ("FRESH_CONTEXT_VERIFIED", "FRESH_CONTEXT_SIMULATED"):
            iso_reason = iso_details.get("reason", iso_status)
            if iso_status == "CONTEXT_REUSED" or "reused" in str(iso_reason).lower():
                reused_cid = iso_details.get("reused_conversation_id", "")
                return False, f"Test Oracle context isolation rejected: conversation ID ({reused_cid}) collides with predecessor: {iso_reason}", {}
            return False, f"Test Oracle context isolation rejected: {iso_reason}", {}

        # Pairwise conversation ID cross-check
        oracle_cid = iso_details.get("verifier_conversation_id")
        for pred_p in ["SPEC_ARCHITECT", "BUILDER"]:
            p_ctx = context_registry.get_registered_context_by_purpose(ws, pred_p)
            if p_ctx:
                p_cid = p_ctx.get("conversationId", "").strip()
                if oracle_cid and p_cid and oracle_cid.lower() == p_cid.lower():
                    return False, f"Test Oracle conversation ID ({oracle_cid}) collides with predecessor conversation ID ({p_cid})", {}
    else:
        iso_details = {
            "runtime_origin_status": "ALLOW_SIMULATED" if allow_simulated else "REGISTRY_UNAVAILABLE",
            "context_proof_hash": "simulated",
            "verifier_conversation_id": "simulated-test-oracle",
        }

    # 2. Validate proposal data
    req_id = str(proposal_data.get("requirementId", "")).strip()
    req_file = acc_dir / f"request-{req_id}.json"
    req_data = None
    if req_file.exists():
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                req_data = json.load(f)
        except Exception:
            pass

    is_valid, val_errors = validate_acceptance_proposal(proposal_data, req_data)
    if not is_valid:
        return False, f"Acceptance proposal validation failed: {'; '.join(val_errors)}", {}

    # 3. Format criteria strings
    raw_crits = proposal_data.get("criteria", [])
    norm_crits: List[str] = []
    for c in raw_crits:
        if isinstance(c, dict):
            norm_crits.append(f"Given {c.get('given', '').strip()} When {c.get('when', '').strip()} Then {c.get('then', '').strip()}")
        else:
            norm_crits.append(str(c).strip())

    # 4. Load requirements and update target requirement
    reqs: List[Dict[str, Any]] = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        reqs = kernel.load_requirements(ws)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        if r_file.exists():
            try:
                with open(r_file, "r", encoding="utf-8") as f:
                    reqs = json.load(f)
            except Exception:
                reqs = []

    target_req = None
    for r in reqs:
        if isinstance(r, dict) and r.get("id") == req_id:
            target_req = r
            break

    if not target_req:
        return False, f"Target requirement '{req_id}' not found in requirements.json", {}

    prop_hash = compute_acceptance_hash(proposal_data)
    old_status = target_req.get("status", "DISCOVERED")
    old_fp = target_req.get("contractFingerprint")

    # Update requirement fields
    target_req["acceptanceCriteria"] = norm_crits
    target_req["acceptanceStatus"] = "LOCKED"
    target_req["acceptanceLocked"] = True
    target_req["acceptanceAuthor"] = "test-oracle"
    target_req["acceptanceProof"] = {
        "conversationIdHash": hashlib.sha256(str(iso_details.get("verifier_conversation_id", "")).encode("utf-8")).hexdigest(),
        "contextProofHash": iso_details.get("context_proof_hash"),
        "proposalHash": prop_hash,
        "runtimeOriginStatus": iso_details.get("runtime_origin_status"),
        "lockedAt": utc_now_iso(),
    }
    target_req["updatedAt"] = utc_now_iso()

    # Recompute fingerprint V2
    if requirement_generator is not None and hasattr(requirement_generator, "compute_requirement_contract_fingerprint"):
        new_fp = requirement_generator.compute_requirement_contract_fingerprint(target_req)
        target_req["contractFingerprint"] = new_fp
        if old_status in ("PASS", "VERIFIED"):
            if old_fp and old_fp != new_fp:
                target_req["status"] = "STALE"
                target_req["previousStatus"] = old_status
                target_req["stalenessReason"] = "Acceptance contract locked/updated by Test Oracle; re-verification required"

    # Save updated requirements
    if kernel is not None and hasattr(kernel, "save_requirements"):
        kernel.save_requirements(ws, reqs)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        temp_file = r_file.with_suffix(".json.tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(reqs, f, indent=2, sort_keys=True)
        os.replace(temp_file, r_file)

    # Save proposal artifact
    prop_file = acc_dir / f"proposal-{req_id}.json"
    temp_prop = prop_file.with_suffix(".json.tmp")
    with open(temp_prop, "w", encoding="utf-8") as f:
        json.dump(proposal_data, f, indent=2, sort_keys=True)
    os.replace(temp_prop, prop_file)

    # Record event in decision ledger
    if decision_events is not None:
        decision_events.record_decision_event(
            workspace_dir=ws,
            event_type="ACCEPTANCE_CONTRACT_LOCKED",
            payload={
                "requirementId": req_id,
                "criteriaCount": len(norm_crits),
                "proposalHash": prop_hash,
                "author": "test-oracle",
            },
            actor="test-oracle",
        )

    return True, f"Acceptance contract locked for {req_id}", target_req
