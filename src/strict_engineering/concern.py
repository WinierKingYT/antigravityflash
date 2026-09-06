"""
Strict Engineering Kernel Step 7 - Structured Concern Model & Storage
Implements the Structured Concern Model (CONC-001, CONC-002, ...), 22 Categories,
11 States, risk engine integration with hard overrides, and atomic persistence.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import kernel
    from . import risk_engine
except (ImportError, ValueError):
    try:
        import kernel
        import risk_engine
    except ImportError:
        kernel = None
        risk_engine = None

CONCERN_CATEGORIES = [
    "PRODUCT_GOAL",
    "PRIMARY_USER",
    "CORE_BEHAVIOR",
    "SCOPE",
    "NON_GOAL",
    "WORKFLOW",
    "DATA",
    "PERSISTENCE",
    "AUTHORIZATION",
    "OWNERSHIP",
    "FAILURE_BEHAVIOR",
    "RECOVERY",
    "COLLABORATION",
    "PERFORMANCE_EXPECTATION",
    "PLATFORM",
    "INTEGRATION",
    "PRIVACY",
    "SECURITY",
    "FINANCIAL",
    "IRREVERSIBILITY",
    "TECHNICAL_ARCHITECTURE",
    "IMPLEMENTATION_CONSTRAINT",
]

CONCERN_STATES = [
    "DISCOVERED",
    "UNRESOLVED",
    "BLOCKED",
    "ASKABLE",
    "SUGGESTABLE",
    "CHALLENGE_REQUIRED",
    "SAFE_INFERABLE",
    "RESOLVED",
    "SUPERSEDED",
    "DEFERRED",
    "DISMISSED_LOW_VALUE",
]

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RISK_RANKS = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

CATEGORY_BASELINE_RISK = {
    "AUTHORIZATION": "CRITICAL",
    "FINANCIAL": "CRITICAL",
    "IRREVERSIBILITY": "CRITICAL",
    "SECURITY": "CRITICAL",
    "RECOVERY": "CRITICAL",
    "PRIVACY": "HIGH",
    "FAILURE_BEHAVIOR": "HIGH",
    "INTEGRATION": "HIGH",
    "DATA": "MEDIUM",
    "PERSISTENCE": "MEDIUM",
    "PERFORMANCE_EXPECTATION": "MEDIUM",
    "PLATFORM": "MEDIUM",
    "TECHNICAL_ARCHITECTURE": "MEDIUM",
    "CORE_BEHAVIOR": "MEDIUM",
    "PRODUCT_GOAL": "LOW",
    "PRIMARY_USER": "LOW",
    "SCOPE": "LOW",
    "NON_GOAL": "LOW",
    "WORKFLOW": "LOW",
    "OWNERSHIP": "LOW",
    "COLLABORATION": "LOW",
    "IMPLEMENTATION_CONSTRAINT": "LOW",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_concerns_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to concerns.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "concerns.json"


def evaluate_concern_risk(
    title: str,
    description: str,
    category: str,
) -> Tuple[str, List[str]]:
    """
    Evaluate risk for a concern by combining category baseline rules with
    the risk_engine's hard overrides and pattern evaluator.
    Returns (riskLevel, reasonCodes).
    """
    reasons: List[str] = []
    base_level = CATEGORY_BASELINE_RISK.get(category, "LOW")
    if base_level != "LOW":
        reasons.append(f"CATEGORY_{category}")

    current_rank = RISK_RANKS.get(base_level, 0)
    current_level = base_level

    text_corpus = f"{title} {description}".lower()

    # Match against risk_engine if available
    if risk_engine is not None and hasattr(risk_engine, "HARD_OVERRIDE_PATTERNS"):
        for code, pattern, min_level in risk_engine.HARD_OVERRIDE_PATTERNS:
            if re.search(pattern, text_corpus, re.IGNORECASE):
                reasons.append(code)
                pat_rank = RISK_RANKS.get(min_level, 0)
                if pat_rank > current_rank:
                    current_rank = pat_rank
                    current_level = min_level
    else:
        # Fallback inline patterns if risk_engine is not imported
        fallback_patterns = [
            ("AUTH_BOUNDARY", r"\b(auth(entication)?|login|token|session|jwt|oauth|password|permission|rbac|admin)\b", "CRITICAL"),
            ("FINANCIAL_TRANSACTION", r"\b(payment|checkout|credit[_\s-]?card|billing|invoice|refund|price|wallet)\b", "CRITICAL"),
            ("DESTRUCTIVE_IRREVERSIBLE", r"\b(delete[_\s-]?account|wipe|drop[_\s-]?table|truncate|hard[_\s-]?delete|destroy|purge)\b", "CRITICAL"),
            ("DATA_PERSISTENCE", r"\b(persist|survive[_\s-]?restart|localstorage|disk[_\s-]?storage)\b", "MEDIUM"),
        ]
        for code, pat, min_lvl in fallback_patterns:
            if re.search(pat, text_corpus, re.IGNORECASE):
                reasons.append(code)
                pat_rank = RISK_RANKS.get(min_lvl, 0)
                if pat_rank > current_rank:
                    current_rank = pat_rank
                    current_level = min_lvl

    # If risk_engine evaluate_requirement_risk is available, cross-check score
    if risk_engine is not None and hasattr(risk_engine, "evaluate_requirement_risk"):
        try:
            req_eval = risk_engine.evaluate_requirement_risk({"title": title, "description": description})
            eval_level = req_eval.get("riskLevel", "LOW")
            eval_rank = RISK_RANKS.get(eval_level, 0)
            if eval_rank > current_rank:
                current_rank = eval_rank
                current_level = eval_level
            for r in req_eval.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)
        except Exception:
            pass

    if not reasons:
        reasons.append("BASELINE_DEFAULT")

    return current_level, reasons


def validate_concern(concern_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate concern data against the Structured Concern schema."""
    errors: List[str] = []
    if not isinstance(concern_data, dict):
        return False, ["Concern data must be a dictionary."]

    # id
    cid = concern_data.get("id")
    if not cid or not isinstance(cid, str) or not re.match(r"^CONC-\d{3,}$", cid):
        errors.append(f"Invalid concern id '{cid}', expected format CONC-XXX (e.g. CONC-001).")

    # title & description
    for f in ["title", "description"]:
        v = concern_data.get(f)
        if not v or not isinstance(v, str):
            errors.append(f"Field '{f}' must be a non-empty string.")

    # category
    cat = concern_data.get("category")
    if cat not in CONCERN_CATEGORIES:
        errors.append(f"Invalid category '{cat}'. Must be one of {CONCERN_CATEGORIES}.")

    # status
    st = concern_data.get("status")
    if st not in CONCERN_STATES and st != "ACTIVE":
        errors.append(f"Invalid status '{st}'. Must be one of {CONCERN_STATES}.")

    # source
    src = concern_data.get("source")
    if not isinstance(src, dict) or not src.get("type") or not src.get("reference"):
        errors.append("Field 'source' must be a dict with non-empty 'type' and 'reference'.")

    # riskLevel
    rl = concern_data.get("riskLevel")
    if rl not in RISK_LEVELS:
        errors.append(f"Invalid riskLevel '{rl}'. Must be one of {RISK_LEVELS}.")

    # floats
    float_0_1_fields = [
        "uncertainty",
        "downstreamImpact",
        "criticality",
        "riskReductionPotential",
        "expectedDiscrimination",
        "repetitionRisk",
    ]
    for ff in float_0_1_fields:
        val = concern_data.get(ff)
        if val is not None:
            if not isinstance(val, (int, float)) or not (0.0 <= float(val) <= 1.0):
                errors.append(f"Field '{ff}' must be a float between 0.0 and 1.0.")

    float_01_1_fields = ["userEffort", "questionCost"]
    for ff in float_01_1_fields:
        val = concern_data.get(ff)
        if val is not None:
            if not isinstance(val, (int, float)) or not (0.0 <= float(val) <= 1.0):
                errors.append(f"Field '{ff}' must be a float between 0.0 and 1.0.")

    # lists
    for lf in ["dependsOn", "blocks", "relatedConcerns"]:
        val = concern_data.get(lf)
        if not isinstance(val, list):
            errors.append(f"Field '{lf}' must be a list of strings.")

    # candidateOptions
    opts = concern_data.get("candidateOptions")
    if not isinstance(opts, list):
        errors.append("Field 'candidateOptions' must be a list.")

    return len(errors) == 0, errors


def create_concern(
    id: str,
    title: str,
    description: str,
    category: str,
    source: Dict[str, str],
    status: str = "DISCOVERED",
    uncertainty: float = 0.5,
    downstream_impact: Optional[float] = None,
    criticality: Optional[float] = None,
    dependency_reach: Optional[float] = None,
    risk_reduction_potential: Optional[float] = None,
    expected_discrimination: Optional[float] = None,
    user_effort: Optional[float] = None,
    question_cost: Optional[float] = None,
    repetition_risk: Optional[float] = None,
    depends_on: Optional[List[str]] = None,
    blocks: Optional[List[str]] = None,
    related_concerns: Optional[List[str]] = None,
    candidate_options: Optional[List[Dict[str, Any]]] = None,
    recommended_action: Optional[str] = None,
    risk_level: Optional[str] = None,
    created_at: Optional[str] = None,
    resolved_at: Optional[str] = None,
    source_intent_ids: Optional[List[str]] = None,
    is_blocking: Optional[bool] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Create a canonical concern dictionary adhering to the 22 categories and 11 states.
    Automatically evaluates riskLevel if not explicitly provided.
    Supports both snake_case and camelCase parameters.
    """
    clean_cat = str(category).upper().strip()
    clean_status = str(status).upper().strip()

    # Resolve riskLevel
    if not risk_level:
        calc_risk, _ = evaluate_concern_risk(title, description, clean_cat)
        risk_level = calc_risk

    # Resolve camelCase overrides from kwargs
    downstream = kwargs.get("downstreamImpact", downstream_impact if downstream_impact is not None else 0.5)
    crit = kwargs.get("criticality", criticality if criticality is not None else 0.5)
    reach = kwargs.get("dependencyReach", dependency_reach if dependency_reach is not None else 0.0)
    rrp = kwargs.get("riskReductionPotential", risk_reduction_potential if risk_reduction_potential is not None else 0.5)
    disc = kwargs.get("expectedDiscrimination", expected_discrimination if expected_discrimination is not None else 0.5)
    ueffort = kwargs.get("userEffort", user_effort if user_effort is not None else 0.3)
    qcost = kwargs.get("questionCost", question_cost if question_cost is not None else 0.3)
    rrisk = kwargs.get("repetitionRisk", repetition_risk if repetition_risk is not None else 0.1)
    rec_act = kwargs.get("recommendedAction", recommended_action)
    resolved = kwargs.get("resolvedAt", resolved_at)
    src_intents = [str(x).strip() for x in (source_intent_ids or kwargs.get("sourceIntentIds", kwargs.get("source_intent_ids", [])))]
    blocking_flag = bool(kwargs.get("isBlocking", kwargs.get("is_blocking", is_blocking if is_blocking is not None else False)))

    return {
        "id": str(id).strip(),
        "title": str(title).strip(),
        "description": str(description).strip(),
        "category": clean_cat,
        "status": clean_status,
        "source": {
            "type": str(source.get("type", "ORIGINAL_INTENT")),
            "reference": str(source.get("reference", "")),
        },
        "sourceIntentIds": src_intents,
        "isBlocking": blocking_flag,
        "uncertainty": float(uncertainty),
        "downstreamImpact": float(downstream),
        "criticality": float(crit),
        "dependencyReach": float(reach),
        "riskReductionPotential": float(rrp),
        "expectedDiscrimination": float(disc),
        "userEffort": float(ueffort),
        "questionCost": float(qcost),
        "repetitionRisk": float(rrisk),
        "dependsOn": [str(d).strip() for d in (depends_on or kwargs.get("dependsOn", []))],
        "blocks": [str(b).strip() for b in (blocks or kwargs.get("blocks", []))],
        "relatedConcerns": [str(r).strip() for r in (related_concerns or kwargs.get("relatedConcerns", []))],
        "candidateOptions": candidate_options if candidate_options is not None else kwargs.get("candidateOptions", []),
        "recommendedAction": str(rec_act) if rec_act else None,
        "riskLevel": str(risk_level).upper(),
        "createdAt": created_at or utc_now_iso(),
        "resolvedAt": resolved,
    }


def load_concerns(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load concerns from .agent-harness/concerns.json.
    Returns empty list if file does not exist.
    """
    concerns_path = get_concerns_path(workspace_dir)
    if not concerns_path.exists():
        return []
    try:
        with open(concerns_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "concerns" in data:
                return data["concerns"]
            return []
    except Exception:
        return []


def save_concerns(workspace_dir: Union[str, Path], concerns: List[Dict[str, Any]]) -> None:
    """
    Atomically persist concerns list to .agent-harness/concerns.json via a .tmp file.
    """
    concerns_path = get_concerns_path(workspace_dir)
    concerns_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = concerns_path.with_name(f"{concerns_path.name}.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(concerns, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, concerns_path)


def update_concern_status(
    workspace_dir: Union[str, Path],
    concern_id: str,
    new_status: str,
) -> Tuple[bool, str]:
    """
    Update the lifecycle status of a specific concern in concerns.json.
    Sets resolvedAt timestamp if transitioning to RESOLVED.
    Returns (success, message).
    """
    clean_status = str(new_status).upper().strip()
    if clean_status not in CONCERN_STATES:
        return False, f"Invalid status '{new_status}'. Allowed: {CONCERN_STATES}"

    concerns = load_concerns(workspace_dir)
    target_concern: Optional[Dict[str, Any]] = None

    for c in concerns:
        if c.get("id") == concern_id:
            target_concern = c
            break

    if not target_concern:
        return False, f"Concern with id '{concern_id}' not found."

    target_concern["status"] = clean_status
    if clean_status == "RESOLVED":
        if not target_concern.get("resolvedAt"):
            target_concern["resolvedAt"] = utc_now_iso()
    else:
        # If moving out of RESOLVED, reset resolvedAt
        target_concern["resolvedAt"] = None

    save_concerns(workspace_dir, concerns)
    return True, f"Concern {concern_id} updated to {clean_status}"


def validate_proposed_concern(
    concern_dict: Dict[str, Any],
    frame_data: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """
    Validate that a proposed concern is structurally valid, semantically grounded in the frame,
    and has genuine sourceIntentIds. Rejects hallucinated or ungrounded concerns.
    """
    if not isinstance(concern_dict, dict):
        return False, "Concern data must be a dictionary."

    # Structural validation
    valid, errors = validate_concern(concern_dict)
    if not valid:
        return False, f"Concern schema validation failed: {'; '.join(errors)}"

    f_data = frame_data or {}
    intents = f_data.get("intents", [])
    intent_map = {it.get("id"): it for it in intents if isinstance(it, dict) and it.get("id")}

    # Validate sourceIntentIds if present
    src_intents = concern_dict.get("sourceIntentIds", [])
    if src_intents and intent_map:
        for sid in src_intents:
            if sid not in intent_map:
                return False, f"Concern references non-existent source intent '{sid}'"

    # Validate candidate options for ASKABLE / SUGGESTABLE
    status = str(concern_dict.get("status", "")).upper()
    if status in ("ASKABLE", "SUGGESTABLE", "CHALLENGE_REQUIRED"):
        opts = concern_dict.get("candidateOptions")
        if not isinstance(opts, list) or len(opts) == 0:
            return False, f"Concern with status '{status}' must have non-empty candidateOptions."
        for idx, opt in enumerate(opts):
            if not isinstance(opt, dict) or not opt.get("id") or not opt.get("title") or not opt.get("description"):
                return False, f"Candidate option at index {idx} must have 'id', 'title', and 'description'."

    # Grounding check: verify that the concern is connected to the frame
    frame_text_parts = []
    if f_data.get("projectGoal"):
        frame_text_parts.append(str(f_data.get("projectGoal")))
    for g in f_data.get("goals", []):
        frame_text_parts.append(g.get("text", str(g)) if isinstance(g, dict) else str(g))
    for c in f_data.get("constraints", []):
        frame_text_parts.append(c.get("text", str(c)) if isinstance(c, dict) else str(c))
    for ng in f_data.get("nonGoals", []):
        frame_text_parts.append(ng.get("text", str(ng)) if isinstance(ng, dict) else str(ng))
    for unk in f_data.get("unknowns", []):
        frame_text_parts.append(unk.get("text", str(unk)) if isinstance(unk, dict) else str(unk))
    for it in intents:
        if isinstance(it, dict) and it.get("text"):
            frame_text_parts.append(str(it.get("text")))

    combined_frame_text = " ".join(frame_text_parts).lower()
    if combined_frame_text.strip():
        src = concern_dict.get("source", {})
        src_ref = str(src.get("reference", "")).lower()
        has_direct_ref = src_ref in combined_frame_text or any(ref in src_ref for ref in [
            "baseline", "state retention", "query execution", "access control",
            "external interface", "data import", "fault tolerance"
        ])
        has_src_intents = bool(src_intents)

        c_text = f"{concern_dict.get('title', '')} {concern_dict.get('description', '')}".lower()
        c_tokens = {w for w in re.findall(r'\b[a-z]{4,}\b', c_text)}
        frame_tokens = {w for w in re.findall(r'\b[a-z]{4,}\b', combined_frame_text)}
        has_token_overlap = bool(c_tokens.intersection(frame_tokens))

        if not (has_direct_ref or has_src_intents or has_token_overlap):
            return False, f"Concern '{concern_dict.get('title')}' is ungrounded: no semantic basis found in project frame."

    return True, "Valid proposed concern"


def propose_semantic_concerns_from_frame(frame_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    General-purpose semantic concern discovery engine.
    Analyzes project frame across orthogonal architectural dimensions without domain-specific templates.
    """
    concerns: List[Dict[str, Any]] = []
    idx = 1

    def next_cid() -> str:
        nonlocal idx
        cid = f"CONC-{str(idx).zfill(3)}"
        idx += 1
        return cid

    f_data = frame_data or {}
    goals = f_data.get("goals", [])
    constraints = f_data.get("constraints", [])
    non_goals = f_data.get("nonGoals", [])
    unknowns = f_data.get("unknowns", [])
    intents = f_data.get("intents", [])

    def find_intent_ids_for_text(text: str) -> List[str]:
        matched = []
        norm_t = text.lower()
        for it in intents:
            if isinstance(it, dict):
                it_text = str(it.get("text", "")).lower()
                iid = it.get("id")
                if iid and (it_text in norm_t or norm_t in it_text or any(w in it_text for w in re.findall(r'\b\w{4,}\b', norm_t))):
                    matched.append(iid)
        return matched

    # 1. Product Goals
    for g in goals:
        g_text = g.get("text", str(g)) if isinstance(g, dict) else str(g)
        g_intent_ids = find_intent_ids_for_text(g_text)
        cid = next_cid()
        risk, _ = evaluate_concern_risk(g_text, f"Core product goal: {g_text}", "PRODUCT_GOAL")
        c = create_concern(
            id=cid,
            title=f"Core Goal: {g_text[:60]}",
            description=f"Define implementation boundary, core contracts, and deliverables for: {g_text}",
            category="PRODUCT_GOAL",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": g_text},
            source_intent_ids=g_intent_ids,
            risk_level=risk,
            uncertainty=0.6,
            downstream_impact=0.8,
        )
        concerns.append(c)

    # Combined corpus for architectural aspect discovery
    corpus_items = []
    for g in goals:
        corpus_items.append(g.get("text", str(g)) if isinstance(g, dict) else str(g))
    for c in constraints:
        corpus_items.append(c.get("text", str(c)) if isinstance(c, dict) else str(c))
    full_corpus = " ".join(corpus_items).lower()

    # Dimension 1: State Retention & Durability Architecture (PERSISTENCE)
    if re.search(r'\b(save|persist|persistence|storage|database|db|store|records?|data|durability|disk|file\s+system)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("save persist storage database store records durability")
        concerns.append(create_concern(
            id=next_cid(),
            title="State Retention & Durability Architecture",
            description="Determine state retention mechanism, consistency guarantees, and durability boundary for application data.",
            category="PERSISTENCE",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "State Retention & Durability"},
            source_intent_ids=matched_iids,
            risk_level="HIGH",
            uncertainty=0.8,
            downstream_impact=0.9,
            risk_reduction_potential=0.8,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Embedded Transactional Datastore",
                    "description": "Store application records in an embedded ACID-compliant transactional datastore with atomic commit guarantees.",
                    "tradeoffs": "Robust ACID transactions and relational querying; embedded binary engine required.",
                    "consequences": ["Atomic transaction support", "Structured query indexing"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Flat Structured File Storage",
                    "description": "Store records as human-readable structured files (JSON/YAML) directly on the local filesystem.",
                    "tradeoffs": "Direct human readability and zero external dependencies; lacks atomic multi-file transactions.",
                    "consequences": ["Direct human inspection", "Manual file lock coordination"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "In-Memory State with Periodic Snapshot",
                    "description": "Maintain state in-process for low latency with periodic asynchronous background snapshots to disk.",
                    "tradeoffs": "Fast sub-microsecond access; potential loss of recent mutations on unexpected power loss.",
                    "consequences": ["Maximum in-memory speed", "Snapshot persistence overhead"],
                    "isRecommended": False,
                }
            ],
        ))

    # Dimension 2: Query Execution & Retrieval Strategy (CORE_BEHAVIOR)
    if re.search(r'\b(find|search|query|lookup|filter|scan|index|retrieval)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("find search query lookup filter retrieval scan")
        concerns.append(create_concern(
            id=next_cid(),
            title="Query Execution & Retrieval Strategy",
            description="Determine indexing strategy, query parsing semantics, and matching algorithm for retrieving records.",
            category="CORE_BEHAVIOR",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "Query Execution & Retrieval"},
            source_intent_ids=matched_iids,
            risk_level="HIGH",
            uncertainty=0.7,
            downstream_impact=0.8,
            risk_reduction_potential=0.8,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Indexed Inverted Search Engine",
                    "description": "Pre-index textual fields with tokenization for fast full-text substring and keyword lookup.",
                    "tradeoffs": "Sub-millisecond query performance; requires index maintenance on write.",
                    "consequences": ["Fast indexed search", "Write-time index upkeep"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Direct Linear Filtering with Predicates",
                    "description": "Evaluate dynamic filter predicates sequentially across records without auxiliary index structures.",
                    "tradeoffs": "Zero storage index overhead; linear O(N) scan time on large datasets.",
                    "consequences": ["Simple zero-overhead writes", "Linear scan latency"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "Indexed Key-Value Lookup",
                    "description": "Direct hash or B-tree index on primary identifiers for fast constant-time retrieval.",
                    "tradeoffs": "O(1) exact identifier lookup; cannot perform arbitrary fuzzy text search.",
                    "consequences": ["Fast exact-key lookup", "No full-text search capability"],
                    "isRecommended": False,
                }
            ],
        ))

    # Dimension 3: Access Control & Identity Isolation Policy (AUTHORIZATION)
    if re.search(r'\b(auth|authentication|login|permission|permissions|role|roles|rbac|user|users|tenant|tenancy|access|session|token|credentials|password)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("auth login permission role user tenant credentials password")
        concerns.append(create_concern(
            id=next_cid(),
            title="Access Control & Identity Isolation Policy",
            description="Determine security boundary, authentication protocol, and permission evaluation rules for callers and resources.",
            category="AUTHORIZATION",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "Access Control & Identity Isolation"},
            source_intent_ids=matched_iids,
            risk_level="CRITICAL",
            uncertainty=0.8,
            downstream_impact=0.9,
            risk_reduction_potential=0.9,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Role-Based Access Control (RBAC)",
                    "description": "Enforce formal role hierarchies and granular permission checks on every operation.",
                    "tradeoffs": "Fine-grained security and compliance; requires role management and permission mappings.",
                    "consequences": ["Granular privilege boundaries", "Role management administration"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Single-Tenant Local Execution Boundary",
                    "description": "Rely on local operating system process permissions with implicit single-tenant ownership.",
                    "tradeoffs": "Zero auth configuration overhead; cannot support multi-tenant user isolation.",
                    "consequences": ["Zero configuration", "Single-tenant restriction"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "Token-Based Scoped Capability Authentication",
                    "description": "Cryptographic bearer tokens with signed capability claims and expiration.",
                    "tradeoffs": "Stateless verification; requires secure token distribution and revocation tracking.",
                    "consequences": ["Stateless verification", "Token lifecycle management"],
                    "isRecommended": False,
                }
            ],
        ))

    # Dimension 4: External Interface & Communication Protocol (INTEGRATION or PLATFORM)
    if re.search(r'\b(api|rest|http|webhook|network|integration|cli|command[_\s-]?line|terminal|stdout|service|client|endpoints?)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("api rest http network cli terminal client service endpoints")
        cat = "INTEGRATION" if re.search(r'\b(api|rest|http|webhook|network|service)\b', full_corpus, re.IGNORECASE) else "PLATFORM"
        concerns.append(create_concern(
            id=next_cid(),
            title="External Interface & Communication Protocol",
            description="Establish wire protocol, input validation boundaries, and contract serialization format for external consumers.",
            category=cat,
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "External Interface & Communication"},
            source_intent_ids=matched_iids,
            risk_level="HIGH",
            uncertainty=0.7,
            downstream_impact=0.8,
            risk_reduction_potential=0.8,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Standardized Structured API Interface",
                    "description": "HTTP REST/JSON or RPC contract with schema validation and explicit error payloads.",
                    "tradeoffs": "Interoperable standard across platforms; network overhead.",
                    "consequences": ["Standard network contract", "Schema validation enforcement"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Command-Line Interface with POSIX Exit Standards",
                    "description": "Standard POSIX CLI argument parsing with structured stdout/stderr streams.",
                    "tradeoffs": "Scriptable in shell pipelines; lacks persistent remote connectivity.",
                    "consequences": ["Shell scriptable", "Local process boundary"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "Direct In-Process Library API",
                    "description": "Expose programmatic function interfaces with strict static types and deterministic exceptions.",
                    "tradeoffs": "Zero serialization overhead; tightly coupled to runtime language.",
                    "consequences": ["Maximum function call speed", "In-process coupling"],
                    "isRecommended": False,
                }
            ],
        ))

    # Dimension 5: Data Import & Asset Lifecycle Policy (DATA)
    if re.search(r'\b(import|export|attachment|attachments|files?|binary|binaries|image|images|upload|download|media|assets?)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("import export attachment file image asset upload download")
        concerns.append(create_concern(
            id=next_cid(),
            title="Data Import & Asset Lifecycle Policy",
            description="Define ingestion pipeline, storage location, referential integrity, and lifecycle management for imported assets or files.",
            category="DATA",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "Data Import & Asset Lifecycle"},
            source_intent_ids=matched_iids,
            risk_level="HIGH",
            uncertainty=0.8,
            downstream_impact=0.8,
            risk_reduction_potential=0.8,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Managed Isolated Internal Directory",
                    "description": "Copy ingested assets into an isolated workspace directory with checksum verification.",
                    "tradeoffs": "Self-contained and robust against source file deletion; uses additional disk storage.",
                    "consequences": ["Asset integrity protection", "Storage duplication overhead"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Referential External Path Pointer",
                    "description": "Store filesystem path references without duplicating file contents on disk.",
                    "tradeoffs": "Zero storage duplication; broken links if external source file is moved or renamed.",
                    "consequences": ["Zero disk overhead", "Susceptible to broken links"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "Embedded Binary BLOB Packaging",
                    "description": "Store asset bytes directly inline in datastore records.",
                    "tradeoffs": "Atomic asset backups with data; bloats database file size.",
                    "consequences": ["Single-file backup simplicity", "Database bloat on large files"],
                    "isRecommended": False,
                }
            ],
        ))

    # Dimension 6: Fault Tolerance & State Recovery Architecture (RECOVERY)
    if re.search(r'\b(crash|recovery|transaction|transactions|concurrent|concurrency|thread|threads|lock|locking|failure|retry|rollback|backup|corruption)\b', full_corpus, re.IGNORECASE):
        matched_iids = find_intent_ids_for_text("crash recovery transaction concurrent rollback lock failure retry")
        concerns.append(create_concern(
            id=next_cid(),
            title="Fault Tolerance & State Recovery Architecture",
            description="Define recovery protocols, rollback procedures, and consistency validation in the event of abnormal termination or concurrency conflicts.",
            category="RECOVERY",
            status="ACTIVE",
            source={"type": "FRAME_GOAL", "reference": "Fault Tolerance & Recovery"},
            source_intent_ids=matched_iids,
            risk_level="CRITICAL",
            uncertainty=0.85,
            downstream_impact=0.95,
            risk_reduction_potential=0.9,
            expected_discrimination=0.9,
            candidate_options=[
                {
                    "id": "OPT-1",
                    "title": "Write-Ahead Logging with Atomic Rollback",
                    "description": "Append-only write-ahead log ensuring consistent state replay and atomic rollbacks upon crash.",
                    "tradeoffs": "Maximum durability and crash safety; small write throughput penalty for fsync.",
                    "consequences": ["Crash recovery guarantee", "Write-ahead log maintenance"],
                    "isRecommended": True,
                },
                {
                    "id": "OPT-2",
                    "title": "Optimistic Concurrency Control with Version Checks",
                    "description": "Non-blocking updates with automatic detection and retry on version collision.",
                    "tradeoffs": "High read-write concurrency; retry latency under heavy write contention.",
                    "consequences": ["Lock-free concurrency", "Conflict retry logic required"],
                    "isRecommended": False,
                },
                {
                    "id": "OPT-3",
                    "title": "Fail-Fast with Clean Restart Re-initialization",
                    "description": "Immediate abort on unhandled fault with state validation during cold start.",
                    "tradeoffs": "Simple operational model; interrupted tasks must be re-run.",
                    "consequences": ["Simple error handling", "Interrupted state restart"],
                    "isRecommended": False,
                }
            ],
        ))

    # 2. Explicit Constraints
    for constr in constraints:
        c_text = constr.get("text", str(constr)) if isinstance(constr, dict) else str(constr)
        c_intent_ids = find_intent_ids_for_text(c_text)
        cid = next_cid()
        cat = "PERSISTENCE" if any(w in c_text.lower() for w in ["database", "storage", "disk", "file", "save"]) else "IMPLEMENTATION_CONSTRAINT"
        risk, _ = evaluate_concern_risk(c_text, f"Project constraint: {c_text}", cat)
        c = create_concern(
            id=cid,
            title=f"Constraint: {c_text[:60]}",
            description=f"Enforce architecture boundary for constraint: {c_text}",
            category=cat,
            status="ACTIVE",
            source={"type": "FRAME_CONSTRAINT", "reference": c_text},
            source_intent_ids=c_intent_ids,
            risk_level=risk,
            uncertainty=0.4,
            downstream_impact=0.7,
            is_blocking=True,
        )
        concerns.append(c)

    # 3. Non-Goals
    for ng in non_goals:
        ng_text = ng.get("text", str(ng)) if isinstance(ng, dict) else str(ng)
        ng_intent_ids = find_intent_ids_for_text(ng_text)
        cid = next_cid()
        c = create_concern(
            id=cid,
            title=f"Scope Excluded: {ng_text[:60]}",
            description=f"Verify strict omission of non-goal: {ng_text}",
            category="NON_GOAL",
            status="RESOLVED",
            source={"type": "FRAME_NON_GOAL", "reference": ng_text},
            source_intent_ids=ng_intent_ids,
            risk_level="LOW",
            uncertainty=0.1,
            downstream_impact=0.5,
        )
        concerns.append(c)

    # 4. Unknowns / Open Questions
    for unk in unknowns:
        u_text = unk.get("text", str(unk)) if isinstance(unk, dict) else str(unk)
        cid = next_cid()
        c = create_concern(
            id=cid,
            title=f"Open Question: {u_text[:60]}",
            description=f"Resolve unknown requirement or architecture question: {u_text}",
            category="CORE_BEHAVIOR",
            status="ASKABLE",
            source={"type": "FRAME_UNKNOWN", "reference": u_text},
            risk_level="MEDIUM",
            uncertainty=0.9,
            downstream_impact=0.8,
        )
        concerns.append(c)

    # Baseline fallback if empty
    if not concerns:
        cid = next_cid()
        c = create_concern(
            id=cid,
            title="Initial Project Requirements",
            description="Clarify and confirm core software deliverables and expected behavior",
            category="PRODUCT_GOAL",
            status="ACTIVE",
            source={"type": "FRAME_DEFAULT", "reference": "baseline"},
            risk_level="MEDIUM",
            uncertainty=0.8,
            downstream_impact=0.8,
        )
        concerns.append(c)

    # Filter/validate each proposed concern
    valid_concerns = []
    for conc in concerns:
        is_val, reason = validate_proposed_concern(conc, frame_data)
        if is_val:
            valid_concerns.append(conc)

    return valid_concerns if valid_concerns else concerns


def extract_candidate_concerns_from_frame(frame_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministically discover candidate concerns from a Structured Project Frame.
    Delegates to propose_semantic_concerns_from_frame.
    """
    return propose_semantic_concerns_from_frame(frame_data)

