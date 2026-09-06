"""
Strict Engineering Kernel Step 7 - Decision Coverage Matrix
Implements the 4-tier traceability matrix:
  INTENT -> CONCERN -> DECISION -> REQ
Canonical persistence file: .agent-harness/decision-coverage.json.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, Set

try:
    from . import kernel
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
except (ImportError, ValueError):
    try:
        import kernel
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
    except ImportError:
        kernel = None
        frame_mod = None
        concern_mod = None
        decision_mod = None

COVERAGE_SCHEMA_VERSION = "7.0"

RESOLVED_CONCERN_STATES = {
    "RESOLVED",
    "SUPERSEDED",
    "DEFERRED",
    "DISMISSED_LOW_VALUE",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_decision_coverage_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to decision-coverage.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "decision-coverage.json"


def load_decision_coverage(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Load decision coverage matrix from .agent-harness/decision-coverage.json.
    Returns default empty structure if file does not exist.
    """
    cov_path = get_decision_coverage_path(workspace_dir)
    if not cov_path.exists():
        return {
            "schemaVersion": COVERAGE_SCHEMA_VERSION,
            "generatedAt": utc_now_iso(),
            "summary": {
                "intentCoverageRate": 1.0,
                "concernCoverageRate": 1.0,
                "decisionCoverageRate": 1.0,
                "requirementTraceabilityRate": 1.0,
                "isFullyCovered": False,
                "totalIntents": 0,
                "coveredIntents": 0,
                "totalConcerns": 0,
                "coveredConcerns": 0,
                "totalDecisions": 0,
                "coveredDecisions": 0,
                "totalRequirements": 0,
                "traceableRequirements": 0,
            },
            "matrix": {
                "intents": [],
                "concerns": [],
                "decisions": [],
                "requirements": [],
            },
            "orphanedRequirements": [],
            "uncoveredIntents": [],
            "uncoveredConcerns": [],
            "uncoveredDecisions": [],
        }

    try:
        with open(cov_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass

    return {
        "schemaVersion": COVERAGE_SCHEMA_VERSION,
        "generatedAt": utc_now_iso(),
        "summary": {
            "intentCoverageRate": 0.0,
            "concernCoverageRate": 0.0,
            "decisionCoverageRate": 0.0,
            "requirementTraceabilityRate": 0.0,
            "isFullyCovered": False,
            "totalIntents": 0,
            "coveredIntents": 0,
            "totalConcerns": 0,
            "coveredConcerns": 0,
            "totalDecisions": 0,
            "coveredDecisions": 0,
            "totalRequirements": 0,
            "traceableRequirements": 0,
        },
        "matrix": {},
        "orphanedRequirements": [],
        "uncoveredIntents": [],
        "uncoveredConcerns": [],
        "uncoveredDecisions": [],
    }


def save_decision_coverage(workspace_dir: Union[str, Path], coverage_data: Dict[str, Any]) -> None:
    """
    Atomically save decision coverage dictionary to .agent-harness/decision-coverage.json via .tmp.
    """
    cov_path = get_decision_coverage_path(workspace_dir)
    cov_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = cov_path.with_suffix(".json.tmp")

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(coverage_data, f, indent=2, sort_keys=True)
    os.replace(temp_path, cov_path)


def _tokenize(text: str) -> Set[str]:
    cleaned = re.sub(r"[^\w\s]", " ", str(text).lower())
    return {w for w in cleaned.split() if len(w) > 2}


def build_decision_coverage_matrix(
    frame: Optional[Dict[str, Any]],
    concerns: Union[List[Dict[str, Any]], Dict[str, Any]],
    decisions: Union[List[Dict[str, Any]], Dict[str, Any]],
    requirements: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Construct the 4-tier decision coverage matrix:
      Tier 1: Intent -> Concern
      Tier 2: Concern -> Decision
      Tier 3: Decision -> Requirement
      Tier 4: Requirement -> Trace
    """
    f_data = frame or {}

    # Normalize concerns
    c_list: List[Dict[str, Any]] = []
    if isinstance(concerns, list):
        c_list = concerns
    elif isinstance(concerns, dict):
        c_list = concerns.get("concerns", list(concerns.values()))

    # Normalize decisions
    d_list: List[Dict[str, Any]] = []
    if isinstance(decisions, list):
        d_list = decisions
    elif isinstance(decisions, dict):
        d_list = decisions.get("decisions", list(decisions.values()))

    # Normalize requirements
    r_list: List[Dict[str, Any]] = []
    if requirements:
        if isinstance(requirements, list):
            r_list = requirements
        elif isinstance(requirements, dict):
            r_list = requirements.get("requirements", list(requirements.values()))

    c_map: Dict[str, Dict[str, Any]] = {c.get("id"): c for c in c_list if c.get("id")}
    d_map: Dict[str, Dict[str, Any]] = {d.get("id"): d for d in d_list if d.get("id")}
    r_map: Dict[str, Dict[str, Any]] = {r.get("id") or r.get("req_id"): r for r in r_list if (r.get("id") or r.get("req_id"))}

    # 1. Tier 1: Intents from Frame
    intents: List[Dict[str, Any]] = []
    intent_idx = 0

    # Goals
    for g in f_data.get("goals", []):
        intents.append({
            "intentId": f"INTENT-GOAL-{intent_idx}",
            "type": "GOAL",
            "text": str(g),
            "concerns": [],
        })
        intent_idx += 1

    # Constraints
    c_idx = 0
    for c in f_data.get("constraints", []):
        intents.append({
            "intentId": f"INTENT-CONST-{c_idx}",
            "type": "CONSTRAINT",
            "text": str(c),
            "concerns": [],
        })
        c_idx += 1

    # Non-goals
    ng_idx = 0
    for ng in f_data.get("nonGoals", []):
        intents.append({
            "intentId": f"INTENT-NONGOAL-{ng_idx}",
            "type": "NON_GOAL",
            "text": str(ng),
            "concerns": [],
        })
        ng_idx += 1

    # Link Intents -> Concerns
    for intent in intents:
        i_tokens = _tokenize(intent["text"])
        i_id = intent["intentId"]
        for c in c_list:
            cid = c.get("id")
            c_text = f"{c.get('title', '')} {c.get('sourceText', '')} {c.get('description', '')}".lower()
            c_tokens = _tokenize(c_text)
            explicit_intent = c.get("intentId") or c.get("sourceIntent")
            if explicit_intent == i_id or (i_tokens and len(i_tokens.intersection(c_tokens)) >= 1):
                if cid not in intent["concerns"]:
                    intent["concerns"].append(cid)

    # 2. Tier 2: Concerns -> Decisions
    concern_matrix: List[Dict[str, Any]] = []
    for c in c_list:
        cid = c.get("id")
        c_status = str(c.get("status", "DISCOVERED")).upper()
        c_decisions: List[str] = []
        for d in d_list:
            did = d.get("id")
            if d.get("concernId") == cid:
                c_decisions.append(did)
            elif cid in d.get("affectedConcerns", []):
                c_decisions.append(did)

        concern_matrix.append({
            "concernId": cid,
            "category": c.get("category", ""),
            "status": c_status,
            "decisions": sorted(list(set(c_decisions))),
        })

    # 3. Tier 3: Decisions -> Requirements
    active_decisions = [d for d in d_list if not d.get("supersededBy") and str(d.get("status", "ACTIVE")).upper() != "SUPERSEDED"]
    decision_matrix: List[Dict[str, Any]] = []
    for d in d_list:
        did = d.get("id")
        d_status = "SUPERSEDED" if d.get("supersededBy") else str(d.get("status", "ACTIVE")).upper()
        d_reqs: List[str] = []
        for r in r_list:
            rid = r.get("id") or r.get("req_id")
            sources = r.get("sources", [])
            d_ref = r.get("decisionId") or r.get("sourceDecision")
            if d_ref == did or did in sources or did in r.get("trace", []):
                d_reqs.append(rid)
        for aff_r in d.get("affectedRequirements", []):
            if aff_r not in d_reqs:
                d_reqs.append(aff_r)

        decision_matrix.append({
            "decisionId": did,
            "title": d.get("title", ""),
            "status": d_status,
            "requirements": sorted(list(set(d_reqs))),
        })

    # 4. Tier 4: Requirements -> Traces & Orphan detection
    requirement_matrix: List[Dict[str, Any]] = []
    orphaned_reqs: List[str] = []
    traceable_reqs: List[str] = []

    for r in r_list:
        rid = r.get("id") or r.get("req_id")
        d_ref = r.get("decisionId") or r.get("sourceDecision")
        c_ref = r.get("concernId") or r.get("sourceConcern")
        sources = r.get("sources", [])

        # Check if requirement has any valid trace
        has_trace = False
        valid_sources: List[str] = []
        if d_ref and (d_ref in d_map or any(d["decisionId"] == d_ref for d in decision_matrix)):
            has_trace = True
            valid_sources.append(d_ref)
        if c_ref and (c_ref in c_map or any(c["concernId"] == c_ref for c in concern_matrix)):
            has_trace = True
            valid_sources.append(c_ref)
        for s in sources:
            if s in d_map or s in c_map or any(i["intentId"] == s for i in intents):
                has_trace = True
                valid_sources.append(s)

        if has_trace:
            traceable_reqs.append(rid)
        else:
            orphaned_reqs.append(rid)

        requirement_matrix.append({
            "requirementId": rid,
            "sources": sorted(list(set(valid_sources))),
            "isOrphaned": not has_trace,
        })

    # Coverage summary metrics
    total_intents = len(intents)
    covered_intents = len([i for i in intents if len(i["concerns"]) > 0])
    uncovered_intents = [i["intentId"] for i in intents if len(i["concerns"]) == 0]

    total_concerns = len(concern_matrix)
    # A concern is covered if it has decisions OR is in a resolved/deferred/dismissed state
    covered_concerns = len([
        c for c in concern_matrix
        if len(c["decisions"]) > 0 or c["status"] in RESOLVED_CONCERN_STATES
    ])
    uncovered_concerns = [
        c["concernId"] for c in concern_matrix
        if len(c["decisions"]) == 0 and c["status"] not in RESOLVED_CONCERN_STATES
    ]

    total_active_decisions = len(active_decisions)
    if r_list:
        # If requirements exist, active decisions are covered if they link to at least 1 requirement
        covered_decisions_list = [
            d["decisionId"] for d in decision_matrix
            if d["status"] != "SUPERSEDED" and len(d["requirements"]) > 0
        ]
        uncovered_decisions = [
            d["decisionId"] for d in decision_matrix
            if d["status"] != "SUPERSEDED" and len(d["requirements"]) == 0
        ]
        covered_decisions = len(covered_decisions_list)
    else:
        # In discovery phase prior to spec generation, active decisions are covered if valid
        covered_decisions = total_active_decisions
        uncovered_decisions = []

    total_requirements = len(r_list)
    traceable_count = len(traceable_reqs)

    intent_rate = (covered_intents / total_intents) if total_intents > 0 else 1.0
    concern_rate = (covered_concerns / total_concerns) if total_concerns > 0 else 1.0
    decision_rate = (covered_decisions / total_active_decisions) if total_active_decisions > 0 else 1.0
    req_rate = (traceable_count / total_requirements) if total_requirements > 0 else 1.0

    is_fully_covered = (
        intent_rate >= 1.0
        and concern_rate >= 1.0
        and decision_rate >= 1.0
        and req_rate >= 1.0
        and len(orphaned_reqs) == 0
    )

    return {
        "schemaVersion": COVERAGE_SCHEMA_VERSION,
        "generatedAt": utc_now_iso(),
        "summary": {
            "intentCoverageRate": round(intent_rate, 4),
            "concernCoverageRate": round(concern_rate, 4),
            "decisionCoverageRate": round(decision_rate, 4),
            "requirementTraceabilityRate": round(req_rate, 4),
            "isFullyCovered": is_fully_covered,
            "totalIntents": total_intents,
            "coveredIntents": covered_intents,
            "totalConcerns": total_concerns,
            "coveredConcerns": covered_concerns,
            "totalDecisions": total_active_decisions,
            "coveredDecisions": covered_decisions,
            "totalRequirements": total_requirements,
            "traceableRequirements": traceable_count,
        },
        "matrix": {
            "intents": intents,
            "concerns": concern_matrix,
            "decisions": decision_matrix,
            "requirements": requirement_matrix,
        },
        "orphanedRequirements": orphaned_reqs,
        "uncoveredIntents": uncovered_intents,
        "uncoveredConcerns": uncovered_concerns,
        "uncoveredDecisions": uncovered_decisions,
    }


def sync_decision_coverage(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Load workspace frame, concerns, decisions, and requirements,
    build coverage matrix, save to .agent-harness/decision-coverage.json,
    and return coverage dictionary.
    """
    ws = Path(workspace_dir).resolve()

    # Load frame
    frame_data = None
    if frame_mod is not None:
        frame_data = frame_mod.load_frame(ws)
    else:
        f_path = ws / ".agent-harness" / "frame.json"
        if f_path.exists():
            try:
                with open(f_path, "r", encoding="utf-8") as f:
                    frame_data = json.load(f)
            except Exception:
                frame_data = None

    # Load concerns
    concerns_list = []
    if concern_mod is not None:
        concerns_list = concern_mod.load_concerns(ws)
    else:
        c_path = ws / ".agent-harness" / "concerns.json"
        if c_path.exists():
            try:
                with open(c_path, "r", encoding="utf-8") as f:
                    concerns_list = json.load(f)
            except Exception:
                concerns_list = []

    # Load decisions
    decisions_list = []
    if decision_mod is not None:
        decisions_list = decision_mod.load_decisions(ws)
    else:
        d_path = ws / ".agent-harness" / "decisions.json"
        if d_path.exists():
            try:
                with open(d_path, "r", encoding="utf-8") as f:
                    decisions_list = json.load(f)
            except Exception:
                decisions_list = []

    # Load requirements
    requirements_list = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        requirements_list = kernel.load_requirements(ws)
    else:
        r_path = ws / ".agent-harness" / "requirements.json"
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    requirements_list = json.load(f)
            except Exception:
                requirements_list = []

    cov_data = build_decision_coverage_matrix(
        frame=frame_data,
        concerns=concerns_list,
        decisions=decisions_list,
        requirements=requirements_list,
    )

    save_decision_coverage(ws, cov_data)
    return cov_data
