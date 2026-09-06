"""
Strict Engineering Kernel Step 7 - Consistency Reviewer
Read-only consistency auditor enforcing alignment across:
  Frame <-> Concerns <-> Decisions <-> Graph.
Audits for:
  1. Frame Contradictions (non-goal / constraint violations)
  2. Unsafe Model Inferences (unconfirmed critical choices)
  3. Conflicting Active Decisions
  4. Broken Dependencies
  5. Scope Drift / Feature Bloat
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, Set

try:
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
    from . import decision_graph
except (ImportError, ValueError):
    try:
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
        import decision_graph
    except ImportError:
        frame_mod = None
        concern_mod = None
        decision_mod = None
        decision_graph = None

UNSAFE_CATEGORIES = {
    "AUTHORIZATION",
    "FINANCIAL",
    "PRIVACY",
    "SECURITY",
    "OWNERSHIP",
    "IRREVERSIBILITY",
    "PERSISTENCE",
}

UNSAFE_KEYWORDS = [
    "delete",
    "deletion",
    "wipe",
    "purge",
    "drop database",
    "billing",
    "payment",
    "credit card",
    "subscription",
    "charge",
    "password",
    "secret",
    "token",
    "credential",
    "permission",
    "rbac",
    "role",
    "admin",
    "sudo",
    "multi-tenant",
    "public access",
    "unauthenticated",
]

USER_AUTHORITIES = {"USER", "USER_DIRECT", "USER_CONFIRMED", "USER_APPROVED_SUGGESTION"}


def _normalize_tokens(text: str) -> Set[str]:
    """Tokenize and normalize text for keyword matching."""
    cleaned = re.sub(r"[^\w\s]", " ", str(text).lower())
    return {w for w in cleaned.split() if len(w) > 2}


def review_decision_consistency(
    frame: Optional[Dict[str, Any]],
    concerns: Union[List[Dict[str, Any]], Dict[str, Any]],
    decisions: Union[List[Dict[str, Any]], Dict[str, Any]],
    graph_data: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Perform a read-only audit of decisions against the project frame, concerns, and graph.
    Returns (is_consistent, issues_list).
    is_consistent is True iff there are zero BLOCKING issues.
    """
    # Normalize inputs
    f_data = frame or {}
    
    c_list: List[Dict[str, Any]] = []
    if isinstance(concerns, list):
        c_list = concerns
    elif isinstance(concerns, dict):
        c_list = concerns.get("concerns", list(concerns.values()))

    d_list: List[Dict[str, Any]] = []
    if isinstance(decisions, list):
        d_list = decisions
    elif isinstance(decisions, dict):
        d_list = decisions.get("decisions", list(decisions.values()))

    c_map: Dict[str, Dict[str, Any]] = {c.get("id"): c for c in c_list if c.get("id")}
    d_map: Dict[str, Dict[str, Any]] = {d.get("id"): d for d in d_list if d.get("id")}

    issues: List[Dict[str, Any]] = []

    non_goals = f_data.get("nonGoals", [])
    constraints = f_data.get("constraints", [])
    goals = f_data.get("goals", [])

    # Active (non-superseded) decisions
    active_decisions = [d for d in d_list if not d.get("supersededBy") and str(d.get("status", "ACTIVE")).upper() != "SUPERSEDED"]

    # 1. FRAME CONTRADICTIONS: Check non-goals and constraints
    for d in active_decisions:
        did = d.get("id", "UNKNOWN")
        d_title = str(d.get("title", ""))
        d_option = str(d.get("chosenOption", ""))
        d_rationale = str(d.get("rationale", ""))
        d_text = f"{d_title} {d_option} {d_rationale}".lower()
        d_tokens = _normalize_tokens(d_text)

        # Non-goal contradictions
        for ng in non_goals:
            ng_text = str(ng).strip()
            ng_tokens = _normalize_tokens(ng_text)
            # Check for strong keyword intersection with non-goal
            # e.g., non-goal "No cloud sync", decision chooses "Enable AWS cloud sync"
            if len(ng_tokens) >= 2:
                matching = ng_tokens.intersection(d_tokens)
                # If majority of non-goal key terms are positively chosen in the decision
                if len(matching) >= 2 and any(k in d_text for k in ["enable", "implement", "use", "add", "support", "choose"]):
                    issues.append({
                        "code": "FRAME_CONTRADICTION",
                        "severity": "BLOCKING",
                        "message": (
                            f"Decision {did} ('{d_title}') contradicts project non-goal: '{ng_text}'"
                        ),
                        "affectedNodes": [did],
                        "recommendation": f"Remove or alter decision {did} to respect non-goal '{ng_text}'.",
                    })

        # Constraint contradictions (e.g. offline only vs remote server)
        for constr in constraints:
            c_text = str(constr).lower()
            if "offline" in c_text or "local only" in c_text or "no internet" in c_text:
                if any(net_term in d_text for net_term in ["cloud", "firebase", "aws", "remote server", "external api", "rest api"]):
                    issues.append({
                        "code": "FRAME_CONTRADICTION",
                        "severity": "BLOCKING",
                        "message": (
                            f"Decision {did} ('{d_title}') violates hard constraint: '{constr}'"
                        ),
                        "affectedNodes": [did],
                        "recommendation": f"Ensure decision {did} is compatible with local/offline constraint.",
                    })
            if "single user" in c_text or "no collaboration" in c_text:
                if any(collab_term in d_text for collab_term in ["multi-user", "collaboration", "realtime sync", "websocket sync"]):
                    issues.append({
                        "code": "FRAME_CONTRADICTION",
                        "severity": "BLOCKING",
                        "message": (
                            f"Decision {did} ('{d_title}') violates constraint: '{constr}'"
                        ),
                        "affectedNodes": [did],
                        "recommendation": f"Revert or adjust decision {did} to maintain single-user scope.",
                    })

    # 2. UNSAFE MODEL INFERENCES (INV-7-06)
    for d in active_decisions:
        did = d.get("id", "UNKNOWN")
        authority = str(d.get("authority", "MODEL_DEFAULT")).upper()
        cid = d.get("concernId")
        associated_concern = c_map.get(cid, {}) if cid else {}
        concern_category = str(associated_concern.get("category", "")).upper()
        concern_risk = str(associated_concern.get("riskLevel", "")).upper()

        d_text = f"{d.get('title', '')} {d.get('chosenOption', '')}".lower()

        is_unsafe = False
        unsafe_reason = ""

        if concern_category in UNSAFE_CATEGORIES:
            is_unsafe = True
            unsafe_reason = f"Concern category is '{concern_category}'"
        elif concern_risk == "CRITICAL":
            is_unsafe = True
            unsafe_reason = "Concern riskLevel is CRITICAL"
        else:
            for kw in UNSAFE_KEYWORDS:
                if kw in d_text:
                    is_unsafe = True
                    unsafe_reason = f"Contains sensitive keyword '{kw}'"
                    break

        if is_unsafe and authority not in USER_AUTHORITIES:
            issues.append({
                "code": "UNSAFE_INFERENCE",
                "severity": "BLOCKING",
                "message": (
                    f"Decision {did} made with authority '{authority}' on unsafe topic ({unsafe_reason}) "
                    "without explicit user confirmation (INV-7-06)."
                ),
                "affectedNodes": [did],
                "recommendation": "Prompt user directly for decision confirmation.",
            })

    # 3. CONFLICTING ACTIVE DECISIONS
    # Group active decisions by concernId
    concern_to_decisions: Dict[str, List[Dict[str, Any]]] = {}
    for d in active_decisions:
        cid = d.get("concernId")
        if cid:
            concern_to_decisions.setdefault(cid, []).append(d)

    for cid, d_group in concern_to_decisions.items():
        if len(d_group) > 1:
            # Multiple active decisions for the same concern without supersession!
            # Check if their chosen options differ
            distinct_options = {d.get("chosenOption") for d in d_group}
            if len(distinct_options) > 1:
                conflicting_ids = [d.get("id") for d in d_group]
                issues.append({
                    "code": "CONFLICTING_DECISIONS",
                    "severity": "BLOCKING",
                    "message": (
                        f"Multiple active conflicting decisions {conflicting_ids} found for concern {cid} "
                        f"with options: {distinct_options}"
                    ),
                    "affectedNodes": conflicting_ids,
                    "recommendation": "Supersede earlier decisions so only one active decision resolves the concern.",
                })

    # 4. BROKEN DEPENDENCIES
    for d in active_decisions:
        did = d.get("id", "UNKNOWN")
        deps = d.get("dependsOn", [])
        for dep_id in deps:
            if dep_id not in d_map:
                issues.append({
                    "code": "BROKEN_DEPENDENCY",
                    "severity": "BLOCKING",
                    "message": f"Decision {did} depends on non-existent decision '{dep_id}'.",
                    "affectedNodes": [did],
                    "recommendation": f"Create prerequisite decision '{dep_id}' or remove broken dependency link.",
                })
            else:
                dep_decision = d_map[dep_id]
                if dep_decision.get("supersededBy"):
                    issues.append({
                        "code": "BROKEN_DEPENDENCY",
                        "severity": "BLOCKING",
                        "message": (
                            f"Decision {did} depends on decision '{dep_id}' which has been superseded by "
                            f"'{dep_decision.get('supersededBy')}'. Trace link is stale."
                        ),
                        "affectedNodes": [did, dep_id],
                        "recommendation": f"Update dependency of {did} to point to '{dep_decision.get('supersededBy')}'.",
                    })

    # 5. SCOPE DRIFT / UNPROMPTED FEATURE BLOAT (WARNING)
    if goals:
        all_goal_tokens: Set[str] = set()
        for g in goals:
            all_goal_tokens.update(_normalize_tokens(g))
        
        for d in active_decisions:
            did = d.get("id", "UNKNOWN")
            d_tokens = _normalize_tokens(d.get("title", ""))
            # If decision is not linked to any recognized concern
            cid = d.get("concernId")
            if not cid or cid not in c_map:
                # Check keyword overlap with goals
                if not d_tokens.intersection(all_goal_tokens):
                    issues.append({
                        "code": "SCOPE_DRIFT",
                        "severity": "WARNING",
                        "message": f"Decision {did} ('{d.get('title')}') has no link to known concerns and low goal relevance.",
                        "affectedNodes": [did],
                        "recommendation": "Verify whether this decision is in scope with original project goals.",
                    })

    is_consistent = not any(issue.get("severity") == "BLOCKING" for issue in issues)
    return is_consistent, issues


def audit_workspace_consistency(workspace_dir: Union[str, Path]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Load frame, concerns, decisions, and graph from workspace and perform consistency audit.
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

    # Load graph
    graph_data = None
    if decision_graph is not None:
        graph_data = decision_graph.load_decision_graph(ws)

    return review_decision_consistency(
        frame=frame_data,
        concerns=concerns_list,
        decisions=decisions_list,
        graph_data=graph_data,
    )
