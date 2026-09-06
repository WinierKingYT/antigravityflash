"""
Strict Engineering Kernel Step 7 - Requirement Generator & Transition Gate
Compiles atomic, verifiable requirements (REQ-xxx) from canonical decisions.
Enforces the DISCOVERY -> SPECIFICATION transition gate.
Isolates suggestions (SUG-xxx) in a separate sandbox.
"""

import os
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import kernel
    from . import risk_engine
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
    from . import decision_graph
    from . import stopping_engine
    from . import consistency_reviewer
    from . import decision_coverage
    from . import decision_events
except (ImportError, ValueError):
    try:
        import kernel
        import risk_engine
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
        import decision_graph
        import stopping_engine
        import consistency_reviewer
        import decision_coverage
        import decision_events
    except ImportError:
        kernel = None
        risk_engine = None
        frame_mod = None
        concern_mod = None
        decision_mod = None
        decision_graph = None
        stopping_engine = None
        consistency_reviewer = None
        decision_coverage = None
        decision_events = None


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_suggestions_path(workspace_dir: Union[str, Path]) -> Path:
    """Return absolute path to suggestions.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "suggestions.json"


def load_suggestions(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load suggestions from suggestions.json."""
    s_path = get_suggestions_path(workspace_dir)
    if not s_path.exists():
        return []
    try:
        with open(s_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_suggestions(workspace_dir: Union[str, Path], suggestions: List[Dict[str, Any]]) -> None:
    """Atomically save suggestions to suggestions.json."""
    s_path = get_suggestions_path(workspace_dir)
    s_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = s_path.with_suffix(".json.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(suggestions, f, indent=2, sort_keys=True)
    os.replace(temp_path, s_path)


def record_suggestion_sandbox(
    workspace_dir: Union[str, Path],
    title: str,
    description: str,
    source_concern_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Record an unconfirmed idea or model recommendation into the SUGGESTION sandbox (SUG-xxx).
    SUG-xxx items are strictly excluded from requirements.json (INV-7-01, INV-7-03).
    """
    existing = load_suggestions(workspace_dir)
    next_num = len(existing) + 1
    sug_id = f"SUG-{str(next_num).zfill(3)}"

    sug = {
        "id": sug_id,
        "title": title,
        "description": description,
        "sourceConcernId": source_concern_id,
        "status": "SANDBOXED",
        "createdAt": utc_now_iso(),
        "metadata": metadata or {},
    }
    existing.append(sug)
    save_suggestions(workspace_dir, existing)
    return sug


def compile_requirements_from_decisions(
    workspace_dir: Union[str, Path],
    force: bool = False,
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Compile atomic requirements from confirmed decisions in .agent-harness/decisions.json.
    
    Transition Gates checked:
    1. Decision Status: canProceedToSpec must be True (stopping conditions satisfied).
    2. Decision Consistency: review_decision_consistency must yield zero BLOCKING issues.
    3. Graph Validation: decision graph must be valid DAG with no cycles.
    
    If gates pass (or force=True):
    - Transforms active decisions into atomic REQ-xxx objects.
    - Evaluates requirement risk level via risk_engine.
    - Persists to .agent-harness/requirements.json.
    - Syncs decision coverage and graph.
    - Records REQUIREMENTS_GENERATED event.
    """
    ws = Path(workspace_dir).resolve()

    # 1. Gate Check: Stopping conditions
    if not force:
        if stopping_engine is not None:
            status_path = stopping_engine.get_decision_status_path(ws)
            if status_path.exists():
                status_data = stopping_engine.load_decision_status(ws)
            else:
                status_data = stopping_engine.sync_decision_status(ws)
            if not status_data.get("canProceedToSpec", False):
                return False, f"Discovery stopping gate blocked: {status_data.get('reason', 'Conditions not met')}", []

        # 2. Gate Check: Consistency review
        if consistency_reviewer is not None:
            is_consistent, issues = consistency_reviewer.audit_workspace_consistency(ws)
            if not is_consistent:
                blocking_msgs = [i["message"] for i in issues if i.get("severity") == "BLOCKING"]
                return False, f"Consistency review gate blocked: {'; '.join(blocking_msgs)}", []

        # 3. Gate Check: Graph validation
        if decision_graph is not None:
            graph_data = decision_graph.load_decision_graph(ws)
            valid, g_errors = decision_graph.validate_decision_graph(graph_data)
            if not valid:
                return False, f"Decision graph validation gate blocked: {'; '.join(g_errors)}", []

    # Load decisions & concerns
    decisions_list = []
    if decision_mod is not None:
        decisions_list = decision_mod.load_decisions(ws)
    else:
        d_path = ws / ".agent-harness" / "decisions.json"
        if d_path.exists():
            with open(d_path, "r", encoding="utf-8") as f:
                decisions_list = json.load(f)

    concerns_list = []
    if concern_mod is not None:
        concerns_list = concern_mod.load_concerns(ws)
    else:
        c_path = ws / ".agent-harness" / "concerns.json"
        if c_path.exists():
            with open(c_path, "r", encoding="utf-8") as f:
                concerns_list = json.load(f)

    c_map = {c.get("id"): c for c in concerns_list if c.get("id")}

    # Active (non-superseded) decisions
    active_decisions = [
        d for d in decisions_list
        if not d.get("supersededBy") and str(d.get("status", "ACTIVE")).upper() != "SUPERSEDED"
    ]

    if not active_decisions:
        return False, "No active decisions available to compile requirements from", []

    # Load existing requirements to preserve IDs if previously generated
    existing_reqs = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        existing_reqs = kernel.load_requirements(ws)
    else:
        r_path = ws / ".agent-harness" / "requirements.json"
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    existing_reqs = json.load(f)
            except Exception:
                existing_reqs = []

    dec_to_existing_req: Dict[str, Dict[str, Any]] = {}
    for r in existing_reqs:
        d_id = r.get("decisionId")
        if d_id:
            dec_to_existing_req[d_id] = r

    compiled_reqs: List[Dict[str, Any]] = []
    req_index = 1

    for d in active_decisions:
        did = d.get("id", "UNKNOWN")
        cid = d.get("concernId")
        associated_concern = c_map.get(cid, {})

        # Reuse existing requirement ID if mapped, else create new
        if did in dec_to_existing_req:
            req_id = dec_to_existing_req[did].get("id", f"REQ-{str(req_index).zfill(3)}")
            prev_status = dec_to_existing_req[did].get("status", "DISCOVERED")
        else:
            req_id = f"REQ-{str(req_index).zfill(3)}"
            prev_status = "DISCOVERED"
        req_index += 1

        title = d.get("title", f"Requirement for {did}")
        chosen_opt = d.get("chosenOption", "")
        rationale = d.get("rationale", "")

        description = f"The system shall implement {title}: {chosen_opt}."
        if rationale:
            description += f" (Rationale: {rationale})"

        # Determine risk level
        concern_risk = associated_concern.get("riskLevel")
        if not concern_risk and risk_engine is not None and hasattr(risk_engine, "evaluate_requirement_risk"):
            try:
                r_eval = risk_engine.evaluate_requirement_risk({"title": title, "description": description})
                concern_risk = r_eval.get("level", "MEDIUM") if isinstance(r_eval, dict) else "MEDIUM"
            except Exception:
                concern_risk = "MEDIUM"
        if not concern_risk:
            concern_risk = "MEDIUM"

        intent_ref = associated_concern.get("source", {}).get("reference", "ORIGINAL_INTENT")
        req_obj = {
            "id": req_id,
            "title": title,
            "description": description,
            "category": associated_concern.get("category", "CORE_BEHAVIOR"),
            "status": prev_status,
            "required": True,
            "riskLevel": concern_risk,
            "decisionId": did,
            "concernId": cid,
            "intentId": intent_ref,
            "sources": [did] + ([cid] if cid else []),
            "authority": d.get("authority", "USER_DIRECT"),
            "acceptanceCriteria": [
                f"Implementation satisfies {title}",
                f"Selected option '{chosen_opt}' is verified by automated test",
            ],
            "verificationContract": f"Verify behavioral compliance of {req_id} according to decision {did}",
            "createdAt": utc_now_iso(),
            "updatedAt": utc_now_iso(),
        }

        # If decision specifies affectedRequirements, link them
        d.setdefault("affectedRequirements", [])
        if req_id not in d["affectedRequirements"]:
            d["affectedRequirements"].append(req_id)

        compiled_reqs.append(req_obj)

    # Save decisions with updated affectedRequirements
    if decision_mod is not None:
        decision_mod.save_decisions(ws, decisions_list)
    else:
        with open(ws / ".agent-harness" / "decisions.json", "w", encoding="utf-8") as f:
            json.dump(decisions_list, f, indent=2)

    # Save compiled requirements
    if kernel is not None and hasattr(kernel, "save_requirements"):
        kernel.save_requirements(ws, compiled_reqs)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        temp_file = r_file.with_suffix(".json.tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(compiled_reqs, f, indent=2, sort_keys=True)
        os.replace(temp_file, r_file)

    # Sync decision graph and coverage matrix
    if decision_graph is not None:
        try:
            decision_graph.sync_decision_graph(ws)
        except Exception:
            pass

    if decision_coverage is not None:
        try:
            decision_coverage.sync_decision_coverage(ws)
        except Exception:
            pass

    # Record event in ledger
    if decision_events is not None:
        try:
            decision_events.record_decision_event(
                workspace_dir=ws,
                event_type="REQUIREMENTS_GENERATED",
                payload={
                    "requirementCount": len(compiled_reqs),
                    "requirementIds": [r["id"] for r in compiled_reqs],
                },
                actor="requirement-generator",
            )
        except Exception:
            pass

    return True, f"Successfully compiled {len(compiled_reqs)} requirements from active decisions", compiled_reqs
