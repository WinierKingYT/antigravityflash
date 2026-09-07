"""
Strict Engineering Kernel Step 7 - Question Fatigue Control & Stopping Engine
Evaluates whether the decision discovery phase should stop and proceed to specification.
Canonical persistence file: .agent-harness/decision-status.json.
"""

import os
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, Set

try:
    from . import question_utility
    from . import decision_graph
except (ImportError, ValueError):
    try:
        import question_utility
        import decision_graph
    except ImportError:
        question_utility = None
        decision_graph = None

DEFAULT_MIN_QUESTION_UTILITY = 0.35
MAX_QUESTIONS_PER_SESSION = 15

UNRESOLVED_CONCERN_STATES = {
    "DISCOVERED",
    "UNRESOLVED",
    "ACTIVE",
    "BLOCKED",
    "ASKABLE",
    "SUGGESTABLE",
    "CHALLENGE_REQUIRED",
    "SAFE_INFERABLE",
}

RESOLVED_CONCERN_STATES = {
    "RESOLVED",
    "SUPERSEDED",
    "DEFERRED",
    "DISMISSED_LOW_VALUE",
}

CRITICAL_RISK_LEVELS = {"CRITICAL", "HIGH"}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_decision_status_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to decision-status.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "decision-status.json"


def load_decision_status(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Load decision status from .agent-harness/decision-status.json.
    Returns a default empty status dictionary if file does not exist or cannot be parsed.
    """
    status_path = get_decision_status_path(workspace_dir)
    if not status_path.exists():
        return {
            "canProceedToSpec": False,
            "reason": "Decision status not yet evaluated",
            "unresolvedConcernsCount": 0,
            "resolvedConcernsCount": 0,
            "totalConcernsCount": 0,
            "blockingConcerns": [],
            "highestRemainingUtility": 0.0,
            "stoppingThreshold": DEFAULT_MIN_QUESTION_UTILITY,
            "stoppingConditionsMet": {
                "noUnresolvedConcerns": False,
                "criticalConcernsResolved": False,
                "remainingUtilityBelowThreshold": False,
                "graphValid": False,
                "sessionFatigueReached": False,
            },
            "timestamp": utc_now_iso(),
        }

    try:
        with open(status_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass

    return {
        "canProceedToSpec": False,
        "reason": "Corrupted decision-status.json",
        "unresolvedConcernsCount": 0,
        "resolvedConcernsCount": 0,
        "totalConcernsCount": 0,
        "blockingConcerns": [],
        "highestRemainingUtility": 0.0,
        "stoppingThreshold": DEFAULT_MIN_QUESTION_UTILITY,
        "stoppingConditionsMet": {},
        "timestamp": utc_now_iso(),
    }


def save_decision_status(workspace_dir: Union[str, Path], status_data: Dict[str, Any]) -> None:
    """
    Atomically save decision status dictionary to .agent-harness/decision-status.json via .tmp.
    """
    status_path = get_decision_status_path(workspace_dir)
    status_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = status_path.with_suffix(".json.tmp")

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(status_data, f, indent=2, sort_keys=True)
    os.replace(temp_path, status_path)


def evaluate_stopping_conditions(
    concerns: Union[List[Dict[str, Any]], Dict[str, Any]],
    graph_data: Optional[Dict[str, Any]] = None,
    asked_questions: Optional[List[Dict[str, Any]]] = None,
    threshold: float = DEFAULT_MIN_QUESTION_UTILITY,
    max_questions: int = MAX_QUESTIONS_PER_SESSION,
    workspace_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Evaluate stopping conditions for decision discovery.
    
    Stop criteria (canProceedToSpec = True):
    1. Decision graph must be valid (no cycles, no corruption).
    2. No blocking critical/high concerns remain unresolved.
    3. AND at least ONE of:
       a) All concerns resolved (unresolved == 0).
       b) All remaining unresolved concerns have utility < threshold.
       c) Question session budget exhausted (fatigue limit reached) AND no critical concerns block.
    """
    # Normalize concerns list
    c_list: List[Dict[str, Any]] = []
    if isinstance(concerns, list):
        c_list = concerns
    elif isinstance(concerns, dict):
        if "concerns" in concerns and isinstance(concerns["concerns"], list):
            c_list = concerns["concerns"]
        else:
            c_list = list(concerns.values())

    resolved: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    blocking_concern_ids: List[str] = []

    for c in c_list:
        cid = c.get("id", "UNKNOWN")
        status = str(c.get("status", "DISCOVERED")).upper()
        risk = str(c.get("riskLevel", "MEDIUM")).upper()
        is_blocking = bool(c.get("isBlocking", False)) or status in ("BLOCKED", "CHALLENGE_REQUIRED")

        if status in RESOLVED_CONCERN_STATES:
            resolved.append(c)
        else:
            unresolved.append(c)
            # CRITICAL and HIGH risk concerns or explicit isBlocking flags make this a blocking concern
            if risk in ("CRITICAL", "HIGH") or is_blocking:
                blocking_concern_ids.append(cid)

    # Validate decision graph if provided
    graph_valid = True
    if graph_data is not None and decision_graph is not None:
        valid, _ = decision_graph.validate_decision_graph(graph_data)
        if not valid:
            graph_valid = False

    # Compute utilities of remaining unresolved concerns
    utilities: List[float] = []
    for u in unresolved:
        if question_utility is not None:
            score = question_utility.calculate_question_utility(
                concern=u,
                graph_data=graph_data,
                asked_questions=asked_questions,
            )
        else:
            score = 0.5
        utilities.append(score)

    highest_utility = max(utilities) if utilities else 0.0
    all_below_threshold = (highest_utility < threshold) if unresolved else True
    critical_resolved = (len(blocking_concern_ids) == 0)

    # Session fatigue check
    asked_count = len(asked_questions or [])
    fatigue_reached = (asked_count >= max_questions)

    # Determine whether discovery can stop and proceed to spec
    can_proceed = False
    reason = ""

    # Check semantic discovery gate: if heuristic seeds exist and status is HEURISTIC_DISCOVERY_ONLY
    if workspace_dir:
        ws_p = Path(workspace_dir).resolve()
        seeds_file = ws_p / ".agent-harness" / "discovery" / "seeds.json"
        if seeds_file.exists():
            try:
                with open(seeds_file, "r", encoding="utf-8") as f:
                    seeds_data = json.load(f)
            except Exception:
                seeds_data = []
            if seeds_data and isinstance(seeds_data, list):
                status_file = ws_p / ".agent-harness" / "discovery" / "discovery-status.json"
                if not status_file.exists():
                    status_file = ws_p / ".agent-harness" / "discovery" / "status.json"
                disc_status_val = "HEURISTIC_DISCOVERY_ONLY"
                if status_file.exists():
                    try:
                        with open(status_file, "r", encoding="utf-8") as f:
                            s_data = json.load(f)
                            disc_status_val = s_data.get("status", "HEURISTIC_DISCOVERY_ONLY")
                    except Exception:
                        pass
                has_high_or_crit_seeds = any(str(s.get("riskLevel", "")).upper() in ("HIGH", "CRITICAL") for s in seeds_data)
                if disc_status_val == "HEURISTIC_DISCOVERY_ONLY" and (has_high_or_crit_seeds or len(c_list) == 0):
                    can_proceed = False
                    reason = "Semantic discovery not yet executed: discovery status is HEURISTIC_DISCOVERY_ONLY with unresolved architectural seeds"
                    return {
                        "canProceedToSpec": False,
                        "reason": reason,
                        "unresolvedConcernsCount": len(unresolved),
                        "resolvedConcernsCount": len(resolved),
                        "totalConcernsCount": len(c_list),
                        "blockingConcerns": blocking_concern_ids,
                        "highestRemainingUtility": round(highest_utility, 4),
                        "stoppingThreshold": threshold,
                        "stoppingConditionsMet": {
                            "noUnresolvedConcerns": False,
                            "criticalConcernsResolved": False,
                            "remainingUtilityBelowThreshold": False,
                            "graphValid": graph_valid,
                            "sessionFatigueReached": fatigue_reached,
                        },
                        "timestamp": utc_now_iso(),
                    }

    if not graph_valid:
        can_proceed = False
        reason = "Decision graph validation failed (cycles, corruption, or missing references)"
    elif not critical_resolved:
        can_proceed = False
        reason = f"Unresolved blocking/critical concerns remain: {', '.join(blocking_concern_ids)}"
    elif len(unresolved) == 0:
        can_proceed = True
        reason = "All discovered concerns have been resolved"
    elif fatigue_reached:
        has_high_utility = any(u >= threshold for u in utilities) or len(blocking_concern_ids) > 0
        if has_high_utility:
            can_proceed = False
            reason = "SESSION_QUESTION_BUDGET_REACHED"
        else:
            can_proceed = True
            reason = (
                f"Session fatigue limit reached ({asked_count}/{max_questions} questions asked); "
                "no blocking or high-utility concerns remain"
            )
    elif all_below_threshold:
        can_proceed = True
        reason = (
            f"All remaining {len(unresolved)} unresolved concerns have utility "
            f"({round(highest_utility, 3)}) below threshold ({threshold})"
        )
    else:
        can_proceed = False
        reason = (
            f"{len(unresolved)} unresolved concerns remain with highest utility "
            f"{round(highest_utility, 3)} >= threshold {threshold}"
        )

    return {
        "canProceedToSpec": can_proceed,
        "reason": reason,
        "unresolvedConcernsCount": len(unresolved),
        "resolvedConcernsCount": len(resolved),
        "totalConcernsCount": len(c_list),
        "blockingConcerns": blocking_concern_ids,
        "highestRemainingUtility": round(highest_utility, 4),
        "stoppingThreshold": threshold,
        "stoppingConditionsMet": {
            "noUnresolvedConcerns": len(unresolved) == 0,
            "criticalConcernsResolved": critical_resolved,
            "remainingUtilityBelowThreshold": all_below_threshold,
            "graphValid": graph_valid,
            "sessionFatigueReached": fatigue_reached,
        },
        "timestamp": utc_now_iso(),
    }


def sync_decision_status(
    workspace_dir: Union[str, Path],
    threshold: float = DEFAULT_MIN_QUESTION_UTILITY,
    max_questions: int = MAX_QUESTIONS_PER_SESSION,
) -> Dict[str, Any]:
    """
    Load workspace concerns, decision graph, and asked questions,
    evaluate stopping conditions, save to .agent-harness/decision-status.json,
    and return the status dictionary.
    """
    ws = Path(workspace_dir).resolve()

    # Load concerns
    concerns_list = []
    c_path = ws / ".agent-harness" / "concerns.json"
    if c_path.exists():
        try:
            with open(c_path, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                if isinstance(c_data, list):
                    concerns_list = c_data
                elif isinstance(c_data, dict):
                    concerns_list = c_data.get("concerns", list(c_data.values()))
        except Exception:
            concerns_list = []

    # Load graph
    graph_data = None
    if decision_graph is not None:
        graph_data = decision_graph.load_decision_graph(ws)

    # Load asked questions
    asked_questions = None
    if question_utility is not None:
        asked_questions = question_utility.load_asked_questions(ws)

    status_data = evaluate_stopping_conditions(
        concerns=concerns_list,
        graph_data=graph_data,
        asked_questions=asked_questions,
        threshold=threshold,
        max_questions=max_questions,
        workspace_dir=ws,
    )

    save_decision_status(ws, status_data)
    return status_data
