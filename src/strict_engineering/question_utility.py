"""
Strict Engineering Kernel Step 7 - Question Utility Engine & Fatigue Control
Implements the deterministic question utility formula:
  Utility = (Uncertainty * DownstreamImpact * Criticality * DependencyReach * RiskReductionPotential * ExpectedDiscrimination)
            / (UserEffort * QuestionCost * RepetitionRisk)
Clamped and normalized to [0.0, 1.0].
Canonical persistence file for question fatigue: .agent-harness/asked-questions.json.
"""

import os
import re
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import decision_graph
except (ImportError, ValueError):
    try:
        import decision_graph
    except ImportError:
        decision_graph = None


RISK_CRITICALITY_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
}

NORMALIZATION_FACTOR = 10.0


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def compute_question_fingerprint(question_text: str, topic: str = "") -> str:
    """
    Compute deterministic sha256 fingerprint from normalized question text and topic.
    Strips punctuation, lowercases, and normalizes whitespace.
    """
    norm_q = re.sub(r"[^\w\s]", "", str(question_text).lower()).strip()
    norm_q = " ".join(norm_q.split())
    norm_t = re.sub(r"[^\w\s]", "", str(topic).lower()).strip()
    norm_t = " ".join(norm_t.split())
    canonical = f"{norm_t}::{norm_q}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_asked_questions_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to asked-questions.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "asked-questions.json"


def load_asked_questions(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load asked questions from .agent-harness/asked-questions.json.
    Returns empty list if file does not exist or is invalid.
    """
    path = get_asked_questions_path(workspace_dir)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "questions" in data:
                return data["questions"]
            return []
    except Exception:
        return []


def record_asked_question(
    workspace_dir: Union[str, Path],
    question_text: str,
    topic: str = "",
    concern_id: str = "",
) -> Dict[str, Any]:
    """
    Record an asked question to prevent question fatigue and suppress repetition.
    Atomically persists to .agent-harness/asked-questions.json.
    """
    ws = Path(workspace_dir).resolve()
    path = get_asked_questions_path(ws)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_asked_questions(ws)

    fingerprint = compute_question_fingerprint(question_text, topic)
    record = {
        "questionText": str(question_text).strip(),
        "topic": str(topic).strip(),
        "concernId": str(concern_id).strip(),
        "fingerprint": fingerprint,
        "askedAt": utc_now_iso(),
    }
    existing.append(record)

    temp_path = path.with_name(f"{path.name}.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, path)
    return record


def calculate_question_utility(
    concern: Dict[str, Any],
    graph_data: Optional[Dict[str, Any]] = None,
    asked_questions: Optional[List[Dict[str, Any]]] = None,
) -> float:
    """
    Deterministic Question Utility Engine:
      Utility = (Uncertainty * DownstreamImpact * Criticality * DependencyReach * RiskReductionPotential * ExpectedDiscrimination)
                / (UserEffort * QuestionCost * RepetitionRisk)
    Normalized and clamped to [0.0, 1.0]. Avoids division-by-zero (denominator clamped >= 0.01).
    """
    if not isinstance(concern, dict):
        return 0.0

    # 1. Uncertainty: float 0.0 - 1.0 (default 0.8)
    raw_u = concern.get("uncertainty")
    u = float(raw_u) if raw_u is not None else 0.8
    u = min(max(u, 0.0), 1.0)

    # 2. DownstreamImpact: float 0.0 - 1.0 (default 0.7)
    raw_di = concern.get("downstreamImpact")
    di = float(raw_di) if raw_di is not None else 0.7
    di = min(max(di, 0.0), 1.0)

    # 3. Criticality: derived from concern riskLevel (CRITICAL: 1.0, HIGH: 0.8, MEDIUM: 0.5, LOW: 0.2)
    rl = str(concern.get("riskLevel", "")).upper()
    if rl in RISK_CRITICALITY_MAP:
        crit = RISK_CRITICALITY_MAP[rl]
    else:
        raw_crit = concern.get("criticality")
        crit = float(raw_crit) if raw_crit is not None else 0.5
    crit = min(max(crit, 0.0), 1.0)

    # 4. DependencyReach: normalized based on graph reach (1.0 + min(reach, 10) * 0.15)
    reach = 0
    cid = concern.get("id")
    if graph_data is not None and cid and decision_graph is not None:
        reach = decision_graph.compute_downstream_reach(graph_data, cid)
    elif "dependencyReach" in concern:
        try:
            reach = float(concern["dependencyReach"])
        except (ValueError, TypeError):
            reach = 0

    clamped_reach = min(max(float(reach), 0.0), 10.0)
    dependency_reach = 1.0 + (clamped_reach * 0.15)

    # 5. RiskReductionPotential: float 0.0 - 1.0 (default 0.7)
    raw_rrp = concern.get("riskReductionPotential")
    rrp = float(raw_rrp) if raw_rrp is not None else 0.7
    rrp = min(max(rrp, 0.0), 1.0)

    # 6. ExpectedDiscrimination: float 0.0 - 1.0
    # High (0.9) if candidate options lead to materially different requirements/architecture;
    # Low (0.1) if candidate options collapse to identical requirements.
    if "expectedDiscrimination" in concern and concern["expectedDiscrimination"] is not None:
        disc = float(concern["expectedDiscrimination"])
    else:
        opts = concern.get("candidateOptions")
        if opts and isinstance(opts, list) and len(opts) > 1:
            conseq_signatures = []
            for opt in opts:
                if isinstance(opt, dict):
                    conseq = opt.get("consequences", [])
                    conseq_signatures.append(tuple(sorted(str(c) for c in conseq)))
            if len(set(conseq_signatures)) <= 1 and len(conseq_signatures) > 1:
                disc = 0.1  # Low discrimination: identical consequences
            else:
                disc = 0.9  # High discrimination: materially different consequences
        else:
            disc = 0.7
    disc = min(max(disc, 0.0), 1.0)

    # 7. Denominator Components:
    # UserEffort: 0.1 - 1.0 (default 0.3)
    raw_ue = concern.get("userEffort")
    user_effort = float(raw_ue) if raw_ue is not None else 0.3
    user_effort = min(max(user_effort, 0.1), 1.0)

    # QuestionCost: 0.1 - 1.0 (default 0.3)
    raw_qc = concern.get("questionCost")
    question_cost = float(raw_qc) if raw_qc is not None else 0.3
    question_cost = min(max(question_cost, 0.1), 1.0)

    # RepetitionRisk: 1.0 default, scales up to 5.0 if question was previously asked
    is_repeated = False
    q_text = concern.get("question") or concern.get("title") or ""
    topic = concern.get("category") or ""
    q_fp = compute_question_fingerprint(q_text, topic)

    if asked_questions:
        for aq in asked_questions:
            if cid and aq.get("concernId") == cid:
                is_repeated = True
                break
            if aq.get("fingerprint") == q_fp:
                is_repeated = True
                break
            aq_text = aq.get("questionText", "")
            if aq_text and q_text:
                n1 = re.sub(r"[^\w\s]", "", q_text.lower()).strip()
                n2 = re.sub(r"[^\w\s]", "", aq_text.lower()).strip()
                if n1 == n2:
                    is_repeated = True
                    break

    if is_repeated:
        repetition_risk = 5.0
    else:
        raw_rr = concern.get("repetitionRisk")
        repetition_risk = float(raw_rr) if raw_rr is not None else 1.0
        repetition_risk = max(repetition_risk, 1.0)

    # Denominator clamping >= 0.01
    denom = max(user_effort * question_cost * repetition_risk, 0.01)

    # Raw Utility calculation
    numerator = u * di * crit * dependency_reach * rrp * disc
    raw_utility = numerator / denom

    # Safe normalization and clamping to [0.0, 1.0]
    normalized = min(max(raw_utility / NORMALIZATION_FACTOR, 0.0), 1.0)
    return round(normalized, 4)


def rank_concerns_by_utility(
    concerns: List[Dict[str, Any]],
    graph_data: Optional[Dict[str, Any]] = None,
    asked_questions: Optional[List[Dict[str, Any]]] = None,
) -> List[Tuple[Dict[str, Any], float]]:
    """
    Rank concerns by calculated question utility.
    Returns list of (concern_dict, utility_score) sorted descending by utility score.
    """
    scored = []
    for c in concerns:
        score = calculate_question_utility(c, graph_data=graph_data, asked_questions=asked_questions)
        scored.append((c, score))
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored
