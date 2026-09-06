"""
Strict Engineering Kernel Step 7 - Interaction Policy Engine
Implements the 4 Interaction Modes: ASK, SUGGEST, CHALLENGE, SAFE-INFER.
Enforces Core Invariants:
  INV-7-01: SUGGESTION != CONCERN
  INV-7-02: CONCERN != DECISION
  INV-7-06: USER AUTHORITY > MODEL PREFERENCE (model cannot silently decide high-impact ambiguous behavior)
Includes strict unsafe inference rejection, reversibility tracking, and escalation.
"""

import re
import datetime
from typing import Dict, Any, List, Optional, Tuple, Union

INTERACTION_MODES = ["ASK", "SUGGEST", "CHALLENGE", "SAFE-INFER"]

UNSAFE_CATEGORIES = {
    "AUTHORIZATION",
    "OWNERSHIP",
    "FINANCIAL",
    "IRREVERSIBILITY",
    "PRIVACY",
    "SECURITY",
    "RECOVERY",
}

UNSAFE_PATTERNS = [
    (r"\b(?:data\s+ownership|ownership)\b", "Data ownership"),
    (r"\b(?:permanent(?:ly)?\s+delet\w*|account\s+delet\w*|data\s+delet\w*|purge|destroy)\b", "Permanent account/data deletion"),
    (r"\b(?:auth\w*|login|password|oauth|jwt|token|credential|session|mfa)\b", "Authentication behavior"),
    (r"\b(?:privacy|pii|gdpr|visibility|confidential|secret)\b", "Privacy visibility"),
    (r"\b(?:financial|payment|billing|credit\s+card|charge|pricing|refund|cost)\b", "Financial effects"),
    (r"\b(?:permission\w*|rbac|role|access\s+control|admin|privilege)\b", "Permissions / RBAC"),
    (r"\b(?:across\s+restart|durability\s+across\s+restart|persistence\s+durability|cold\s+start)\b", "Persistence durability across restart"),
    (r"\b(?:scope\s+expand\w*|new\s+product\s+feature|scope\s+creep)\b", "Scope-expanding product features"),
    (r"\b(?:irreversible|destructive)\b", "Irreversible actions"),
]

SAFE_CANDIDATE_PATTERNS = [
    (r"\b(?:naming|internal\s+naming|variable\s+naming|symbol\s+naming|field\s+naming)\b", "Minor internal naming"),
    (r"\b(?:temp(?:orary)?\s+file|temp\s+format|tmp\s+dir|temp\s+directory)\b", "Temporary file format"),
    (r"\b(?:id\s+prefix|internal\s+id|prefix\s+format)\b", "Internal ID prefix"),
    (r"\b(?:log(?:ging)?\s+level|log\s+level|logger\s+level|default\s+logging)\b", "Obvious default logging level"),
    (r"\b(?:reversible|buffer\s+size|cache\s+ttl|timeout\s+default)\b", "Standard reversible technical details"),
]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def is_safe_to_infer(concern: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluate whether a concern can be safely inferred without explicit user authority.
    Strictly enforces:
    - Attempting to safe-infer data ownership, permanent deletion, auth, privacy,
      financial effects, RBAC, persistence across restart, scope expansion, or
      irreversible actions MUST BE REJECTED!
    - Risk level must be LOW.
    - Downstream impact must be <= 0.4.
    - Must match approved reversible candidates.
    Returns (is_safe, reason).
    """
    if not isinstance(concern, dict):
        return False, "Invalid concern data."

    category = str(concern.get("category", "")).upper()
    title = str(concern.get("title", ""))
    desc = str(concern.get("description", ""))
    full_text = f"{title} {desc} {category}".lower()

    # 1. Unsafe Category Check
    if category in UNSAFE_CATEGORIES:
        return False, f"Unsafe to infer: Category '{category}' is strictly restricted under INV-7-06."

    # 2. Unsafe Pattern Checks
    for pattern, aspect in UNSAFE_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            return False, f"Unsafe to infer: Concern involves {aspect}. Attempting to safe-infer is strictly prohibited (INV-7-06)."

    # 3. Risk Level Check (CRITICAL and HIGH are never safe to infer)
    risk_level = str(concern.get("riskLevel", "")).upper()
    if risk_level in {"CRITICAL", "HIGH"}:
        return False, f"Unsafe to infer: Risk level '{risk_level}' exceeds safe inference ceiling."

    # 4. Downstream Impact Check
    downstream = float(concern.get("downstreamImpact", 0.2))
    if downstream > 0.4:
        return False, f"Unsafe to infer: Downstream impact ({downstream:.2f}) exceeds safe inference threshold (0.40)."

    # 5. Check against approved safe candidate patterns
    for pattern, candidate in SAFE_CANDIDATE_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            return True, f"Safe to infer: Matches approved reversible candidate pattern '{candidate}'."

    # Default fail-closed
    return False, "Unsafe to infer: Does not match approved reversible technical candidate patterns."


def generate_candidate_options(concern: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate 2-4 discriminative candidate options with:
    id, title, description, tradeoffs, consequences, isRecommended.
    """
    existing_opts = concern.get("candidateOptions")
    if existing_opts and isinstance(existing_opts, list) and len(existing_opts) >= 2:
        normalized: List[Dict[str, Any]] = []
        has_rec = False
        for idx, opt in enumerate(existing_opts):
            if isinstance(opt, dict):
                is_rec = bool(opt.get("isRecommended", False))
                if is_rec:
                    has_rec = True
                normalized.append({
                    "id": str(opt.get("id", f"OPT-{idx+1}")),
                    "title": str(opt.get("title", f"Option {idx+1}")),
                    "description": str(opt.get("description", "")),
                    "tradeoffs": str(opt.get("tradeoffs", "Standard tradeoffs apply.")),
                    "consequences": list(opt.get("consequences", [])),
                    "isRecommended": is_rec,
                })
        if not has_rec and normalized:
            normalized[0]["isRecommended"] = True
        return normalized

    # Auto-generate discriminative candidate options based on concern
    title = str(concern.get("title", "Proposed Architecture Decision"))
    cat = str(concern.get("category", "TECHNICAL_ARCHITECTURE")).upper()

    opt1 = {
        "id": "OPT-1",
        "title": f"Standard / Recommended: {title}",
        "description": f"Adopt standard industry conventions and deterministic defaults for {title}.",
        "tradeoffs": "Highest maintainability and standard tooling compatibility; less custom flexibility.",
        "consequences": [f"Establishes standard baseline for {cat}", "Predictable operational behavior"],
        "isRecommended": True,
    }

    opt2 = {
        "id": "OPT-2",
        "title": f"Strict / Conservative: Minimal {title}",
        "description": f"Enforce strict validation, minimal surface area, and conservative bounds for {title}.",
        "tradeoffs": "Maximum security and isolation; slightly higher initial configuration effort.",
        "consequences": [f"Strict isolation for {cat}", "Additional validation gates required"],
        "isRecommended": False,
    }

    opt3 = {
        "id": "OPT-3",
        "title": f"Configurable / Extensible: Pluggable {title}",
        "description": f"Provide configurable adapters or environment-variable overrides for {title}.",
        "tradeoffs": "Maximum flexibility across environments; requires documentation and testing of variants.",
        "consequences": [f"Adapter contract required for {cat}", "Multiple execution branches supported"],
        "isRecommended": False,
    }

    return [opt1, opt2, opt3]


def determine_interaction_mode(
    concern: Dict[str, Any],
    utility: float,
    candidate_options: Optional[List[Dict[str, Any]]] = None,
    existing_constraints: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    Determine appropriate interaction mode: ASK, SUGGEST, CHALLENGE, or SAFE-INFER.
    Returns:
      {
        mode: "ASK"|"SUGGEST"|"CHALLENGE"|"SAFE-INFER",
        reason: str,
        recommendedOption: Optional[Dict],
        options: List[Dict],
        challengeDetails: Optional[Dict],
        inferenceRecord: Optional[Dict]
      }
    """
    options = candidate_options if candidate_options is not None else generate_candidate_options(concern)
    rec_opt = next((o for o in options if o.get("isRecommended")), (options[0] if options else None))
    cid = concern.get("id", "CONC-???")
    status = str(concern.get("status", "")).upper()
    category = str(concern.get("category", "")).upper()
    risk_level = str(concern.get("riskLevel", "")).upper()
    full_text = f"{concern.get('title', '')} {concern.get('description', '')}".lower()

    # 1. Check for CHALLENGE
    if status == "CHALLENGE_REQUIRED":
        return {
            "mode": "CHALLENGE",
            "reason": "Concern status explicitly marks challenge required.",
            "recommendedOption": None,
            "options": options,
            "challengeDetails": {
                "concernId": cid,
                "conflict": "Explicit status CHALLENGE_REQUIRED.",
                "action": "Present conflicting requirements and request user resolution.",
            },
        }

    # Check for contradictions with existing constraints
    if existing_constraints:
        for constraint in existing_constraints:
            c_text = constraint.get("text", "") if isinstance(constraint, dict) else str(constraint)
            c_norm = c_text.lower()
            has_neg = any(neg in full_text for neg in ["skip", "bypass", "disable", "override", "ignore"]) and any(
                w in full_text for w in c_norm.split() if len(w) > 4
            )
            has_semantic = False
            if ("offline" in c_norm or "local only" in c_norm) and any(w in full_text for w in ["cloud", "remote", "online", "sync"]):
                has_semantic = True
            elif ("single user" in c_norm or "no multi-user" in c_norm) and any(w in full_text for w in ["multi-user", "collaboration", "shared"]):
                has_semantic = True

            if has_neg or has_semantic:
                return {
                    "mode": "CHALLENGE",
                    "reason": f"Concern conflicts with existing constraint: '{c_text}'.",
                    "recommendedOption": None,
                    "options": options,
                    "challengeDetails": {
                        "concernId": cid,
                        "conflict": c_text,
                        "action": "Highlight contradiction to user before committing decision.",
                    },
                }

    # 2. Check for SAFE-INFER
    safe, safe_reason = is_safe_to_infer(concern)
    if safe:
        # Eligible for safe inference if utility is low or status is explicitly SAFE_INFERABLE
        if utility < 0.40 or status == "SAFE_INFERABLE":
            return {
                "mode": "SAFE-INFER",
                "reason": safe_reason,
                "recommendedOption": rec_opt,
                "options": options,
                "challengeDetails": None,
                "inferenceRecord": {
                    "concernId": cid,
                    "reversibility": "HIGH",
                    "downstreamImpact": concern.get("downstreamImpact", 0.2),
                    "sourceBasis": "STANDARD_CONVENTION",
                    "selectedOption": rec_opt,
                    "status": "INFERRED",
                    "timestamp": utc_now_iso(),
                },
            }

    # 3. Distinguish between ASK and SUGGEST
    # Under INV-7-06, high utility or critical/high risk items require direct user authority (ASK).
    if status == "ASKABLE":
        mode = "ASK"
        reason = "Concern status is marked ASKABLE."
    elif status == "SUGGESTABLE":
        mode = "SUGGEST"
        reason = "Concern status is marked SUGGESTABLE."
    elif risk_level in {"CRITICAL", "HIGH"}:
        mode = "ASK"
        reason = f"Risk level '{risk_level}' requires direct user decision (INV-7-06)."
    elif utility >= 0.60:
        mode = "ASK"
        reason = f"High utility score ({utility:.3f}) warrants direct user engagement."
    elif utility >= 0.35 or rec_opt is not None:
        mode = "SUGGEST"
        reason = f"Moderate utility ({utility:.3f}) with clear recommended option. Suggesting to user (INV-7-01)."
    else:
        # Low utility but not safe to infer: default to SUGGEST so user retains authority
        mode = "SUGGEST"
        reason = "Low utility but sensitive topic not eligible for safe inference. Providing recommendation for approval."

    return {
        "mode": mode,
        "reason": reason,
        "recommendedOption": rec_opt,
        "options": options,
        "challengeDetails": None,
    }


def format_recommendation(
    concern: Dict[str, Any],
    recommended_option: Dict[str, Any],
    rationale: str,
) -> str:
    """
    Format recommendation conforming to INV-7-01 (SUGGESTION != CONCERN)
    and INV-7-06 (USER AUTHORITY > MODEL PREFERENCE).
    """
    cid = concern.get("id", "CONC-???")
    title = concern.get("title", "Untitled Concern")
    opt_title = recommended_option.get("title", "Recommended Option")
    opt_desc = recommended_option.get("description", "")
    tradeoffs = recommended_option.get("tradeoffs", "None specified.")
    conseq = recommended_option.get("consequences", [])
    conseq_str = ", ".join(conseq) if conseq else "No downstream side-effects reported."

    return (
        f"### Recommendation for [{cid}] {title}\n\n"
        f"**Proposed Option**: {opt_title}\n"
        f"**Details**: {opt_desc}\n\n"
        f"**Rationale**: {rationale}\n\n"
        f"**Tradeoffs**: {tradeoffs}\n\n"
        f"**Consequences**: {conseq_str}\n\n"
        f"> [!IMPORTANT]\n"
        f"> **INV-7-01 & INV-7-06 Notice**: This suggestion is a proposal, not a decision. "
        f"It does not take effect until explicitly confirmed by user authority."
    )


def escalate_safe_inference_to_confirmation(inference_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Escalate a safe inference record to CONFIRMATION_REQUIRED if downstream risk
    escalates or reversibility is lower than anticipated.
    """
    escalated = dict(inference_record)
    escalated["status"] = "CONFIRMATION_REQUIRED"
    escalated["escalatedAt"] = utc_now_iso()
    escalated["previousStatus"] = inference_record.get("status", "INFERRED")
    escalated["escalationReason"] = "Downstream risk escalation or low reversibility requires explicit user confirmation."
    return escalated
