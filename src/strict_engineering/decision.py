"""
Strict Engineering Kernel Step 7 - Canonical Decision Model & Response Parser
Implements the Canonical Decision Model (DEC-001, DEC-002, ...), 6 Decision Types,
4 Authorities, user response parsing (Option A, ordinals, delegation, uncertainty, rejection),
superseding logic, and atomic persistence.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

DECISION_TYPES = [
    "USER_EXPLICIT",
    "USER_APPROVED_SUGGESTION",
    "SAFE_INFERENCE",
    "CONSTRAINT_DERIVATION",
    "TECHNICAL_DECISION",
    "CHANGE_DECISION",
]

AUTHORITIES = [
    "USER",
    "USER_DELEGATED",
    "ARCHITECT_AUTHORIZED",
    "POLICY_REQUIRED",
]

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_decisions_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to decisions.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "decisions.json"


def load_decisions(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load decisions from .agent-harness/decisions.json.
    Returns empty list if file does not exist.
    """
    dec_path = get_decisions_path(workspace_dir)
    if not dec_path.exists():
        return []
    try:
        with open(dec_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "decisions" in data:
                return data["decisions"]
            return []
    except Exception:
        return []


def save_decisions(workspace_dir: Union[str, Path], decisions: List[Dict[str, Any]]) -> None:
    """
    Atomically persist decisions list to .agent-harness/decisions.json via a .tmp file.
    """
    dec_path = get_decisions_path(workspace_dir)
    dec_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dec_path.with_name(f"{dec_path.name}.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(decisions, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, dec_path)


def validate_decision(decision_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Strictly validate decision schema fields."""
    errors: List[str] = []
    if not isinstance(decision_data, dict):
        return False, ["Decision data must be a dictionary."]

    # id
    did = decision_data.get("id")
    if not did or not isinstance(did, str) or not re.match(r"^DEC-\d{3,}$", did):
        errors.append(f"Invalid decision id '{did}', expected format DEC-XXX (e.g. DEC-001).")

    # concernId
    cid = decision_data.get("concernId")
    if not cid or not isinstance(cid, str):
        errors.append("Field 'concernId' must be a non-empty string.")

    # question
    q = decision_data.get("question")
    if not q or not isinstance(q, str):
        errors.append("Field 'question' must be a non-empty string.")

    # selectedOption
    if "selectedOption" not in decision_data:
        errors.append("Field 'selectedOption' is required.")

    # decisionType
    dt = decision_data.get("decisionType")
    if dt not in DECISION_TYPES:
        errors.append(f"Invalid decisionType '{dt}'. Allowed: {DECISION_TYPES}")

    # authority
    auth = decision_data.get("authority")
    if auth not in AUTHORITIES:
        errors.append(f"Invalid authority '{auth}'. Allowed: {AUTHORITIES}")

    # confidence
    conf = decision_data.get("confidence")
    if conf is None or not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
        errors.append(f"Field 'confidence' must be a float between 0.0 and 1.0.")

    # rationaleSummary
    rs = decision_data.get("rationaleSummary")
    if not rs or not isinstance(rs, str):
        errors.append("Field 'rationaleSummary' must be a non-empty string.")

    # lists
    for lf in ["alternativesConsidered", "consequences", "affectedConcerns", "affectedRequirements"]:
        v = decision_data.get(lf)
        if not isinstance(v, list):
            errors.append(f"Field '{lf}' must be a list of strings.")

    # riskLevel
    rl = decision_data.get("riskLevel")
    if rl not in RISK_LEVELS:
        errors.append(f"Invalid riskLevel '{rl}'. Allowed: {RISK_LEVELS}")

    # createdAt
    ca = decision_data.get("createdAt")
    if not ca or not isinstance(ca, str):
        errors.append("Field 'createdAt' must be an ISO timestamp string.")

    return len(errors) == 0, errors


def create_decision(
    concern_id: str,
    question: str = "",
    selected_option: Any = None,
    decision_type: str = "USER_EXPLICIT",
    authority: str = "USER",
    rationale_summary: str = "",
    id: Optional[str] = None,
    confidence: float = 1.0,
    alternatives_considered: Optional[List[str]] = None,
    consequences: Optional[List[str]] = None,
    affected_concerns: Optional[List[str]] = None,
    affected_requirements: Optional[List[str]] = None,
    risk_level: str = "LOW",
    source_reference: str = "",
    created_at: Optional[str] = None,
    superseded_by: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Construct a canonical decision dictionary conforming to the Decision schema.
    Supports both snake_case and camelCase kwargs, with title/chosenOption aliases.
    """
    dec_id = id or kwargs.get("decisionId") or f"DEC-{int(datetime.datetime.now().timestamp()*1000)%1000000:03d}"

    q = question or kwargs.get("title") or f"Decision for {concern_id}"
    opt = selected_option if selected_option is not None else kwargs.get("chosen_option", kwargs.get("chosenOption", "Standard Default"))
    rat = rationale_summary or kwargs.get("rationale") or kwargs.get("tradeoffs_summary") or f"Architectural choice for concern {concern_id}"

    clean_type = str(kwargs.get("decision_type", kwargs.get("decisionType", decision_type))).upper().strip()
    if clean_type not in DECISION_TYPES:
        clean_type = "USER_EXPLICIT"

    raw_auth = kwargs.get("authority", authority)
    clean_auth = str(raw_auth).upper().strip()
    if clean_auth not in AUTHORITIES:
        if "USER" in clean_auth:
            clean_auth = "USER"
        else:
            clean_auth = "ARCHITECT_AUTHORIZED"

    clean_risk = str(kwargs.get("risk_level", kwargs.get("riskLevel", risk_level))).upper().strip()
    if clean_risk not in RISK_LEVELS:
        clean_risk = "LOW"

    alts = kwargs.get("alternativesConsidered", kwargs.get("alternatives_considered", alternatives_considered or []))
    conseq = kwargs.get("consequences", kwargs.get("tradeoffs", consequences or []))
    aff_conc = kwargs.get("affectedConcerns", kwargs.get("affected_concerns", affected_concerns or [concern_id]))
    aff_reqs = kwargs.get("affectedRequirements", kwargs.get("affected_requirements", affected_requirements or []))
    src_ref = kwargs.get("sourceReference", kwargs.get("source_reference", source_reference)) or f"concern:{concern_id}"
    super_by = kwargs.get("supersededBy", kwargs.get("superseded_by", superseded_by))

    return {
        "id": str(dec_id).strip(),
        "concernId": str(concern_id).strip(),
        "question": str(q).strip(),
        "title": str(q).strip(),
        "selectedOption": opt,
        "chosenOption": opt,
        "decisionType": clean_type,
        "authority": clean_auth,
        "confidence": float(confidence),
        "rationaleSummary": str(rat).strip(),
        "rationale": str(rat).strip(),
        "alternativesConsidered": [str(a).strip() for a in alts],
        "consequences": [str(c).strip() for c in conseq],
        "affectedConcerns": [str(ac).strip() for ac in aff_conc],
        "affectedRequirements": [str(ar).strip() for ar in aff_reqs],
        "riskLevel": clean_risk,
        "sourceReference": str(src_ref).strip(),
        "createdAt": created_at or utc_now_iso(),
        "supersededBy": str(super_by).strip() if super_by else None,
    }


def supersede_decision(
    workspace_dir: Union[str, Path],
    old_decision_id: str,
    new_decision_id: Optional[str] = None,
    new_decision_data: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Mark old_decision_id as superseded by new_decision_id (or new_decision_data) in decisions.json.
    Returns (success, message) or new_decision_data.
    """
    decisions = load_decisions(workspace_dir)
    target: Optional[Dict[str, Any]] = None
    for d in decisions:
        if d.get("id") == old_decision_id:
            target = d
            break

    if not target:
        if new_decision_data is not None:
            raise ValueError(f"Decision '{old_decision_id}' not found.")
        return False, f"Decision '{old_decision_id}' not found."

    if new_decision_data is not None:
        target_new_id = new_decision_data.get("id") or f"DEC-{int(datetime.datetime.now().timestamp()*1000)%1000000:03d}"
        new_decision_data["id"] = target_new_id
        target["supersededBy"] = target_new_id
        target["status"] = "SUPERSEDED"
        decisions.append(new_decision_data)
        save_decisions(workspace_dir, decisions)
        return new_decision_data

    target["supersededBy"] = new_decision_id
    target["status"] = "SUPERSEDED"
    save_decisions(workspace_dir, decisions)
    return True, f"Decision '{old_decision_id}' marked as superseded by '{new_decision_id}'."


def _parse_user_response_impl(
    raw_input: str,
    candidate_options: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Parse natural language user responses to a clarification or decision prompt.
    Handles:
    - Direct option numbers / letters: "Option A", "Option 1", "A", "1", "2"
    - Ordinals: "the first one", "the second one", "first", "second", "third", "last"
    - Yes / No affirmative / negative matching
    - Delegation keywords: "you decide", "whatever you think is best", "up to you" -> authority="USER_DELEGATED"
    - Uncertainty keywords: "not sure", "don't know", "unsure"
    - Rejection keywords: "none of these", "neither", "no to all"
    - Free-text semantic / title matching with candidate options
    - Free-text fallback

    Returns structured dictionary:
    {
        "status": "MATCHED" | "DELEGATED" | "UNCERTAIN" | "REJECTED" | "FREE_TEXT",
        "selectedOption": Optional[Dict[str, Any] or str],
        "optionIndex": Optional[int],
        "authority": "USER" | "USER_DELEGATED",
        "confidence": float,
        "rawInput": str,
        "intent": str,
        "parsedText": str,
        "matchedCriteria": str
    }
    """
    cleaned = (raw_input or "").strip()
    norm = cleaned.lower()

    num_options = len(candidate_options)

    # 1. Delegation Check
    delegation_patterns = [
        r"\b(?:you\s+decide|whatever\s+you\s+think(?:\s+is\s+best)?|up\s+to\s+you|agent\s+decide|you\s+choose|your\s+call|i\s+leave\s+it\s+to\s+you|whichever\s+you\s+prefer|do\s+what\s+you\s+think(?:\s+is\s+right|\s+best)?|use\s+your\s+judgment|best\s+judgment|recommend(?:\s+one)?)\b",
    ]
    for pat in delegation_patterns:
        if re.search(pat, norm):
            # Delegated to agent
            recommended_opt = None
            opt_idx = None
            for idx, opt in enumerate(candidate_options):
                if opt.get("isRecommended") or opt.get("recommended"):
                    recommended_opt = opt
                    opt_idx = idx
                    break
            if not recommended_opt and num_options > 0:
                recommended_opt = candidate_options[0]
                opt_idx = 0

            return {
                "status": "DELEGATED",
                "selectedOption": recommended_opt,
                "optionIndex": opt_idx,
                "authority": "USER_DELEGATED",
                "confidence": 1.0,
                "rawInput": cleaned,
                "intent": "DELEGATION",
                "parsedText": "User explicitly delegated decision authority.",
                "matchedCriteria": "DELEGATION_KEYWORD",
            }

    # 2. Uncertainty Check
    uncertainty_patterns = [
        r"\b(?:not\s+sure|don'?t\s+know|unsure|no\s+idea|dunno|not\s+certain|i\s+have\s+no\s+preference|no\s+preference|hard\s+to\s+say|can'?t\s+decide|unclear)\b",
    ]
    for pat in uncertainty_patterns:
        if re.search(pat, norm):
            return {
                "status": "UNCERTAIN",
                "selectedOption": None,
                "optionIndex": None,
                "authority": "USER",
                "confidence": 0.0,
                "rawInput": cleaned,
                "intent": "UNCERTAINTY",
                "parsedText": "User expressed uncertainty or lack of preference.",
                "matchedCriteria": "UNCERTAINTY_KEYWORD",
            }

    # 3. Rejection Check
    rejection_patterns = [
        r"\b(?:none\s+of\s+these|neither(?:\s+one)?|no\s+to\s+all|none\s+of\s+the\s+above|reject\s+all|neither\s+option|nothing\s+above|disagree\s+with\s+all|none)\b",
    ]
    for pat in rejection_patterns:
        if re.search(pat, norm):
            return {
                "status": "REJECTED",
                "selectedOption": None,
                "optionIndex": None,
                "authority": "USER",
                "confidence": 1.0,
                "rawInput": cleaned,
                "intent": "REJECTION",
                "parsedText": "User rejected all candidate options.",
                "matchedCriteria": "REJECTION_KEYWORD",
            }

    # 4. Ordinal Matching
    ordinal_map = {
        "first": 0,
        "1st": 0,
        "the first": 0,
        "the first one": 0,
        "second": 1,
        "2nd": 1,
        "the second": 1,
        "the second one": 1,
        "third": 2,
        "3rd": 2,
        "the third": 2,
        "the third one": 2,
        "fourth": 3,
        "4th": 3,
        "the fourth": 3,
        "the fourth one": 3,
        "fifth": 4,
        "5th": 4,
        "the fifth": 4,
        "last": num_options - 1 if num_options > 0 else 0,
        "the last": num_options - 1 if num_options > 0 else 0,
        "the last one": num_options - 1 if num_options > 0 else 0,
    }
    for ord_str, target_idx in ordinal_map.items():
        if re.search(rf"\b{re.escape(ord_str)}\b", norm):
            if 0 <= target_idx < num_options:
                return {
                    "status": "MATCHED",
                    "selectedOption": candidate_options[target_idx],
                    "optionIndex": target_idx,
                    "authority": "USER",
                    "confidence": 1.0,
                    "rawInput": cleaned,
                    "intent": "SELECTION",
                    "parsedText": f"Matched ordinal '{ord_str}' to option index {target_idx}.",
                    "matchedCriteria": "ORDINAL_MATCH",
                }

    # 5. Direct Option Letters (Option A, Option B, or just A, B, C...)
    letter_match = re.search(r"^(?:option\s+)?([a-zA-Z])(?:\)|\.|\:|\s|$)", cleaned, re.IGNORECASE)
    if letter_match:
        letter = letter_match.group(1).upper()
        target_idx = ord(letter) - ord("A")
        if 0 <= target_idx < num_options:
            return {
                "status": "MATCHED",
                "selectedOption": candidate_options[target_idx],
                "optionIndex": target_idx,
                "authority": "USER",
                "confidence": 1.0,
                "rawInput": cleaned,
                "intent": "SELECTION",
                "parsedText": f"Matched letter '{letter}' to option index {target_idx}.",
                "matchedCriteria": "OPTION_LETTER",
            }

    # 6. Direct Option Numbers (Option 1, 1, Option 2, 2...)
    num_match = re.search(r"^(?:option\s+|#)?(\d+)(?:\)|\.|\s|$)", cleaned, re.IGNORECASE)
    if num_match:
        idx_val = int(num_match.group(1)) - 1  # 1-indexed to 0-indexed
        if 0 <= idx_val < num_options:
            return {
                "status": "MATCHED",
                "selectedOption": candidate_options[idx_val],
                "optionIndex": idx_val,
                "authority": "USER",
                "confidence": 1.0,
                "rawInput": cleaned,
                "intent": "SELECTION",
                "parsedText": f"Matched number '{num_match.group(1)}' to option index {idx_val}.",
                "matchedCriteria": "OPTION_NUMBER",
            }

    # 7. Yes / No binary matching
    yes_pattern = re.compile(r"^(?:yes|y|yep|yeah|sure|affirmative|agreed|true|approved?)\b", re.IGNORECASE)
    no_pattern = re.compile(r"^(?:no|n|nope|nah|negative|false|disagreed?)\b", re.IGNORECASE)

    if yes_pattern.match(cleaned):
        for idx, opt in enumerate(candidate_options):
            opt_str = json.dumps(opt).lower()
            if any(k in opt_str for k in ["yes", "true", "enable", "allow", "accept"]):
                return {
                    "status": "MATCHED",
                    "selectedOption": opt,
                    "optionIndex": idx,
                    "authority": "USER",
                    "confidence": 0.95,
                    "rawInput": cleaned,
                    "intent": "SELECTION",
                    "parsedText": "Affirmative response mapped to positive option.",
                    "matchedCriteria": "BINARY_YES",
                }
        if num_options > 0:
            return {
                "status": "MATCHED",
                "selectedOption": candidate_options[0],
                "optionIndex": 0,
                "authority": "USER",
                "confidence": 0.9,
                "rawInput": cleaned,
                "intent": "SELECTION",
                "parsedText": "Affirmative response accepted first candidate option.",
                "matchedCriteria": "BINARY_YES_DEFAULT",
            }

    if no_pattern.match(cleaned):
        for idx, opt in enumerate(candidate_options):
            opt_str = json.dumps(opt).lower()
            if any(k in opt_str for k in ["no", "false", "disable", "deny", "reject"]):
                return {
                    "status": "MATCHED",
                    "selectedOption": opt,
                    "optionIndex": idx,
                    "authority": "USER",
                    "confidence": 0.95,
                    "rawInput": cleaned,
                    "intent": "SELECTION",
                    "parsedText": "Negative response mapped to negative option.",
                    "matchedCriteria": "BINARY_NO",
                }
        return {
            "status": "REJECTED",
            "selectedOption": None,
            "optionIndex": None,
            "authority": "USER",
            "confidence": 0.95,
            "rawInput": cleaned,
            "intent": "REJECTION",
            "parsedText": "Negative response interpreted as rejection.",
            "matchedCriteria": "BINARY_NO_REJECTION",
        }

    # 8. Text Substring / Keyword Matching against Options
    best_opt = None
    best_idx = None
    best_score = 0.0

    user_tokens = set(re.findall(r"\w+", norm))

    for idx, opt in enumerate(candidate_options):
        # Extract searchable text from option fields
        searchable_parts = []
        for key in ["label", "title", "text", "id", "name", "description"]:
            if key in opt and isinstance(opt[key], str):
                searchable_parts.append(opt[key].lower())
        combined_text = " ".join(searchable_parts)

        # Exact substring: either user input is in option text, or an option part is in user input
        if (norm in combined_text and len(norm) >= 3) or any(len(p) >= 4 and p in norm for p in searchable_parts):
            return {
                "status": "MATCHED",
                "selectedOption": opt,
                "optionIndex": idx,
                "authority": "USER",
                "confidence": 0.95,
                "rawInput": cleaned,
                "intent": "SELECTION",
                "parsedText": f"Matched option '{opt.get('title') or opt.get('label') or opt.get('id')}'.",
                "matchedCriteria": "SUBSTRING_MATCH",
            }

        # Token overlap and prefix/substring match
        opt_tokens = set(re.findall(r"\w+", combined_text))
        if user_tokens and opt_tokens:
            common = user_tokens.intersection(opt_tokens)
            token_sub_match = any(
                (len(ut) >= 4 and ut in ot) or (len(ot) >= 4 and ot in ut)
                for ut in user_tokens
                for ot in opt_tokens
            )
            # Calculate overlap relative to option tokens and user tokens
            opt_score = len(common) / max(len(opt_tokens), 1)
            user_score = len(common) / max(len(user_tokens), 1)
            score = max(opt_score, user_score)
            if token_sub_match:
                score = max(score, 0.8)
            if score > best_score and (score >= 0.4 or len(common) >= 2 or token_sub_match):
                best_score = score
                best_opt = opt
                best_idx = idx

    if best_opt is not None:
        return {
            "status": "MATCHED",
            "selectedOption": best_opt,
            "optionIndex": best_idx,
            "authority": "USER",
            "confidence": min(round(0.6 + (best_score * 0.35), 2), 0.95),
            "rawInput": cleaned,
            "intent": "SELECTION",
            "parsedText": f"Fuzzy matched to option index {best_idx} with token overlap score {best_score:.2f}.",
            "matchedCriteria": "TOKEN_OVERLAP",
        }

    # 9. Free-Text Fallback
    return {
        "status": "FREE_TEXT",
        "selectedOption": cleaned,
        "optionIndex": None,
        "authority": "USER",
        "confidence": 0.7,
        "rawInput": cleaned,
        "intent": "FREE_TEXT",
        "parsedText": "Free-text input provided by user.",
        "matchedCriteria": "FREE_TEXT_FALLBACK",
    }


def parse_user_response(
    raw_input: str,
    candidate_options: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Parse user response and normalize fields so both matchedOptionIndex and optionIndex,
    and type and intent are accessible.
    """
    opts = candidate_options or []
    res = _parse_user_response_impl(raw_input, opts)
    res["matchedOptionIndex"] = res.get("optionIndex")
    res["type"] = res.get("intent")
    if "selectedOption" in res and isinstance(res["selectedOption"], dict):
        res["matchedOptionTitle"] = res["selectedOption"].get("title")
    elif "selectedOption" in res and isinstance(res["selectedOption"], str):
        res["matchedOptionTitle"] = res["selectedOption"]
    if "value" not in res:
        res["value"] = res.get("matchedOptionTitle", res.get("selectedOption", res.get("rawInput")))
    return res

