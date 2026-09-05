"""
Strict Engineering Kernel Step 3 - Risk Engine
Provides deterministic, structured risk analysis, hard risk overrides,
user risk escalation, anti-downgrade protection, dynamic risk escalation,
and dependency-derived effective risk calculation.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import kernel
    from . import fingerprint
except (ImportError, ValueError):
    import kernel
    import fingerprint

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RISK_RANKS = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

# Structured risk factor weights
FACTOR_WEIGHTS = {
    "dataLoss": 25,
    "security": 25,
    "privacy": 20,
    "financial": 25,
    "irreversibility": 20,
    "authControl": 25,
    "persistence": 20,
    "migration": 20,
    "blastRadius": 15,
    "criticalJourney": 15,
    "recoveryDifficulty": 15,
    "externalDependence": 10,
    "concurrencyComplexity": 15,
    "novelty": 10,
    "regressionReach": 15,
}

HARD_OVERRIDE_PATTERNS = [
    ("AUTH_BOUNDARY", r"\b(auth(entication)?|login|signin|logout|token(s)?|session(s)?|jwt|oauth|password(s)?|credential(s)?|rbac|permission(s)?|admin|privilege(s)?)\b", "CRITICAL"),
    ("FINANCIAL_TRANSACTION", r"\b(payment(s)?|checkout|credit[_\s-]?card(s)?|billing|invoice(s)?|refund(s)?|financial|price(s)?|wallet(s)?)\b", "CRITICAL"),
    ("DESTRUCTIVE_IRREVERSIBLE", r"\b(delete[_\s-]?account|wipe|permanent(ly)?[_\s-]?delete|drop[_\s-]?table|truncate|hard[_\s-]?delete|destroy|purge)\b", "CRITICAL"),
    ("SCHEMA_MIGRATION", r"\b(migration(s)?|migrate|schema[_\s-]?upgrade|schema[_\s-]?migration|alter[_\s-]?table|database[_\s-]?migration(s)?)\b", "CRITICAL"),
    ("BACKUP_RESTORE", r"\b(backup(s)?|restore|disaster[_\s-]?recovery|corrupted[_\s-]?recovery|recover[_\s-]?state)\b", "CRITICAL"),
    ("INPUT_VALIDATION_UNTRUSTED", r"\b(parse[_\s-]?untrusted|file[_\s-]?upload|arbitrary[_\s-]?file|sanitize|sanitization|xss|sql[_\s-]?injection|deserialize|deserialization)\b", "HIGH"),
    ("DATA_PERSISTENCE", r"\b(persist(ence|ent|ed|ing|s)?|survive[_\s-]?restart|reload[_\s-]?state|localstorage|disk[_\s-]?storage)\b", "MEDIUM"),
]

LOW_RISK_PATTERNS = [
    r"\b(static[_\s-]?footer|footer[_\s-]?text|label[_\s-]?text|cosmetic|icon[_\s-]?alignment|spacing|typo|padding|margin|color[_\s-]?theme(?!.*persist))\b"
]


def score_to_risk_level(score: int) -> str:
    """Map deterministic score (0-100) to risk level."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def evaluate_requirement_risk(
    req: Dict[str, Any],
    user_declared_risk: Optional[str] = None,
    parent_effective_risk: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deterministic risk analysis of a requirement based on structured factors,
    hard overrides, user declarations, and dependency propagation.
    """
    title = str(req.get("title", ""))
    desc = str(req.get("description", ""))
    text_corpus = f"{title} {desc}".lower()
    req_factors = req.get("factors", {})

    reason_codes: List[str] = []
    override_level: Optional[str] = None

    # 1. Evaluate Hard Overrides
    for code, pattern, min_level in HARD_OVERRIDE_PATTERNS:
        if re.search(pattern, text_corpus, re.IGNORECASE):
            reason_codes.append(code)
            if not override_level or RISK_RANKS[min_level] > RISK_RANKS[override_level]:
                override_level = min_level

    # 2. Check Low-Risk Anti-Theater
    is_pure_cosmetic = any(re.search(p, text_corpus, re.IGNORECASE) for p in LOW_RISK_PATTERNS)
    if is_pure_cosmetic and not override_level:
        reason_codes.append("COSMETIC_SURFACE")

    # 3. Calculate Factor Scores
    calculated_factors: Dict[str, int] = {}
    total_raw_points = 0
    max_possible_points = 0

    for factor_name, weight in FACTOR_WEIGHTS.items():
        val = req_factors.get(factor_name, 0)
        # Auto-infer if not explicitly set
        if val == 0:
            if factor_name == "persistence" and "DATA_PERSISTENCE" in reason_codes:
                val = 15
            elif factor_name == "security" and "AUTH_BOUNDARY" in reason_codes:
                val = 25
            elif factor_name == "dataLoss" and "DESTRUCTIVE_IRREVERSIBLE" in reason_codes:
                val = 25
            elif factor_name == "financial" and "FINANCIAL_TRANSACTION" in reason_codes:
                val = 25
            elif factor_name == "migration" and "SCHEMA_MIGRATION" in reason_codes:
                val = 20
            elif factor_name == "security" and "INPUT_VALIDATION_UNTRUSTED" in reason_codes:
                val = 18

        calculated_factors[factor_name] = min(val, weight)
        total_raw_points += calculated_factors[factor_name]
        max_possible_points += weight

    # Normalized score between 0 and 100
    base_score = int(min(100, (total_raw_points / max(1, max_possible_points)) * 100 * 3.5))
    if is_pure_cosmetic and not override_level:
        base_score = min(base_score, 10)

    computed_level = score_to_risk_level(base_score)

    # Apply Hard Override if higher than computed score
    if override_level and RISK_RANKS[override_level] > RISK_RANKS[computed_level]:
        effective_level = override_level
        base_score = max(base_score, 75 if override_level == "CRITICAL" else 50 if override_level == "HIGH" else 25)
    else:
        effective_level = computed_level

    # 4. User-Declared Escalation
    user_decl = user_declared_risk or req.get("userDeclaredRisk")
    if user_decl:
        user_decl_upper = user_decl.upper()
        if user_decl_upper in RISK_RANKS:
            if RISK_RANKS[user_decl_upper] > RISK_RANKS[effective_level]:
                effective_level = user_decl_upper
                base_score = max(base_score, 75 if user_decl_upper == "CRITICAL" else 50)
                reason_codes.append("USER_DECLARED_RISK")

    # 5. Dependency-Derived Effective Risk
    intrinsic_level = effective_level
    if parent_effective_risk:
        p_upper = parent_effective_risk.upper()
        if p_upper in RISK_RANKS and RISK_RANKS[p_upper] > RISK_RANKS[effective_level]:
            effective_level = p_upper
            reason_codes.append(f"DEPENDENCY_INHERITED_{p_upper}")

    risk_obj = {
        "level": effective_level,
        "intrinsicLevel": intrinsic_level,
        "score": min(100, max(0, base_score)),
        "factors": calculated_factors,
        "reasonCodes": sorted(list(set(reason_codes))),
    }
    return risk_obj


def can_modify_risk_level(
    old_level: str,
    new_level: str,
    caller_identity: str,
    is_spec_locked: bool,
) -> Tuple[bool, str]:
    """
    Validate risk modifications against single-writer and spec-lock rules.
    Prohibits Builder from downgrading risk post-spec-lock.
    """
    old_norm = old_level.upper()
    new_norm = new_level.upper()

    if old_norm not in RISK_RANKS or new_norm not in RISK_RANKS:
        return False, f"Invalid risk level '{old_level}' or '{new_level}'"

    # If increasing risk -> Always permitted
    if RISK_RANKS[new_norm] >= RISK_RANKS[old_norm]:
        return True, "Risk escalation allowed"

    # If reducing risk post-spec-lock: Builder is strictly prohibited!
    if is_spec_locked and caller_identity.lower() == "builder":
        return False, f"Security Gate Deny: Builder is prohibited from reducing risk level from '{old_norm}' to '{new_norm}' after specification lock."

    return True, "Risk modification permitted"


def escalate_requirement_risk(
    workspace_dir: Path,
    req_id: str,
    new_level: str,
    reason: str,
    escalater_identity: str,
) -> Tuple[bool, str]:
    """
    Dynamically escalate requirement risk upon discovering latent vulnerabilities.
    Invalidates affected requirement verification and recompiles policy.
    """
    workspace_path = Path(workspace_dir).resolve()
    reqs = kernel.load_requirements(workspace_path)
    found = False

    for req in reqs:
        if req.get("id") == req_id:
            found = True
            current_risk = req.get("risk", {}).get("level", "LOW")
            if RISK_RANKS.get(new_level.upper(), 0) < RISK_RANKS.get(current_risk.upper(), 0):
                return False, f"Cannot downgrade risk from {current_risk} to {new_level} via escalate_requirement_risk"
            
            req_risk = req.setdefault("risk", {})
            req_risk["level"] = new_level.upper()
            req_risk.setdefault("reasonCodes", []).append(f"DYNAMIC_ESCALATION_{reason.upper()}")
            req["status"] = "STALE"  # Invalidate previous verification!
            break

    if not found:
        return False, f"Requirement '{req_id}' not found"

    # Save updated risk level to requirements.json first
    kernel.save_requirements(workspace_path, reqs)

    # Invalidate and record change in audit log
    kernel.record_change(
        workspace_path,
        [req_id],
        f"Risk level: {current_risk}",
        f"Risk level: {new_level}",
        f"Dynamic escalation: {reason}",
        escalater_identity,
    )

    return True, f"Requirement '{req_id}' risk escalated to {new_level}"
