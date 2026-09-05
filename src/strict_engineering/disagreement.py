"""
Strict Engineering Kernel Step 6 - Disagreement Engine & Consensus Gate
Provides:
- Deterministic verdict comparison matrix (AGREEMENT_PASS, AGREEMENT_FAIL, DISAGREEMENT)
- Reason code classification (IMPLEMENTATION_DEFECT, MISSING_EVIDENCE, TEST_DEFICIENCY, SPEC_AMBIGUITY, etc.)
- Evidence-driven dispute resolution engine
- Disagreement cycle tracking and loop protection (max attempts -> ESCALATED_BLOCKED)
- Risk escalation handler (prohibiting downgrades, triggering policy re-compilation and STALE invalidation)
"""

import os
import sys
import json
import time
import uuid
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    from . import kernel
    from . import fingerprint
    from . import verification_policy
except (ImportError, ValueError):
    import kernel
    import fingerprint
    import verification_policy


REASON_CODES = [
    "IMPLEMENTATION_DEFECT",
    "MISSING_EVIDENCE",
    "TEST_DEFICIENCY",
    "SPEC_AMBIGUITY",
    "REQUIREMENT_MISMATCH",
    "RISK_MISCLASSIFICATION",
    "STALE_EVIDENCE",
    "AUDITOR_ERROR",
    "ENVIRONMENT_DIFFERENCE",
    "UNKNOWN"
]

RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def classify_disagreement(
    req_id: str,
    primary_verdict: str,
    ind_req_data: Dict[str, Any]
) -> Tuple[str, List[str], str]:
    """
    Classifies disagreement reason code and disputed facts from independent audit findings.
    """
    findings = ind_req_data.get("findings", [])
    missing = ind_req_data.get("missingEvidence", [])
    given_reasons = ind_req_data.get("reasonCodes", [])
    ind_verdict = ind_req_data.get("verdict", "FAIL")
    
    # 1. Missing evidence classification
    if ind_verdict == "INSUFFICIENT_EVIDENCE" or missing:
        disputed = missing if missing else ["Missing deterministic execution evidence for requirement"]
        return "MISSING_EVIDENCE", disputed, "Execute automated test or runtime verification command and append evidence."
        
    # 2. Check for explicit reason code
    for r in given_reasons:
        if r in REASON_CODES:
            return r, findings, f"Investigate {r.lower().replace('_', ' ')} through deterministic checks."
            
    # 3. Analyze findings text
    findings_str = " ".join(findings).lower()
    if any(w in findings_str for w in ["weak test", "tautology", "assertion missing", "mock bypass", "vacuous"]):
        return "TEST_DEFICIENCY", findings, "Strengthen test assertions and run mutation analysis."
    elif any(w in findings_str for w in ["ambiguous", "unclear intent", "conflict in spec"]):
        return "SPEC_AMBIGUITY", findings, "Clarify specification with user decision."
    elif any(w in findings_str for w in ["bug", "defect", "fails to", "incorrect return", "wrong output", "exception"]):
        return "IMPLEMENTATION_DEFECT", findings, "Repair defect in builder sandbox."
        
    return "IMPLEMENTATION_DEFECT", findings, "Repair candidate or verify with additional test."


def compare_verdicts(
    primary_verdicts: Dict[str, str],
    independent_audit: Dict[str, Any],
    target_requirement_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Compares PRIMARY_VERDICT vs INDEPENDENT_VERDICT per requirement.
    Never averages conflicting verdicts. Disagreements strictly block consensus.
    """
    ind_reqs = {r["id"]: r for r in independent_audit.get("requirements", []) if "id" in r}
    
    all_req_ids = list(target_requirement_ids) if target_requirement_ids else list(set(list(primary_verdicts.keys()) + list(ind_reqs.keys())))
    
    comparisons = []
    disagreements = []
    agreements_pass = []
    agreements_fail = []
    
    for rid in all_req_ids:
        p_verdict = primary_verdicts.get(rid, "UNVERIFIED")
        ind_data = ind_reqs.get(rid, {})
        i_verdict = ind_data.get("verdict", "INSUFFICIENT_EVIDENCE")
        
        status = "UNKNOWN"
        disagreement_item = None
        
        # Matrix comparison
        p_norm = "FAIL" if p_verdict in ["FAIL", "FAILED"] else p_verdict
        i_norm = "FAIL" if i_verdict in ["FAIL", "FAILED"] else i_verdict

        if p_norm == "PASS" and i_norm == "PASS":
            status = "AGREEMENT_PASS"
            agreements_pass.append(rid)
        elif p_norm == "FAIL" and i_norm == "FAIL":
            status = "AGREEMENT_FAIL"
            agreements_fail.append(rid)
        elif i_verdict == "NOT_APPLICABLE":
            status = "NOT_APPLICABLE"
        else:
            # Any divergence is a DISAGREEMENT
            status = "DISAGREEMENT"
            reason, disputed_facts, resolution_plan = classify_disagreement(rid, p_verdict, ind_data)
            disagreement_item = {
                "requirementId": rid,
                "primaryVerdict": p_verdict,
                "independentVerdict": i_verdict,
                "reasonCode": reason,
                "disputedFacts": disputed_facts,
                "findings": ind_data.get("findings", []),
                "resolutionPlan": resolution_plan
            }
            disagreements.append(disagreement_item)
            
        comparisons.append({
            "requirementId": rid,
            "primaryVerdict": p_verdict,
            "independentVerdict": i_verdict,
            "status": status,
            "disagreement": disagreement_item
        })
        
    overall_consensus = "AGREEMENT_PASS"
    if disagreements:
        overall_consensus = "DISAGREEMENT"
    elif agreements_fail:
        overall_consensus = "AGREEMENT_FAIL"
    elif not comparisons:
        overall_consensus = "EMPTY"
        
    return {
        "overallConsensus": overall_consensus,
        "isConsensusPass": overall_consensus == "AGREEMENT_PASS",
        "totalAudited": len(all_req_ids),
        "agreementPassCount": len(agreements_pass),
        "agreementFailCount": len(agreements_fail),
        "disagreementCount": len(disagreements),
        "comparisons": comparisons,
        "disagreements": disagreements
    }


def track_disagreement_cycle(
    workspace_dir: Path,
    disagreement_id: str,
    max_attempts: int = 3
) -> Dict[str, Any]:
    """
    Tracks disagreement resolution attempts to prevent infinite debate loops.
    Escalates to ESCALATED_BLOCKED when max_attempts is exceeded.
    """
    harness = Path(workspace_dir) / ".agent-harness"
    dis_file = harness / "disagreements.json"
    
    state = {}
    if dis_file.exists():
        try:
            state = json.loads(dis_file.read_text(encoding="utf-8"))
        except Exception:
            state = {}
            
    cycles = state.get("cycles", {})
    entry = cycles.get(disagreement_id, {
        "disagreementId": disagreement_id,
        "attempts": 0,
        "status": "ACTIVE",
        "firstObserved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidenceAppended": []
    })
    
    entry["attempts"] += 1
    entry["lastUpdated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    if entry["attempts"] >= max_attempts:
        entry["status"] = "ESCALATED_BLOCKED"
        entry["details"] = f"Disagreement exceeded {max_attempts} resolution cycles without empirical convergence."
    else:
        entry["status"] = "ACTIVE"
        
    cycles[disagreement_id] = entry
    state["cycles"] = cycles
    state["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    harness.mkdir(parents=True, exist_ok=True)
    dis_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return entry


def resolve_disagreement_with_evidence(
    workspace_dir: Path,
    requirement_id: str,
    verification_type: str,
    command: str,
    exit_code: int,
    output: str,
    rationale: str
) -> Dict[str, Any]:
    """
    Appends empirical verification evidence to resolve a disagreement.
    Records event in the tamper-evident hash chain.
    """
    ws = Path(workspace_dir)
    ev_id = kernel.record_evidence(
        workspace_dir=ws,
        requirement_ids=[requirement_id],
        verification_type=verification_type,
        command_or_interaction=command,
        result="PASS" if exit_code == 0 else "FAILED",
        verifier_identity="independent_disagreement_resolver",
        relevant_output=output
    )
    return {
        "eventId": ev_id,
        "requirementId": requirement_id,
        "verificationType": verification_type,
        "command": command,
        "exitCode": exit_code,
        "outputSnippet": output[:500],
        "rationale": rationale,
        "isDisagreementResolution": True
    }


def process_risk_escalations(
    workspace_dir: Path,
    risk_escalations: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Processes auditor-proposed risk escalations.
    Auditors may ONLY escalate risk (never downgrade).
    Invalidates affected requirement to STALE and logs change.
    """
    ws = Path(workspace_dir)
    harness = ws / ".agent-harness"
    reqs_file = harness / "requirements.json"
    
    if not risk_escalations:
        return []
        
    reqs_list = kernel.load_requirements(ws)
    req_map = {r["id"]: r for r in reqs_list}
    
    processed = []
    
    for esc in risk_escalations:
        rid = esc.get("requirementId")
        proposed_risk = esc.get("proposedRisk", "").upper()
        rationale = esc.get("rationale", "Proposed by independent compliance auditor")
        
        if rid in req_map and proposed_risk in RISK_ORDER:
            current_risk = req_map[rid].get("riskLevel", "LOW").upper()
            curr_rank = RISK_ORDER.get(current_risk, 1)
            prop_rank = RISK_ORDER.get(proposed_risk, 1)
            
            # Anti-downgrade rule: only allow strictly higher risk
            if prop_rank > curr_rank:
                req_map[rid]["riskLevel"] = proposed_risk
                req_map[rid]["status"] = "STALE"
                
                # Recompile verification policy
                new_pol = verification_policy.compile_verification_policy(req_map[rid])
                req_map[rid]["verificationPolicy"] = new_pol
                
                # Record change
                kernel.record_change(
                    workspace_dir=ws,
                    requirement_ids=[rid],
                    old_behavior=f"Risk: {current_risk}",
                    new_behavior=f"Risk: {proposed_risk}",
                    reason=f"Auditor escalated {rid} risk: {rationale}",
                    source_of_change="INDEPENDENT_AUDITOR_ESCALATION"
                )
                
                processed.append({
                    "requirementId": rid,
                    "previousRisk": current_risk,
                    "newRisk": proposed_risk,
                    "status": "ESCALATED",
                    "rationale": rationale
                })
            else:
                processed.append({
                    "requirementId": rid,
                    "previousRisk": current_risk,
                    "proposedRisk": proposed_risk,
                    "status": "REJECTED_DOWNGRADE",
                    "rationale": "Independent auditor cannot downgrade requirement risk level."
                })
                
    kernel.save_requirements(ws, list(req_map.values()))
    return processed
