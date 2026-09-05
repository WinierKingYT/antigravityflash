"""
Strict Engineering Kernel Step 6S - Deterministic Evidence Resolution Gate
Provides:
- Evidence-driven resolution replacing AI debates, voting, and opinion consensus
- State machine: CONSISTENT_PASS, CONSISTENT_FAIL, COUNTEREXAMPLE_PENDING,
  EVIDENCE_MISSING, EVIDENCE_CONTRADICTION, RESOLUTION_REQUIRED, RESOLVED_PASS, RESOLVED_FAIL, BLOCKED
- Automated counterexample conversion to deterministic executable check
- Loop protection (max 3 repair/resolution cycles before ESCALATED_BLOCKED)
- Auditor risk escalation with strict anti-downgrade enforcement and STALE invalidation
"""

import os
import sys
import json
import time
import uuid
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable

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


def evaluate_evidence_resolution(
    blind_audit: Any,
    counterexample_audit: Any = None,
    execution_evidence_or_count: Any = None,
    target_requirement_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Evaluates empirical resolution between Blind Verifier, Counterexample Auditor, and Execution Evidence.
    Never averages model opinions.
    """
    if isinstance(blind_audit, str):
        b_verdict = blind_audit
        b_reqs = {}
    elif isinstance(blind_audit, dict):
        b_verdict = blind_audit.get("overallVerdict", "INSUFFICIENT_EVIDENCE")
        b_reqs = {r.get("id"): r for r in blind_audit.get("requirements", []) if isinstance(r, dict) and "id" in r}
    else:
        b_verdict = "INSUFFICIENT_EVIDENCE"
        b_reqs = {}

    if isinstance(counterexample_audit, str):
        cx_verdict = counterexample_audit
        cxs = []
    elif isinstance(counterexample_audit, dict):
        cx_verdict = counterexample_audit.get("verdict") or counterexample_audit.get("overallVerdict", "NO_COUNTEREXAMPLE_FOUND")
        cxs = counterexample_audit.get("counterexamples", [])
    else:
        cx_verdict = "NO_COUNTEREXAMPLE_FOUND"
        cxs = []

    if isinstance(execution_evidence_or_count, int):
        cx_count = execution_evidence_or_count
        if cx_count > 0 and len(cxs) == 0:
            cxs = [{"id": f"CX-SIM-{i}"} for i in range(cx_count)]
        all_ev = []
    elif isinstance(execution_evidence_or_count, list):
        all_ev = execution_evidence_or_count
    else:
        all_ev = []

    has_exec_fail = any(isinstance(e, dict) and e.get("result") == "FAIL" for e in all_ev)

    # 1. Check for missing evidence
    if b_verdict == "INSUFFICIENT_EVIDENCE":
        return {
            "state": "EVIDENCE_MISSING",
            "isComplete": False,
            "blindVerdict": b_verdict,
            "counterexampleVerdict": cx_verdict,
            "details": "Blind verifier flagged INSUFFICIENT_EVIDENCE; deterministic execution proof missing",
            "unresolvedCounterexamples": cxs,
        }

    # 2. Check for explicit implementation defects in blind audit
    if b_verdict == "FAIL" or has_exec_fail:
        return {
            "state": "CONSISTENT_FAIL",
            "isComplete": False,
            "blindVerdict": b_verdict,
            "counterexampleVerdict": cx_verdict,
            "details": "Implementation defect detected by blind verifier or failing execution evidence",
            "unresolvedCounterexamples": cxs,
        }

    # 3. Disagreement: Blind Verifier says PASS but Counterexample Auditor found concrete counterexample
    if b_verdict == "PASS" and cx_verdict == "COUNTEREXAMPLE_FOUND" and len(cxs) > 0:
        return {
            "state": "RESOLUTION_REQUIRED",
            "isComplete": False,
            "blindVerdict": b_verdict,
            "counterexampleVerdict": cx_verdict,
            "details": f"{len(cxs)} counterexample(s) found breaking claimed invariants. Deterministic check required.",
            "unresolvedCounterexamples": cxs,
        }

    # 4. Consistent Pass: Blind Verifier PASS + No Counterexamples + No execution failures
    if b_verdict == "PASS" and cx_verdict == "NO_COUNTEREXAMPLE_FOUND":
        return {
            "state": "CONSISTENT_PASS",
            "isComplete": True,
            "blindVerdict": b_verdict,
            "counterexampleVerdict": cx_verdict,
            "details": "Consistent verification pass: blind audit passed, zero counterexamples found, execution valid.",
            "unresolvedCounterexamples": [],
        }

    return {
        "state": "EVIDENCE_CONTRADICTION",
        "isComplete": False,
        "blindVerdict": b_verdict,
        "counterexampleVerdict": cx_verdict,
        "details": "Contradictory or unresolvable audit state",
        "unresolvedCounterexamples": cxs,
    }


def resolve_counterexample_with_execution(
    workspace_dir: Path,
    counterexample: Dict[str, Any],
    custom_runner: Optional[Callable[[Any], Any]] = None,
    runner: Optional[Callable[[Any], Any]] = None,
) -> Dict[str, Any]:
    """
    Sections 15, 17, S6S-E3, S6S-E4:
    Converts a proposed counterexample into a deterministic executable check in the sandbox.
    Runs the check and appends real execution evidence to evidence.jsonl.
    If check passes -> RESOLVED_PASS / COUNTEREXAMPLE_REFUTED (invariant held).
    If check fails -> RESOLVED_FAIL / DEFECT_CONFIRMED (real defect confirmed).
    """
    ws = Path(workspace_dir).resolve()
    req_id = counterexample.get("requirementId", "REQ-UNKNOWN")
    repro = counterexample.get("reproductionCommand") or counterexample.get("reproductionProposal", "")
    cx_type = counterexample.get("type", "NEGATIVE_PATH")
    start_time = time.time()

    actual_runner = runner if runner is not None else custom_runner

    if actual_runner is not None:
        try:
            try:
                res = actual_runner(counterexample)
            except Exception:
                res = actual_runner(repro)

            duration_ms = int((time.time() - start_time) * 1000)
            if isinstance(res, dict):
                exit_code = res.get("exitCode", 0)
                passed = (exit_code == 0)
                output = str(res.get("stdout") or res.get("output") or "")
                duration_ms = res.get("durationMs", duration_ms)
            elif isinstance(res, (tuple, list)):
                passed = bool(res[0])
                output = str(res[1])
                exit_code = 0 if passed else 1
            elif isinstance(res, bool):
                passed = res
                exit_code = 0 if passed else 1
                output = "PASS" if passed else "FAIL"
            else:
                passed = False
                exit_code = 1
                output = str(res)
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            passed = False
            exit_code = 1
            output = f"Execution exception: {str(e)}"
    else:
        # Execute reproduction command in subprocess
        cmd = repro if repro.startswith("python") or repro.startswith("pytest") else f"{sys.executable} -c \"{repro}\""
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=str(ws),
                capture_output=True,
                text=True,
                timeout=30
            )
            duration_ms = int((time.time() - start_time) * 1000)
            exit_code = proc.returncode
            passed = (exit_code == 0)
            output = proc.stdout if passed else (proc.stderr or proc.stdout)
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            exit_code = 1
            passed = False
            output = f"Subprocess failed: {str(e)}"

    # Record real execution evidence in kernel
    ev_id = kernel.record_evidence(
        workspace_dir=ws,
        requirement_ids=[req_id],
        verification_type="AUTOMATED_TEST",
        command_or_interaction=repro[:200] if repro else f"cx_check_{req_id}",
        result="PASS" if passed else "FAIL",
        relevant_output=output[:1000],
        verifier_identity="evidence-resolution-engine",
        origin="REAL_PROJECT_EXECUTION",
        execution_record={
            "executionType": "TEST",
            "exitCode": exit_code,
            "durationMs": duration_ms,
            "stdoutHash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "stderrHash": hashlib.sha256(b"").hexdigest(),
        }
    )

    resolution_verdict = "RESOLVED_PASS" if passed else "RESOLVED_FAIL"
    status = "COUNTEREXAMPLE_REFUTED" if passed else "DEFECT_CONFIRMED"
    return {
        "eventId": ev_id,
        "requirementId": req_id,
        "counterexampleType": cx_type,
        "resolutionVerdict": resolution_verdict,
        "outcome": resolution_verdict,
        "status": status,
        "isResolved": passed,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "output": output[:500],
        "details": "Counterexample behavior verified empirically: " + ("behavior is correct" if passed else "defect reproduced"),
    }


def track_resolution_cycle(
    workspace_dir: Path,
    resolution_id: str,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    """
    Tracks resolution cycles to enforce loop protection (Section 44).
    Escalates to BLOCKED when max_attempts is reached.
    """
    harness = Path(workspace_dir) / ".agent-harness"
    res_file = harness / "evidence-resolutions.json"

    state = {}
    if res_file.exists():
        try:
            state = json.loads(res_file.read_text(encoding="utf-8"))
        except Exception:
            state = {}

    cycles = state.get("cycles", {})
    entry = cycles.get(resolution_id, {
        "resolutionId": resolution_id,
        "attempts": 0,
        "status": "ACTIVE",
        "firstObserved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    entry["attempts"] += 1
    entry["lastUpdated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if entry["attempts"] >= max_attempts:
        entry["status"] = "BLOCKED"
        entry["details"] = f"Resolution exceeded {max_attempts} attempts without empirical convergence. Escalate to diagnostic engineer."
    else:
        entry["status"] = "ACTIVE"

    cycles[resolution_id] = entry
    state["cycles"] = cycles
    state["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    harness.mkdir(parents=True, exist_ok=True)
    res_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return entry


def process_risk_escalations(
    workspace_dir: Path,
    *args,
    **kwargs,
) -> Any:
    """
    Processes auditor-proposed risk escalations (Section 32).
    Auditors may ONLY escalate risk (never downgrade).
    Invalidates affected requirement to STALE and logs change.

    Supports two signatures:
    1) Single requirement: (workspace_dir, req_id, proposed_level, proposer="auditor") -> Tuple[bool, str]
    2) Batch list: (workspace_dir, risk_escalations=[...]) -> List[Dict[str, Any]]
    """
    ws = Path(workspace_dir)

    # Detect if single-requirement call:
    if args and isinstance(args[0], str):
        req_id = args[0]
        proposed_risk = str(args[1] if len(args) > 1 else kwargs.get("proposed_level", "")).upper()
        proposer = args[2] if len(args) > 2 else kwargs.get("proposer", "auditor")

        reqs_list = kernel.load_requirements(ws)
        req_map = {r["id"]: r for r in reqs_list}
        req = req_map.get(req_id)
        if not req:
            return False, f"Requirement '{req_id}' not found"

        current_risk = (
            req.get("risk", {}).get("level")
            if isinstance(req.get("risk"), dict)
            else req.get("riskLevel", "LOW")
        ).upper()
        curr_rank = RISK_ORDER.get(current_risk, 1)
        prop_rank = RISK_ORDER.get(proposed_risk, 1)

        if prop_rank < curr_rank:
            return False, f"DOWNGRADE_PROHIBITED: Cannot downgrade {req_id} from {current_risk} to {proposed_risk}"

        if prop_rank == curr_rank:
            return True, f"Risk level unchanged for {req_id} ({current_risk})"

        req["riskLevel"] = proposed_risk
        if "risk" in req and isinstance(req["risk"], dict):
            req["risk"]["level"] = proposed_risk
        req["status"] = "STALE"

        new_pol = verification_policy.compile_verification_policy(req)
        req["verificationPolicy"] = new_pol

        kernel.record_change(
            workspace_dir=ws,
            requirement_ids=[req_id],
            old_behavior=f"Risk: {current_risk}",
            new_behavior=f"Risk: {proposed_risk}",
            reason=f"Proposer '{proposer}' escalated {req_id} risk to {proposed_risk}",
            source_of_change="AUDITOR_RISK_ESCALATION",
        )
        kernel.save_requirements(ws, list(req_map.values()))
        return True, f"Risk successfully escalated for {req_id} to {proposed_risk}"

    # Batch list of escalations:
    risk_escalations = args[0] if args and isinstance(args[0], list) else kwargs.get("risk_escalations", [])
    if not risk_escalations:
        return []

    reqs_list = kernel.load_requirements(ws)
    req_map = {r["id"]: r for r in reqs_list}
    processed = []

    for esc in risk_escalations:
        rid = esc.get("requirementId")
        proposed_risk = esc.get("proposedRisk", "").upper()
        rationale = esc.get("rationale", "Proposed by compliance auditor")

        if rid in req_map and proposed_risk in RISK_ORDER:
            current_risk = (req_map[rid].get("risk", {}).get("level") or req_map[rid].get("riskLevel", "LOW")).upper()
            curr_rank = RISK_ORDER.get(current_risk, 1)
            prop_rank = RISK_ORDER.get(proposed_risk, 1)

            if prop_rank > curr_rank:
                req_map[rid]["riskLevel"] = proposed_risk
                if "risk" in req_map[rid] and isinstance(req_map[rid]["risk"], dict):
                    req_map[rid]["risk"]["level"] = proposed_risk
                req_map[rid]["status"] = "STALE"

                # Recompile verification policy
                new_pol = verification_policy.compile_verification_policy(req_map[rid])
                req_map[rid]["verificationPolicy"] = new_pol

                kernel.record_change(
                    workspace_dir=ws,
                    requirement_ids=[rid],
                    old_behavior=f"Risk: {current_risk}",
                    new_behavior=f"Risk: {proposed_risk}",
                    reason=f"Auditor escalated {rid} risk: {rationale}",
                    source_of_change="AUDITOR_RISK_ESCALATION",
                )

                processed.append({
                    "requirementId": rid,
                    "previousRisk": current_risk,
                    "newRisk": proposed_risk,
                    "status": "ESCALATED",
                    "rationale": rationale,
                })
            else:
                processed.append({
                    "requirementId": rid,
                    "previousRisk": current_risk,
                    "proposedRisk": proposed_risk,
                    "status": "REJECTED_DOWNGRADE",
                    "rationale": "Auditors cannot downgrade requirement risk level.",
                })

    kernel.save_requirements(ws, list(req_map.values()))
    return processed
