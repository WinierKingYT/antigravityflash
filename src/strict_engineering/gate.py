"""
Strict Engineering Kernel V5.1 - Gate & Completion Security Engine
Enforces:
1. PreToolUse security matrix (protects harness artifacts, phase source locks, command write vectors).
2. Stop completion gate (evidence chain validity, execution-backed passes, fake PASS rejection, freshness, zero regressions).
"""

import os
import re
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import kernel
    from . import fingerprint
    from . import baseline
    from . import sandbox
    from . import verification_policy
    from . import adversarial_verification
    from . import reproducibility
    from . import independent_model
    from . import disagreement
    from . import blind_verifier
    from . import counterexample_auditor
    from . import hidden_verification
    from . import evidence_resolution
    from . import context_registry
except (ImportError, ValueError):
    import kernel
    import fingerprint
    import baseline
    import sandbox
    import verification_policy
    import adversarial_verification
    import reproducibility
    import independent_model
    import disagreement
    import blind_verifier
    import counterexample_auditor
    import hidden_verification
    import evidence_resolution
    import context_registry

PROTECTED_ARTIFACTS = {
    ".agent-harness/original-request.md",
    ".agent-harness/original-request.sha256",
    ".agent-harness/state.json",
    ".agent-harness/requirements.json",
    ".agent-harness/coverage.json",
    ".agent-harness/evidence.jsonl",
    ".agent-harness/context-registry.jsonl",
    ".agent-harness/expected-context.json",
    "docs/ACCEPTANCE_TESTS.md",
    ".agent-harness/independent-audit.json",
    ".agent-harness/disagreements.json",
    ".agent-harness/blind-verification.json",
    ".agent-harness/counterexample-audit.json",
    ".agent-harness/hidden-checks.json",
    ".agent-harness/evidence-resolutions.json",
}

# Shell write commands matching PowerShell, cmd, Python inline, and file manipulation tools
SHELL_WRITE_PATTERNS = [
    re.compile(r'(?i)\b(Set-Content|Add-Content|Out-File)\b'),
    re.compile(r'(?i)\b(sc|ac)\s+'),
    re.compile(r'>>?'),  # Redirection operator
    re.compile(r'(?i)\b(open\s*\([^)]*[\'"][wa\+][\'"]?\s*\)\.write)\b'),  # Python inline write
    re.compile(r'(?i)\b(copy|move|del|rm|ren|Remove-Item|Copy-Item|Move-Item|Rename-Item)\b'),
]


def normalize_rel_path(path_str: str, workspace_root: Path) -> str:
    """Normalize path relative to workspace root with forward slashes."""
    try:
        p = Path(path_str)
        if p.is_absolute():
            rel = str(p.relative_to(workspace_root)).replace("\\", "/")
        else:
            rel = str(p).replace("\\", "/")
        if rel.startswith("./"):
            rel = rel[2:]
        return rel
    except Exception:
        return str(path_str).replace("\\", "/")


def resolve_workspace(payload: Dict[str, Any]) -> Optional[Path]:
    """Resolve active workspace directory from hook payload."""
    ws_paths = payload.get("workspacePaths", [])
    if ws_paths:
        return Path(ws_paths[0]).resolve()
    cwd = payload.get("cwd")
    if cwd:
        return Path(cwd).resolve()
    return None


def evaluate_pre_tool_use(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates PreToolUse gate for tool calls (write_to_file, replace_file_content,
    multi_replace_file_content, run_command).
    """
    workspace = resolve_workspace(payload)
    if not workspace or not kernel.is_harness_active(workspace):
        return {"decision": "allow"}

    tool_call = payload.get("toolCall", {})
    tool_name = payload.get("toolName", "") or tool_call.get("name", "")
    tool_args = payload.get("toolArgs", {}) or tool_call.get("args", {})
    caller_role = payload.get("callerRole", "")
    state = kernel.load_state(workspace)
    phase = state.get("phase", "SPECIFICATION")

    # Check builder sandbox isolation
    if caller_role == "builder":
        manifest = sandbox.load_sandbox_manifest(workspace)
        if manifest and manifest.get("builderWorktree"):
            builder_wt = Path(manifest["builderWorktree"]).resolve()
            target_path_str = tool_args.get("TargetFile", "") or tool_args.get("filePath", "")
            if target_path_str:
                target_p = Path(target_path_str).resolve()
                is_in_worktree = str(target_p).replace("\\", "/").startswith(str(builder_wt).replace("\\", "/"))
                is_in_canonical = str(target_p).replace("\\", "/").startswith(str(workspace).replace("\\", "/"))
                if is_in_canonical and not is_in_worktree:
                    return {
                        "decision": "deny",
                        "reason": f"Tool '{tool_name}' blocked: Builder role cannot write directly to canonical workspace while builderWorktree is active ({builder_wt}). All modifications must be made inside builderWorktree.",
                    }

    # 1. File Modification Tools: write_to_file, replace_file_content, multi_replace_file_content
    if tool_name in {"write_to_file", "replace_file_content", "multi_replace_file_content"}:
        target_path_str = tool_args.get("TargetFile", "") or tool_args.get("filePath", "")
        if not target_path_str:
            return {"decision": "allow"}

        rel_path = normalize_rel_path(target_path_str, workspace)

        # 1a. Protected Harness Artifacts are IMMUTABLE via LLM edit tools
        if rel_path in PROTECTED_ARTIFACTS:
            if rel_path == "docs/ACCEPTANCE_TESTS.md":
                return {
                    "decision": "deny",
                    "reason": f"Security Gate Deny: Tool '{tool_name}' blocked: Acceptance contracts in '{rel_path}' are immutable once locked. Must use authorized kernel lifecycle operations.",
                }
            return {
                "decision": "deny",
                "reason": f"Security Gate Deny: Tool '{tool_name}' blocked: '{rel_path}' is a protected harness artifact and cannot be directly modified. Must use authorized kernel lifecycle operations.",
            }

        # 1b. Specification Phase Protection: Builder cannot modify source files during SPECIFICATION
        if phase == "SPECIFICATION":
            is_allowed_spec_file = rel_path.startswith(".agent-harness/") or rel_path.startswith("docs/")
            if not is_allowed_spec_file:
                return {
                    "decision": "deny",
                    "reason": f"Phase Gate Deny: Tool '{tool_name}' blocked: Workspace is in 'SPECIFICATION' phase. Application source code modifications ('{rel_path}') are denied until requirements and acceptance tests are locked.",
                }

    # 2. Command Execution Tool: run_command
    elif tool_name == "run_command":
        cmd_line = tool_args.get("CommandLine", "") or tool_args.get("command", "")
        if not cmd_line:
            return {"decision": "allow"}

        # Inspect if command writes to protected files
        for protected_rel in PROTECTED_ARTIFACTS:
            protected_name = Path(protected_rel).name
            if protected_name in cmd_line or protected_rel in cmd_line:
                for pat in SHELL_WRITE_PATTERNS:
                    if pat.search(cmd_line):
                        return {
                            "decision": "deny",
                            "reason": f"Security Gate Deny: Command blocked: CommandLine attempts to modify protected harness artifact '{protected_rel}'.",
                        }

        # Specification Phase Protection: Deny command write vectors to source files
        if phase == "SPECIFICATION":
            for pat in SHELL_WRITE_PATTERNS:
                if pat.search(cmd_line):
                    # If command contains redirection or write to source files
                    if any(ext in cmd_line for ext in [".py", ".ts", ".js", ".rs", ".go", ".cpp", ".c", ".java", ".html", ".css"]):
                        if not any(d in cmd_line for d in [".agent-harness", "docs"]):
                            return {
                                "decision": "deny",
                                "reason": "Phase Gate Deny: Command blocked: Shell command write vector to application source detected during 'SPECIFICATION' phase.",
                            }

    return {"decision": "allow"}


def evaluate_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates Stop completion gate.
    Verifies 100% pass rate, fresh fingerprints, evidence chain validity,
    execution-backed passes, fake PASS rejection, zero regressions, and full policy satisfaction.
    """
    # Check for unrecoverable termination reasons (fatal errors, max steps, abort)
    term_reason = payload.get("terminationReason", "")
    if term_reason in {"error", "fatal_error", "max_steps", "user_abort", "abort", "cancelled", "user_cancelled", "aborted"}:
        return {"decision": "allow"}

    workspace = resolve_workspace(payload)
    if not workspace or not kernel.is_harness_active(workspace):
        return {"decision": "allow"}

    state = kernel.load_state(workspace)
    unresolved_gates: List[str] = []

    # 1. Original Request Integrity Check
    if not kernel.verify_original_intent_integrity(workspace):
        unresolved_gates.append("Original request SHA-256 integrity check FAILED (original-request.md was tampered with)")

    # 2. Specification & Acceptance Locks
    if not state.get("specLocked", False):
        unresolved_gates.append("Specification is not locked (specLocked=false)")
    if not state.get("acceptanceLocked", False):
        unresolved_gates.append("Acceptance contracts are not locked (acceptanceLocked=false)")

    # 3. Cryptographic Evidence Chain Validation
    ev_valid, ev_reason = kernel.verify_evidence_chain(workspace)
    if not ev_valid:
        unresolved_gates.append(f"Evidence hash chain validation failed: {ev_reason}")

    # 4. Coverage Completeness
    cov_file = kernel.get_harness_dir(workspace) / "coverage.json"
    if cov_file.exists():
        try:
            with open(cov_file, "r", encoding="utf-8") as f:
                cov_data = json.load(f)
                cov_pct = cov_data.get("coveragePercent", 0)
                is_complete = cov_data.get("complete", False)
                uncovered = cov_data.get("uncoveredStatements", [])
                if not is_complete or cov_pct < 100 or len(uncovered) > 0:
                    unresolved_gates.append(
                        f"Requirement coverage incomplete ({cov_pct}% mapped, {len(uncovered)} uncovered statements)"
                    )
        except Exception:
            unresolved_gates.append("Could not parse coverage.json")
    else:
        unresolved_gates.append("coverage.json does not exist")

    # 5. Invalidate Stale Requirements & Check Freshness
    stale_ids = kernel.check_and_invalidate_stale(workspace)

    # 6. Requirement Ledger Audit & Execution-Backed Pass Verification
    reqs = kernel.load_requirements(workspace)
    if not reqs:
        unresolved_gates.append("No requirements recorded in requirements.json")
    else:
        req_counts = {
            "NOT_STARTED": 0,
            "IN_PROGRESS": 0,
            "IMPLEMENTED_UNVERIFIED": 0,
            "PASS": 0,
            "FAILED": 0,
            "STALE": 0,
            "BLOCKED": 0,
            "DEFERRED": 0,
        }

        required_total = 0
        for req in reqs:
            is_req = req.get("required", True)
            status = req.get("status", "NOT_STARTED")
            if is_req:
                required_total += 1
                req_counts[status] = req_counts.get(status, 0) + 1

        if req_counts["FAILED"] > 0:
            unresolved_gates.append(f"{req_counts['FAILED']} required requirement(s) in FAILED status")
        if req_counts["STALE"] > 0:
            unresolved_gates.append(f"{req_counts['STALE']} required requirement(s) in STALE status (code modified after verification)")
        if req_counts["IMPLEMENTED_UNVERIFIED"] > 0:
            unresolved_gates.append(f"{req_counts['IMPLEMENTED_UNVERIFIED']} required requirement(s) in IMPLEMENTED_UNVERIFIED status (independent verification missing)")
        if req_counts["IN_PROGRESS"] > 0:
            unresolved_gates.append(f"{req_counts['IN_PROGRESS']} required requirement(s) in IN_PROGRESS status")
        if req_counts["NOT_STARTED"] > 0:
            unresolved_gates.append(f"{req_counts['NOT_STARTED']} required requirement(s) in NOT_STARTED status")
        if req_counts["BLOCKED"] > 0:
            unresolved_gates.append(f"{req_counts['BLOCKED']} required requirement(s) BLOCKED without authorized deferral")

    # 7. Anti-Placeholder Production Scan
    placeholders = kernel.scan_for_placeholders(workspace)
    if placeholders:
        unresolved_gates.append(f"Unfinished placeholders detected in production source: {len(placeholders)} instances found")

    # 8. STEP 3: Verification Policy Audit
    policy_file = kernel.get_harness_dir(workspace) / "verification-policy.json"
    if policy_file.exists():
        policy_ok, policy_issues, _ = verification_policy.audit_verification_policy(workspace)
        if not policy_ok:
            for issue in policy_issues:
                unresolved_gates.append(issue)

    # 8b. STEP 4: Adversarial Test Quality Audit
    adv_ok, adv_issues, _ = adversarial_verification.audit_test_quality(workspace)
    if not adv_ok:
        for issue in adv_issues:
            unresolved_gates.append(issue)

    # 8c. STEP 5 & 5.1: Clean Environment, Execution Reality & Reproducibility Audit
    env_file = kernel.get_harness_dir(workspace) / "environment-verification.json"
    ev_file = kernel.get_harness_dir(workspace) / "evidence.jsonl"
    
    # Load all raw evidence events
    evidence_events = []
    if ev_file.exists():
        with open(ev_file, "r", encoding="utf-8") as f_ev:
            for line in f_ev:
                if line.strip():
                    try:
                        evidence_events.append(json.loads(line.strip()))
                    except Exception:
                        pass

    if state.get("cleanEnvRequired", False) or policy_file.exists() or env_file.exists():
        if env_file.exists():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    env_data = json.load(f)
                    env_status = env_data.get("status")
                    if env_status != "CLEAN_ENVIRONMENT_PASS":
                        unresolved_gates.append(f"Clean environment verification failed (status: '{env_status}')")
                    rep_data = env_data.get("reproducibility", {})
                    if rep_data and rep_data.get("status") not in {"REPRODUCIBILITY_PASS", "IDENTICAL", "EXPECTED_NONDETERMINISM"}:
                        unresolved_gates.append(f"Reproducibility verification failed (status: '{rep_data.get('status')}')")

                    # Fake PASS Forgery Protection (Sections 31, 60, 67)
                    real_builds = [e for e in evidence_events if e.get("verificationType") in {"BUILD", "REAL_PROJECT_EXECUTION"} and e.get("origin") in {"REAL_PROJECT_EXECUTION", "LIVE_KERNEL_EXECUTION"}]
                    real_tests = [e for e in evidence_events if e.get("verificationType") in {"TEST", "AUTOMATED_TEST"} and e.get("origin") in {"REAL_PROJECT_EXECUTION", "LIVE_KERNEL_EXECUTION"}]
                    real_runtimes = [e for e in evidence_events if e.get("verificationType") in {"RUNTIME_START", "RUNTIME_OBSERVATION"} and e.get("origin") in {"REAL_PROJECT_EXECUTION", "LIVE_KERNEL_EXECUTION"}]
                    real_migrations = [e for e in evidence_events if e.get("verificationType") in {"MIGRATION", "DATABASE_BOOTSTRAP"} and e.get("origin") in {"REAL_PROJECT_EXECUTION", "LIVE_KERNEL_EXECUTION"}]

                    if env_data.get("cleanBuildFactory", {}).get("scratchBuildAndHashing") == "PASS" and not real_builds and not evidence_events:
                        unresolved_gates.append("BUILD PASS HAS NO EXECUTION EVIDENCE")
                    if env_data.get("cleanBuildFactory", {}).get("cleanTestExecution") == "PASS" and not real_tests and not evidence_events:
                        unresolved_gates.append("TEST PASS HAS NO EXECUTION EVIDENCE")
                    if env_data.get("runtimeAndMigration", {}).get("cleanStartupVerification") == "PASS" and not real_runtimes and not evidence_events:
                        unresolved_gates.append("RUNTIME PASS HAS NO EXECUTION EVIDENCE")
                    if env_data.get("runtimeAndMigration", {}).get("migrationVerification") == "PASS" and not real_migrations and not evidence_events:
                        unresolved_gates.append("MIGRATION PASS HAS NO EXECUTION EVIDENCE")

            except Exception:
                unresolved_gates.append("Could not parse environment-verification.json")
        elif state.get("cleanEnvRequired", False):
            unresolved_gates.append("Clean environment verification record (.agent-harness/environment-verification.json) does not exist")

    # 8d. STEP 6 & 6S: Independent Model Verification / Single-Model Blind Verification Gate
    v_mode = state.get("verificationMode")
    if not v_mode:
        if state.get("blindAuditRequired"):
            v_mode = "SINGLE_MODEL_BLIND"
        elif state.get("independentAuditRequired"):
            v_mode = "MULTI_MODEL"
        else:
            v_mode = "SINGLE_MODEL_BLIND"

    ind_audit_mandatory = bool(state.get("independentAuditRequired", False) or state.get("blindAuditRequired", False))

    if v_mode == "SINGLE_MODEL_BLIND":
        blind_file = kernel.get_harness_dir(workspace) / "blind-verification.json"
        cx_file = kernel.get_harness_dir(workspace) / "counterexample-audit.json"
        hidden_file = kernel.get_harness_dir(workspace) / "hidden-checks.json"
        res_file = kernel.get_harness_dir(workspace) / "evidence-resolutions.json"

        # Check Context Registry cryptographic integrity & pairwise isolation (Step 6S.1 REQ-005, REQ-007)
        reg_valid, reg_errors = context_registry.verify_context_registry(workspace)
        if not reg_valid:
            unresolved_gates.append(f"Context Registry cryptographic chain broken/tampered: {', '.join(reg_errors)}")

        builder_ctx = context_registry.get_registered_context_by_purpose(workspace, "BUILDER")
        blind_ctx = context_registry.get_registered_context_by_purpose(workspace, "BLIND_FINAL_VERIFIER")
        cx_ctx = context_registry.get_registered_context_by_purpose(workspace, "COUNTEREXAMPLE_AUDITOR")

        builder_cid = (builder_ctx.get("conversationId") or "").strip().lower() if builder_ctx else ""
        blind_cid = (blind_ctx.get("conversationId") or "").strip().lower() if blind_ctx else ""
        cx_cid = (cx_ctx.get("conversationId") or "").strip().lower() if cx_ctx else ""

        # Pairwise inequality checks
        if blind_cid and builder_cid and blind_cid == builder_cid:
            unresolved_gates.append(f"Context Reuse Detected (CONTEXT_REUSED): Blind Verifier conversation ID matches Builder ({blind_cid})")

        if cx_cid and builder_cid and cx_cid == builder_cid:
            unresolved_gates.append(f"Context Reuse Detected (CONTEXT_REUSED): Counterexample Auditor conversation ID matches Builder ({cx_cid})")

        if cx_cid and blind_cid and cx_cid == blind_cid:
            unresolved_gates.append(f"Context Reuse Detected (CONTEXT_REUSED): Counterexample Auditor conversation ID matches Blind Verifier ({cx_cid})")

        # Check if HIGH or CRITICAL requirements exist
        has_high_or_critical = any(
            (r.get("risk", {}).get("level") in {"HIGH", "CRITICAL"} or r.get("riskLevel") in {"HIGH", "CRITICAL"})
            for r in reqs
        )

        allow_sim = bool(state.get("allowSimulatedContext", False))
        if has_high_or_critical and ind_audit_mandatory:
            blind_iso, blind_det = context_registry.evaluate_context_isolation(
                workspace, "BLIND_FINAL_VERIFIER", ["BUILDER"], allow_simulated=allow_sim
            )
            if blind_iso != "FRESH_CONTEXT_VERIFIED" and not (allow_sim and blind_iso == "FRESH_CONTEXT_SIMULATED"):
                unresolved_gates.append(f"Blind Verifier context isolation not proven for HIGH/CRITICAL requirements ({blind_iso}: {blind_det.get('reason', '')})")
            elif not allow_sim:
                if blind_det.get("runtimeOriginStatus") != "TRUSTED_HOOK_PATH" or blind_det.get("bindingStatus") not in {"EXPECTATION_CONSUMED", "EXPECTATION_ALREADY_BOUND"}:
                    unresolved_gates.append(f"Blind Verifier context lacks trusted hook origin or consumed expectation (originStatus='{blind_det.get('runtimeOriginStatus')}', binding='{blind_det.get('bindingStatus')}')")

            cx_iso, cx_det = context_registry.evaluate_context_isolation(
                workspace, "COUNTEREXAMPLE_AUDITOR", ["BUILDER", "BLIND_FINAL_VERIFIER"], allow_simulated=allow_sim
            )
            if cx_iso != "FRESH_CONTEXT_VERIFIED" and not (allow_sim and cx_iso == "FRESH_CONTEXT_SIMULATED"):
                unresolved_gates.append(f"Counterexample Auditor context isolation not proven for HIGH/CRITICAL requirements ({cx_iso}: {cx_det.get('reason', '')})")
            elif not allow_sim:
                if cx_det.get("runtimeOriginStatus") != "TRUSTED_HOOK_PATH" or cx_det.get("bindingStatus") not in {"EXPECTATION_CONSUMED", "EXPECTATION_ALREADY_BOUND"}:
                    unresolved_gates.append(f"Counterexample Auditor context lacks trusted hook origin or consumed expectation (originStatus='{cx_det.get('runtimeOriginStatus')}', binding='{cx_det.get('bindingStatus')}')")

        # Check Blind Verification
        if blind_file.exists() or ind_audit_mandatory:
            if blind_file.exists():
                try:
                    with open(blind_file, "r", encoding="utf-8") as f:
                        blind_audit = json.load(f)
                    if blind_audit.get("status") != "COMPLETED":
                        unresolved_gates.append(f"Blind verification audit not completed (status: '{blind_audit.get('status')}')")
                    elif blind_audit.get("overallVerdict") != "PASS":
                        unresolved_gates.append(f"Blind verification audit failed (overallVerdict: '{blind_audit.get('overallVerdict')}')")
                    fresh, fresh_reason = blind_verifier.is_audit_fresh(workspace, blind_audit)
                    if not fresh:
                        unresolved_gates.append(f"Blind verification audit record is STALE: {fresh_reason}")
                except Exception:
                    unresolved_gates.append("Could not parse blind-verification.json")
            else:
                unresolved_gates.append("Blind verification record (.agent-harness/blind-verification.json) does not exist")

        # Check Counterexample Audit
        if cx_file.exists() or ind_audit_mandatory:
            if cx_file.exists():
                try:
                    with open(cx_file, "r", encoding="utf-8") as f:
                        cx_data = json.load(f)
                    if cx_data.get("status") != "COMPLETED":
                        unresolved_gates.append(f"Counterexample audit not completed (status: '{cx_data.get('status')}')")
                    elif cx_data.get("overallVerdict") == "COUNTEREXAMPLE_FOUND":
                        unresolved_cxs = [
                            cx for cx in cx_data.get("counterexamples", [])
                            if not cx.get("resolved", False)
                        ]
                        if unresolved_cxs:
                            unresolved_gates.append(f"Counterexample Audit Gate blocked: {len(unresolved_cxs)} unresolved counterexample(s) found by auditor")
                except Exception:
                    unresolved_gates.append("Could not parse counterexample-audit.json")
            elif ind_audit_mandatory:
                unresolved_gates.append("Counterexample audit record (.agent-harness/counterexample-audit.json) does not exist")

        # Check Hidden Verification
        if hidden_file.exists() or ind_audit_mandatory:
            if hidden_file.exists():
                try:
                    with open(hidden_file, "r", encoding="utf-8") as f:
                        hidden_data = json.load(f)
                    if hidden_data.get("overallStatus") != "PASS":
                        failed_count = hidden_data.get("failedChecks", 0)
                        unresolved_gates.append(f"Hidden Verification Gate blocked: {failed_count} hidden check(s) failed (status: '{hidden_data.get('overallStatus')}')")
                except Exception:
                    unresolved_gates.append("Could not parse hidden-checks.json")
            elif ind_audit_mandatory:
                unresolved_gates.append("Hidden verification record (.agent-harness/hidden-checks.json) does not exist")

        # Check Evidence Resolution cycle tracking
        if res_file.exists():
            try:
                with open(res_file, "r", encoding="utf-8") as f:
                    res_data = json.load(f)
                cycles = res_data.get("cycles", {})
                for cid, cinfo in cycles.items():
                    if cinfo.get("status") in {"BLOCKED", "ESCALATED_BLOCKED"}:
                        unresolved_gates.append(f"Evidence Resolution Gate blocked on {cid}: max resolution cycles exceeded without empirical convergence")
            except Exception:
                unresolved_gates.append("Could not parse evidence-resolutions.json")

    else:
        # Legacy MULTI_MODEL mode
        ind_audit_file = kernel.get_harness_dir(workspace) / "independent-audit.json"
        critical_reqs = [
            r["id"] for r in reqs
            if r.get("risk", {}).get("level") == "CRITICAL"
            or r.get("riskLevel") == "CRITICAL"
            or "INDEPENDENT_MODEL_AUDIT" in r.get("verificationPolicy", {}).get("requiredChecks", [])
        ]
        has_critical_req = len(critical_reqs) > 0

        if ind_audit_file.exists() or ind_audit_mandatory:
            if ind_audit_file.exists():
                try:
                    with open(ind_audit_file, "r", encoding="utf-8") as f:
                        ind_audit = json.load(f)
                        
                    if ind_audit.get("status") not in {"COMPLETED"}:
                        unresolved_gates.append(f"Independent model audit not completed (status: '{ind_audit.get('status')}')")
                    elif ind_audit.get("overallVerdict") != "PASS":
                        unresolved_gates.append(f"Independent model audit failed (overallVerdict: '{ind_audit.get('overallVerdict')}')")
                        
                    target_rids = critical_reqs if critical_reqs else [r["id"] for r in reqs]
                    p_verdicts = {r["id"]: r.get("status", "UNVERIFIED") for r in reqs}
                    comp = disagreement.compare_verdicts(p_verdicts, ind_audit, target_requirement_ids=target_rids)
                    if comp.get("overallConsensus") == "DISAGREEMENT":
                        dis_count = comp.get("disagreementCount", 0)
                        unresolved_gates.append(f"Disagreement Gate blocked: {dis_count} unresolved disagreement(s) between primary and independent auditor")
                except Exception:
                    unresolved_gates.append("Could not parse independent-audit.json")
            else:
                ind_disc = independent_model.discover_independent_models()
                if ind_disc.get("status") == "NOT_CONFIGURED":
                    if has_critical_req:
                        unresolved_gates.append("Independent model audit is MANDATORY for CRITICAL requirements, but INDEPENDENT_MODEL is NOT_CONFIGURED via CLI")
                else:
                    unresolved_gates.append("Independent model audit record (.agent-harness/independent-audit.json) does not exist")

    # 9. STEP 2: Sandbox Promotion Check
    if state.get("sandboxActive", False):
        manifest = sandbox.load_sandbox_manifest(workspace)
        if manifest:
            prom_status = manifest.get("promotionStatus", "BUILDING")
            if prom_status not in {"PROMOTED", "COMPLETE"}:
                unresolved_gates.append(f"Sandbox candidate promotion incomplete (current status: '{prom_status}')")

    # 10. Final Audit Status
    if not state.get("finalAuditPassed", False):
        unresolved_gates.append("Final clean-room verifier audit has not passed (finalAuditPassed=false)")

    if unresolved_gates:
        issues_summary = "\n- " + "\n- ".join(unresolved_gates)
        return {
            "decision": "continue",
            "reason": f"Strict Engineering Completion Gate BLOCKED ({len(unresolved_gates)} issues):{issues_summary}\nResolve all issues and obtain genuine verifier execution evidence before completing.",
        }

    # Mark state as complete
    state["phase"] = "COMPLETE"
    state["active"] = False
    state["completedAt"] = kernel.utc_now_iso()
    kernel.save_state(workspace, state)

    return {"decision": "allow"}
