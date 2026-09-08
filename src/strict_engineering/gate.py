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
from typing import Dict, Any, List, Optional, Tuple, Set, Union

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
    from . import decision_events
    from . import decision_coverage
    from . import consistency_reviewer
    from . import runtime_safety
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
    try:
        import decision_events
        import decision_coverage
        import consistency_reviewer
    except ImportError:
        decision_events = None
        decision_coverage = None
        consistency_reviewer = None
    try:
        import runtime_safety
    except ImportError:
        runtime_safety = None

PROTECTED_ARTIFACTS = {
    ".agent-harness/original-request.md",
    ".agent-harness/original-request.sha256",
    ".agent-harness/state.json",
    ".agent-harness/requirements.json",
    ".agent-harness/coverage.json",
    ".agent-harness/evidence.jsonl",
    ".agent-harness/context-registry.jsonl",
    ".agent-harness/expected-context.json",
    ".agent-harness/circuit-breaker.json",
    ".agent-harness/runtime-events.jsonl",
    "docs/ACCEPTANCE_TESTS.md",
    ".agent-harness/independent-audit.json",
    ".agent-harness/disagreements.json",
    ".agent-harness/blind-verification.json",
    ".agent-harness/counterexample-audit.json",
    ".agent-harness/hidden-checks.json",
    ".agent-harness/evidence-resolutions.json",
    ".agent-harness/frame.json",
    ".agent-harness/concerns.json",
    ".agent-harness/decisions.json",
    ".agent-harness/decision-graph.json",
    ".agent-harness/decision-coverage.json",
    ".agent-harness/decision-events.jsonl",
    ".agent-harness/decision-status.json",
    ".agent-harness/asked-questions.json",
    ".agent-harness/suggestions.json",
    ".agent-harness/discovery/request.json",
    ".agent-harness/discovery/proposals.json",
    ".agent-harness/discovery/status.json",
    ".agent-harness/discovery/seeds.json",
    ".agent-harness/discovery/evidence.json",
    ".agent-harness/discovery/discovery-status.json",
    ".agent-harness/acceptance/requests.json",
    ".agent-harness/acceptance/proposals.json",
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
        p = Path(path_str).resolve()
        ws = Path(workspace_root).resolve()
        rel = str(p.relative_to(ws)).replace("\\", "/")
        if rel.startswith("./"):
            rel = rel[2:]
        return rel
    except Exception:
        pass

    try:
        norm_p = os.path.normcase(os.path.abspath(path_str)).replace("\\", "/")
        norm_ws = os.path.normcase(os.path.abspath(str(workspace_root))).replace("\\", "/")
        if not norm_ws.endswith("/"):
            norm_ws += "/"
        if norm_p.startswith(norm_ws):
            rel = norm_p[len(norm_ws):]
            if rel.startswith("./"):
                rel = rel[2:]
            return rel
    except Exception:
        pass

    rel = str(path_str).replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    return rel


def resolve_workspace(payload: Any) -> Optional[Path]:
    """Resolve active workspace directory from hook payload or path."""
    if isinstance(payload, (str, Path)):
        return Path(payload).resolve()
    if not isinstance(payload, dict):
        return None
    ws_paths = payload.get("workspacePaths", [])
    if ws_paths:
        return Path(ws_paths[0]).resolve()
    cwd = payload.get("cwd")
    if cwd:
        return Path(cwd).resolve()
    return None


def is_write_safe(
    target_path: Union[str, Path],
    calling_role: str = "builder",
    workspace_root: Optional[Union[str, Path]] = None,
) -> Tuple[bool, str]:
    """
    Check if a file write is safe and allowed by the kernel gate.
    """
    if workspace_root:
        ws = Path(workspace_root).resolve()
        rel_path = normalize_rel_path(str(target_path), ws)
    else:
        rel_path = str(target_path).replace("\\", "/")
        if rel_path.startswith("./"):
            rel_path = rel_path[2:]

    norm_rel = rel_path.replace("\\", "/")
    if (
        norm_rel in PROTECTED_ARTIFACTS
        or norm_rel.startswith(".agent-harness/discovery/")
        or norm_rel.startswith(".agent-harness/acceptance/")
        or any(norm_rel.endswith("/" + pa) for pa in PROTECTED_ARTIFACTS)
        or "/.agent-harness/discovery/" in norm_rel
        or "/.agent-harness/acceptance/" in norm_rel
    ):
        return False, f"Direct write denied: '{rel_path}' is a protected harness artifact."
    return True, "Allowed"



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
        is_protected = (
            rel_path in PROTECTED_ARTIFACTS
            or rel_path.startswith(".agent-harness/discovery/")
            or rel_path.startswith(".agent-harness/acceptance/")
            or any(rel_path.endswith("/" + pa) for pa in PROTECTED_ARTIFACTS)
            or "/.agent-harness/discovery/" in rel_path
            or "/.agent-harness/acceptance/" in rel_path
        )
        if is_protected:
            if rel_path == "docs/ACCEPTANCE_TESTS.md" or rel_path.endswith("/docs/ACCEPTANCE_TESTS.md"):
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
            is_allowed_spec_file = (
                rel_path.startswith(".agent-harness/")
                or rel_path.startswith("docs/")
                or "/.agent-harness/" in rel_path
                or "/docs/" in rel_path
            )
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
            if (
                protected_name in cmd_line
                or protected_rel in cmd_line
                or ".agent-harness/acceptance" in cmd_line
                or ".agent-harness/discovery" in cmd_line
            ):
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


def inspect_completion_readiness(workspace: Union[str, Path]) -> Tuple[bool, List[str]]:
    """
    Authoritative, read-only inspection of all engineering kernel completion gates.
    Returns:
    (is_ready: bool, unresolved_gates: List[str])
    """
    ws = Path(workspace).resolve()
    state = kernel.load_state(ws)
    unresolved_gates: List[str] = []

    if not state:
        unresolved_gates.append("No active Strict Engineering harness state found")
        return False, unresolved_gates

    # Runtime Execution Readiness Check
    runtime_status = str(state.get("runtimeStatus", "RUNNING"))
    pause_reason = state.get("pauseReason")
    if runtime_status.startswith("PAUSED_") or runtime_status in {"DISABLED", "INACTIVE", "STOPPED"}:
        msg = f"Runtime execution is paused or disabled: {runtime_status}"
        if pause_reason:
            msg += f" (Reason: {pause_reason})"
        unresolved_gates.append(msg)

    # Circuit Breaker Check across project conversations
    if runtime_safety is not None:
        try:
            cb_summary = runtime_safety.get_circuit_breaker_project_summary(ws)
            if cb_summary.get("anyTripped", False):
                unresolved_gates.append("Circuit breaker is TRIPPED across project conversations")
            else:
                cb_data = runtime_safety.load_circuit_breaker(ws)
                if cb_data.get("tripped", False) or cb_data.get("circuitBreakerTripped", False):
                    unresolved_gates.append("Circuit breaker is TRIPPED")
        except Exception:
            pass

    # 1. Original Request Integrity Check
    if not kernel.verify_original_intent_integrity(ws):
        unresolved_gates.append("Original request SHA-256 integrity check FAILED (original-request.md was tampered with)")

    # 2. Specification & Acceptance Locks
    if not state.get("specLocked", False):
        unresolved_gates.append("Specification is not locked (specLocked=false)")
    if not state.get("acceptanceLocked", False):
        unresolved_gates.append("Acceptance contracts are not locked (acceptanceLocked=false)")

    # 3. Cryptographic Evidence Chain Validation
    ev_valid, ev_reason = kernel.verify_evidence_chain(ws)
    if not ev_valid:
        unresolved_gates.append(f"Evidence hash chain validation failed: {ev_reason}")

    # 4. Coverage Completeness
    cov_file = kernel.get_harness_dir(ws) / "coverage.json"
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

    # 5. Detect Stale Requirements & Check Freshness (Pure Inspection)
    if hasattr(kernel, "detect_stale_requirements"):
        stale_ids = kernel.detect_stale_requirements(ws)
    else:
        stale_ids = kernel.check_and_invalidate_stale(ws)
    if stale_ids:
        unresolved_gates.append(
            f"{len(stale_ids)} requirement(s) would become STALE due to workspace modifications post-verification: {', '.join(stale_ids)}"
        )

    # 6. Requirement Ledger Audit & Execution-Backed Pass Verification
    reqs = kernel.load_requirements(ws)
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
    placeholders = kernel.scan_for_placeholders(ws)
    if placeholders:
        unresolved_gates.append(f"Unfinished placeholders detected in production source: {len(placeholders)} instances found")

    # 8. STEP 3: Verification Policy Audit
    policy_file = kernel.get_harness_dir(ws) / "verification-policy.json"
    if policy_file.exists():
        policy_ok, policy_issues, _ = verification_policy.audit_verification_policy(ws)
        if not policy_ok:
            for issue in policy_issues:
                unresolved_gates.append(issue)

    # 8b. STEP 4: Adversarial Test Quality Audit
    adv_ok, adv_issues, _ = adversarial_verification.audit_test_quality(ws)
    if not adv_ok:
        for issue in adv_issues:
            unresolved_gates.append(issue)

    # 8c. STEP 5 & 5.1: Clean Environment, Execution Reality & Reproducibility Audit
    env_file = kernel.get_harness_dir(ws) / "environment-verification.json"
    ev_file = kernel.get_harness_dir(ws) / "evidence.jsonl"
    
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
        blind_file = kernel.get_harness_dir(ws) / "blind-verification.json"
        cx_file = kernel.get_harness_dir(ws) / "counterexample-audit.json"
        hidden_file = kernel.get_harness_dir(ws) / "hidden-checks.json"
        res_file = kernel.get_harness_dir(ws) / "evidence-resolutions.json"

        # Check Context Registry cryptographic integrity & pairwise isolation (Step 6S.1 REQ-005, REQ-007)
        reg_valid, reg_errors = context_registry.verify_context_registry(ws)
        if not reg_valid:
            unresolved_gates.append(f"Context Registry cryptographic chain broken/tampered: {', '.join(reg_errors)}")

        builder_ctx = context_registry.get_registered_context_by_purpose(ws, "BUILDER")
        blind_ctx = context_registry.get_registered_context_by_purpose(ws, "BLIND_FINAL_VERIFIER")
        cx_ctx = context_registry.get_registered_context_by_purpose(ws, "COUNTEREXAMPLE_AUDITOR")

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
                ws, "BLIND_FINAL_VERIFIER", ["BUILDER"], allow_simulated=allow_sim
            )
            if blind_iso != "FRESH_CONTEXT_VERIFIED" and not (allow_sim and blind_iso == "FRESH_CONTEXT_SIMULATED"):
                unresolved_gates.append(f"Blind Verifier context isolation not proven for HIGH/CRITICAL requirements ({blind_iso}: {blind_det.get('reason', '')})")
            elif not allow_sim:
                if blind_det.get("runtimeOriginStatus") != "TRUSTED_HOOK_PATH" or blind_det.get("bindingStatus") not in {"EXPECTATION_CONSUMED", "EXPECTATION_ALREADY_BOUND"}:
                    unresolved_gates.append(f"Blind Verifier context lacks trusted hook origin or consumed expectation (originStatus='{blind_det.get('runtimeOriginStatus')}', binding='{blind_det.get('bindingStatus')}')")

            cx_iso, cx_det = context_registry.evaluate_context_isolation(
                ws, "COUNTEREXAMPLE_AUDITOR", ["BUILDER", "BLIND_FINAL_VERIFIER"], allow_simulated=allow_sim
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
                    fresh, fresh_reason = blind_verifier.is_audit_fresh(ws, blind_audit)
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
        ind_audit_file = kernel.get_harness_dir(ws) / "independent-audit.json"
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
        manifest = sandbox.load_sandbox_manifest(ws)
        if manifest:
            prom_status = manifest.get("promotionStatus", "BUILDING")
            if prom_status not in {"PROMOTED", "COMPLETE"}:
                unresolved_gates.append(f"Sandbox candidate promotion incomplete (current status: '{prom_status}')")

    # 10. Final Audit Status
    if not state.get("finalAuditPassed", False):
        unresolved_gates.append("Final clean-room verifier audit has not passed (finalAuditPassed=false)")

    # 11. STEP 7: Decision Engine Integrity, Consistency, and Coverage Audit
    frame_file = kernel.get_harness_dir(ws) / "frame.json"
    dec_file = kernel.get_harness_dir(ws) / "decisions.json"
    dec_events_file = kernel.get_harness_dir(ws) / "decision-events.jsonl"

    if frame_file.exists() or dec_file.exists() or dec_events_file.exists():
        # Check Decision Event Ledger Cryptographic Integrity
        if dec_events_file.exists() and decision_events is not None:
            ledger_ok, ledger_errors = decision_events.verify_decision_events_integrity(ws)
            if not ledger_ok:
                unresolved_gates.append(f"Decision event ledger integrity violated: {'; '.join(ledger_errors)}")

        # Check Decision Consistency
        if consistency_reviewer is not None and frame_file.exists():
            consist_ok, consist_issues = consistency_reviewer.audit_workspace_consistency(ws)
            if not consist_ok:
                blocking_consist = [i["message"] for i in consist_issues if i.get("severity") == "BLOCKING"]
                unresolved_gates.append(f"Decision consistency audit blocked: {'; '.join(blocking_consist)}")

        # Check Decision Coverage and detect Orphaned Requirements
        if decision_coverage is not None:
            try:
                if hasattr(decision_coverage, "compute_decision_coverage"):
                    dec_cov = decision_coverage.compute_decision_coverage(ws)
                else:
                    dec_cov = decision_coverage.sync_decision_coverage(ws)
                orphans = dec_cov.get("orphanedRequirements", [])
                if orphans:
                    unresolved_gates.append(f"Orphaned requirements detected without decision trace: {', '.join(orphans)}")
            except Exception:
                pass

    # 12. Unresolved CRITICAL/HIGH Concerns check
    concerns_file = kernel.get_harness_dir(ws) / "concerns.json"
    if concerns_file.exists():
        try:
            with open(concerns_file, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                concerns = c_data if isinstance(c_data, list) else c_data.get("concerns", [])
                unresolved_states = {"DISCOVERED", "UNRESOLVED", "ACTIVE", "BLOCKED", "ASKABLE", "SUGGESTABLE", "CHALLENGE_REQUIRED", "SAFE_INFERABLE"}
                for c in concerns:
                    c_status = c.get("status", "UNRESOLVED")
                    c_risk = c.get("riskLevel") or c.get("risk") or "LOW"
                    if c_status in unresolved_states and c_risk in {"CRITICAL", "HIGH"}:
                        unresolved_gates.append(f"Unresolved {c_risk} concern: {c.get('id', 'CONCERN')} ({c.get('title', c.get('statement', ''))})")
        except Exception:
            pass

    return (len(unresolved_gates) == 0, unresolved_gates)


def evaluate_stop(payload: Any) -> Dict[str, Any]:
    """
    Evaluates Stop completion gate.
    Verifies 100% pass rate, fresh fingerprints, evidence chain validity,
    execution-backed passes, fake PASS rejection, zero regressions, and full policy satisfaction.
    """
    if isinstance(payload, (str, Path)):
        payload = {"workspacePaths": [str(payload)]}
    elif not isinstance(payload, dict):
        payload = {}

    workspace = resolve_workspace(payload)
    if not workspace or not kernel.is_harness_active(workspace):
        return {"decision": "allow"}

    # Normalize termination information deterministically (V1.0.2)
    if runtime_safety is not None:
        term_class, term_details = runtime_safety.normalize_termination(payload)
    else:
        raw_tr = str(payload.get("terminationReason", "")).lower()
        if raw_tr in {"error", "fatal_error", "max_steps", "max_steps_exceeded", "user_abort", "abort", "cancelled", "user_cancelled", "aborted"}:
            return {"decision": "allow"}
        term_class = "NORMAL_MODEL_STOP"
        term_details = {"rawReason": raw_tr}

    state = kernel.load_state(workspace)
    conv_id = (
        payload.get("conversationId")
        or payload.get("conversation_id")
        or payload.get("conversationID")
        or ""
    )

    # USER_CANCELLED: allow stop, never auto continue, preserve state in pause
    if runtime_safety is not None and term_class == runtime_safety.TerminationClass.USER_CANCELLED:
        state["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_USER_CANCEL
        state["pauseReason"] = "User cancellation requested"
        kernel.save_state(workspace, state)
        runtime_safety.record_runtime_event(
            workspace_dir=workspace,
            event_type="STOP_USER_CANCELLED",
            termination_class=term_class,
            raw_reason=term_details.get("rawReason"),
            phase=state.get("phase"),
            runtime_status=state.get("runtimeStatus"),
            decision="allow",
            conversation_id=conv_id,
            state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
        )
        return {"decision": "allow", "reason": "Execution cancelled by user. State preserved in pause."}

    # MAX_STEPS: allow stop, never auto continue, preserve state in pause
    if runtime_safety is not None and term_class == runtime_safety.TerminationClass.MAX_STEPS:
        state["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_MAX_STEPS
        state["pauseReason"] = "Maximum execution steps reached"
        kernel.save_state(workspace, state)
        runtime_safety.record_runtime_event(
            workspace_dir=workspace,
            event_type="STOP_MAX_STEPS",
            termination_class=term_class,
            raw_reason=term_details.get("rawReason"),
            phase=state.get("phase"),
            runtime_status=state.get("runtimeStatus"),
            decision="allow",
            conversation_id=conv_id,
            state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
        )
        return {"decision": "allow", "reason": "Maximum execution steps reached. Pausing without completion."}

    # EXTERNAL_ERROR: allow stop, never auto continue, never false failure
    if runtime_safety is not None and term_class == runtime_safety.TerminationClass.EXTERNAL_ERROR:
        err_msg = term_details.get("rawError") or term_details.get("rawReason") or "External runtime failure"
        state["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_EXTERNAL_ERROR
        state["pauseReason"] = f"External error: {err_msg}"
        kernel.save_state(workspace, state)
        runtime_safety.record_runtime_event(
            workspace_dir=workspace,
            event_type="STOP_EXTERNAL_ERROR",
            termination_class=term_class,
            raw_reason=err_msg,
            phase=state.get("phase"),
            runtime_status=state.get("runtimeStatus"),
            decision="allow",
            conversation_id=conv_id,
            state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
            details=term_details,
        )
        return {"decision": "allow", "reason": f"External runtime failure detected ({err_msg}). Pausing execution safely without false completion."}

    # UNKNOWN_TERMINATION: conservative stop if abnormal token present
    if runtime_safety is not None and term_class == runtime_safety.TerminationClass.UNKNOWN_TERMINATION:
        raw_token = term_details.get("rawReason") or "unknown"
        state["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_UNKNOWN
        state["pauseReason"] = f"Unknown termination: {raw_token}"
        kernel.save_state(workspace, state)
        runtime_safety.record_runtime_event(
            workspace_dir=workspace,
            event_type="STOP_UNKNOWN_TERMINATION",
            termination_class=term_class,
            raw_reason=raw_token,
            phase=state.get("phase"),
            runtime_status=state.get("runtimeStatus"),
            decision="allow",
            conversation_id=conv_id,
            state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
        )
        return {"decision": "allow", "reason": f"Unknown abnormal termination token ({raw_token}). Halting safely."}

    state = kernel.load_state(workspace)
    # Authorized lifecycle mutation on stop: actively transition any stale requirements
    if hasattr(kernel, "check_and_invalidate_stale"):
        try:
            kernel.check_and_invalidate_stale(workspace)
        except Exception:
            pass
    is_ready, unresolved_gates = inspect_completion_readiness(workspace)

    if not is_ready:
        # Check Bounded Automatic-Continue Circuit Breaker (V1.0.2)
        if runtime_safety is not None:
            can_continue, cont_count, cb_reason = runtime_safety.evaluate_circuit_breaker(
                workspace_dir=workspace,
                conversation_id=conv_id,
            )
            if not can_continue:
                # Circuit breaker tripped! Halt automatic continues
                state["runtimeStatus"] = runtime_safety.RuntimeStatus.PAUSED_CIRCUIT_BREAKER
                state["pauseReason"] = cb_reason
                kernel.save_state(workspace, state)
                runtime_safety.record_runtime_event(
                    workspace_dir=workspace,
                    event_type="CIRCUIT_BREAKER_TRIPPED",
                    termination_class=term_class,
                    raw_reason=cb_reason,
                    phase=state.get("phase"),
                    runtime_status=state.get("runtimeStatus"),
                    decision="allow",
                    continue_count=cont_count,
                    conversation_id=conv_id,
                    state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
                )
                return {
                    "decision": "allow",
                    "reason": f"Strict Engineering Circuit Breaker TRIPPED: {cb_reason} Pausing execution.",
                }
            else:
                # Bounded continue permitted
                runtime_safety.record_runtime_event(
                    workspace_dir=workspace,
                    event_type="AUTO_CONTINUE_ISSUED",
                    termination_class=term_class,
                    raw_reason=cb_reason,
                    phase=state.get("phase"),
                    runtime_status=state.get("runtimeStatus", "RUNNING"),
                    decision="continue",
                    continue_count=cont_count,
                    conversation_id=conv_id,
                    state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
                )

        issues_summary = "\n- " + "\n- ".join(unresolved_gates)
        return {
            "decision": "continue",
            "reason": f"Strict Engineering Completion Gate BLOCKED ({len(unresolved_gates)} issues):{issues_summary}\nResolve all issues and obtain genuine verifier execution evidence before completing.",
        }

    # Mark state as complete
    state["phase"] = "COMPLETE"
    state["active"] = False
    state["runtimeStatus"] = runtime_safety.RuntimeStatus.COMPLETED if runtime_safety is not None else "COMPLETED"
    state["completedAt"] = kernel.utc_now_iso()
    kernel.save_state(workspace, state)

    if runtime_safety is not None:
        runtime_safety.reset_circuit_breaker(workspace)
        runtime_safety.record_runtime_event(
            workspace_dir=workspace,
            event_type="STOP_COMPLETED",
            termination_class=term_class,
            phase="COMPLETE",
            runtime_status="COMPLETED",
            decision="allow",
            conversation_id=conv_id,
            state_fingerprint=runtime_safety.compute_state_progress_fingerprint(workspace),
        )

    return {"decision": "allow"}
