"""
Strict Engineering Kernel V4.1 & Step 2 - Gating & Policy Engine
Evaluates PreToolUse file/phase protections, command shell bypasses,
builder worktree isolation enforcement, and Stop hook completion gates.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import kernel
    from . import fingerprint
    from . import baseline
    from . import sandbox
    from . import verification_policy
    from . import risk_engine
    from . import adversarial_verification
except (ImportError, ValueError):
    import kernel
    import fingerprint
    import baseline
    import sandbox
    import verification_policy
    import risk_engine
    import adversarial_verification

PROTECTED_ARTIFACTS = {
    ".agent-harness/original-request.md",
    ".agent-harness/original-request.sha256",
    ".agent-harness/state.json",
    ".agent-harness/requirements.json",
    ".agent-harness/coverage.json",
    ".agent-harness/evidence.jsonl",
    ".agent-harness/sandbox.json",
    ".agent-harness/verification-policy.json",
    ".agent-harness/adversarial-policy.json",
    ".agent-harness/environment-verification.json",
    "docs/ACCEPTANCE_TESTS.md",
}


def normalize_path(path_str: str) -> str:
    """Normalize path string to forward slashes."""
    return str(Path(path_str)).replace("\\", "/")


def resolve_workspace(payload: Dict[str, Any]) -> Optional[Path]:
    """Extract primary workspace directory from hook payload."""
    workspace_paths = payload.get("workspacePaths") or []
    if workspace_paths:
        return Path(workspace_paths[0]).resolve()
    return Path.cwd().resolve()


def get_relative_path(target_path_str: str, workspace: Path) -> str:
    """Calculate relative path to workspace cleanly."""
    try:
        target_path = Path(target_path_str).resolve()
        workspace_path = workspace.resolve()
        rel = target_path.relative_to(workspace_path)
        p = str(rel).replace("\\", "/")
        if p.startswith("./"):
            p = p[2:]
        return p
    except Exception:
        norm_t = normalize_path(target_path_str)
        norm_w = normalize_path(str(workspace))
        if norm_t.lower().startswith(norm_w.lower()):
            p = norm_t[len(norm_w):].lstrip("/\\")
            return p
        p = norm_t
        if p.startswith("./"):
            p = p[2:]
        return p


def is_protected_artifact(rel_path: str) -> Optional[str]:
    """Check if relative path matches any of the protected artifacts."""
    norm = rel_path.replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    norm_lower = norm.lower()

    for protected in PROTECTED_ARTIFACTS:
        prot_lower = protected.lower()
        if norm_lower == prot_lower or norm_lower.endswith("/" + prot_lower):
            return protected
    return None


def inspect_shell_command_for_bypasses(
    command_line: str,
    workspace: Path,
    phase: str,
    spec_locked: bool,
    acceptance_locked: bool,
) -> Tuple[bool, str]:
    """
    Inspect run_command CommandLine for PowerShell, Cmd, and Python file-write / bypass attempts
    against protected artifacts or phase locks.
    """
    cmd_lower = command_line.lower()

    # 1. Check for references to protected artifacts in destructive/write contexts
    for protected in PROTECTED_ARTIFACTS:
        base_name = Path(protected).name.lower()
        full_rel = protected.lower()

        # Check if protected artifact name is present in command
        if base_name in cmd_lower or full_rel in cmd_lower:
            dangerous_patterns = [
                # Redirections
                r">\s*",
                r">>\s*",
                r"\|\s*out-file",
                r"\|\s*set-content",
                r"\|\s*add-content",
                r"\|\s*sc\b",
                r"\|\s*ac\b",
                # File creation / modification cmdlets & commands
                r"\bset-content\b",
                r"\badd-content\b",
                r"\bout-file\b",
                r"\bsc\b",
                r"\bac\b",
                r"\bset-content-path\b",
                r"\bcopy-item\b",
                r"\bmove-item\b",
                r"\bremove-item\b",
                r"\brename-item\b",
                r"\bcopy\b",
                r"\bmove\b",
                r"\bdel\b",
                r"\brm\b",
                r"\bren\b",
                r"\berase\b",
                r"\becho\b.*>",
                # Python inline file writes
                r"\bopen\s*\(.*['\"].*,\s*['\"][w|a]",
                r"\.write\s*\(",
                r"\.write_text\s*\(",
                r"\.write_bytes\s*\(",
                r"os\.remove\s*\(",
                r"os\.unlink\s*\(",
                r"shutil\.(copy|move|rmtree)",
            ]

            for pat in dangerous_patterns:
                if re.search(pat, cmd_lower):
                    return False, f"Security Gate Deny: Command contains forbidden shell bypass attempting to modify protected artifact '{protected}'."

    # 2. Check for SPECIFICATION phase source modifications via shell
    if phase in {"DISCOVERY", "SPECIFICATION"}:
        spec_write_patterns = [
            r">\s*([^&|<>]*\.(py|ts|js|tsx|jsx|go|rs|java|c|cpp|dart|html|css|json|yaml|yml))",
            r">>\s*([^&|<>]*\.(py|ts|js|tsx|jsx|go|rs|java|c|cpp|dart|html|css|json|yaml|yml))",
            r"\b(set-content|add-content|out-file|sc|ac)\b.*-path\s+['\"]?([^'\"\s]+\.(py|ts|js|tsx|jsx|go|rs|java|c|cpp|dart))",
        ]
        for pat in spec_write_patterns:
            m = re.search(pat, cmd_lower)
            if m:
                target = m.group(1) if len(m.groups()) >= 1 else ""
                if not (target.startswith(".agent-harness") or target.startswith("docs")):
                    return False, f"Phase Gate Deny: Phase '{phase}' is active. Modifying application source code via shell commands is locked until specification is complete."

    return True, ""


def evaluate_pre_tool_use(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    PreToolUse policy evaluation.
    Enforces phase protections, protected critical artifacts, command-shell bypass inspections,
    and Builder worktree isolation.
    """
    workspace = resolve_workspace(payload)
    if not workspace or not kernel.is_harness_active(workspace):
        return {"decision": "allow"}

    tool_call = payload.get("toolCall", {})
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {})

    state = kernel.load_state(workspace)
    phase = state.get("phase", "DISCOVERY")
    spec_locked = bool(state.get("specLocked", False))
    acceptance_locked = bool(state.get("acceptanceLocked", False))
    sandbox_active = bool(state.get("sandboxActive", False))
    builder_wt_str = state.get("builderWorktree", "")
    builder_wt_path = Path(builder_wt_str).resolve() if builder_wt_str else None

    # Caller identity
    caller_role = (payload.get("callerRole") or payload.get("agentRole") or "").lower()

    # 1. Handle command execution tool (run_command)
    if tool_name == "run_command":
        cmd_line = args.get("CommandLine") or args.get("command") or args.get("command_line") or ""
        allowed, reason = inspect_shell_command_for_bypasses(
            cmd_line,
            workspace,
            phase,
            spec_locked,
            acceptance_locked,
        )
        if not allowed:
            return {"decision": "deny", "reason": reason}
        return {"decision": "allow"}

    # 2. Handle file writing and editing tools
    target_path_str = (
        args.get("TargetFile")
        or args.get("target_file")
        or args.get("FilePath")
        or args.get("file_path")
        or args.get("Path")
        or args.get("path")
    )

    if target_path_str:
        target_path = Path(target_path_str).resolve()
        rel_target = get_relative_path(target_path_str, workspace)
        protected_match = is_protected_artifact(rel_target)

        # 2a. STEP 2: Builder Worktree Isolation Gating
        if sandbox_active and builder_wt_path:
            is_inside_builder_wt = False
            try:
                target_path.relative_to(builder_wt_path)
                is_inside_builder_wt = True
            except Exception:
                is_inside_builder_wt = False

            # If caller is Builder or during implementation phase writing application code
            is_builder_write = ("builder" in caller_role) or (phase in {"IMPLEMENTATION", "PLANNING"})

            if is_builder_write:
                # If target is in canonical workspace outside .agent-harness and docs, and NOT in builder worktree: DENIED!
                if not is_inside_builder_wt:
                    is_canon_src = not (rel_target.startswith(".agent-harness") or rel_target.startswith("docs"))
                    if is_canon_src:
                        return {
                            "decision": "deny",
                            "reason": f"Security Gate Deny: Builder must perform all implementation source modifications in builderWorktree ({builder_wt_str}). Direct mutation of canonical workspace source files is prohibited.",
                        }

        # 2b. Check if modifying a protected artifact
        if protected_match:
            # Original request immutability
            if protected_match in {".agent-harness/original-request.md", ".agent-harness/original-request.sha256"}:
                if spec_locked:
                    return {
                        "decision": "deny",
                        "reason": "Security Gate Deny: Original user request and its SHA-256 hash are immutable once specification is locked.",
                    }

            # Kernel state & ledger artifacts
            if protected_match in {
                ".agent-harness/state.json",
                ".agent-harness/requirements.json",
                ".agent-harness/coverage.json",
                ".agent-harness/evidence.jsonl",
                ".agent-harness/sandbox.json",
    ".agent-harness/verification-policy.json",
    ".agent-harness/adversarial-policy.json",
                ".agent-harness/environment-verification.json",
            }:
                return {
                    "decision": "deny",
                    "reason": f"Security Gate Deny: {protected_match} is managed exclusively by the deterministic kernel.",
                }

            # Acceptance contract immutability
            if protected_match == "docs/ACCEPTANCE_TESTS.md":
                if acceptance_locked:
                    return {
                        "decision": "deny",
                        "reason": "Security Gate Deny: Acceptance contracts in docs/ACCEPTANCE_TESTS.md are immutable once locked.",
                    }

        # 2c. Phase Gate: In DISCOVERY / SPECIFICATION phases, lock application source mutations
        if phase in {"DISCOVERY", "SPECIFICATION"}:
            if not (rel_target.startswith(".agent-harness/") or rel_target.startswith("docs/")):
                return {
                    "decision": "deny",
                    "reason": f"Phase Gate Deny: Phase '{phase}' is active. Application source modifications are locked until specification and acceptance contracts are formally locked.",
                }

    return {"decision": "allow"}


def evaluate_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stop hook evaluation.
    Determines whether execution loop may terminate or must continue.
    Full completion formula verified including Step 2 sandbox promotion.
    """
    workspace = resolve_workspace(payload)
    if not workspace or not kernel.is_harness_active(workspace):
        return {"decision": "allow"}

    # Error loop safety
    term_reason = payload.get("terminationReason", "")
    error_msg = payload.get("error", "")
    if term_reason in {"error", "user_abort", "max_steps"} or (term_reason and error_msg):
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

    # 6. Requirement Ledger Audit
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


    # 8c. STEP 5: Clean Environment & Reproducibility Audit
    env_file = kernel.get_harness_dir(workspace) / "environment-verification.json"
    if state.get("cleanEnvRequired", False) or policy_file.exists():
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
            except Exception:
                unresolved_gates.append("Could not parse environment-verification.json")
        elif state.get("cleanEnvRequired", False):
            unresolved_gates.append("Clean environment verification record (.agent-harness/environment-verification.json) does not exist")

    # 9. STEP 2: Sandbox Promotion Check
    if state.get("sandboxActive", False):
        manifest = sandbox.load_sandbox_manifest(workspace)
        if manifest:
            prom_status = manifest.get("promotionStatus", "BUILDING")
            if prom_status not in {"PROMOTED", "COMPLETE"}:
                unresolved_gates.append(f"Sandbox candidate promotion incomplete (current status: '{prom_status}')")

    # 9. Final Audit Status
    if not state.get("finalAuditPassed", False):
        if not unresolved_gates:
            unresolved_gates.append("Clean-room final verifier audit required before completion")

    # If all criteria passed, allow termination!
    if not unresolved_gates:
        state["phase"] = "COMPLETE"
        state["active"] = False
        kernel.save_state(workspace, state)
        return {"decision": "allow"}

    # --- LOOP PROTECTION & ESCALATION ---
    issues_key = " | ".join(sorted(unresolved_gates))
    counters = state.setdefault("attemptCounters", {})
    count = counters.get(issues_key, 0) + 1
    counters[issues_key] = count
    kernel.save_state(workspace, state)

    if count >= 3:
        if state.get("escalatedToDiagnostics"):
            return {
                "decision": "allow",
                "reason": f"Loop breaker: Repeated failures persisted after diagnostic escalation ({count} attempts). Unresolved: {'; '.join(unresolved_gates)}",
            }
        else:
            state["escalatedToDiagnostics"] = True
            kernel.save_state(workspace, state)
            return {
                "decision": "continue",
                "reason": (
                    f"ESCALATION: Repeated failure threshold reached (attempt {count}). "
                    f"Orchestrator must invoke diagnostic-engineer to analyze root causes. "
                    f"Unresolved gates: {'; '.join(unresolved_gates)}"
                ),
            }

    return {
        "decision": "continue",
        "reason": f"Strict Engineering Completion Gate: Work cannot terminate until all required conditions pass. Unresolved: {'; '.join(unresolved_gates)}"
    }
