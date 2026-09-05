"""
Strict Engineering Kernel Step 3, 4, 5 & 6 - Verification Policy Compiler
Compiles machine-readable verification policies (.agent-harness/verification-policy.json),
enforces capability awareness, adversarial test quality, clean environment,
independent model verification (Step 6), and validates policy satisfaction against the evidence chain.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import kernel
    from . import risk_engine
    from . import environment_detector
    from . import reproducibility
    from . import independent_model
    from . import disagreement
except (ImportError, ValueError):
    import kernel
    import risk_engine
    import environment_detector
    import reproducibility
    import independent_model
    import disagreement

POLICY_SCHEMA_VERSION = "3.0.0"

CHECK_TYPES = [
    "STATIC",
    "AUTOMATED_TEST",
    "RUNTIME_OBSERVATION",
    "NEGATIVE_PATH",
    "RESTART_PERSISTENCE",
    "RECOVERY_OBSERVATION",
    "CLEAN_ROOM_AUDIT",
    "POST_PROMOTION",
    "CLEAN_ENVIRONMENT",
    "REPRODUCIBILITY",
    "INDEPENDENT_MODEL_AUDIT",
]


def detect_project_capabilities(workspace_dir: Path) -> Dict[str, Any]:
    """
    Discover available verification capabilities in workspace.
    Distinguishes CONFIGURED vs NOT_CONFIGURED vs NOT_APPLICABLE.
    """
    workspace_path = Path(workspace_dir).resolve()
    base_file = workspace_path / ".agent-harness" / "baseline.json"
    
    has_typecheck = False
    has_build = False
    has_test = False
    has_lint = False
    
    if base_file.exists():
        try:
            with open(base_file, "r", encoding="utf-8") as f:
                base_data = json.load(f)
                has_typecheck = base_data.get("typecheckStatus") in {"PASSED", "FAILED"}
                has_build = bool(base_data.get("buildCommand"))
                has_test = bool(base_data.get("testCommand"))
                has_lint = bool(base_data.get("lintCommand"))
        except Exception:
            pass

    # Check for web UI vs CLI/Library
    is_web_ui = False
    for root, _, files in os.walk(workspace_path):
        if any(f in {"package.json", "index.html", "App.tsx", "App.vue"} for f in files):
            is_web_ui = True
            break

    # Discover independent model availability and workspace configuration
    state_file = workspace_path / ".agent-harness" / "state.json"
    independent_audit_req = False
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                s_data = json.load(f)
                independent_audit_req = bool(s_data.get("independentAuditRequired", False))
        except Exception:
            pass

    ind_disc = independent_model.discover_independent_models()
    has_independent_model = ind_disc.get("status") == "AVAILABLE" or independent_audit_req

    return {
        "independentAuditRequired": independent_audit_req,
        "hasTypecheck": has_typecheck,
        "hasBuild": has_build,
        "hasTest": has_test,
        "hasLint": has_lint,
        "isWebUi": is_web_ui,
        "isCli": not is_web_ui,
        "hasIndependentModel": has_independent_model,
        "independentModelSlug": ind_disc.get("independentModelSlug"),
    }


def compile_verification_policy(
    req: Dict[str, Any], capabilities: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Compile deterministic verification policy for a requirement based on risk level
    and requirement characteristics.
    """
    risk_info = req.get("risk", {})
    risk_level = risk_info.get("level", "LOW").upper()
    title = str(req.get("title", "")).lower()
    desc = str(req.get("description", "")).lower()
    text = f"{title} {desc}"

    required_checks: List[str] = ["STATIC", "AUTOMATED_TEST"]
    applicable_checks: List[str] = ["STATIC", "AUTOMATED_TEST"]

    # Characteristics detection
    codes_text = " ".join(str(c) for c in risk_info.get("reasonCodes", [])).lower()
    all_text = f"{text} {codes_text}"

    is_persistence = "persist" in all_text or "data_persistence" in all_text
    is_auth = "auth" in all_text or "auth_boundary" in all_text
    is_destructive = "delete" in all_text or "wipe" in all_text or "destructive_irreversible" in all_text
    is_untrusted_input = "sanitize" in all_text or "xss" in all_text or "input_validation_untrusted" in all_text
    is_dep_change = "dependency" in all_text or "package" in all_text or "toolchain" in all_text
    is_migration = "migration" in all_text or "schema" in all_text or "database" in all_text
    is_repro = "reproducib" in all_text or "double-build" in all_text
    is_ind_audit_flagged = "independent" in all_text or req.get("independentAuditRequired", False)

    is_ind_audit_enabled = (
        bool(capabilities and capabilities.get("hasIndependentModel"))
        or bool(capabilities and capabilities.get("independentAuditRequired"))
        or bool(req.get("independentAuditRequired"))
        or is_ind_audit_flagged
    )

    if risk_level == "LOW":
        # Low risk: static check + single automated behavioral check
        pass
    elif risk_level == "MEDIUM":
        required_checks.append("RUNTIME_OBSERVATION")
        applicable_checks.append("RUNTIME_OBSERVATION")
        if is_persistence:
            required_checks.append("RESTART_PERSISTENCE")
            applicable_checks.append("RESTART_PERSISTENCE")
        if is_ind_audit_enabled and is_ind_audit_flagged:
            required_checks.append("INDEPENDENT_MODEL_AUDIT")
            applicable_checks.append("INDEPENDENT_MODEL_AUDIT")
    elif risk_level == "HIGH":
        required_checks.extend(["RUNTIME_OBSERVATION", "NEGATIVE_PATH", "POST_PROMOTION"])
        applicable_checks.extend(["RUNTIME_OBSERVATION", "NEGATIVE_PATH", "POST_PROMOTION"])
        if is_persistence:
            required_checks.append("RESTART_PERSISTENCE")
            applicable_checks.append("RESTART_PERSISTENCE")
        if is_untrusted_input or is_auth:
            if "NEGATIVE_PATH" not in required_checks:
                required_checks.append("NEGATIVE_PATH")
        if is_ind_audit_enabled and (is_auth or is_destructive or is_ind_audit_flagged):
            required_checks.append("INDEPENDENT_MODEL_AUDIT")
            applicable_checks.append("INDEPENDENT_MODEL_AUDIT")
    elif risk_level == "CRITICAL":
        required_checks.extend([
            "RUNTIME_OBSERVATION",
            "NEGATIVE_PATH",
            "CLEAN_ROOM_AUDIT",
            "POST_PROMOTION",
        ])
        if is_ind_audit_enabled:
            required_checks.append("INDEPENDENT_MODEL_AUDIT")
        applicable_checks.extend([
            "RUNTIME_OBSERVATION",
            "NEGATIVE_PATH",
            "CLEAN_ROOM_AUDIT",
            "POST_PROMOTION",
            "INDEPENDENT_MODEL_AUDIT",
        ])
        if is_persistence:
            required_checks.append("RESTART_PERSISTENCE")
            applicable_checks.append("RESTART_PERSISTENCE")
        if is_destructive or "BACKUP_RESTORE" in risk_info.get("reasonCodes", []):
            required_checks.append("RECOVERY_OBSERVATION")
            applicable_checks.append("RECOVERY_OBSERVATION")

    # Step 5 Clean Environment & Reproducibility integration
    if is_dep_change or is_migration:
        required_checks.append("CLEAN_ENVIRONMENT")
        applicable_checks.append("CLEAN_ENVIRONMENT")
    if is_repro or (is_migration and risk_level == "CRITICAL"):
        if "CLEAN_ENVIRONMENT" not in required_checks:
            required_checks.append("CLEAN_ENVIRONMENT")
            applicable_checks.append("CLEAN_ENVIRONMENT")
        required_checks.append("REPRODUCIBILITY")
        applicable_checks.append("REPRODUCIBILITY")

    policy_entry = {
        "requirementId": req.get("id"),
        "riskLevel": risk_level,
        "riskScore": risk_info.get("score", 0),
        "reasonCodes": risk_info.get("reasonCodes", []),
        "requiredChecks": sorted(list(set(required_checks))),
        "applicableChecks": sorted(list(set(applicable_checks))),
        "completedChecks": [],
        "missingChecks": sorted(list(set(required_checks))),
        "policySatisfied": False,
    }
    return policy_entry


def save_verification_policy_matrix(
    workspace_dir: Path, matrix: Dict[str, Any]
) -> Path:
    """Save .agent-harness/verification-policy.json"""
    harness_dir = Path(workspace_dir).resolve() / ".agent-harness"
    harness_dir.mkdir(parents=True, exist_ok=True)
    policy_file = harness_dir / "verification-policy.json"
    temp_file = harness_dir / "verification-policy.json.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(matrix, f, indent=2)
    os.replace(temp_file, policy_file)
    return policy_file


def load_verification_policy_matrix(
    workspace_dir: Path,
) -> Optional[Dict[str, Any]]:
    """Load .agent-harness/verification-policy.json"""
    policy_file = Path(workspace_dir).resolve() / ".agent-harness" / "verification-policy.json"
    if not policy_file.exists():
        return None
    try:
        with open(policy_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def generate_and_save_policy_matrix(workspace_dir: Path) -> Dict[str, Any]:
    """Generate and save full verification policy matrix for all requirements."""
    workspace_path = Path(workspace_dir).resolve()
    reqs = kernel.load_requirements(workspace_path)
    caps = detect_project_capabilities(workspace_path)

    policies = {}
    for req in reqs:
        if "risk" not in req or not req["risk"].get("level"):
            req["risk"] = risk_engine.evaluate_requirement_risk(req)
        p = compile_verification_policy(req, caps)
        policies[req.get("id")] = p

    kernel.save_requirements(workspace_path, reqs)

    matrix = {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "capabilities": caps,
        "policies": policies,
    }
    save_verification_policy_matrix(workspace_path, matrix)
    return matrix


def audit_verification_policy(workspace_dir: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Authoritative completion audit verifying that all required policy checks
    are satisfied by genuine evidence in evidence.jsonl and Step 5/6 artifacts.
    """
    workspace_path = Path(workspace_dir).resolve()
    matrix = load_verification_policy_matrix(workspace_path)
    if not matrix:
        matrix = generate_and_save_policy_matrix(workspace_path)

    policies = matrix.get("policies", {})
    ev_file = workspace_path / ".agent-harness" / "evidence.jsonl"
    
    evidence_events = []
    if ev_file.exists():
        with open(ev_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ev = json.loads(line)
                        if ev.get("result") == "PASS":
                            evidence_events.append(ev)
                    except Exception:
                        pass

    unresolved_issues: List[str] = []
    stats = {
        "total": len(policies),
        "satisfied": 0,
        "incomplete": 0,
        "byRisk": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
    }

    env_state = reproducibility.load_environment_verification_state(workspace_path)
    clean_env_passed = env_state is not None and env_state.get("status") == "CLEAN_ENVIRONMENT_PASS"
    reproducibility_passed = env_state is not None and env_state.get("reproducibility", {}).get("status") in {"REPRODUCIBILITY_PASS", "IDENTICAL", "EXPECTED_NONDETERMINISM"}

    # Independent audit state
    ind_audit = independent_model.load_audit_record(workspace_path)
    ind_passed_reqs = set()
    if ind_audit and ind_audit.get("status") == "COMPLETED" and ind_audit.get("overallVerdict") == "PASS":
        for r in ind_audit.get("requirements", []):
            if r.get("verdict") == "PASS":
                ind_passed_reqs.add(r.get("id"))

    for req_id, policy in policies.items():
        risk_lvl = policy.get("riskLevel", "LOW")
        stats["byRisk"][risk_lvl] = stats["byRisk"].get(risk_lvl, 0) + 1
        required = set(policy.get("requiredChecks", []))
        
        completed = set()
        for ev in evidence_events:
            req_ids = ev.get("requirementIds", [])
            if req_id in req_ids or not req_ids:
                cmd = ev.get("commandOrInteraction", "").upper()
                v_type = ev.get("verificationType", "").upper()
                
                if v_type in {"AUTOMATED_TEST", "EXECUTED_COMMAND"}:
                    completed.add("STATIC")
                    completed.add("AUTOMATED_TEST")
                if v_type == "RUNTIME_OBSERVATION" or "RUNTIME" in cmd:
                    completed.add("RUNTIME_OBSERVATION")
                if "NEGATIVE" in cmd or "INVALID" in cmd or "UNAUTHORIZED" in cmd:
                    completed.add("NEGATIVE_PATH")
                if "RESTART" in cmd or "PERSIST" in cmd or "RELOAD" in cmd:
                    completed.add("RESTART_PERSISTENCE")
                if "RECOVERY" in cmd or "CONFIRM" in cmd or "RESTORE" in cmd:
                    completed.add("RECOVERY_OBSERVATION")
                if ev.get("verifierIdentity") == "final-verifier" or "CLEAN_ROOM" in cmd:
                    completed.add("CLEAN_ROOM_AUDIT")
                if "POST_PROMOTION" in cmd or "PROMOT" in cmd or v_type == "POST_PROMOTION":
                    completed.add("POST_PROMOTION")
                if "CLEAN_ENV" in cmd or "CLEAN" in cmd or v_type == "CLEAN_ENVIRONMENT":
                    completed.add("CLEAN_ENVIRONMENT")
                if "REPRO" in cmd or v_type == "REPRODUCIBILITY":
                    completed.add("REPRODUCIBILITY")
                if "INDEPENDENT" in cmd or v_type == "INDEPENDENT_MODEL_AUDIT":
                    completed.add("INDEPENDENT_MODEL_AUDIT")

        if clean_env_passed:
            completed.add("CLEAN_ENVIRONMENT")
        if reproducibility_passed:
            completed.add("REPRODUCIBILITY")
        if req_id in ind_passed_reqs:
            completed.add("INDEPENDENT_MODEL_AUDIT")

        missing = required - completed
        policy["completedChecks"] = sorted(list(completed & required))
        policy["missingChecks"] = sorted(list(missing))
        policy["policySatisfied"] = len(missing) == 0

        if len(missing) == 0:
            stats["satisfied"] += 1
        else:
            stats["incomplete"] += 1
            unresolved_issues.append(
                f"Requirement {req_id} ({risk_lvl}) missing required verification: {', '.join(sorted(missing))}"
            )

    save_verification_policy_matrix(workspace_path, matrix)
    is_complete = len(unresolved_issues) == 0
    return is_complete, unresolved_issues, stats
