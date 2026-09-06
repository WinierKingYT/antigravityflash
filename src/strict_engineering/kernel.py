"""
Strict Engineering Kernel V5.1 - Core State, Lifecycle & Execution Evidence Engine
Manages project harness, immutable original request, requirement ledger,
tamper-evident SHA-256 evidence chain, execution provenance, and single-writer state mutations.
"""

import os
import re
import sys
import json
import time
import hashlib
import datetime
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import fingerprint
    from . import baseline
    from . import context_registry
except (ImportError, ValueError):
    import fingerprint
    import baseline
    import context_registry

compute_context_event_hash = context_registry.compute_context_event_hash
register_runtime_context = context_registry.register_runtime_context
register_simulated_context = context_registry.register_simulated_context
create_context_expectation = context_registry.create_context_expectation
load_context_expectation = context_registry.load_context_expectation
_ingest_antigravity_hook_context = context_registry._ingest_antigravity_hook_context
verify_context_registry = context_registry.verify_context_registry
load_context_registry = context_registry.load_context_registry
get_registered_context_by_purpose = context_registry.get_registered_context_by_purpose
evaluate_context_isolation = context_registry.evaluate_context_isolation

ALLOWED_STATUSES = {
    "NOT_STARTED",
    "IN_PROGRESS",
    "IMPLEMENTED_UNVERIFIED",
    "PASS",
    "FAILED",
    "STALE",
    "BLOCKED",
    "DEFERRED",
}

VALID_VERIFICATION_TYPES = {
    "EXECUTED_COMMAND",
    "AUTOMATED_TEST",
    "RUNTIME_OBSERVATION",
    "BROWSER_OBSERVATION",
    "MANUAL_USER_ACCEPTANCE",
    "REAL_PROJECT_EXECUTION",
    "DEPENDENCY_RESTORE",
    "BUILD",
    "TEST",
    "RUNTIME_START",
    "HEALTH_CHECK",
    "USER_JOURNEY",
    "DATABASE_BOOTSTRAP",
    "MIGRATION",
    "REPRODUCIBILITY_RUN",
    "BLIND_AUDIT",
    "COUNTEREXAMPLE_AUDIT",
    "HIDDEN_VERIFICATION",
}

ANALYTICAL_EVIDENCE_TYPES = {
    "BLIND_AUDIT",
    "COUNTEREXAMPLE_AUDIT",
    "HIDDEN_VERIFICATION",
}

INVALID_PASS_TYPES = {
    "CLAIM",
    "UNVERIFIED",
    "ASSUMPTION",
    "MODEL_CONFIDENCE",
    "MOCK",
    "MODEL_CLAIM",
}

VALID_EXECUTION_TYPES = {
    "DEPENDENCY_RESTORE",
    "BUILD",
    "TEST",
    "RUNTIME_START",
    "HEALTH_CHECK",
    "USER_JOURNEY",
    "DATABASE_BOOTSTRAP",
    "MIGRATION",
    "REPRODUCIBILITY_RUN",
}

VALID_ORIGINS = {
    "REAL_PROJECT_EXECUTION",
    "LIVE_KERNEL_EXECUTION",
    "SIMULATED_INTEGRATION",
    "KERNEL_UNIT_TEST",
    "MOCK",
    "MODEL_CLAIM",
    "USER_ACCEPTANCE",
}

SECRET_SCRUB_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?'),
    re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{12,})'),
    re.compile(r'(?i)(ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{22,})'),
    re.compile(r'(?i)(sk-[a-zA-Z0-9]{20,})'),
]

PHASES = [
    "DISCOVERY",
    "SPECIFICATION",
    "ACCEPTANCE",
    "PLANNING",
    "IMPLEMENTATION",
    "VERIFICATION",
    "REGRESSION",
    "FINAL_AUDIT",
    "COMPLETE",
]


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def scrub_secrets(text: Optional[str]) -> str:
    """Scrub sensitive secrets (API keys, tokens, passwords) from strings."""
    if not text:
        return ""
    scrubbed = str(text)
    for pat in SECRET_SCRUB_PATTERNS:
        scrubbed = pat.sub(r"\1 [REDACTED_SECRET]", scrubbed)
    return scrubbed


def get_harness_dir(workspace_dir: Path) -> Path:
    return Path(workspace_dir).resolve() / ".agent-harness"


def is_harness_active(workspace_dir: Path) -> bool:
    """Check if the given workspace has an active Strict Engineering harness."""
    state_file = get_harness_dir(workspace_dir) / "state.json"
    if not state_file.exists():
        return False
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return bool(data.get("active", False))
    except Exception:
        return False


def load_state(workspace_dir: Path) -> Dict[str, Any]:
    state_file = get_harness_dir(workspace_dir) / "state.json"
    if not state_file.exists():
        return {}
    with open(state_file, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(workspace_dir: Path, state: Dict[str, Any]) -> None:
    harness_dir = get_harness_dir(workspace_dir)
    harness_dir.mkdir(parents=True, exist_ok=True)
    state["updatedAt"] = utc_now_iso()
    state_file = harness_dir / "state.json"
    temp_file = harness_dir / "state.json.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(temp_file, state_file)


def initialize_harness(
    workspace_dir: Path,
    original_intent: str,
    test_command: Optional[str] = None,
    build_command: Optional[str] = None,
    lint_command: Optional[str] = None,
    typecheck_command: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Initialize .agent-harness directory and baseline documents for a project.
    """
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = get_harness_dir(workspace_path)
    docs_dir = workspace_path / "docs"

    harness_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    # 1. Immutable Original Request & SHA-256
    orig_req_file = harness_dir / "original-request.md"
    orig_req_sha_file = harness_dir / "original-request.sha256"
    
    with open(orig_req_file, "w", encoding="utf-8") as f:
        f.write(original_intent.strip() + "\n")
    
    orig_sha = hashlib.sha256(original_intent.strip().encode("utf-8")).hexdigest()
    with open(orig_req_sha_file, "w", encoding="utf-8") as f:
        f.write(orig_sha + "\n")

    # 2. Baseline Document Templates
    doc_templates = {
        "PRODUCT_SPEC.md": f"# Product Specification\n\n## Original User Intent\n\n{original_intent.strip()}\n\n## Atomic Requirements Ledger\n*(To be populated and locked by spec-architect)*\n",
        "ACCEPTANCE_TESTS.md": "# Acceptance Test Contracts\n\n*(Immutable acceptance criteria and test oracle contracts)*\n",
        "IMPLEMENTATION_PLAN.md": "# Dependency-Aware Implementation Plan\n\n*(Implementation plan with topological ordering)*\n",
        "IMPLEMENTATION_STATUS.md": "# Live Implementation Status\n\n- Current Phase: SPECIFICATION\n- Spec Locked: false\n- Acceptance Locked: false\n",
        "DECISIONS.md": "# Architecture Decision Records (ADRs)\n\n*(Log of authorized architectural and requirement changes)*\n",
        "ARCHITECTURE.md": "# Architecture & Component Overview\n\n*(Component topology and dependency mappings)*\n",
    }
    for doc_name, content in doc_templates.items():
        doc_path = docs_dir / doc_name
        if not doc_path.exists():
            with open(doc_path, "w", encoding="utf-8") as f:
                f.write(content)

    # 3. Initial Baseline Capture
    bl = baseline.capture_workspace_baseline(
        workspace_path,
        test_command=test_command,
        build_command=build_command,
        lint_command=lint_command,
        typecheck_command=typecheck_command,
    )

    # 4. Initialize State
    initial_state = {
        "active": True,
        "schemaVersion": "5.1.0",
        "phase": "SPECIFICATION",
        "specLocked": False,
        "acceptanceLocked": False,
        "originalRequestSha256": orig_sha,
        "workspaceFingerprint": bl.get("initialFingerprint"),
        "activeTask": None,
        "builderSubagentActive": False,
        "finalAuditPassed": False,
        "createdAt": utc_now_iso(),
        "updatedAt": utc_now_iso(),
    }
    save_state(workspace_path, initial_state)

    # 5. Empty Requirements, Coverage, Evidence Chain, Changes, Dependency Map
    save_requirements(workspace_path, [])
    
    with open(harness_dir / "coverage.json", "w", encoding="utf-8") as f:
        json.dump({"complete": False, "coveragePercent": 0, "uncoveredStatements": [original_intent.strip()]}, f, indent=2)
    
    open(harness_dir / "evidence.jsonl", "w", encoding="utf-8").close()
    open(harness_dir / "changes.jsonl", "w", encoding="utf-8").close()
    
    with open(harness_dir / "dependency-map.json", "w", encoding="utf-8") as f:
        json.dump({"version": "5.1.0", "dependencies": {}}, f, indent=2)

    return initial_state


def verify_original_intent_integrity(workspace_dir: Path) -> bool:
    """Verify that original-request.md matches original-request.sha256."""
    harness_dir = get_harness_dir(workspace_dir)
    req_file = harness_dir / "original-request.md"
    sha_file = harness_dir / "original-request.sha256"

    if not req_file.exists() or not sha_file.exists():
        return False

    with open(req_file, "r", encoding="utf-8") as f:
        content = f.read().strip()
    with open(sha_file, "r", encoding="utf-8") as f:
        expected_sha = f.read().strip()

    actual_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return actual_sha == expected_sha


def load_requirements(workspace_dir: Path) -> List[Dict[str, Any]]:
    req_file = get_harness_dir(workspace_dir) / "requirements.json"
    if not req_file.exists():
        return []
    try:
        with open(req_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_requirements(workspace_dir: Path, requirements: List[Dict[str, Any]]) -> None:
    req_file = get_harness_dir(workspace_dir) / "requirements.json"
    temp_file = get_harness_dir(workspace_dir) / "requirements.json.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(requirements, f, indent=2)
    os.replace(temp_file, req_file)


def update_requirement_status(
    workspace_dir: Path,
    req_id: str,
    new_status: str,
    verifier_identity: str,
    fingerprint_hash: Optional[str] = None,
    subset_fingerprint_hash: Optional[str] = None,
    verification_id: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Update requirement status according to strict single-writer rules.
    """
    if new_status not in ALLOWED_STATUSES:
        return False, f"Invalid status '{new_status}'. Allowed: {ALLOWED_STATUSES}"

    # Single-writer / builder gate: builder cannot promote to PASS
    if verifier_identity.lower() == "builder" and new_status == "PASS":
        return False, "Builder is strictly prohibited from self-certifying PASS. Must use IMPLEMENTED_UNVERIFIED."

    reqs = load_requirements(workspace_dir)
    found = False
    for req in reqs:
        if req.get("id") == req_id:
            found = True
            req["status"] = new_status
            req["updatedAt"] = utc_now_iso()
            if new_status == "PASS":
                if fingerprint_hash:
                    req["lastVerifiedFingerprint"] = fingerprint_hash
                if subset_fingerprint_hash:
                    req["lastVerifiedSubsetFingerprint"] = subset_fingerprint_hash
                if verification_id:
                    vids = req.setdefault("verificationIds", [])
                    if verification_id not in vids:
                        vids.append(verification_id)
            break

    if not found:
        return False, f"Requirement {req_id} not found"

    save_requirements(workspace_dir, reqs)
    return True, f"Requirement {req_id} status updated to {new_status}"


def compute_evidence_event_hash(entry: Dict[str, Any]) -> str:
    """
    Compute cryptographic SHA-256 hash over canonical representation of evidence entry fields.
    """
    fields = [
        str(entry.get("previousHash", "")),
        str(entry.get("evidenceId", "")),
        str(entry.get("timestamp", "")),
        json.dumps(sorted(entry.get("requirementIds", []))),
        str(entry.get("verificationType", "")),
        str(entry.get("commandOrInteraction", "")),
        str(entry.get("result", "")),
        str(entry.get("relevantOutput", "")),
        str(entry.get("artifactReference", "")),
        str(entry.get("workspaceFingerprint", "")),
        str(entry.get("verifierIdentity", "")),
        str(entry.get("origin", "")),
        json.dumps(entry.get("executionDetails", {}), sort_keys=True) if entry.get("executionDetails") else "",
    ]
    payload = "|".join(fields).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_last_evidence_hash(workspace_dir: Path) -> str:
    """Read the last entry in evidence.jsonl and return its eventHash, or 'GENESIS' if empty."""
    ev_file = get_harness_dir(workspace_dir) / "evidence.jsonl"
    if not ev_file.exists() or ev_file.stat().st_size == 0:
        return "GENESIS"

    last_hash = "GENESIS"
    try:
        with open(ev_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    if "eventHash" in entry:
                        last_hash = entry["eventHash"]
    except Exception:
        pass
    return last_hash


def verify_evidence_chain(workspace_dir: Path) -> Tuple[bool, str]:
    """
    Cryptographically validate the entire SHA-256 evidence chain in evidence.jsonl.
    Verifies previousHash continuity and eventHash cryptographic integrity.
    """
    ev_file = get_harness_dir(workspace_dir) / "evidence.jsonl"
    if not ev_file.exists() or ev_file.stat().st_size == 0:
        return True, "Evidence chain is empty (valid)"

    expected_prev = "GENESIS"
    entry_count = 0

    try:
        with open(ev_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                entry_count += 1

                actual_prev = entry.get("previousHash")
                if actual_prev != expected_prev:
                    return False, f"Evidence chain broken at entry {idx} ({entry.get('evidenceId')}): expected previousHash '{expected_prev}', found '{actual_prev}'"

                actual_event_hash = entry.get("eventHash")
                recalculated_hash = compute_evidence_event_hash(entry)
                if actual_event_hash != recalculated_hash:
                    return False, f"Evidence tamper detected at entry {idx} ({entry.get('evidenceId')}): computed eventHash '{recalculated_hash}', recorded '{actual_event_hash}'"

                expected_prev = actual_event_hash

        return True, f"Evidence chain cryptographically valid ({entry_count} entries verified)"
    except Exception as e:
        return False, f"Error reading evidence chain: {e}"


def validate_execution_claim(entry: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates execution claim provenance (Sections 34, 37, S6S-T1).
    Rejects manual claims claiming REAL_PROJECT_EXECUTION without trusted runner details.
    """
    origin = entry.get("origin", "")
    if origin == "REAL_PROJECT_EXECUTION":
        details = entry.get("executionDetails")
        if not details or not isinstance(details, dict):
            return False, "UNTRUSTED_EXECUTION_CLAIM: origin 'REAL_PROJECT_EXECUTION' missing executionDetails proof"
        if details.get("exitCode") is None or not details.get("stdoutHash"):
            return False, "UNTRUSTED_EXECUTION_CLAIM: incomplete executionDetails proof"
        if entry.get("result") == "PASS" and details.get("exitCode") != 0:
            return False, "UNTRUSTED_EXECUTION_CLAIM: execution exitCode != 0 cannot be PASS"
    elif origin in {"MODEL_CLAIM", "MOCK"}:
        if entry.get("result") == "PASS":
            return False, f"UNTRUSTED_EXECUTION_CLAIM: origin '{origin}' cannot produce PASS"
    return True, "Execution claim is valid"


def record_trusted_execution(
    workspace_dir: Path,
    requirement_ids: List[str],
    command: str,
    execution_type: str = "TEST",
    cwd: Optional[Path] = None,
    timeout_sec: int = 60,
    verifier_identity: str = "trusted-execution-runner",
) -> Dict[str, Any]:
    """
    Authoritative deterministic execution runner (Sections 36, S6S-T2).
    Executes real subprocess, captures exitCode, duration, stdoutHash, stderrHash,
    and writes cryptographically bound execution evidence.
    """
    ws = Path(workspace_dir).resolve()
    run_cwd = Path(cwd).resolve() if cwd else ws
    start_time = time.time()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(run_cwd),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        duration_ms = int((time.time() - start_time) * 1000)
        stdout_hash = hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest()
        stderr_hash = hashlib.sha256(proc.stderr.encode("utf-8")).hexdigest()
        exit_code = proc.returncode
        result = "PASS" if exit_code == 0 else "FAIL"
        output = proc.stdout if exit_code == 0 else (proc.stderr or proc.stdout)
    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        stdout_hash = hashlib.sha256(b"").hexdigest()
        stderr_hash = hashlib.sha256(b"TIMEOUT").hexdigest()
        exit_code = 124
        result = "FAIL"
        output = f"Execution timed out after {timeout_sec}s"
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        stdout_hash = hashlib.sha256(b"").hexdigest()
        stderr_hash = hashlib.sha256(str(e).encode("utf-8")).hexdigest()
        exit_code = 1
        result = "FAIL"
        output = f"Execution failed: {str(e)}"

    exec_record = {
        "executionType": execution_type,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "stdoutHash": stdout_hash,
        "stderrHash": stderr_hash,
    }

    ev_id = record_evidence(
        workspace_dir=ws,
        requirement_ids=requirement_ids,
        verification_type=execution_type,
        command_or_interaction=command,
        result=result,
        relevant_output=output[:2000],
        verifier_identity=verifier_identity,
        origin="REAL_PROJECT_EXECUTION",
        execution_record=exec_record,
    )

    return {
        "evidenceId": ev_id,
        "requirementIds": requirement_ids,
        "command": command,
        "result": result,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "stdoutHash": stdout_hash,
        "stderrHash": stderr_hash,
        "output": output,
    }


def record_evidence(
    workspace_dir: Path,
    requirement_ids: List[str],
    verification_type: str,
    command_or_interaction: str,
    result: str,  # PASS / FAIL
    relevant_output: str,
    verifier_identity: str,
    artifact_reference: Optional[str] = None,
    origin: str = "LIVE_KERNEL_EXECUTION",
    execution_record: Optional[Dict[str, Any]] = None,
    require_trusted_record: bool = False,
) -> str:
    """
    Append verification evidence to evidence.jsonl in a tamper-evident SHA-256 hash chain
    and update requirement statuses.
    Enforces that CLAIM / MOCK cannot produce PASS, Builder cannot self-certify PASS,
    and untrusted claims claiming REAL_PROJECT_EXECUTION are rejected.
    """
    if require_trusted_record and origin == "REAL_PROJECT_EXECUTION" and not execution_record:
        raise ValueError("UNTRUSTED_EXECUTION_CLAIM: origin 'REAL_PROJECT_EXECUTION' requires a verified execution_record.")
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = get_harness_dir(workspace_path)
    ev_file = harness_dir / "evidence.jsonl"

    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    curr_fp = fingerprint.compute_workspace_fingerprint(workspace_path, file_hashes)

    prev_hash = get_last_evidence_hash(workspace_path)
    ev_id = f"EV-{hashlib.sha256((utc_now_iso() + command_or_interaction + prev_hash).encode()).hexdigest()[:8].upper()}"

    # Scrub secrets from command and output
    clean_command = scrub_secrets(command_or_interaction)
    clean_output = scrub_secrets(relevant_output)

    # Enforce evidence validity
    norm_result = result.upper()
    is_claim = (
        verification_type.upper() in INVALID_PASS_TYPES
        or verification_type.upper() not in VALID_VERIFICATION_TYPES
        or origin.upper() in {"MOCK", "MODEL_CLAIM"}
    )
    is_builder = verifier_identity.lower() == "builder"

    entry: Dict[str, Any] = {
        "evidenceId": ev_id,
        "timestamp": utc_now_iso(),
        "requirementIds": requirement_ids,
        "verificationType": verification_type,
        "commandOrInteraction": clean_command,
        "result": norm_result,
        "relevantOutput": clean_output[:2000] if clean_output else "",
        "artifactReference": artifact_reference or "",
        "workspaceFingerprint": curr_fp,
        "verifierIdentity": verifier_identity,
        "origin": origin,
        "previousHash": prev_hash,
    }

    if execution_record:
        entry["executionDetails"] = {
            "executionType": execution_record.get("executionType"),
            "exitCode": execution_record.get("exitCode"),
            "durationMs": execution_record.get("durationMs"),
            "stdoutHash": execution_record.get("stdoutHash"),
            "stderrHash": execution_record.get("stderrHash"),
        }

    event_hash = compute_evidence_event_hash(entry)
    entry["eventHash"] = event_hash

    with open(ev_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    reqs = load_requirements(workspace_path)
    req_map = {r.get("id"): r for r in reqs}

    # Determine requirement status update
    if norm_result == "PASS":
        if is_claim or is_builder:
            # CLAIM, MOCK, or Builder cannot produce PASS! Transition to IMPLEMENTED_UNVERIFIED
            for r_id in requirement_ids:
                r_obj = req_map.get(r_id, {})
                affected = r_obj.get("affectedPaths", [])
                subset_fp = (
                    fingerprint.compute_path_subset_fingerprint(file_hashes, affected)
                    if affected
                    else None
                )
                update_requirement_status(
                    workspace_path,
                    req_id=r_id,
                    new_status="IMPLEMENTED_UNVERIFIED",
                    verifier_identity=verifier_identity,
                    fingerprint_hash=curr_fp,
                    subset_fingerprint_hash=subset_fp,
                    verification_id=ev_id,
                )
        else:
            # Authorized verifier with valid verification method
            for r_id in requirement_ids:
                r_obj = req_map.get(r_id, {})
                affected = r_obj.get("affectedPaths", [])
                subset_fp = (
                    fingerprint.compute_path_subset_fingerprint(file_hashes, affected)
                    if affected
                    else None
                )
                update_requirement_status(
                    workspace_path,
                    req_id=r_id,
                    new_status="PASS",
                    verifier_identity=verifier_identity,
                    fingerprint_hash=curr_fp,
                    subset_fingerprint_hash=subset_fp,
                    verification_id=ev_id,
                )
    elif norm_result == "FAIL":
        for r_id in requirement_ids:
            update_requirement_status(
                workspace_path,
                req_id=r_id,
                new_status="FAILED",
                verifier_identity=verifier_identity,
                fingerprint_hash=curr_fp,
                verification_id=ev_id,
            )

    return ev_id


def is_execution_backed_pass(
    req: Dict[str, Any],
    evidence_events: List[Dict[str, Any]],
    workspace_dir: Path,
) -> Tuple[bool, str]:
    """
    Deterministic Pass Eligibility Function.
    Evaluates whether requirement has real, execution-backed, fresh PASS evidence.
    """
    req_id = req.get("id")
    if req.get("status") != "PASS":
        return False, f"Requirement status is '{req.get('status')}', not 'PASS'"

    matching_evidence = [
        ev for ev in evidence_events
        if req_id in ev.get("requirementIds", []) and ev.get("result") == "PASS"
    ]

    if not matching_evidence:
        return False, f"No PASS evidence recorded for {req_id}"

    # Filter by origin and verification type (exclude analytical evidence and untrusted claims)
    valid_exec_ev = []
    for ev in matching_evidence:
        v_orig = ev.get("origin")
        v_type = ev.get("verificationType")
        if v_orig in {"REAL_PROJECT_EXECUTION", "LIVE_KERNEL_EXECUTION", "USER_ACCEPTANCE"}:
            if v_type not in INVALID_PASS_TYPES and v_type not in ANALYTICAL_EVIDENCE_TYPES:
                is_valid_claim, _ = validate_execution_claim(ev)
                if is_valid_claim:
                    valid_exec_ev.append(ev)

    if not valid_exec_ev:
        return False, f"All PASS evidence for {req_id} lacks acceptable execution origin (claims/mocks rejected)"

    # Check freshness against current workspace fingerprint
    file_hashes = fingerprint.get_workspace_file_hashes(workspace_dir)
    curr_fp = fingerprint.compute_workspace_fingerprint(workspace_dir, file_hashes)
    
    last_verified_fp = req.get("lastVerifiedFingerprint")
    if last_verified_fp and last_verified_fp != curr_fp:
        # Check if subset fingerprint matches (for path-isolated changes)
        affected = req.get("affectedPaths", [])
        if affected:
            curr_subset = fingerprint.compute_path_subset_fingerprint(file_hashes, affected)
            if curr_subset != req.get("lastVerifiedSubsetFingerprint"):
                return False, f"Evidence for {req_id} is STALE (affected source files modified after verification)"
        else:
            return False, f"Evidence for {req_id} is STALE (workspace modified after verification)"

    return True, "Requirement has verified, fresh, execution-backed PASS evidence"


def check_and_invalidate_stale(workspace_dir: Path) -> List[str]:
    """
    Check all PASS requirements and invalidate to STALE if affected files have been modified.
    Returns list of invalidated requirement IDs.
    """
    workspace_path = Path(workspace_dir).resolve()
    reqs = load_requirements(workspace_path)
    if not reqs:
        return []

    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    curr_fp = fingerprint.compute_workspace_fingerprint(workspace_path, file_hashes)

    dep_map = {}
    dep_file = workspace_path / ".agent-harness" / "dependency-map.json"
    if dep_file.exists():
        try:
            dep_map = json.loads(dep_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    invalidated: List[str] = []
    for req in reqs:
        if req.get("status") == "PASS":
            rid = req.get("id")
            last_fp = req.get("lastVerifiedFingerprint")
            affected = req.get("affectedPaths", []) or dep_map.get(rid, [])
            
            is_stale = False
            if affected:
                curr_sub = fingerprint.compute_path_subset_fingerprint(file_hashes, affected)
                last_sub = req.get("lastVerifiedSubsetFingerprint")
                if last_sub is None or curr_sub != last_sub:
                    is_stale = True
            elif last_fp:
                if last_fp != curr_fp:
                    is_stale = True
            else:
                # If no last_fp recorded, mark stale on workspace modification
                is_stale = True

            if is_stale:
                req["status"] = "STALE"
                req["updatedAt"] = utc_now_iso()
                invalidated.append(rid)

    if invalidated:
        save_requirements(workspace_path, reqs)
        # Record change event
        record_change(
            workspace_path,
            change_description=f"Source modification detected: invalidated requirements {invalidated} to STALE",
            rationale="Automatic fingerprint invalidation post-verification",
            affected_requirements=invalidated,
        )

    return invalidated


def propagate_decision_change(
    workspace_dir: Path,
    superseded_decision_id: str,
    new_decision_id: Optional[str] = None,
) -> List[str]:
    """
    Find requirements deriving from superseded decision and invalidate them to STALE.
    Records change in changes.jsonl and invalidates downstream requirement states.
    """
    workspace_path = Path(workspace_dir).resolve()
    reqs = load_requirements(workspace_path)
    if not reqs:
        return []

    invalidated: List[str] = []
    for r in reqs:
        d_ref = r.get("decisionId") or r.get("sourceDecision")
        sources = r.get("sources", [])
        if d_ref == superseded_decision_id or superseded_decision_id in sources:
            r["status"] = "STALE"
            r["stalenessReason"] = f"Derives from superseded decision {superseded_decision_id}"
            r["updatedAt"] = utc_now_iso()
            if new_decision_id and new_decision_id not in sources:
                sources.append(new_decision_id)
            invalidated.append(r.get("id"))

    if invalidated:
        save_requirements(workspace_path, reqs)
        record_change(
            workspace_path,
            change_description=f"Decision supersession ({superseded_decision_id} -> {new_decision_id or 'REVOKED'}): invalidated requirements {invalidated} to STALE",
            rationale="Automatic decision supersession requirement invalidation",
            affected_requirements=invalidated,
        )

    return invalidated


def record_change(
    workspace_dir: Path,
    *args,
    **kwargs,
) -> str:
    """
    Log an authorized change to changes.jsonl and docs/DECISIONS.md.
    Invalidates affected requirements to STALE.
    Supports all legacy and v5.1 calling patterns:
    - record_change(ws, change_description, rationale, affected_requirements)
    - record_change(ws, requirement_ids, old_behavior, new_behavior, reason, source_of_change)
    - record_change(workspace_dir=ws, requirement_ids=[...], old_behavior=..., new_behavior=..., reason=..., source_of_change=...)
    """
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = get_harness_dir(workspace_path)
    changes_file = harness_dir / "changes.jsonl"
    decisions_file = workspace_path / "docs" / "DECISIONS.md"

    requirement_ids = kwargs.get("requirement_ids") or kwargs.get("affected_requirements") or []
    old_behavior = kwargs.get("old_behavior", "")
    new_behavior = kwargs.get("new_behavior", "")
    reason = kwargs.get("reason") or kwargs.get("rationale", "")
    source_of_change = kwargs.get("source_of_change") or kwargs.get("actor", "AUTHOR")
    description = kwargs.get("description") or kwargs.get("change_description", "")

    if args:
        if len(args) == 1 and isinstance(args[0], (list, set)):
            requirement_ids = list(args[0])
        elif len(args) >= 3 and isinstance(args[0], str) and isinstance(args[2], (list, set)):
            description = args[0]
            reason = args[1]
            requirement_ids = list(args[2])
        elif len(args) >= 1 and isinstance(args[0], (list, set)):
            requirement_ids = list(args[0])
            if len(args) >= 2:
                old_behavior = str(args[1])
            if len(args) >= 3:
                new_behavior = str(args[2])
            if len(args) >= 4:
                reason = str(args[3])
            if len(args) >= 5:
                source_of_change = str(args[4])
        elif len(args) == 3:
            description = str(args[0])
            reason = str(args[1])
            if isinstance(args[2], (list, set)):
                requirement_ids = list(args[2])
            else:
                requirement_ids = [str(args[2])]

    if not description:
        if old_behavior and new_behavior:
            description = f"Changed from '{old_behavior}' to '{new_behavior}'"
        elif requirement_ids:
            description = f"Modified requirements: {', '.join(requirement_ids)}"
        else:
            description = f"Change recorded: {reason}"

    if not reason:
        reason = "Specification update or risk escalation"

    change_id = f"CHG-{hashlib.sha256((utc_now_iso() + description).encode()).hexdigest()[:8].upper()}"
    entry = {
        "changeId": change_id,
        "timestamp": utc_now_iso(),
        "description": description,
        "rationale": reason,
        "reason": reason,
        "oldBehavior": old_behavior,
        "newBehavior": new_behavior,
        "affectedRequirements": requirement_ids,
        "requirementIds": requirement_ids,
        "sourceOfChange": source_of_change,
    }

    with open(changes_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    decisions_file.parent.mkdir(parents=True, exist_ok=True)
    adr_entry = f"\n## [{change_id}] {description}\n- **Date:** {utc_now_iso()}\n- **Rationale:** {reason}\n- **Affected Requirements:** {', '.join(requirement_ids)}\n"
    with open(decisions_file, "a", encoding="utf-8") as f:
        f.write(adr_entry)

    # Invalidate affected requirements to STALE
    reqs = load_requirements(workspace_path)
    for req in reqs:
        if req.get("id") in requirement_ids and req.get("status") == "PASS":
            req["status"] = "STALE"
            req["updatedAt"] = utc_now_iso()
    save_requirements(workspace_path, reqs)

    return change_id



def scan_for_placeholders(workspace_dir: Path) -> List[Dict[str, Any]]:
    """Scan workspace files for unfinished placeholders (TODO, FIXME, pass, etc.)."""
    workspace_path = Path(workspace_dir).resolve()
    placeholders = []
    
    # Patterns indicating unfinished logic
    patterns = [
        re.compile(r'\b(TODO|FIXME|XXX|TBD|PLACEHOLDER)\b', re.IGNORECASE),
        re.compile(r'raise NotImplementedError'),
    ]

    for root, dirs, files in os.walk(workspace_path):
        # Skip harness, docs, tests, and ignored dirs
        dirs[:] = [d for d in dirs if d not in {".git", ".agent-harness", "docs", "tests", "venv", ".venv", "node_modules", "__pycache__", "target", "dist", "build"}]
        
        for f in files:
            if f.endswith((".py", ".ts", ".js", ".rs", ".go")):
                fp = Path(root) / f
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f_in:
                        for line_no, line in enumerate(f_in, 1):
                            for pat in patterns:
                                if pat.search(line):
                                    rel_path = str(fp.relative_to(workspace_path)).replace("\\", "/")
                                    placeholders.append({
                                        "file": rel_path,
                                        "line": line_no,
                                        "content": line.strip(),
                                    })
                                    break
                except Exception:
                    pass
    return placeholders
