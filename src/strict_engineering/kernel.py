"""
Strict Engineering Kernel V4.1 - Core State & Lifecycle Engine
Manages project harness, immutable original request, requirement ledger,
tamper-evident SHA-256 evidence chain, phase transitions, and single-writer state mutations.
"""

import os
import sys
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from . import fingerprint
    from . import baseline
except (ImportError, ValueError):
    import fingerprint
    import baseline

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
}

INVALID_PASS_TYPES = {
    "CLAIM",
    "UNVERIFIED",
    "ASSUMPTION",
    "MODEL_CONFIDENCE",
}

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
    orig_sha_file = harness_dir / "original-request.sha256"

    cleaned_intent = original_intent.strip()
    with open(orig_req_file, "w", encoding="utf-8") as f:
        f.write(cleaned_intent + "\n")

    intent_sha256 = hashlib.sha256(cleaned_intent.encode("utf-8")).hexdigest()
    with open(orig_sha_file, "w", encoding="utf-8") as f:
        f.write(intent_sha256 + "\n")

    # 2. Requirements & Coverage Ledger
    reqs_file = harness_dir / "requirements.json"
    if not reqs_file.exists():
        with open(reqs_file, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)

    cov_file = harness_dir / "coverage.json"
    if not cov_file.exists():
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "statements": [],
                    "coveragePercent": 0,
                    "uncoveredStatements": [],
                    "complete": False,
                },
                f,
                indent=2,
            )

    dep_file = harness_dir / "dependency-map.json"
    if not dep_file.exists():
        with open(dep_file, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)

    # 3. Evidence & Change logs
    ev_file = harness_dir / "evidence.jsonl"
    if not ev_file.exists():
        ev_file.touch()

    ch_file = harness_dir / "changes.jsonl"
    if not ch_file.exists():
        ch_file.touch()

    # 4. Baseline
    base_file = harness_dir / "baseline.json"
    base_data = baseline.capture_project_baseline(
        workspace_path,
        test_command=test_command,
        build_command=build_command,
        lint_command=lint_command,
        typecheck_command=typecheck_command,
    )
    with open(base_file, "w", encoding="utf-8") as f:
        json.dump(base_data, f, indent=2)

    # 5. Documentation Templates
    doc_templates = {
        "PRODUCT_SPEC.md": "# Product Specification\n\n## Original Intent Reference\nSee `.agent-harness/original-request.md`\n\n## Requirements\nDetailed requirements extracted by Spec Architect.\n",
        "ACCEPTANCE_TESTS.md": "# Acceptance Contracts\n\nBehavioral test contracts defined by Test Oracle prior to implementation.\n",
        "ARCHITECTURE.md": "# Architecture & Technical Design\n\nSystem overview, invariants, and component boundaries.\n",
        "IMPLEMENTATION_PLAN.md": "# Implementation Plan\n\nBounded vertical implementation slices.\n",
        "DECISIONS.md": "# Decision & Change Control Log\n\nAll requirement adjustments and architectural decisions recorded here.\n",
        "IMPLEMENTATION_STATUS.md": "# Implementation & Verification Status\n\nSummary of requirement states and verification evidence.\n",
    }

    for doc_name, content in doc_templates.items():
        doc_path = docs_dir / doc_name
        if not doc_path.exists():
            with open(doc_path, "w", encoding="utf-8") as f:
                f.write(content)

    # 6. State Machine
    state = {
        "active": True,
        "version": "4.1.0",
        "phase": "SPECIFICATION",
        "specLocked": False,
        "acceptanceLocked": False,
        "verificationFresh": True,
        "finalAuditPassed": False,
        "originalRequestSha256": intent_sha256,
        "attemptCounters": {},
        "createdAt": utc_now_iso(),
        "updatedAt": utc_now_iso(),
    }
    save_state(workspace_path, state)
    return state


def verify_original_intent_integrity(workspace_dir: Path) -> bool:
    """Verify that original-request.md has not been modified."""
    harness_dir = get_harness_dir(workspace_dir)
    orig_req_file = harness_dir / "original-request.md"
    orig_sha_file = harness_dir / "original-request.sha256"

    if not orig_req_file.exists() or not orig_sha_file.exists():
        return False

    with open(orig_sha_file, "r", encoding="utf-8") as f:
        expected_sha = f.read().strip()

    with open(orig_req_file, "r", encoding="utf-8") as f:
        actual_content = f.read().strip()

    actual_sha = hashlib.sha256(actual_content.encode("utf-8")).hexdigest()
    return actual_sha == expected_sha


def load_requirements(workspace_dir: Path) -> List[Dict[str, Any]]:
    req_file = get_harness_dir(workspace_dir) / "requirements.json"
    if not req_file.exists():
        return []
    with open(req_file, "r", encoding="utf-8") as f:
        return json.load(f)


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


def record_evidence(
    workspace_dir: Path,
    requirement_ids: List[str],
    verification_type: str,
    command_or_interaction: str,
    result: str,  # PASS / FAIL
    relevant_output: str,
    verifier_identity: str,
    artifact_reference: Optional[str] = None,
) -> str:
    """
    Append verification evidence to evidence.jsonl in a tamper-evident SHA-256 hash chain
    and update requirement statuses.
    Enforces that CLAIM cannot produce PASS and Builder cannot self-certify PASS.
    """
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = get_harness_dir(workspace_path)
    ev_file = harness_dir / "evidence.jsonl"

    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    curr_fp = fingerprint.compute_workspace_fingerprint(workspace_path, file_hashes)

    prev_hash = get_last_evidence_hash(workspace_path)
    ev_id = f"EV-{hashlib.sha256((utc_now_iso() + command_or_interaction + prev_hash).encode()).hexdigest()[:8].upper()}"

    # Enforce evidence validity
    norm_result = result.upper()
    is_claim = verification_type.upper() in INVALID_PASS_TYPES or verification_type.upper() not in VALID_VERIFICATION_TYPES
    is_builder = verifier_identity.lower() == "builder"

    entry: Dict[str, Any] = {
        "evidenceId": ev_id,
        "timestamp": utc_now_iso(),
        "requirementIds": requirement_ids,
        "verificationType": verification_type,
        "commandOrInteraction": command_or_interaction,
        "result": norm_result,
        "relevantOutput": relevant_output[:2000] if relevant_output else "",
        "artifactReference": artifact_reference or "",
        "workspaceFingerprint": curr_fp,
        "verifierIdentity": verifier_identity,
        "previousHash": prev_hash,
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
            # CLAIM or Builder cannot produce PASS! Transition to IMPLEMENTED_UNVERIFIED
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
    else:
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


def record_change(
    workspace_dir: Path,
    requirement_ids: List[str],
    old_behavior: str,
    new_behavior: str,
    reason: str,
    source_of_change: str,  # USER_REQUESTED_CHANGE / ARCHITECTURAL_DECISION
) -> str:
    """
    Record change control entry into changes.jsonl, append to docs/DECISIONS.md,
    and invalidate affected requirements to STALE.
    """
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = get_harness_dir(workspace_path)
    ch_file = harness_dir / "changes.jsonl"
    decisions_file = workspace_path / "docs" / "DECISIONS.md"

    change_id = f"CHG-{hashlib.sha256((utc_now_iso() + reason).encode()).hexdigest()[:8].upper()}"

    entry = {
        "changeId": change_id,
        "timestamp": utc_now_iso(),
        "requirementIds": requirement_ids,
        "oldBehavior": old_behavior,
        "newBehavior": new_behavior,
        "reason": reason,
        "sourceOfChange": source_of_change,
    }

    with open(ch_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    if decisions_file.exists():
        md_entry = (
            f"\n### [{change_id}] - {utc_now_iso()}\n"
            f"- **Requirements:** {', '.join(requirement_ids)}\n"
            f"- **Source:** {source_of_change}\n"
            f"- **Reason:** {reason}\n"
            f"- **Old Behavior:** {old_behavior}\n"
            f"- **New Behavior:** {new_behavior}\n"
        )
        with open(decisions_file, "a", encoding="utf-8") as f:
            f.write(md_entry)

    # Invalidate affected requirements to STALE
    for r_id in requirement_ids:
        update_requirement_status(
            workspace_path,
            req_id=r_id,
            new_status="STALE",
            verifier_identity="change_control_manager",
        )

    return change_id


def check_and_invalidate_stale(workspace_dir: Path) -> List[str]:
    """
    Scan workspace and invalidate PASS requirements whose dependent source files have changed.
    """
    workspace_path = Path(workspace_dir).resolve()
    reqs = load_requirements(workspace_path)
    dep_map_file = get_harness_dir(workspace_path) / "dependency-map.json"
    dep_map = {}
    if dep_map_file.exists():
        try:
            with open(dep_map_file, "r", encoding="utf-8") as f:
                dep_map = json.load(f)
        except Exception:
            dep_map = {}

    file_hashes = fingerprint.get_workspace_file_hashes(workspace_path)
    stale_ids = fingerprint.find_stale_requirements(workspace_path, reqs, dep_map, file_hashes)

    if stale_ids:
        for r_id in stale_ids:
            update_requirement_status(
                workspace_path,
                req_id=r_id,
                new_status="STALE",
                verifier_identity="kernel_freshness_monitor",
            )
    return stale_ids


def scan_for_placeholders(workspace_dir: Path) -> List[Dict[str, Any]]:
    """
    Scan application production code for unfinished placeholders.
    """
    workspace_path = Path(workspace_dir).resolve()
    findings = []
    forbidden_tokens = ["TODO", "FIXME", "placeholder", "dummy", "fake data", "coming soon", "not implemented"]

    # Ignored directories for placeholder check
    ignore_dirs = {".git", ".agent-harness", "node_modules", "dist", "build", "tests", "test", "docs"}

    for root, dirs, files in os.walk(workspace_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".agent-")]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".dart"}:
                fpath = Path(root) / f
                rel_path = fpath.relative_to(workspace_path)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as file_obj:
                        for line_num, line in enumerate(file_obj, 1):
                            line_lower = line.lower()
                            for token in forbidden_tokens:
                                if token.lower() in line_lower:
                                    findings.append({
                                        "file": str(rel_path).replace("\\", "/"),
                                        "line": line_num,
                                        "token": token,
                                        "snippet": line.strip()[:100],
                                    })
                except Exception:
                    pass

    return findings
