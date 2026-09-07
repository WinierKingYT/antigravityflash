"""
Strict Engineering Kernel V1.0.2 - Runtime Safety & Resilience Engine
Provides:
- 7-class deterministic termination normalization
- Bounded automatic-continue circuit breaker with state progress fingerprinting
- Privacy-safe append-only SHA-256 chained runtime event ledger (.agent-harness/runtime-events.jsonl)
- Operational pause state and deterministic resume semantics
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Canonical Enums / Constants
# ---------------------------------------------------------------------------

class TerminationClass:
    NORMAL_MODEL_STOP = "NORMAL_MODEL_STOP"
    USER_CANCELLED = "USER_CANCELLED"
    MAX_STEPS = "MAX_STEPS"
    EXTERNAL_ERROR = "EXTERNAL_ERROR"
    HOOK_INTERNAL_ERROR = "HOOK_INTERNAL_ERROR"
    HARNESS_BLOCKED = "HARNESS_BLOCKED"
    UNKNOWN_TERMINATION = "UNKNOWN_TERMINATION"


class RuntimeStatus:
    RUNNING = "RUNNING"
    PAUSED_EXTERNAL_ERROR = "PAUSED_EXTERNAL_ERROR"
    PAUSED_CIRCUIT_BREAKER = "PAUSED_CIRCUIT_BREAKER"
    PAUSED_USER_CANCEL = "PAUSED_USER_CANCEL"
    PAUSED_USER_REQUEST = "PAUSED_USER_REQUEST"
    PAUSED_MAX_STEPS = "PAUSED_MAX_STEPS"
    PAUSED_HOOK_ERROR = "PAUSED_HOOK_ERROR"
    PAUSED_UNKNOWN = "PAUSED_UNKNOWN"
    COMPLETED = "COMPLETED"


CIRCUIT_BREAKER_FILENAME = "circuit-breaker.json"
RUNTIME_EVENTS_FILENAME = "runtime-events.jsonl"
DEFAULT_MAX_AUTOMATIC_CONTINUES = 2

KNOWN_USER_CANCEL_PATTERNS = {
    "user_abort",
    "user_cancelled",
    "user_canceled",
    "abort",
    "cancelled",
    "canceled",
    "aborted",
    "user_cancel",
    "user_stopped",
    "interrupted",
}

KNOWN_MAX_STEPS_PATTERNS = {
    "max_steps",
    "max_steps_exceeded",
    "step_limit_reached",
    "max_turns",
    "max_turn_limit",
    "turn_limit_exceeded",
}

KNOWN_EXTERNAL_ERROR_PATTERNS = {
    "error",
    "fatal_error",
    "network_error",
    "server_error",
    "connection_error",
    "connection_reset",
    "econnreset",
    "timeout",
    "server_timeout",
    "transport_error",
    "rate_limit",
    "rate_limit_exceeded",
    "quota_exceeded",
    "client_error",
    "socket_error",
    "internal_error",
    "backend_error",
    "service_unavailable",
    "gateway_timeout",
    "stream_error",
    "rpc_error",
}

KNOWN_NORMAL_STOP_PATTERNS = {
    "model_stop",
    "normal",
    "end_turn",
    "stop",
    "complete_turn",
    "tool_use_complete",
    "finished",
    "success",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Termination Normalization
# ---------------------------------------------------------------------------

def normalize_termination(payload: Any) -> Tuple[str, Dict[str, Any]]:
    """
    Deterministically normalizes Antigravity Stop payload into one of the 7 canonical classes.
    Inspects terminationReason, error, status, and metadata without fragile single-string assumptions.
    """
    if not isinstance(payload, dict):
        return TerminationClass.UNKNOWN_TERMINATION, {
            "rawReason": "",
            "rawError": "",
            "classificationRationale": "Payload is not a dictionary",
        }

    # Extract raw candidate fields
    raw_reason = str(
        payload.get("terminationReason")
        or payload.get("termination_reason")
        or payload.get("terminationCode")
        or payload.get("reason")
        or ""
    ).strip()

    raw_error = payload.get("error")
    error_str = ""
    if raw_error:
        if isinstance(raw_error, dict):
            error_str = str(raw_error.get("message") or raw_error.get("error") or str(raw_error)).strip()
        else:
            error_str = str(raw_error).strip()

    status_str = str(payload.get("status") or "").strip().lower()
    fully_idle = payload.get("fullyIdle")

    clean_reason = raw_reason.lower()
    # Normalize underscores and hyphens
    norm_token = clean_reason.replace("-", "_").strip()

    details = {
        "rawReason": raw_reason,
        "rawError": error_str,
        "status": status_str,
        "fullyIdle": fully_idle,
        "cleanToken": norm_token,
    }

    # 1. User Cancellation
    if norm_token in KNOWN_USER_CANCEL_PATTERNS or any(p in norm_token for p in ["cancel", "abort"]):
        details["classificationRationale"] = "Matched user cancellation pattern"
        return TerminationClass.USER_CANCELLED, details

    # 2. Max Steps
    if norm_token in KNOWN_MAX_STEPS_PATTERNS or any(p in norm_token for p in ["max_steps", "step_limit", "max_turns"]):
        details["classificationRationale"] = "Matched max steps pattern"
        return TerminationClass.MAX_STEPS, details

    # 3. External Error / Network / Server Failure
    # If explicit error field is present and non-empty
    if error_str:
        details["classificationRationale"] = "Payload contains non-empty error field"
        return TerminationClass.EXTERNAL_ERROR, details

    if status_str in {"error", "failed", "crashed", "timeout"}:
        details["classificationRationale"] = f"Payload status is '{status_str}'"
        return TerminationClass.EXTERNAL_ERROR, details

    if norm_token in KNOWN_EXTERNAL_ERROR_PATTERNS or any(
        err_kw in norm_token for err_kw in ["network", "server", "timeout", "connection", "rate_limit", "quota", "transport", "socket"]
    ):
        details["classificationRationale"] = "Matched external error reason pattern"
        return TerminationClass.EXTERNAL_ERROR, details

    # 4. Normal Model Stop
    if not norm_token or norm_token in KNOWN_NORMAL_STOP_PATTERNS:
        details["classificationRationale"] = "Normal model completion"
        return TerminationClass.NORMAL_MODEL_STOP, details

    # 5. Unknown abnormal termination
    details["classificationRationale"] = f"Unrecognized termination token '{norm_token}'"
    return TerminationClass.UNKNOWN_TERMINATION, details


# ---------------------------------------------------------------------------
# State Progress Fingerprinting & Circuit Breaker
# ---------------------------------------------------------------------------

def get_circuit_breaker_path(workspace_dir: Union[str, Path]) -> Path:
    return Path(workspace_dir).resolve() / ".agent-harness" / CIRCUIT_BREAKER_FILENAME


def compute_state_progress_fingerprint(workspace_dir: Union[str, Path]) -> str:
    """
    Computes a deterministic cryptographic hash representing current engineering progress.
    Combines:
    - workspace code fingerprint
    - requirement status dictionary
    - evidence event count
    - active phase & lock states
    """
    ws = Path(workspace_dir).resolve()
    harness_dir = ws / ".agent-harness"

    # 1. Requirements status map
    req_map = {}
    req_file = harness_dir / "requirements.json"
    if req_file.exists():
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                reqs = json.load(f)
                if isinstance(reqs, list):
                    for r in sorted(reqs, key=lambda x: str(x.get("id", ""))):
                        if isinstance(r, dict) and r.get("id"):
                            req_map[r["id"]] = {
                                "status": r.get("status", "NOT_STARTED"),
                                "verifiedFp": r.get("lastVerifiedFingerprint", ""),
                            }
        except Exception:
            pass

    # 2. Evidence count
    ev_count = 0
    ev_file = harness_dir / "evidence.jsonl"
    if ev_file.exists():
        try:
            with open(ev_file, "r", encoding="utf-8") as f:
                ev_count = sum(1 for line in f if line.strip())
        except Exception:
            pass

    # 3. State phase & locks
    phase = "UNKNOWN"
    spec_locked = False
    acceptance_locked = False
    state_file = harness_dir / "state.json"
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                st = json.load(f)
                phase = st.get("phase", "UNKNOWN")
                spec_locked = bool(st.get("specLocked", False))
                acceptance_locked = bool(st.get("acceptanceLocked", False))
        except Exception:
            pass

    # 4. Code / file hashes if available via fingerprint module
    code_fp = "NO_FINGERPRINT"
    fp_mod = None
    try:
        from . import fingerprint
        fp_mod = fingerprint
    except (ImportError, ValueError):
        try:
            import fingerprint
            fp_mod = fingerprint
        except ImportError:
            fp_mod = None

    if fp_mod is not None:
        try:
            code_fp = fp_mod.compute_workspace_fingerprint(ws)
        except Exception:
            pass

    composite = {
        "phase": phase,
        "specLocked": spec_locked,
        "acceptanceLocked": acceptance_locked,
        "evidenceCount": ev_count,
        "requirements": req_map,
        "codeFingerprint": code_fp,
    }

    canonical_bytes = json.dumps(composite, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def load_circuit_breaker(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    cb_path = get_circuit_breaker_path(workspace_dir)
    if not cb_path.exists():
        return {
            "automaticContinueCount": 0,
            "lastStateFingerprint": None,
            "lastTerminationClass": None,
            "lastContinueTimestamp": None,
            "tripped": False,
            "tripReason": None,
            "maxContinues": DEFAULT_MAX_AUTOMATIC_CONTINUES,
        }
    try:
        with open(cb_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "automaticContinueCount": 0,
            "lastStateFingerprint": None,
            "lastTerminationClass": None,
            "lastContinueTimestamp": None,
            "tripped": False,
            "tripReason": None,
            "maxContinues": DEFAULT_MAX_AUTOMATIC_CONTINUES,
        }


def save_circuit_breaker(workspace_dir: Union[str, Path], data: Dict[str, Any]) -> None:
    cb_path = get_circuit_breaker_path(workspace_dir)
    cb_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = cb_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_path, cb_path)


def evaluate_circuit_breaker(
    workspace_dir: Union[str, Path],
    conversation_id: Optional[str] = None,
    max_continues: int = DEFAULT_MAX_AUTOMATIC_CONTINUES,
) -> Tuple[bool, int, str]:
    """
    Evaluates whether an automatic continue is permitted or if the circuit breaker trips.
    Returns:
    (can_continue: bool, current_count: int, reason: str)
    """
    ws = Path(workspace_dir).resolve()
    cb_data = load_circuit_breaker(ws)
    current_fp = compute_state_progress_fingerprint(ws)
    last_fp = cb_data.get("lastStateFingerprint")
    current_count = int(cb_data.get("automaticContinueCount", 0))

    # Check for progress
    if last_fp is None or current_fp != last_fp:
        # Progress has occurred (or first evaluation)! Reset counter.
        cb_data["automaticContinueCount"] = 0
        cb_data["lastStateFingerprint"] = current_fp
        cb_data["lastContinueTimestamp"] = utc_now_iso()
        cb_data["tripped"] = False
        cb_data["tripReason"] = None
        cb_data["maxContinues"] = max_continues
        save_circuit_breaker(ws, cb_data)
        return True, 0, "Engineering progress detected; circuit breaker counter reset"

    # Fingerprint is IDENTICAL: no progress made since last Stop
    current_count += 1
    cb_data["automaticContinueCount"] = current_count
    cb_data["lastContinueTimestamp"] = utc_now_iso()

    if current_count >= max_continues:
        # Trip circuit breaker
        trip_reason = (
            f"Maximum automatic continues without progress ({max_continues}) reached. "
            f"State fingerprint remained identical ({current_fp[:12]}). Pausing execution."
        )
        cb_data["tripped"] = True
        cb_data["tripReason"] = trip_reason
        save_circuit_breaker(ws, cb_data)
        return False, current_count, trip_reason

    # Bounded continue allowed
    cb_data["tripped"] = False
    cb_data["tripReason"] = None
    save_circuit_breaker(ws, cb_data)
    return True, current_count, f"Automatic continue {current_count}/{max_continues} permitted"


def reset_circuit_breaker(workspace_dir: Union[str, Path]) -> None:
    ws = Path(workspace_dir).resolve()
    cb_data = load_circuit_breaker(ws)
    cb_data["automaticContinueCount"] = 0
    cb_data["tripped"] = False
    cb_data["tripReason"] = None
    save_circuit_breaker(ws, cb_data)


# ---------------------------------------------------------------------------
# Privacy-Safe Runtime Event Ledger (.agent-harness/runtime-events.jsonl)
# ---------------------------------------------------------------------------

def get_runtime_events_path(workspace_dir: Union[str, Path]) -> Path:
    return Path(workspace_dir).resolve() / ".agent-harness" / RUNTIME_EVENTS_FILENAME


def compute_runtime_event_hash(entry: Dict[str, Any]) -> str:
    canonical = {
        "previousHash": str(entry.get("previousHash", "GENESIS")),
        "eventId": str(entry.get("eventId", "")),
        "timestamp": str(entry.get("timestamp", "")),
        "eventType": str(entry.get("eventType", "")),
        "terminationClass": str(entry.get("terminationClass", "")),
        "phase": str(entry.get("phase", "")),
        "runtimeStatus": str(entry.get("runtimeStatus", "")),
        "decision": str(entry.get("decision", "")),
        "continueCount": int(entry.get("continueCount", 0)),
        "stateFingerprint": str(entry.get("stateFingerprint", "")),
        "conversationIdHash": str(entry.get("conversationIdHash", "")),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record_runtime_event(
    workspace_dir: Union[str, Path],
    event_type: str,
    termination_class: str,
    raw_reason: Optional[str] = None,
    phase: Optional[str] = None,
    runtime_status: Optional[str] = None,
    decision: Optional[str] = None,
    continue_count: int = 0,
    state_fingerprint: Optional[str] = None,
    conversation_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Appends a privacy-safe, SHA-256 chained runtime event to .agent-harness/runtime-events.jsonl.
    Zero prompts, zero transcripts, zero source code contents, zero secrets.
    """
    ws = Path(workspace_dir).resolve()
    ev_path = get_runtime_events_path(ws)
    ev_path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = "GENESIS"
    event_count = 0
    if ev_path.exists():
        try:
            with open(ev_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str:
                        event_count += 1
                        try:
                            last_rec = json.loads(line_str)
                            previous_hash = last_rec.get("eventHash", previous_hash)
                        except Exception:
                            pass
        except Exception:
            pass

    event_seq = event_count + 1
    event_id = f"rt-evt-{event_seq:04d}-{hashlib.sha256(f'{event_seq}-{utc_now_iso()}'.encode()).hexdigest()[:8]}"
    
    cid_hash = ""
    if conversation_id:
        cid_hash = hashlib.sha256(str(conversation_id).encode("utf-8")).hexdigest()[:16]

    clean_reason = ""
    if raw_reason:
        clean_reason = str(raw_reason)[:200].replace("\n", " ").strip()

    entry: Dict[str, Any] = {
        "eventId": event_id,
        "previousHash": previous_hash,
        "timestamp": utc_now_iso(),
        "eventType": str(event_type),
        "terminationClass": str(termination_class),
        "rawReason": clean_reason,
        "phase": str(phase or "UNKNOWN"),
        "runtimeStatus": str(runtime_status or "RUNNING"),
        "decision": str(decision or "allow"),
        "continueCount": int(continue_count),
        "stateFingerprint": str(state_fingerprint or ""),
        "conversationIdHash": cid_hash,
    }

    if details and isinstance(details, dict):
        safe_details = {k: str(v)[:200] for k, v in details.items() if k not in {"prompt", "content", "transcript"}}
        entry["metadata"] = safe_details

    entry["eventHash"] = compute_runtime_event_hash(entry)

    with open(ev_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")

    return entry


def verify_runtime_events_integrity(workspace_dir: Union[str, Path]) -> Tuple[bool, List[str]]:
    """Verifies continuous SHA-256 hash chaining of runtime-events.jsonl."""
    ws = Path(workspace_dir).resolve()
    ev_path = get_runtime_events_path(ws)
    if not ev_path.exists():
        return True, []

    errors: List[str] = []
    expected_prev = "GENESIS"
    with open(ev_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                rec = json.loads(line_str)
            except Exception as e:
                errors.append(f"Line {idx}: JSON parse error: {e}")
                continue

            if rec.get("previousHash") != expected_prev:
                errors.append(
                    f"Line {idx} ({rec.get('eventId')}): previousHash mismatch. "
                    f"Expected '{expected_prev}', got '{rec.get('previousHash')}'"
                )

            recorded_hash = rec.get("eventHash")
            computed = compute_runtime_event_hash(rec)
            if recorded_hash != computed:
                errors.append(
                    f"Line {idx} ({rec.get('eventId')}): eventHash tampering detected. "
                    f"Recorded '{recorded_hash}', computed '{computed}'"
                )

            expected_prev = recorded_hash or computed

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Deterministic Resume Semantics
# ---------------------------------------------------------------------------

def resume_harness(workspace_dir: Union[str, Path]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Deterministic resume operation for a paused or interrupted Strict Engineering project.
    Invariants:
    - Never reinitializes project
    - Never duplicates requirements
    - Validates original intent integrity
    - Re-evaluates requirement freshness (invalidates stale if code changed)
    - Clears pause status back to RUNNING
    - Resets circuit breaker continue counter
    - Preserves all valid verified PASS statuses
    """
    ws = Path(workspace_dir).resolve()
    harness_dir = ws / ".agent-harness"
    state_file = harness_dir / "state.json"

    if not state_file.exists():
        return False, "Cannot resume: .agent-harness/state.json not found", {}

    try:
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception as e:
        return False, f"Cannot resume: failed to read state.json: {e}", {}

    # 1. Verify Original Intent Integrity
    orig_file = harness_dir / "original-request.md"
    orig_sha_file = harness_dir / "original-request.sha256"
    if orig_file.exists() and orig_sha_file.exists():
        try:
            with open(orig_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            with open(orig_sha_file, "r", encoding="utf-8") as f:
                expected_sha = f.read().strip()
            actual_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if actual_sha != expected_sha:
                return False, "Cannot resume: original-request.md SHA-256 integrity check failed", state
        except Exception as e:
            return False, f"Cannot resume: error verifying original intent: {e}", state

    # 2. Check and invalidate stale requirements if code was touched while paused
    k_mod = None
    try:
        from . import kernel
        k_mod = kernel
    except (ImportError, ValueError):
        try:
            import kernel
            k_mod = kernel
        except ImportError:
            k_mod = None

    if k_mod is not None and hasattr(k_mod, "check_and_invalidate_stale"):
        try:
            k_mod.check_and_invalidate_stale(ws)
        except Exception:
            pass

    # 3. Reset circuit breaker
    reset_circuit_breaker(ws)

    # 4. Clear transient pause markers while preserving phase
    current_phase = state.get("phase", "IMPLEMENTATION")
    prev_status = state.get("runtimeStatus", RuntimeStatus.RUNNING)

    if current_phase != "COMPLETE":
        state["active"] = True
        state["runtimeStatus"] = RuntimeStatus.RUNNING
        state["pauseReason"] = None
        state["resumedAt"] = utc_now_iso()
        state["updatedAt"] = utc_now_iso()

        temp_file = state_file.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(temp_file, state_file)

    # 5. Record runtime event
    record_runtime_event(
        workspace_dir=ws,
        event_type="RESUME_EXECUTED",
        termination_class="N/A",
        raw_reason=f"Resumed from {prev_status}",
        phase=current_phase,
        runtime_status=state.get("runtimeStatus", RuntimeStatus.RUNNING),
        decision="allow",
        state_fingerprint=compute_state_progress_fingerprint(ws),
    )

    msg = f"Strict Engineering Harness successfully resumed in phase '{current_phase}' (prior status: '{prev_status}')"
    return True, msg, state


def pause_harness(
    workspace_dir: Union[str, Path],
    reason: str = "Paused via CLI",
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Deterministic pause operation for an active Strict Engineering project.
    Invariants:
    - Never unlocks acceptance
    - Never alters requirements
    - Never erases evidence
    - Never fabricates completion
    - Updates runtimeStatus to PAUSED_USER_REQUEST
    - Records PAUSE_EXECUTED in runtime-events.jsonl
    """
    ws = Path(workspace_dir).resolve()
    harness_dir = ws / ".agent-harness"
    state_file = harness_dir / "state.json"

    if not state_file.exists():
        return False, "Cannot pause: .agent-harness/state.json not found", {}

    try:
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception as e:
        return False, f"Cannot pause: failed to read state.json: {e}", {}

    current_phase = state.get("phase", "IMPLEMENTATION")
    if current_phase == "COMPLETE":
        return False, "Cannot pause: project is already COMPLETE", state

    prev_status = state.get("runtimeStatus", RuntimeStatus.RUNNING)
    new_status = RuntimeStatus.PAUSED_USER_REQUEST

    state["runtimeStatus"] = new_status
    state["pauseReason"] = reason
    state["pausedAt"] = utc_now_iso()
    state["updatedAt"] = utc_now_iso()

    temp_file = state_file.with_suffix(".tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(temp_file, state_file)

    # Record runtime event
    record_runtime_event(
        workspace_dir=ws,
        event_type="PAUSE_EXECUTED",
        termination_class="USER_REQUESTED",
        raw_reason=reason,
        phase=current_phase,
        runtime_status=new_status,
        decision="allow",
        state_fingerprint=compute_state_progress_fingerprint(ws),
    )

    msg = f"Strict Engineering Harness paused in phase '{current_phase}' (prior status: '{prev_status}', reason: '{reason}')"
    return True, msg, state

