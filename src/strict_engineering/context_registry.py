"""Runtime Context Proof & Registry for Strict Engineering Kernel (Step 6S.1).

Enforces:
- Cryptographic hash-chained registry of runtime contexts (.agent-harness/context-registry.jsonl)
- Invalidation of caller-claimed context freshness
- Mechanical cross-checks between conversationId, transcriptPath, and artifactDirectoryPath
- Pairwise context inequality enforcement (builder != verifier != counterexample)
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


CONTEXT_REGISTRY_FILENAME = "context-registry.jsonl"
EXPECTED_CONTEXT_FILENAME = "expected-context.json"
VALID_CONTEXT_PURPOSES = {
    "BUILDER",
    "BLIND_FINAL_VERIFIER",
    "COUNTEREXAMPLE_AUDITOR",
    "ADVERSARIAL_REVIEWER",
    "GENERAL",
    "SPEC_ARCHITECT",
    "SCOPE_AUDITOR",
    "TEST_ORACLE",
}
VALID_ORIGINS = {
    "ANTIGRAVITY_RUNTIME_HOOK",
    "MOCK",
    "SIMULATED_INTEGRATION",
    "UNTRUSTED_CALLER",
}
VALID_RUNTIME_ORIGIN_STATUSES = {
    "TRUSTED_HOOK_PATH",
    "UNTRUSTED_CALLER",
    "SIMULATED_PATH",
}
VALID_BINDING_STATUSES = {
    "EXPECTATION_CONSUMED",
    "EXPECTATION_ALREADY_BOUND",
    "NO_EXPECTATION",
    "EXPECTATION_REPLAY_REJECTED",
    "FIRST_INVOCATION_MISSED",
    "CONTEXT_IDENTITY_INVALID",
    "SIMULATED_BINDING",
}


def get_context_registry_path(workspace_dir: Union[str, Path]) -> Path:
    """Returns path to .agent-harness/context-registry.jsonl."""
    harness_dir = Path(workspace_dir) / ".agent-harness"
    return harness_dir / CONTEXT_REGISTRY_FILENAME


def get_expected_context_path(workspace_dir: Union[str, Path]) -> Path:
    """Returns path to .agent-harness/expected-context.json."""
    harness_dir = Path(workspace_dir) / ".agent-harness"
    return harness_dir / EXPECTED_CONTEXT_FILENAME


def compute_context_event_hash(entry: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash over canonical context entry fields."""
    canonical_payload = {
        "previousHash": str(entry.get("previousHash", "GENESIS")),
        "contextEventId": str(entry.get("contextEventId", "")),
        "taskId": str(entry.get("taskId", "")),
        "conversationId": str(entry.get("conversationId", "")),
        "transcriptPath": str(entry.get("transcriptPath", "")).replace("\\", "/"),
        "artifactDirectoryPath": str(entry.get("artifactDirectoryPath", "")).replace("\\", "/"),
        "workspacePaths": [str(p).replace("\\", "/") for p in sorted(entry.get("workspacePaths", []))],
        "modelName": str(entry.get("modelName", "")),
        "invocationNum": int(entry.get("invocationNum", 0)),
        "initialNumSteps": entry.get("initialNumSteps"),
        "contextPurpose": str(entry.get("contextPurpose", "")),
        "origin": str(entry.get("origin", "")),
        "runtimeOriginStatus": str(entry.get("runtimeOriginStatus", "")),
        "expectationId": str(entry.get("expectationId") or ""),
        "expectationPurpose": str(entry.get("expectationPurpose") or ""),
        "bindingStatus": str(entry.get("bindingStatus", "")),
        "observedAt": str(entry.get("observedAt", "")),
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def cross_check_paths_with_conversation_id(
    conversation_id: str,
    transcript_path: Optional[str] = None,
    artifact_directory_path: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Mechanically cross-checks transcriptPath and artifactDirectoryPath against conversationId."""
    if not conversation_id or not isinstance(conversation_id, str):
        return False, "CONTEXT_IDENTITY_INVALID: Missing or invalid conversationId"

    cid = conversation_id.strip()
    if not cid:
        return False, "CONTEXT_IDENTITY_INVALID: Empty conversationId"

    norm_cid = cid.lower()

    if transcript_path:
        norm_tp = str(transcript_path).replace("\\", "/").lower()
        if norm_cid not in norm_tp:
            return False, (
                f"CONTEXT_IDENTITY_INVALID: transcriptPath '{transcript_path}' "
                f"does not embed conversationId '{conversation_id}'"
            )

    if artifact_directory_path:
        norm_adp = str(artifact_directory_path).replace("\\", "/").lower()
        if norm_cid not in norm_adp:
            return False, (
                f"CONTEXT_IDENTITY_INVALID: artifactDirectoryPath '{artifact_directory_path}' "
                f"does not embed conversationId '{conversation_id}'"
            )

    return True, None


def load_context_registry(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """Loads all records from .agent-harness/context-registry.jsonl."""
    reg_path = get_context_registry_path(workspace_dir)
    if not reg_path.exists():
        return []
    records: List[Dict[str, Any]] = []
    with open(reg_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
                records.append(record)
            except json.JSONDecodeError:
                pass
    return records


def verify_context_registry(workspace_dir: Union[str, Path]) -> Tuple[bool, List[str]]:
    """Verifies cryptographic hash chain continuity and absence of tampering in registry."""
    reg_path = get_context_registry_path(workspace_dir)
    if not reg_path.exists():
        return True, []  # Empty/uninitialized registry is valid

    errors: List[str] = []
    records: List[Dict[str, Any]] = []
    with open(reg_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                records.append(json.loads(line_str))
            except json.JSONDecodeError as ex:
                errors.append(f"Line {idx}: JSONDecodeError: {str(ex)}")

    if errors:
        return False, errors

    expected_prev = "GENESIS"
    for idx, rec in enumerate(records):
        actual_prev = rec.get("previousHash")
        if actual_prev != expected_prev:
            errors.append(
                f"Record {idx} ({rec.get('contextEventId')}): previousHash mismatch. "
                f"Expected '{expected_prev}', got '{actual_prev}'"
            )

        recorded_hash = rec.get("eventHash")
        computed_hash = compute_context_event_hash(rec)
        if recorded_hash != computed_hash:
            errors.append(
                f"Record {idx} ({rec.get('contextEventId')}): eventHash mismatch. "
                f"Recorded '{recorded_hash}', computed '{computed_hash}'"
            )

        expected_prev = recorded_hash

    return (len(errors) == 0), errors


def load_context_expectation(workspace_dir: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Loads active context expectation if present, otherwise returns None."""
    exp_path = get_expected_context_path(workspace_dir)
    if not exp_path.exists():
        return None
    try:
        with open(exp_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def create_context_expectation(
    workspace_dir: Union[str, Path],
    expected_purpose: str,
    predecessor_conversation_ids: Optional[List[str]] = None,
    task_id: str = "TASK-STEP6S1",
) -> Dict[str, Any]:
    """
    Creates a protected single-use context expectation in .agent-harness/expected-context.json.
    Authorizes the next authentic PreInvocation hook from an independent conversation
    to bind a privileged verification role (BLIND_FINAL_VERIFIER or COUNTEREXAMPLE_AUDITOR).
    """
    if expected_purpose not in VALID_CONTEXT_PURPOSES:
        raise ValueError(f"Invalid expected_purpose: {expected_purpose}")

    harness_dir = Path(workspace_dir) / ".agent-harness"
    harness_dir.mkdir(parents=True, exist_ok=True)
    exp_path = get_expected_context_path(workspace_dir)

    created_at = datetime.now(timezone.utc).isoformat()
    raw_sig = f"{expected_purpose}:{task_id}:{created_at}"
    exp_id = f"exp-{expected_purpose.lower()}-{hashlib.sha256(raw_sig.encode()).hexdigest()[:8]}"

    predecessors = [str(c).strip() for c in (predecessor_conversation_ids or []) if str(c).strip()]

    # Automatically include all existing registered conversation IDs as predecessors
    existing_records = load_context_registry(workspace_dir)
    for rec in existing_records:
        cid = rec.get("conversationId", "").strip()
        if cid and cid not in predecessors:
            predecessors.append(cid)

    expectation = {
        "expectationId": exp_id,
        "taskId": str(task_id),
        "expectedPurpose": expected_purpose,
        "predecessorConversationIds": predecessors,
        "createdAt": created_at,
        "consumed": False,
        "consumedByConversationId": None,
        "consumedAt": None,
        "firstInvocationNum": None,
    }

    with open(exp_path, "w", encoding="utf-8") as f:
        json.dump(expectation, f, indent=2)

    return expectation


def consume_context_expectation(
    workspace_dir: Union[str, Path],
    conversation_id: str,
    invocation_num: int = 0,
    task_id: Optional[str] = None,
) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Evaluates and consumes an active context expectation.
    Returns (assigned_purpose, binding_status, expectation_id, expectation_purpose).
    """
    expectation = load_context_expectation(workspace_dir)
    if not expectation:
        # If no expectations exist and registry is empty, default initial conversation to BUILDER
        existing_records = load_context_registry(workspace_dir)
        if not existing_records:
            return "BUILDER", "NO_EXPECTATION", None, None
        return "GENERAL", "NO_EXPECTATION", None, None

    exp_id = expectation.get("expectationId")
    exp_purpose = expectation.get("expectedPurpose", "GENERAL")
    is_consumed = expectation.get("consumed", False)
    consumed_by = expectation.get("consumedByConversationId", "")
    predecessors = [p.lower() for p in expectation.get("predecessorConversationIds", [])]

    norm_cid = conversation_id.strip().lower()

    if is_consumed:
        if consumed_by and consumed_by.strip().lower() == norm_cid:
            return exp_purpose, "EXPECTATION_ALREADY_BOUND", exp_id, exp_purpose
        else:
            return "GENERAL", "EXPECTATION_REPLAY_REJECTED", exp_id, exp_purpose

    # Expectation is active (unconsumed)
    # 1. Predecessor / Builder inequality check
    if norm_cid in predecessors:
        return "GENERAL", "EXPECTATION_REPLAY_REJECTED", exp_id, exp_purpose

    # 2. First invocation rule (Section 10)
    if int(invocation_num) != 0:
        return "GENERAL", "FIRST_INVOCATION_MISSED", exp_id, exp_purpose

    # 3. Consume expectation
    expectation["consumed"] = True
    expectation["consumedByConversationId"] = conversation_id.strip()
    expectation["consumedAt"] = datetime.now(timezone.utc).isoformat()
    expectation["firstInvocationNum"] = int(invocation_num)

    exp_path = get_expected_context_path(workspace_dir)
    with open(exp_path, "w", encoding="utf-8") as f:
        json.dump(expectation, f, indent=2)

    return exp_purpose, "EXPECTATION_CONSUMED", exp_id, exp_purpose


def _ingest_antigravity_hook_context(
    workspace_dir: Union[str, Path],
    hook_payload: Dict[str, Any],
    event_type: str = "PreInvocation",
    task_id: str = "TASK-STEP6S1",
    _caller_boundary: str = "HOOKS_HANDLER_CLI",
) -> Dict[str, Any]:
    """
    Authoritative ingestion path for Antigravity runtime hook events.
    Strictly ignores caller-injected origin, role, or contextPurpose fields.
    Binds role dynamically through protected one-time context expectations.
    """
    reg_path = get_context_registry_path(workspace_dir)
    reg_path.parent.mkdir(parents=True, exist_ok=True)

    # Extract Antigravity runtime fields
    conv_id = (
        hook_payload.get("conversationId")
        or hook_payload.get("conversation_id")
        or hook_payload.get("conversationID")
        or ""
    )
    transcript_path = (
        hook_payload.get("transcriptPath")
        or hook_payload.get("transcript_path")
        or ""
    )
    artifact_dir = (
        hook_payload.get("artifactDirectoryPath")
        or hook_payload.get("artifact_directory_path")
        or hook_payload.get("artifactDirectory")
        or ""
    )
    workspace_paths = hook_payload.get("workspacePaths") or hook_payload.get("workspace_paths") or [str(workspace_dir)]
    if isinstance(workspace_paths, str):
        workspace_paths = [workspace_paths]

    model_name = hook_payload.get("modelName") or hook_payload.get("model_name") or hook_payload.get("model") or "unknown-model"
    inv_num = hook_payload.get("invocationNum", hook_payload.get("invocation_num", 0))
    initial_steps = hook_payload.get("initialNumSteps", hook_payload.get("initial_num_steps"))

    # Cross check paths
    path_valid, path_err = cross_check_paths_with_conversation_id(
        conv_id, transcript_path, artifact_dir
    )

    if not path_valid:
        assigned_purpose = "GENERAL"
        binding_status = "CONTEXT_IDENTITY_INVALID"
        exp_id = None
        exp_purpose = None
    else:
        # Evaluate expectation
        assigned_purpose, binding_status, exp_id, exp_purpose = consume_context_expectation(
            workspace_dir=workspace_dir,
            conversation_id=conv_id,
            invocation_num=int(inv_num),
            task_id=task_id,
        )

    # Replay protection: deduplicate identical (conversationId, invocationNum, contextPurpose)
    existing_records = load_context_registry(workspace_dir)
    for rec in existing_records:
        if (
            rec.get("conversationId") == str(conv_id)
            and rec.get("invocationNum") == int(inv_num)
            and rec.get("contextPurpose") == assigned_purpose
        ):
            return rec

    previous_hash = "GENESIS"
    if existing_records:
        previous_hash = existing_records[-1].get("eventHash", "GENESIS")

    event_seq = len(existing_records) + 1
    event_id = f"ctx-evt-{event_seq:04d}-{hashlib.sha256(f'{conv_id}-{event_seq}'.encode()).hexdigest()[:8]}"
    observed_at = datetime.now(timezone.utc).isoformat()

    origin = "ANTIGRAVITY_RUNTIME_HOOK"
    runtime_origin_status = "TRUSTED_HOOK_PATH"

    entry = {
        "contextEventId": event_id,
        "taskId": str(task_id),
        "conversationId": str(conv_id),
        "transcriptPath": str(transcript_path),
        "artifactDirectoryPath": str(artifact_dir),
        "workspacePaths": [str(p) for p in workspace_paths],
        "modelName": str(model_name),
        "invocationNum": int(inv_num),
        "initialNumSteps": int(initial_steps) if initial_steps is not None else None,
        "contextPurpose": assigned_purpose,
        "origin": origin,
        "runtimeOriginStatus": runtime_origin_status,
        "expectationId": exp_id,
        "expectationPurpose": exp_purpose,
        "bindingStatus": binding_status,
        "observedAt": observed_at,
        "previousHash": previous_hash,
    }

    event_hash = compute_context_event_hash(entry)
    entry["eventHash"] = event_hash

    with open(reg_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")

    return entry


def register_simulated_context(
    workspace_dir: Union[str, Path],
    hook_payload: Dict[str, Any],
    context_purpose: str = "GENERAL",
    origin: str = "SIMULATED_INTEGRATION",
    task_id: str = "TASK-STEP6S1",
) -> Dict[str, Any]:
    """
    Test and simulation context registration API.
    Refuses ANTIGRAVITY_RUNTIME_HOOK: callers cannot manufacture trusted runtime origin.
    Always assigns runtimeOriginStatus="SIMULATED_PATH" and bindingStatus="SIMULATED_BINDING".
    """
    if origin == "ANTIGRAVITY_RUNTIME_HOOK":
        raise ValueError(
            "Untrusted callers cannot register ANTIGRAVITY_RUNTIME_HOOK context. "
            "Trusted runtime hook events are ingested strictly via _ingest_antigravity_hook_context."
        )
    if origin not in {"SIMULATED_INTEGRATION", "MOCK"}:
        raise ValueError(f"Invalid simulated origin: {origin}. Must be MOCK or SIMULATED_INTEGRATION.")
    if context_purpose not in VALID_CONTEXT_PURPOSES:
        raise ValueError(f"Invalid context_purpose: {context_purpose}")

    reg_path = get_context_registry_path(workspace_dir)
    reg_path.parent.mkdir(parents=True, exist_ok=True)

    existing_records = load_context_registry(workspace_dir)
    previous_hash = "GENESIS"
    if existing_records:
        previous_hash = existing_records[-1].get("eventHash", "GENESIS")

    conv_id = (
        hook_payload.get("conversationId")
        or hook_payload.get("conversation_id")
        or hook_payload.get("conversationID")
        or ""
    )
    transcript_path = (
        hook_payload.get("transcriptPath")
        or hook_payload.get("transcript_path")
        or ""
    )
    artifact_dir = (
        hook_payload.get("artifactDirectoryPath")
        or hook_payload.get("artifact_directory_path")
        or hook_payload.get("artifactDirectory")
        or ""
    )
    workspace_paths = hook_payload.get("workspacePaths") or hook_payload.get("workspace_paths") or [str(workspace_dir)]
    if isinstance(workspace_paths, str):
        workspace_paths = [workspace_paths]

    model_name = hook_payload.get("modelName") or hook_payload.get("model_name") or hook_payload.get("model") or "mock-model"
    inv_num = hook_payload.get("invocationNum", hook_payload.get("invocation_num", 0))
    initial_steps = hook_payload.get("initialNumSteps", hook_payload.get("initial_num_steps"))

    event_seq = len(existing_records) + 1
    event_id = f"ctx-evt-{event_seq:04d}-{hashlib.sha256(f'{conv_id}-{event_seq}'.encode()).hexdigest()[:8]}"
    observed_at = datetime.now(timezone.utc).isoformat()

    entry = {
        "contextEventId": event_id,
        "taskId": str(task_id),
        "conversationId": str(conv_id),
        "transcriptPath": str(transcript_path),
        "artifactDirectoryPath": str(artifact_dir),
        "workspacePaths": [str(p) for p in workspace_paths],
        "modelName": str(model_name),
        "invocationNum": int(inv_num),
        "initialNumSteps": int(initial_steps) if initial_steps is not None else None,
        "contextPurpose": context_purpose,
        "origin": origin,
        "runtimeOriginStatus": "SIMULATED_PATH",
        "expectationId": None,
        "expectationPurpose": None,
        "bindingStatus": "SIMULATED_BINDING",
        "observedAt": observed_at,
        "previousHash": previous_hash,
    }

    event_hash = compute_context_event_hash(entry)
    entry["eventHash"] = event_hash

    with open(reg_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")

    return entry


def register_runtime_context(
    workspace_dir: Union[str, Path],
    hook_payload: Dict[str, Any],
    context_purpose: str = "GENERAL",
    origin: str = "ANTIGRAVITY_RUNTIME_HOOK",
    task_id: str = "TASK-STEP6S1",
) -> Dict[str, Any]:
    """
    Public registration entrypoint.
    Refuses attempts by callers to supply origin='ANTIGRAVITY_RUNTIME_HOOK'.
    Redirects simulated origins to register_simulated_context.
    """
    if origin == "ANTIGRAVITY_RUNTIME_HOOK":
        raise PermissionError(
            "Direct public registration of ANTIGRAVITY_RUNTIME_HOOK is forbidden. "
            "Antigravity runtime hook events are ingested strictly via _ingest_antigravity_hook_context. "
            "Test suites must use register_simulated_context with MOCK or SIMULATED_INTEGRATION."
        )
    return register_simulated_context(
        workspace_dir=workspace_dir,
        hook_payload=hook_payload,
        context_purpose=context_purpose,
        origin=origin,
        task_id=task_id,
    )


def get_registered_context_by_purpose(
    workspace_dir: Union[str, Path],
    purpose: str,
) -> Optional[Dict[str, Any]]:
    """Retrieves the latest verified registered context for a given purpose."""
    records = load_context_registry(workspace_dir)
    for rec in reversed(records):
        if rec.get("contextPurpose") == purpose:
            return rec
    return None


def get_all_registered_contexts(
    workspace_dir: Union[str, Path],
) -> List[Dict[str, Any]]:
    """Retrieves all registered contexts from the registry."""
    return load_context_registry(workspace_dir)


def evaluate_context_isolation(
    workspace_dir: Union[str, Path],
    verifier_purpose: str = "BLIND_FINAL_VERIFIER",
    predecessor_purposes: Optional[List[str]] = None,
    allow_simulated: bool = False,
) -> Tuple[str, Dict[str, Any]]:
    """Evaluates context isolation between verifier and predecessor roles.

    Returns status and details dictionary.
    Possible statuses:
    - FRESH_CONTEXT_VERIFIED
    - CONTEXT_ISOLATION_NOT_PROVEN
    - CONTEXT_IDENTITY_INVALID
    - CONTEXT_REUSED
    - CONTEXT_REGISTRY_CORRUPT
    """
    if predecessor_purposes is None:
        predecessor_purposes = ["BUILDER"]

    is_valid, errors = verify_context_registry(workspace_dir)
    if not is_valid:
        return "CONTEXT_REGISTRY_CORRUPT", {
            "status": "FAIL",
            "reason": "Context registry cryptographic chain validation failed",
            "errors": errors,
        }

    verifier_ctx = get_registered_context_by_purpose(workspace_dir, verifier_purpose)
    if not verifier_ctx:
        return "CONTEXT_ISOLATION_NOT_PROVEN", {
            "status": "FAIL",
            "reason": f"No registered runtime context found for verifier purpose '{verifier_purpose}'",
        }

    origin = verifier_ctx.get("origin", "")
    runtime_origin_status = verifier_ctx.get("runtimeOriginStatus", "")
    binding_status = verifier_ctx.get("bindingStatus", "")

    if origin not in VALID_ORIGINS:
        return "CONTEXT_ISOLATION_NOT_PROVEN", {
            "status": "FAIL",
            "reason": f"Untrusted context origin: '{origin}'",
        }

    if not allow_simulated:
        if origin != "ANTIGRAVITY_RUNTIME_HOOK" or runtime_origin_status != "TRUSTED_HOOK_PATH":
            return "UNTRUSTED_HOOK_INVOCATION", {
                "status": "FAIL",
                "reason": f"Context origin is not a trusted Antigravity runtime hook: origin='{origin}', runtimeOriginStatus='{runtime_origin_status}'",
            }
        if binding_status not in {"EXPECTATION_CONSUMED", "EXPECTATION_ALREADY_BOUND"}:
            return "CONTEXT_ROLE_BINDING_NOT_PROVEN", {
                "status": "FAIL",
                "reason": f"Context role '{verifier_purpose}' was not bound through a valid kernel expectation: bindingStatus='{binding_status}'",
            }
        if verifier_ctx.get("invocationNum", 0) != 0 and binding_status != "EXPECTATION_ALREADY_BOUND":
            return "CONTEXT_ROLE_BINDING_NOT_PROVEN", {
                "status": "FAIL",
                "reason": "First invocation rule violated: context role was not bound at invocationNum == 0",
            }
    else:
        if origin in {"MOCK", "SIMULATED_INTEGRATION"}:
            pass
        elif origin != "ANTIGRAVITY_RUNTIME_HOOK":
            return "CONTEXT_ISOLATION_NOT_PROVEN", {
                "status": "FAIL",
                "reason": f"Simulated context origin '{origin}' rejected in simulated mode",
            }

    verifier_cid = verifier_ctx.get("conversationId", "").strip()
    if not verifier_cid:
        return "CONTEXT_IDENTITY_INVALID", {
            "status": "FAIL",
            "reason": "Verifier context has empty conversationId",
        }

    # Cross check paths against conversationId
    path_valid, path_err = cross_check_paths_with_conversation_id(
        verifier_cid,
        verifier_ctx.get("transcriptPath"),
        verifier_ctx.get("artifactDirectoryPath"),
    )
    if not path_valid:
        return "CONTEXT_IDENTITY_INVALID", {
            "status": "FAIL",
            "reason": path_err,
        }

    # Pairwise inequality checks
    for pred_purpose in predecessor_purposes:
        pred_ctx = get_registered_context_by_purpose(workspace_dir, pred_purpose)
        if pred_ctx:
            pred_cid = pred_ctx.get("conversationId", "").strip()
            if pred_cid and pred_cid.lower() == verifier_cid.lower():
                return "CONTEXT_REUSED", {
                    "status": "FAIL",
                    "reason": (
                        f"Conversation ID '{verifier_cid}' was reused between "
                        f"'{verifier_purpose}' and '{pred_purpose}'"
                    ),
                    "verifier_purpose": verifier_purpose,
                    "predecessor_purpose": pred_purpose,
                    "reused_conversation_id": verifier_cid,
                }

    # If first invocation observed, note it
    is_first_invocation = (verifier_ctx.get("invocationNum") == 0)

    status_label = "FRESH_CONTEXT_SIMULATED" if (allow_simulated and origin in {"MOCK", "SIMULATED_INTEGRATION"}) else "FRESH_CONTEXT_VERIFIED"

    return status_label, {
        "status": "PASS",
        "verifier_purpose": verifier_purpose,
        "verifier_conversation_id": verifier_cid,
        "context_event_id": verifier_ctx.get("contextEventId"),
        "context_proof_hash": verifier_ctx.get("eventHash"),
        "origin": origin,
        "runtime_origin_status": runtime_origin_status,
        "binding_status": binding_status,
        "expectation_id": verifier_ctx.get("expectationId"),
        "is_first_invocation": is_first_invocation,
        "model_name": verifier_ctx.get("modelName"),
    }
