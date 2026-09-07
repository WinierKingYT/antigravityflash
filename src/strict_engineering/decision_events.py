"""
Strict Engineering Kernel Step 7 - Append-Only Cryptographic Decision Events Ledger
Maintains .agent-harness/decision-events.jsonl with SHA-256 hash chaining,
event validation, and cryptographic tamper-evidence verification.
"""

import os
import json
import uuid
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

DECISION_EVENT_TYPES = [
    "FRAME_CREATED",
    "CONCERN_DISCOVERED",
    "CONCERN_UPDATED",
    "QUESTION_ASKED",
    "USER_DECISION_RECORDED",
    "USER_UNCERTAINTY_RECORDED",
    "USER_REJECTION_RECORDED",
    "DELEGATION_RESTRICTED_HIGH_RISK",
    "SAFE_INFERENCE_RECORDED",
    "DECISION_SUPERSEDED",
    "CONCERN_RESOLVED",
    "CONCERN_DEFERRED",
    "CONSISTENCY_CONFLICT",
    "DISCOVERY_STOP_PROPOSED",
    "DISCOVERY_STOP_ACCEPTED",
    "REQUIREMENTS_GENERATED",
    "SEMANTIC_CONCERN_PROPOSAL_INGESTED",
    "SEMANTIC_CONCERNS_INGESTED",
]

GENESIS_HASH = "0" * 64


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_decision_events_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to decision-events.jsonl in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "decision-events.jsonl"


def compute_decision_event_hash(entry: Dict[str, Any]) -> str:
    """
    Compute cryptographic SHA-256 hash over canonical representation of decision event fields.
    """
    canonical_payload = {
        "previousHash": str(entry.get("previousHash", GENESIS_HASH)),
        "eventId": str(entry.get("eventId", "")),
        "timestamp": str(entry.get("timestamp", "")),
        "eventType": str(entry.get("eventType", "")),
        "payload": entry.get("payload", {}),
        "actor": str(entry.get("actor", "decision-engine")),
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def get_last_decision_event_hash(workspace_dir: Union[str, Path]) -> str:
    """
    Read the last event in decision-events.jsonl and return its eventHash.
    Returns GENESIS_HASH ('0'*64) if file does not exist or is empty.
    """
    events_file = get_decision_events_path(workspace_dir)
    if not events_file.exists() or events_file.stat().st_size == 0:
        return GENESIS_HASH

    last_hash = GENESIS_HASH
    try:
        with open(events_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    if "eventHash" in entry:
                        last_hash = entry["eventHash"]
    except Exception:
        pass
    return last_hash


def record_decision_event(
    workspace_dir: Union[str, Path],
    event_type: str,
    payload: Dict[str, Any],
    actor: str = "decision-engine",
) -> Dict[str, Any]:
    """
    Append a new cryptographically chained event to .agent-harness/decision-events.jsonl.
    Validates eventType, connects previousHash, computes eventHash, and appends to the file.
    Returns the created event dictionary.
    """
    clean_type = str(event_type).strip().upper()
    if clean_type not in DECISION_EVENT_TYPES:
        raise ValueError(f"Invalid eventType '{event_type}'. Allowed: {DECISION_EVENT_TYPES}")

    events_file = get_decision_events_path(workspace_dir)
    events_file.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = get_last_decision_event_hash(workspace_dir)
    event_id = f"DEV-{uuid.uuid4().hex[:8].upper()}"
    timestamp = utc_now_iso()

    entry = {
        "eventId": event_id,
        "timestamp": timestamp,
        "eventType": clean_type,
        "payload": payload if isinstance(payload, dict) else {"data": payload},
        "actor": str(actor).strip(),
        "previousHash": previous_hash,
    }

    entry["eventHash"] = compute_decision_event_hash(entry)

    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with open(events_file, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())

    return entry


def load_decision_events(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load all decision events from .agent-harness/decision-events.jsonl.
    Returns empty list if file does not exist.
    """
    events_file = get_decision_events_path(workspace_dir)
    if not events_file.exists():
        return []

    events: List[Dict[str, Any]] = []
    try:
        with open(events_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except Exception:
        pass
    return events


def verify_decision_events_integrity(workspace_dir: Union[str, Path]) -> Tuple[bool, List[str]]:
    """
    Cryptographically validate the entire SHA-256 decision events chain in decision-events.jsonl.
    Checks:
    1. Genesis previousHash equals '0' * 64.
    2. Hash continuity: previousHash matches prior event's eventHash.
    3. Content integrity: recalculated canonical eventHash matches stored eventHash.
    4. Required schema fields and valid eventType.
    Returns (isValid, errors).
    """
    events_file = get_decision_events_path(workspace_dir)
    if not events_file.exists() or events_file.stat().st_size == 0:
        return True, []

    errors: List[str] = []
    expected_prev = GENESIS_HASH
    entry_count = 0

    try:
        with open(events_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception as e:
                    errors.append(f"Malformed JSON at line {idx + 1}: {e}")
                    continue

                entry_count += 1
                eid = entry.get("eventId", f"UNKNOWN-{idx}")

                # Required fields
                for req_f in ["eventId", "timestamp", "eventType", "payload", "actor", "previousHash", "eventHash"]:
                    if req_f not in entry:
                        errors.append(f"Event {idx} ({eid}) missing required field '{req_f}'.")

                # Event type validation
                ev_type = entry.get("eventType")
                if ev_type not in DECISION_EVENT_TYPES:
                    errors.append(f"Event {idx} ({eid}) has invalid eventType '{ev_type}'.")

                # Previous hash continuity
                actual_prev = entry.get("previousHash")
                if actual_prev != expected_prev:
                    errors.append(
                        f"Hash chain broken at event {idx} ({eid}): expected previousHash '{expected_prev}', found '{actual_prev}'."
                    )

                # Event hash verification
                actual_event_hash = entry.get("eventHash")
                computed_hash = compute_decision_event_hash(entry)
                if actual_event_hash != computed_hash:
                    errors.append(
                        f"Event tamper detected at event {idx} ({eid}): computed hash '{computed_hash}', recorded '{actual_event_hash}'."
                    )

                expected_prev = actual_event_hash

    except Exception as e:
        errors.append(f"Error reading decision events ledger: {e}")

    return len(errors) == 0, errors
