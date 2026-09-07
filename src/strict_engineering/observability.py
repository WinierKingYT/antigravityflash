"""
Strict Engineering Kernel V1.2.0 - Privacy-Safe Global Observability Engine
Provides bounded, privacy-safe runtime event logging and diagnostics across
hook invocations, latencies, termination classes, circuit breaker trips, and lifecycle events.
Guarantees:
- Zero prompt, transcript, source code, token, or credential leakage
- Bounded log file growth with automatic rotation (max 2 MB)
- Fail-safe execution: logging errors never interrupt hooks or kernel execution
"""

import os
import sys
import json
import re
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

DEFAULT_MAX_LOG_BYTES = 2 * 1024 * 1024  # 2 MB
OBSERVABILITY_FILENAME = "observability.jsonl"

FORBIDDEN_KEY_SUBSTRINGS = (
    "prompt",
    "transcript",
    "content",
    "source",
    "code",
    "token",
    "secret",
    "password",
    "auth",
    "bearer",
    "credential",
    "api_key",
    "apikey",
)

SECRET_SCRUB_RULES = [
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?'), r"\1: [REDACTED_SECRET]"),
    (re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{12,})'), r"\1[REDACTED_SECRET]"),
    (re.compile(r'(?i)(ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{22,})'), r"[REDACTED_SECRET]"),
    (re.compile(r'(?i)(sk-[a-zA-Z0-9]{20,})'), r"[REDACTED_SECRET]"),
]


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def scrub_string(text: Optional[str]) -> str:
    """Scrub sensitive credentials, tokens, and keys from string values."""
    if not text:
        return ""
    scrubbed = str(text)
    for pat, repl in SECRET_SCRUB_RULES:
        scrubbed = pat.sub(repl, scrubbed)
    return scrubbed


def sanitize_observability_data(data: Any) -> Any:
    """
    Recursively sanitize dictionaries/lists to ensure zero private prompts,
    transcripts, source code, or credentials can be persisted to logs.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(forbidden in k_lower for forbidden in FORBIDDEN_KEY_SUBSTRINGS):
                continue
            sanitized[k] = sanitize_observability_data(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_observability_data(item) for item in data]
    elif isinstance(data, str):
        # Truncate overly long strings to prevent accidental text payload dumps
        cleaned = scrub_string(data)
        if len(cleaned) > 256:
            cleaned = cleaned[:253] + "..."
        return cleaned
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        return scrub_string(str(data))


def get_default_observability_dir(gemini_dir: Optional[Path] = None) -> Path:
    if gemini_dir is None:
        gemini_dir = Path.home() / ".gemini"
    target_dir = Path(gemini_dir).resolve() / "config" / "strict-engineering"
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def rotate_log_if_needed(log_file: Path, max_bytes: int = DEFAULT_MAX_LOG_BYTES) -> None:
    """Rotate log file if it exceeds max_bytes, keeping at most 2 historical files."""
    try:
        if not log_file.exists():
            return
        if log_file.stat().st_size >= max_bytes:
            bak2 = log_file.with_suffix(".jsonl.2")
            bak1 = log_file.with_suffix(".jsonl.1")
            if bak1.exists():
                if bak2.exists():
                    bak2.unlink()
                bak1.rename(bak2)
            log_file.rename(bak1)
    except Exception:
        # Non-blocking: fail-safe
        pass


def record_global_event(
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    workspace: Optional[Union[str, Path]] = None,
    latency_ms: Optional[float] = None,
    gemini_dir: Optional[Path] = None,
) -> bool:
    """
    Record an operational event in the global observability log.
    Never throws an unhandled exception.
    """
    try:
        log_dir = get_default_observability_dir(gemini_dir)
        log_file = log_dir / OBSERVABILITY_FILENAME

        rotate_log_if_needed(log_file)

        project_name = None
        if workspace:
            project_name = Path(workspace).name

        sanitized_details = sanitize_observability_data(details or {})

        event = {
            "eventId": f"EVT-{os.urandom(6).hex()}",
            "timestamp": utc_now_iso(),
            "eventType": str(event_type),
            "projectName": project_name,
            "latencyMs": round(latency_ms, 2) if latency_ms is not None else None,
            "details": sanitized_details,
        }

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        return True
    except Exception as e:
        # Non-blocking fail-safe
        try:
            sys.stderr.write(f"[Strict-Engineering-Observability] Notice: failed recording event: {e}\n")
        except Exception:
            pass
        return False


def load_global_events(
    limit: int = 50,
    event_type: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Load recent global operational events safely."""
    try:
        log_dir = get_default_observability_dir(gemini_dir)
        log_file = log_dir / OBSERVABILITY_FILENAME
        if not log_file.exists():
            return []

        events = []
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    if event_type and ev.get("eventType") != event_type:
                        continue
                    events.append(ev)
                except Exception:
                    continue

        return events[-limit:]
    except Exception:
        return []


def get_latency_summary(gemini_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Calculate summary statistics for recent hook latencies."""
    events = load_global_events(limit=200, gemini_dir=gemini_dir)
    latencies = [
        ev["latencyMs"]
        for ev in events
        if isinstance(ev.get("latencyMs"), (int, float))
    ]
    if not latencies:
        return {
            "count": 0,
            "p50Ms": 0.0,
            "p95Ms": 0.0,
            "maxMs": 0.0,
            "avgMs": 0.0,
        }
    latencies.sort()
    n = len(latencies)
    p50_idx = int(n * 0.5)
    p95_idx = min(int(n * 0.95), n - 1)
    return {
        "count": n,
        "p50Ms": round(latencies[p50_idx], 2),
        "p95Ms": round(latencies[p95_idx], 2),
        "maxMs": round(latencies[-1], 2),
        "avgMs": round(sum(latencies) / n, 2),
    }
